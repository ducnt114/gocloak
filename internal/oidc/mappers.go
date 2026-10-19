package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// Token kinds protocol mappers can target.
const (
	kindAccess        = "access"
	kindID            = "id"
	kindUserinfo      = "userinfo"
	kindIntrospection = "introspection"
)

// tokenContext is everything protocol mappers need to compute claims for
// one user, client and set of applied client scopes.
type tokenContext struct {
	svc     *service.Service
	realm   *model.Realm
	client  *model.Client
	user    *model.User
	session *model.UserSession
	base    string // server base URL

	scopes  []*model.ClientScope
	mappers []*model.ProtocolMapper
	notes   map[string]string // user session notes (AUTH_TIME, client_id, ...)

	realmRoles  []string
	clientRoles map[string][]string // clientId -> role names
	groups      []*model.Group      // lazily loaded
	groupPaths  map[string]string
}

// scopeError is returned for requested scopes the client may not use.
type scopeError struct{ scopes []string }

func (e *scopeError) Error() string { return "Invalid scopes: " + strings.Join(e.scopes, " ") }

// newTokenContext resolves the client scopes applied for the requested
// scope parameter, the mappers to run and the roles allowed in tokens. With
// strict, unknown requested scopes fail with a *scopeError (Keycloak's
// invalid_scope); otherwise they are ignored (refresh, userinfo).
func newTokenContext(ctx context.Context, svc *service.Service, base string, realm *model.Realm, client *model.Client,
	user *model.User, session *model.UserSession, requested string, strict bool) (*tokenContext, string, error) {
	st := svc.Store
	tc := &tokenContext{svc: svc, realm: realm, client: client, user: user, session: session, base: base,
		notes: map[string]string{}, clientRoles: map[string][]string{}}

	scopes, claim, invalid, err := resolveScopes(ctx, st, realm, client, requested)
	if err != nil {
		return nil, "", err
	}
	if strict && len(invalid) > 0 {
		return nil, "", &scopeError{invalid}
	}
	tc.scopes = scopes

	owners := []string{client.ID}
	for _, s := range tc.scopes {
		owners = append(owners, s.ID)
	}
	for _, owner := range owners {
		ms, err := st.ListMappers(ctx, owner)
		if err != nil {
			return nil, "", err
		}
		tc.mappers = append(tc.mappers, ms...)
	}

	if session != nil {
		for k, v := range session.Notes {
			tc.notes[k] = v
		}
	}
	if err := tc.resolveRoles(ctx); err != nil {
		return nil, "", err
	}
	return tc, claim, nil
}

// allScopes is the "scope" claim of refresh tokens: every applied client
// scope, including those not listed in access tokens (roles, acr...).
func (tc *tokenContext) allScopes(openid bool) string {
	var names []string
	if openid {
		names = append(names, "openid")
	}
	for _, s := range tc.scopes {
		names = append(names, s.Name)
	}
	return strings.Join(names, " ")
}

// resolveScopes returns the client scopes applied for a requested scope
// parameter (the client's default scopes plus the requested optional ones),
// the resulting "scope" claim, and the requested names the client may not use.
func resolveScopes(ctx context.Context, st *store.Store, realm *model.Realm, client *model.Client, requested string) ([]*model.ClientScope, string, []string, error) {
	all, err := st.ListClientScopes(ctx, realm.ID)
	if err != nil {
		return nil, "", nil, err
	}
	byID := map[string]*model.ClientScope{}
	for _, s := range all {
		byID[s.ID] = s
	}
	links, err := st.ListClientScopeLinks(ctx, client.ID)
	if err != nil {
		return nil, "", nil, err
	}
	var applied []*model.ClientScope
	optional := map[string]*model.ClientScope{}
	defaults := map[string]bool{}
	for _, l := range links {
		s := byID[l.ScopeID]
		if s == nil {
			continue
		}
		if l.Default {
			applied = append(applied, s)
			defaults[s.Name] = true
		} else {
			optional[s.Name] = s
		}
	}
	openid := false
	var invalid []string
	added := map[string]bool{}
	for _, name := range strings.Fields(requested) {
		switch {
		case name == "openid":
			openid = true
		case defaults[name] || added[name]:
		case optional[name] != nil:
			applied = append(applied, optional[name])
			added[name] = true
		default:
			invalid = append(invalid, name)
		}
	}
	sort.Slice(applied, func(i, j int) bool { return applied[i].Name < applied[j].Name })
	var claim []string
	if openid {
		claim = append(claim, "openid")
	}
	for _, s := range applied {
		if s.IncludeInTokenScope() {
			claim = append(claim, s.Name)
		}
	}
	return applied, strings.Join(claim, " "), invalid, nil
}

// resolveRoles computes the roles that may appear in tokens: the user's
// effective roles, limited by the client's scope when full scope is not
// allowed, then adjusted by hardcoded-role and role-name mappers.
func (tc *tokenContext) resolveRoles(ctx context.Context) error {
	st := tc.svc.Store
	roles, err := tc.svc.EffectiveRoles(ctx, tc.realm.ID, tc.user.ID)
	if err != nil {
		return err
	}
	if !tc.client.FullScopeAllowed {
		var scoped []*model.Role
		owners := []string{tc.client.ID}
		for _, s := range tc.scopes {
			owners = append(owners, s.ID)
		}
		for _, owner := range owners {
			rs, err := st.ListScopeMappings(ctx, owner)
			if err != nil {
				return err
			}
			scoped = append(scoped, rs...)
		}
		expanded, err := tc.svc.ExpandComposites(ctx, tc.realm.ID, scoped)
		if err != nil {
			return err
		}
		allowed := map[string]bool{}
		for _, r := range expanded {
			allowed[r.ID] = true
		}
		var kept []*model.Role
		for _, r := range roles {
			if r.ClientID == tc.client.ID || allowed[r.ID] {
				kept = append(kept, r)
			}
		}
		roles = kept
	}

	clientIDs := map[string]string{}
	realmSet := map[string]bool{}
	clientSet := map[string]map[string]bool{}
	addClientRole := func(clientID, name string) {
		if clientSet[clientID] == nil {
			clientSet[clientID] = map[string]bool{}
		}
		clientSet[clientID][name] = true
	}
	for _, r := range roles {
		if r.ClientID == "" {
			realmSet[r.Name] = true
			continue
		}
		cid, ok := clientIDs[r.ClientID]
		if !ok {
			c, err := st.GetClient(ctx, tc.realm.ID, r.ClientID)
			if err != nil {
				return err
			}
			cid = c.ClientID
			clientIDs[r.ClientID] = cid
		}
		addClientRole(cid, r.Name)
	}

	// "client.role" or "role" as used by the hardcoded-role and role-name mappers.
	split := func(ref string) (client, role string) {
		if i := strings.LastIndexByte(ref, '.'); i > 0 {
			if _, err := st.GetClientByClientID(ctx, tc.realm.ID, ref[:i]); err == nil {
				return ref[:i], ref[i+1:]
			}
		}
		return "", ref
	}
	for _, m := range tc.mappers {
		switch m.Type {
		case service.MapperHardcodedRole:
			if c, role := split(m.Config["role"]); role != "" {
				if c == "" {
					realmSet[role] = true
				} else {
					addClientRole(c, role)
				}
			}
		case service.MapperRoleName:
			c, role := split(m.Config["role"])
			newName := m.Config["new.role.name"]
			if role == "" || newName == "" {
				continue
			}
			nc, nr := c, newName
			if i := strings.LastIndexByte(newName, '.'); i > 0 {
				nc, nr = newName[:i], newName[i+1:]
			}
			if c == "" && realmSet[role] {
				delete(realmSet, role)
			} else if c != "" && clientSet[c][role] {
				delete(clientSet[c], role)
			} else {
				continue
			}
			if nc == "" {
				realmSet[nr] = true
			} else {
				addClientRole(nc, nr)
			}
		}
	}
	tc.realmRoles = sortedKeys(realmSet)
	for c, set := range clientSet {
		if len(set) > 0 {
			tc.clientRoles[c] = sortedKeys(set)
		}
	}
	return nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// includes reports whether mapper m contributes to the given token kind.
func includes(m *model.ProtocolMapper, kind string) bool {
	switch kind {
	case kindAccess:
		return m.Config["access.token.claim"] == "true"
	case kindID:
		return m.Config["id.token.claim"] == "true"
	case kindUserinfo:
		return m.Config["userinfo.token.claim"] == "true"
	case kindIntrospection:
		v, ok := m.Config["introspection.token.claim"]
		if !ok {
			return m.Config["access.token.claim"] == "true"
		}
		return v == "true"
	}
	return false
}

// apply runs every mapper targeting kind on claims.
func (tc *tokenContext) apply(ctx context.Context, claims jwt.Claims, kind string) error {
	for _, m := range tc.mappers {
		if !includes(m, kind) {
			continue
		}
		if err := tc.applyOne(ctx, m, claims, kind); err != nil {
			return err
		}
	}
	finalizeAudience(claims)
	return nil
}

func (tc *tokenContext) applyOne(ctx context.Context, m *model.ProtocolMapper, claims jwt.Claims, kind string) error {
	cfg := m.Config
	u := tc.user
	switch m.Type {
	case service.MapperUserProperty:
		if v, ok := userProperty(u, cfg["user.attribute"]); ok {
			setTyped(claims, cfg["claim.name"], v, cfg["jsonType.label"])
		}
	case service.MapperUserAttribute:
		values := u.Attributes[cfg["user.attribute"]]
		if len(values) == 0 {
			if v, ok := userProperty(u, cfg["user.attribute"]); ok && v != "" {
				values = []string{v}
			}
		}
		if len(values) == 0 {
			return nil
		}
		if cfg["multivalued"] == "true" {
			setClaim(claims, cfg["claim.name"], convertAll(values, cfg["jsonType.label"]))
		} else {
			setTyped(claims, cfg["claim.name"], values[0], cfg["jsonType.label"])
		}
	case service.MapperFullName:
		if name := strings.TrimSpace(u.FirstName + " " + u.LastName); name != "" {
			claims["name"] = name
		}
	case service.MapperAddress:
		addr := map[string]any{}
		for _, part := range []struct{ key, claim string }{
			{"formatted", "formatted"}, {"street", "street_address"}, {"locality", "locality"},
			{"region", "region"}, {"postal_code", "postal_code"}, {"country", "country"},
		} {
			attr := cfg["user.attribute."+part.key]
			if attr == "" {
				attr = part.key
			}
			if v := u.Attributes[attr]; len(v) > 0 {
				addr[part.claim] = v[0]
			}
		}
		claims["address"] = addr // Keycloak emits the object even when empty
	case service.MapperRealmRoles:
		if len(tc.realmRoles) == 0 {
			return nil
		}
		name := cfg["claim.name"]
		if name == "" {
			name = "realm_access.roles"
		}
		roles := prefixed(tc.realmRoles, strings.ReplaceAll(cfg["usermodel.realmRoleMapping.rolePrefix"], "${client_id}", tc.client.ClientID))
		setClaim(claims, name, multi(roles, cfg["multivalued"]))
	case service.MapperClientRoles:
		only := cfg["usermodel.clientRoleMapping.clientId"]
		name := cfg["claim.name"]
		if name == "" {
			name = "resource_access.${client_id}.roles"
		}
		for clientID, roles := range tc.clientRoles {
			if only != "" && only != clientID {
				continue
			}
			prefix := strings.ReplaceAll(cfg["usermodel.clientRoleMapping.rolePrefix"], "${client_id}", clientID)
			setClaim(claims, strings.ReplaceAll(name, "${client_id}", clientID), multi(prefixed(roles, prefix), cfg["multivalued"]))
		}
	case service.MapperGroupMembership:
		if err := tc.loadGroups(ctx); err != nil {
			return err
		}
		if len(tc.groups) == 0 {
			return nil
		}
		var names []string
		for _, g := range tc.groups {
			if cfg["full.path"] == "true" {
				names = append(names, tc.groupPaths[g.ID])
			} else {
				names = append(names, g.Name)
			}
		}
		name := cfg["claim.name"]
		if name == "" {
			name = "groups"
		}
		setClaim(claims, name, multi(names, cfg["multivalued"]))
	case service.MapperAudience:
		if a := cfg["included.client.audience"]; a != "" {
			addAudience(claims, a)
		}
		if a := cfg["included.custom.audience"]; a != "" {
			addAudience(claims, a)
		}
	case service.MapperAudienceResolve:
		if kind != kindAccess && kind != kindIntrospection {
			return nil
		}
		for clientID := range tc.clientRoles {
			if clientID != tc.client.ClientID {
				addAudience(claims, clientID)
			}
		}
	case service.MapperHardcodedClaim:
		setTyped(claims, cfg["claim.name"], cfg["claim.value"], cfg["jsonType.label"])
	case service.MapperAllowedOrigins:
		if origins := allowedOrigins(tc.base, tc.client); len(origins) > 0 {
			claims["allowed-origins"] = origins
		}
	case service.MapperSub:
		claims["sub"] = u.ID
	case service.MapperACR:
		if _, ok := claims["acr"]; !ok {
			claims["acr"] = "1"
		}
	case service.MapperSessionNote:
		if v, ok := tc.notes[cfg["user.session.note"]]; ok {
			setTyped(claims, cfg["claim.name"], v, cfg["jsonType.label"])
		}
	case service.MapperHardcodedRole, service.MapperRoleName:
		// already applied to the role set in resolveRoles
	}
	return nil
}

func (tc *tokenContext) loadGroups(ctx context.Context) error {
	if tc.groupPaths != nil {
		return nil
	}
	st := tc.svc.Store
	groups, err := st.UserGroups(ctx, tc.user.ID)
	if err != nil {
		return err
	}
	all, err := st.ListAllGroups(ctx, tc.realm.ID)
	if err != nil {
		return err
	}
	byID := map[string]*model.Group{}
	for _, g := range all {
		byID[g.ID] = g
	}
	tc.groupPaths = map[string]string{}
	for _, g := range groups {
		path := ""
		for cur, depth := g, 0; cur != nil && depth < 100; cur, depth = byID[cur.ParentID], depth+1 {
			path = "/" + cur.Name + path
		}
		tc.groupPaths[g.ID] = path
	}
	tc.groups = groups
	return nil
}

func userProperty(u *model.User, name string) (string, bool) {
	switch name {
	case "username":
		return u.Username, true
	case "email":
		return u.Email, u.Email != ""
	case "firstName":
		return u.FirstName, u.FirstName != ""
	case "lastName":
		return u.LastName, u.LastName != ""
	case "emailVerified":
		return strconv.FormatBool(u.EmailVerified), true
	case "enabled":
		return strconv.FormatBool(u.Enabled), true
	case "id":
		return u.ID, true
	case "createdTimestamp":
		return strconv.FormatInt(u.CreatedTimestamp, 10), true
	}
	return "", false
}

func prefixed(names []string, prefix string) []string {
	if prefix == "" {
		return names
	}
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = prefix + n
	}
	return out
}

func multi(values []string, multivalued string) any {
	if multivalued == "false" {
		return strings.Join(values, ",")
	}
	return values
}

// convert turns a string into the JSON type named by jsonType.label.
func convert(v, typ string) (any, bool) {
	switch strings.ToLower(typ) {
	case "long", "int":
		n, err := strconv.ParseInt(v, 10, 64)
		return n, err == nil
	case "boolean":
		b, err := strconv.ParseBool(v)
		return b, err == nil
	case "json":
		var out any
		err := json.Unmarshal([]byte(v), &out)
		return out, err == nil
	}
	return v, true
}

func convertAll(values []string, typ string) []any {
	out := make([]any, 0, len(values))
	for _, v := range values {
		if c, ok := convert(v, typ); ok {
			out = append(out, c)
		}
	}
	return out
}

func setTyped(claims jwt.Claims, name, value, typ string) {
	if v, ok := convert(value, typ); ok {
		setClaim(claims, name, v)
	}
}

// claimPath splits a claim name on dots, honouring "\." escapes.
func claimPath(name string) []string {
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(name); i++ {
		switch {
		case name[i] == '\\' && i+1 < len(name) && name[i+1] == '.':
			cur.WriteByte('.')
			i++
		case name[i] == '.':
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(name[i])
		}
	}
	return append(parts, cur.String())
}

// setClaim sets a possibly nested claim. Lists written to the same claim
// by several mappers are merged.
func setClaim(claims jwt.Claims, name string, value any) {
	if name == "" {
		return
	}
	path := claimPath(name)
	m := map[string]any(claims)
	for _, p := range path[:len(path)-1] {
		next, ok := m[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[p] = next
		}
		m = next
	}
	leaf := path[len(path)-1]
	if existing, ok := m[leaf]; ok {
		if merged, ok := mergeLists(existing, value); ok {
			m[leaf] = merged
			return
		}
	}
	m[leaf] = value
}

func mergeLists(a, b any) (any, bool) {
	la, ok1 := toList(a)
	lb, ok2 := toList(b)
	if !ok1 || !ok2 {
		return nil, false
	}
	seen := map[string]bool{}
	var out []any
	for _, v := range append(la, lb...) {
		k, _ := json.Marshal(v)
		if !seen[string(k)] {
			seen[string(k)] = true
			out = append(out, v)
		}
	}
	return out, true
}

func toList(v any) ([]any, bool) {
	switch l := v.(type) {
	case []any:
		return l, true
	case []string:
		out := make([]any, len(l))
		for i, s := range l {
			out[i] = s
		}
		return out, true
	}
	return nil, false
}

func addAudience(claims jwt.Claims, aud string) {
	for _, a := range claims.Audience() {
		if a == aud {
			return
		}
	}
	claims["aud"] = append(claims.Audience(), aud)
}

// finalizeAudience writes a single audience as a string, like Keycloak.
func finalizeAudience(claims jwt.Claims) {
	switch aud := claims.Audience(); len(aud) {
	case 0:
		delete(claims, "aud")
	case 1:
		claims["aud"] = aud[0]
	default:
		claims["aud"] = aud
	}
}

// ExampleClaims computes the claims gocloak would put in a token of the
// given kind ("access", "id" or "userinfo") for user and client, as the
// admin console's "evaluate scopes" feature does. No token is issued.
func ExampleClaims(ctx context.Context, svc *service.Service, issuer, base string, realm *model.Realm, client *model.Client,
	user *model.User, scope, kind string) (jwt.Claims, error) {
	tc, granted, err := newTokenContext(ctx, svc, base, realm, client, user, nil, scope, false)
	if err != nil {
		return nil, err
	}
	now := svc.Now()
	claims := jwt.Claims{"iss": issuer, "sub": user.ID, "azp": client.ClientID, "iat": now.Unix(),
		"exp": now.Unix() + int64(realm.AccessTokenLifespan), "jti": service.NewID()}
	switch kind {
	case kindAccess:
		claims["typ"], claims["scope"] = service.TokenBearer, granted
	case kindID:
		claims["typ"], claims["aud"] = service.TokenID, client.ClientID
	case kindUserinfo:
		claims = jwt.Claims{"sub": user.ID}
	default:
		return nil, errors.New("unknown token kind")
	}
	if err := tc.apply(ctx, claims, kind); err != nil {
		return nil, err
	}
	return claims, nil
}

// AppliedScopes returns the client scopes applied to tokens for a scope
// parameter, ignoring names the client may not use.
func AppliedScopes(ctx context.Context, st *store.Store, realm *model.Realm, client *model.Client, requested string) ([]*model.ClientScope, error) {
	scopes, _, _, err := resolveScopes(ctx, st, realm, client, requested)
	return scopes, err
}
