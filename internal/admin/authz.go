package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/ducnt114/gocloak/internal/authz"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/oidc"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// Authorization services admin API: /clients/{id}/authz/resource-server.

type authzCtx struct {
	realm  *model.Realm
	client *model.Client
	data   *authz.Data
}

// loadAuthz loads the resource server of the client in the path.
func (h *Handler) loadAuthz(r *http.Request, p *principal, write bool) (*authzCtx, error) {
	perm := permViewClients
	if write {
		perm = permManageClients
	}
	realm, err := h.realmFor(r, p, perm)
	if err != nil {
		return nil, err
	}
	c, err := h.loadClient(r, realm)
	if err != nil {
		return nil, err
	}
	d, err := h.Svc.LoadAuthz(r.Context(), h.Svc.Store, c.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("HTTP 404 Not Found")
	}
	if err != nil {
		return nil, err
	}
	return &authzCtx{realm: realm, client: c, data: d}, nil
}

// ---------------------------------------------------------------- representations

type authzScopeRep struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
	IconURI     string `json:"iconUri,omitempty"`
}

type ownerRep struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type authzResourceRep struct {
	ID                 string          `json:"_id,omitempty"`
	Name               string          `json:"name"`
	DisplayName        string          `json:"displayName,omitempty"`
	Type               string          `json:"type,omitempty"`
	Owner              *ownerRep       `json:"owner,omitempty"`
	OwnerManagedAccess bool            `json:"ownerManagedAccess"`
	URIs               []string        `json:"uris,omitempty"`
	Scopes             []authzScopeRep `json:"scopes,omitempty"`
	Attributes         any             `json:"attributes,omitempty"`
	IconURI            string          `json:"icon_uri,omitempty"`
}

// authzResourceInput is a resource as sent by clients (owner as a string or
// an object, scopes as objects or names).
type authzResourceInput struct {
	Name               string          `json:"name"`
	DisplayName        string          `json:"displayName"`
	Type               string          `json:"type"`
	Owner              json.RawMessage `json:"owner"`
	OwnerManagedAccess bool            `json:"ownerManagedAccess"`
	URIs               []string        `json:"uris"`
	URI                string          `json:"uri"`
	Scopes             json.RawMessage `json:"scopes"`
	ResourceScopes     json.RawMessage `json:"resource_scopes"`
	Attributes         listMap         `json:"attributes"`
	IconURI            string          `json:"icon_uri"`
}

// scopeNames reads scopes given as names or {"name"} / {"id"} objects.
func scopeNames(raw json.RawMessage) (names, ids []string) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) != nil {
		return nil, nil
	}
	for _, it := range list {
		var s string
		if json.Unmarshal(it, &s) == nil {
			names = append(names, s)
			continue
		}
		var o struct{ ID, Name string }
		if json.Unmarshal(it, &o) == nil {
			if o.Name != "" {
				names = append(names, o.Name)
			} else if o.ID != "" {
				ids = append(ids, o.ID)
			}
		}
	}
	return names, ids
}

func ownerOf(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var o struct{ ID, Name string }
	if json.Unmarshal(raw, &o) == nil {
		if o.ID != "" {
			return o.ID
		}
		return o.Name
	}
	return ""
}

func (h *Handler) ownerRep(ctx context.Context, ac *authzCtx, owner string) *ownerRep {
	if owner == ac.client.ID {
		return &ownerRep{ID: owner, Name: ac.client.ClientID}
	}
	if u, err := h.Svc.Store.GetUser(ctx, ac.realm.ID, owner); err == nil {
		return &ownerRep{ID: u.ID, Name: u.Username}
	}
	if c, err := h.Svc.Store.GetClient(ctx, ac.realm.ID, owner); err == nil {
		return &ownerRep{ID: c.ID, Name: c.ClientID}
	}
	return &ownerRep{ID: owner}
}

func scopeToRep(s *model.AuthzScope) authzScopeRep {
	return authzScopeRep{ID: s.ID, Name: s.Name, DisplayName: s.DisplayName, IconURI: s.IconURI}
}

func (h *Handler) resourceToRep(ctx context.Context, ac *authzCtx, r *model.AuthzResource, deep bool) authzResourceRep {
	rep := authzResourceRep{ID: r.ID, Name: r.Name, DisplayName: r.DisplayName, Type: r.Type, Owner: h.ownerRep(ctx, ac, r.Owner),
		OwnerManagedAccess: r.OwnerManagedAccess, URIs: r.URIs, IconURI: r.IconURI}
	if deep {
		rep.Attributes = nonNilListMap(r.Attributes)
		for _, sid := range r.ScopeIDs {
			if s := ac.data.Scope(sid); s != nil {
				rep.Scopes = append(rep.Scopes, scopeToRep(s))
			}
		}
	}
	return rep
}

// policyRep is the generic representation of a policy or permission.
type policyRep struct {
	ID               string `json:"id,omitempty"`
	Name             string `json:"name"`
	Description      string `json:"description,omitempty"`
	Type             string `json:"type"`
	Logic            string `json:"logic"`
	DecisionStrategy string `json:"decisionStrategy"`
	Owner            string `json:"owner,omitempty"`
	Config           any    `json:"config,omitempty"`
	ResourceType     string `json:"resourceType,omitempty"`
}

func policyToRep(p *model.AuthzPolicy, withConfig bool) policyRep {
	rep := policyRep{ID: p.ID, Name: p.Name, Description: p.Description, Type: p.Type, Logic: p.Logic,
		DecisionStrategy: p.DecisionStrategy, Owner: p.Owner}
	cfg := map[string]string{}
	if withConfig {
		for k, v := range p.Config {
			cfg[k] = v
		}
	}
	rep.Config = cfg
	return rep
}

// typedPolicyInput is a policy as created through /policy/{type}.
type typedPolicyInput struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	Description      string          `json:"description"`
	Type             string          `json:"type"`
	Logic            string          `json:"logic"`
	DecisionStrategy string          `json:"decisionStrategy"`
	Policies         []string        `json:"policies"`
	Resources        []string        `json:"resources"`
	Scopes           []string        `json:"scopes"`
	ResourceType     string          `json:"resourceType"`
	Roles            json.RawMessage `json:"roles"`
	Users            []string        `json:"users"`
	Groups           json.RawMessage `json:"groups"`
	GroupsClaim      string          `json:"groupsClaim"`
	Clients          []string        `json:"clients"`
	ClientScopes     json.RawMessage `json:"clientScopes"`
	Code             string          `json:"code"`
	TargetClaim      string          `json:"targetClaim"`
	Pattern          string          `json:"pattern"`
	TargetContext    *bool           `json:"targetContextAttributes"`
	Time             map[string]any  `json:"-"`
	Config           strMap          `json:"config"`
}

var timeFields = map[string]string{"notBefore": "nbf", "notOnOrAfter": "noa", "dayMonth": "dayMonth", "dayMonthEnd": "dayMonthEnd",
	"month": "month", "monthEnd": "monthEnd", "year": "year", "yearEnd": "yearEnd", "hour": "hour", "hourEnd": "hourEnd",
	"minute": "minute", "minuteEnd": "minuteEnd"}

func (h *Handler) readPolicy(r *http.Request) (*typedPolicyInput, error) {
	var raw map[string]json.RawMessage
	if err := decode(r, &raw); err != nil {
		return nil, err
	}
	b, _ := json.Marshal(raw)
	in := &typedPolicyInput{}
	if err := json.Unmarshal(b, in); err != nil {
		return nil, badRequest("Invalid JSON: " + err.Error())
	}
	in.Time = map[string]any{}
	for k := range timeFields {
		if v, ok := raw[k]; ok {
			var x any
			json.Unmarshal(v, &x)
			in.Time[k] = x
		}
	}
	return in, nil
}

// resolve names or ids to ids.
func (h *Handler) resolveIDs(ac *authzCtx, values []string, kind string) ([]string, error) {
	var out []string
	for _, v := range values {
		switch kind {
		case "resource":
			if r := ac.data.Resource(v); r != nil {
				out = append(out, r.ID)
			} else if r := ac.data.ResourceByName(v); r != nil {
				out = append(out, r.ID)
			} else {
				return nil, badRequest("Resource [" + v + "] does not exist")
			}
		case "scope":
			if s := ac.data.Scope(v); s != nil {
				out = append(out, s.ID)
			} else if s := ac.data.ScopeByName(v); s != nil {
				out = append(out, s.ID)
			} else {
				return nil, badRequest("Scope [" + v + "] does not exist")
			}
		case "policy":
			found := ""
			for _, p := range ac.data.Policies {
				if p.ID == v || p.Name == v {
					found = p.ID
				}
			}
			if found == "" {
				return nil, badRequest("Policy [" + v + "] does not exist")
			}
			out = append(out, found)
		}
	}
	return out, nil
}

// applyPolicyInput fills a policy from a typed representation.
func (h *Handler) applyPolicyInput(ac *authzCtx, p *model.AuthzPolicy, typ string, in *typedPolicyInput) error {
	if in.Name != "" {
		p.Name = in.Name
	}
	if strings.TrimSpace(p.Name) == "" {
		return badRequest("Policy name is required")
	}
	p.Description = in.Description
	p.Type = typ
	p.Logic = in.Logic
	if p.Logic == "" {
		p.Logic = authz.Positive
	}
	p.DecisionStrategy = in.DecisionStrategy
	if p.DecisionStrategy == "" {
		p.DecisionStrategy = authz.Unanimous
	}
	if p.Config == nil {
		p.Config = map[string]string{}
	}
	for k, v := range in.Config {
		p.Config[k] = v
	}
	var err error
	if p.AssociatedIDs, err = h.resolveIDs(ac, in.Policies, "policy"); err != nil {
		return err
	}
	if p.ResourceIDs, err = h.resolveIDs(ac, in.Resources, "resource"); err != nil {
		return err
	}
	if p.ScopeIDs, err = h.resolveIDs(ac, in.Scopes, "scope"); err != nil {
		return err
	}
	set := func(k, v string) {
		if v == "" {
			delete(p.Config, k)
		} else {
			p.Config[k] = v
		}
	}
	switch typ {
	case "role":
		set("roles", string(in.Roles))
	case "user":
		set("users", service.PolicyConfigList(nonNil(in.Users)))
	case "group":
		set("groups", string(in.Groups))
		set("groupsClaim", in.GroupsClaim)
	case "client":
		set("clients", service.PolicyConfigList(nonNil(in.Clients)))
	case "client-scope":
		set("clientScopes", string(in.ClientScopes))
	case "js":
		set("code", in.Code)
	case "regex":
		set("targetClaim", in.TargetClaim)
		set("pattern", in.Pattern)
		if in.TargetContext != nil {
			set("targetContextAttributes", fmt.Sprint(*in.TargetContext))
		}
	case "time":
		for field, key := range timeFields {
			if v, ok := in.Time[field]; ok && v != nil && fmt.Sprint(v) != "" {
				p.Config[key] = fmt.Sprint(v)
			} else {
				delete(p.Config, key)
			}
		}
		if p.Config["nbf"] == "" && p.Config["noa"] == "" && p.Config["dayMonth"] == "" && p.Config["month"] == "" &&
			p.Config["year"] == "" && p.Config["hour"] == "" && p.Config["minute"] == "" {
			return badRequest("You must provide at least one time constraint")
		}
	case authz.TypeResource:
		set("defaultResourceType", in.ResourceType)
	case authz.TypeScope:
		set("defaultResourceType", in.ResourceType)
	}
	for _, k := range []string{"roles", "groups", "clientScopes"} {
		if p.Config[k] == "null" {
			delete(p.Config, k)
		}
	}
	return nil
}

// typedPolicyRep renders /policy/{type}/{id}: the type's own fields.
func typedPolicyRep(p *model.AuthzPolicy) map[string]any {
	rep := map[string]any{"id": p.ID, "name": p.Name, "type": p.Type, "logic": p.Logic, "decisionStrategy": p.DecisionStrategy}
	if p.Description != "" {
		rep["description"] = p.Description
	}
	raw := func(k string) any {
		var v any
		if json.Unmarshal([]byte(p.Config[k]), &v) == nil {
			return v
		}
		return []any{}
	}
	c := p.Config
	switch p.Type {
	case "role":
		rep["roles"] = raw("roles")
	case "user":
		rep["users"] = raw("users")
	case "group":
		rep["groups"] = raw("groups")
		if c["groupsClaim"] != "" {
			rep["groupsClaim"] = c["groupsClaim"]
		}
	case "client":
		rep["clients"] = raw("clients")
	case "client-scope":
		rep["clientScopes"] = raw("clientScopes")
	case "js":
		rep["code"] = c["code"]
	case "regex":
		rep["targetClaim"], rep["pattern"] = c["targetClaim"], c["pattern"]
		rep["targetContextAttributes"] = c["targetContextAttributes"] == "true"
	case "time":
		for field, key := range timeFields {
			if v := c[key]; v != "" {
				rep[field] = v
			}
		}
	case authz.TypeResource, authz.TypeScope:
		if c["defaultResourceType"] != "" {
			rep["resourceType"] = c["defaultResourceType"]
		}
	}
	return rep
}

type resourceServerRep struct {
	ID                            string             `json:"id"`
	ClientID                      string             `json:"clientId"`
	Name                          string             `json:"name"`
	AllowRemoteResourceManagement bool               `json:"allowRemoteResourceManagement"`
	PolicyEnforcementMode         string             `json:"policyEnforcementMode"`
	DecisionStrategy              string             `json:"decisionStrategy"`
	Resources                     []authzResourceRep `json:"resources"`
	Policies                      []any              `json:"policies"`
	Scopes                        []authzScopeRep    `json:"scopes"`
}

// ---------------------------------------------------------------- resource server

func (h *Handler) getResourceServer(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, false)
	if err != nil {
		return err
	}
	rs := ac.data.Server
	return ok(w, resourceServerRep{ID: ac.client.ID, ClientID: ac.client.ID, Name: ac.client.ClientID,
		AllowRemoteResourceManagement: rs.AllowRemoteResourceManagement, PolicyEnforcementMode: rs.PolicyEnforcementMode,
		DecisionStrategy: rs.DecisionStrategy, Resources: []authzResourceRep{}, Policies: []any{}, Scopes: []authzScopeRep{}})
}

func validMode(mode string) bool {
	return mode == authz.Enforcing || mode == authz.Permissive || mode == authz.Disabled
}

func validStrategy(s string) bool {
	return s == authz.Unanimous || s == authz.Affirmative || s == authz.Consensus
}

func (h *Handler) updateResourceServer(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, true)
	if err != nil {
		return err
	}
	var rep struct {
		AllowRemoteResourceManagement *bool  `json:"allowRemoteResourceManagement"`
		PolicyEnforcementMode         string `json:"policyEnforcementMode"`
		DecisionStrategy              string `json:"decisionStrategy"`
	}
	if err := decode(r, &rep); err != nil {
		return err
	}
	rs := ac.data.Server
	if rep.AllowRemoteResourceManagement != nil {
		rs.AllowRemoteResourceManagement = *rep.AllowRemoteResourceManagement
	}
	if rep.PolicyEnforcementMode != "" {
		if !validMode(rep.PolicyEnforcementMode) {
			return badRequest("Invalid policy enforcement mode")
		}
		rs.PolicyEnforcementMode = rep.PolicyEnforcementMode
	}
	if rep.DecisionStrategy != "" {
		if !validStrategy(rep.DecisionStrategy) {
			return badRequest("Invalid decision strategy")
		}
		rs.DecisionStrategy = rep.DecisionStrategy
	}
	if err := h.Svc.Store.UpdateResourceServer(r.Context(), rs); err != nil {
		return err
	}
	return noContent(w)
}

// exportSettings is the resource server as in exports (/settings and the
// client's authorizationSettings): references by name.
func (h *Handler) exportSettings(ctx context.Context, ac *authzCtx) map[string]any {
	d := ac.data
	resources := []map[string]any{}
	for _, res := range d.Resources {
		e := map[string]any{"name": res.Name, "ownerManagedAccess": res.OwnerManagedAccess, "attributes": nonNilListMap(res.Attributes),
			"uris": nonNil(res.URIs)}
		if res.Type != "" {
			e["type"] = res.Type
		}
		if res.DisplayName != "" {
			e["displayName"] = res.DisplayName
		}
		if res.IconURI != "" {
			e["icon_uri"] = res.IconURI
		}
		if res.Owner != ac.client.ID {
			e["owner"] = h.ownerRep(ctx, ac, res.Owner)
		}
		var scopes []map[string]string
		for _, sid := range res.ScopeIDs {
			if s := d.Scope(sid); s != nil {
				scopes = append(scopes, map[string]string{"name": s.Name})
			}
		}
		if scopes != nil {
			e["scopes"] = scopes
		}
		resources = append(resources, e)
	}
	names := func(ids []string, name func(string) string) string {
		var out []string
		for _, id := range ids {
			if n := name(id); n != "" {
				out = append(out, n)
			}
		}
		return service.PolicyConfigList(out)
	}
	policies := []map[string]any{}
	// policies first, then permissions, as in realm exports
	ordered := slices.Clone(d.Policies)
	sort.SliceStable(ordered, func(i, j int) bool { return !authz.IsPermission(ordered[i]) && authz.IsPermission(ordered[j]) })
	for _, p := range ordered {
		cfg := map[string]string{}
		for k, v := range p.Config {
			cfg[k] = v
		}
		if len(p.AssociatedIDs) > 0 {
			cfg["applyPolicies"] = names(p.AssociatedIDs, func(id string) string {
				if x := d.Policy(id); x != nil {
					return x.Name
				}
				return ""
			})
		}
		if len(p.ResourceIDs) > 0 {
			cfg["resources"] = names(p.ResourceIDs, func(id string) string {
				if x := d.Resource(id); x != nil {
					return x.Name
				}
				return ""
			})
		}
		if len(p.ScopeIDs) > 0 {
			cfg["scopes"] = names(p.ScopeIDs, func(id string) string {
				if x := d.Scope(id); x != nil {
					return x.Name
				}
				return ""
			})
		}
		e := map[string]any{"name": p.Name, "type": p.Type, "logic": p.Logic, "decisionStrategy": p.DecisionStrategy, "config": cfg}
		if p.Description != "" {
			e["description"] = p.Description
		}
		policies = append(policies, e)
	}
	scopes := []authzScopeRep{}
	for _, s := range d.Scopes {
		rep := scopeToRep(s)
		rep.ID = ""
		scopes = append(scopes, rep)
	}
	return map[string]any{"allowRemoteResourceManagement": d.Server.AllowRemoteResourceManagement,
		"policyEnforcementMode": d.Server.PolicyEnforcementMode, "decisionStrategy": d.Server.DecisionStrategy,
		"resources": resources, "policies": policies, "scopes": scopes}
}

func nonNilListMap(m map[string][]string) map[string][]string {
	if m == nil {
		return map[string][]string{}
	}
	return m
}

func (h *Handler) resourceServerSettings(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, false)
	if err != nil {
		return err
	}
	return ok(w, h.exportSettings(r.Context(), ac))
}

// AuthzSettings is an exported resource server.
type AuthzSettings struct {
	AllowRemoteResourceManagement *bool                `json:"allowRemoteResourceManagement"`
	PolicyEnforcementMode         string               `json:"policyEnforcementMode"`
	DecisionStrategy              string               `json:"decisionStrategy"`
	Resources                     []authzResourceInput `json:"resources"`
	Policies                      []struct {
		Name             string `json:"name"`
		Description      string `json:"description"`
		Type             string `json:"type"`
		Logic            string `json:"logic"`
		DecisionStrategy string `json:"decisionStrategy"`
		Config           strMap `json:"config"`
	} `json:"policies"`
	Scopes []authzScopeRep `json:"scopes"`
}

// importSettings replaces a resource server's content with an export.
func (h *Handler) importSettings(ctx context.Context, tx *store.Store, realm *model.Realm, c *model.Client, s *AuthzSettings) error {
	rs, err := tx.GetResourceServer(ctx, c.ID)
	if err != nil {
		return err
	}
	if s.AllowRemoteResourceManagement != nil {
		rs.AllowRemoteResourceManagement = *s.AllowRemoteResourceManagement
	}
	if validMode(s.PolicyEnforcementMode) {
		rs.PolicyEnforcementMode = s.PolicyEnforcementMode
	}
	if validStrategy(s.DecisionStrategy) {
		rs.DecisionStrategy = s.DecisionStrategy
	}
	if err := tx.UpdateResourceServer(ctx, rs); err != nil {
		return err
	}
	// start from an empty server
	existing, err := h.Svc.LoadAuthz(ctx, tx, c.ID)
	if err != nil {
		return err
	}
	for _, p := range existing.Policies {
		if err := tx.DeleteAuthzPolicy(ctx, c.ID, p.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	for _, res := range existing.Resources {
		if err := tx.DeleteAuthzResource(ctx, c.ID, res.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	for _, sc := range existing.Scopes {
		if err := tx.DeleteAuthzScope(ctx, c.ID, sc.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	scopeIDs := map[string]string{}
	for _, sc := range s.Scopes {
		x := &model.AuthzScope{ID: service.NewID(), ResourceServerID: c.ID, Name: sc.Name, DisplayName: sc.DisplayName, IconURI: sc.IconURI}
		if err := tx.CreateAuthzScope(ctx, x); err != nil {
			return err
		}
		scopeIDs[x.Name] = x.ID
	}
	resourceIDs := map[string]string{}
	for _, in := range s.Resources {
		x := &model.AuthzResource{ID: service.NewID(), ResourceServerID: c.ID, Name: in.Name, DisplayName: in.DisplayName, Type: in.Type,
			OwnerManagedAccess: in.OwnerManagedAccess, URIs: in.URIs, Attributes: in.Attributes, IconURI: in.IconURI, Owner: c.ID}
		if o := ownerOf(in.Owner); o != "" && o != c.ClientID {
			if u, err := tx.GetUserByUsername(ctx, realm.ID, o); err == nil {
				x.Owner = u.ID
			} else if _, err := tx.GetUser(ctx, realm.ID, o); err == nil {
				x.Owner = o
			}
		}
		names, _ := scopeNames(in.Scopes)
		for _, n := range names {
			id, ok := scopeIDs[n]
			if !ok {
				sc := &model.AuthzScope{ID: service.NewID(), ResourceServerID: c.ID, Name: n}
				if err := tx.CreateAuthzScope(ctx, sc); err != nil {
					return err
				}
				id = sc.ID
				scopeIDs[n] = id
			}
			x.ScopeIDs = append(x.ScopeIDs, id)
		}
		if err := tx.CreateAuthzResource(ctx, x); err != nil {
			return err
		}
		resourceIDs[x.Name] = x.ID
	}
	policyIDs := map[string]string{}
	var created []*model.AuthzPolicy
	for _, in := range s.Policies {
		x := &model.AuthzPolicy{ID: service.NewID(), ResourceServerID: c.ID, Name: in.Name, Description: in.Description, Type: in.Type,
			Logic: in.Logic, DecisionStrategy: in.DecisionStrategy, Config: map[string]string{}}
		if x.Logic == "" {
			x.Logic = authz.Positive
		}
		if x.DecisionStrategy == "" {
			x.DecisionStrategy = authz.Unanimous
		}
		for k, v := range in.Config {
			x.Config[k] = v
		}
		policyIDs[x.Name] = x.ID
		created = append(created, x)
	}
	// references by name, once every policy has an id
	for _, x := range created {
		var list []string
		for key, target := range map[string]map[string]string{"applyPolicies": policyIDs, "resources": resourceIDs, "scopes": scopeIDs} {
			list = nil
			json.Unmarshal([]byte(x.Config[key]), &list)
			delete(x.Config, key)
			for _, n := range list {
				id := target[n]
				if id == "" {
					return badRequest(fmt.Sprintf("%s [%s] of policy %s does not exist", key, n, x.Name))
				}
				switch key {
				case "applyPolicies":
					x.AssociatedIDs = append(x.AssociatedIDs, id)
				case "resources":
					x.ResourceIDs = append(x.ResourceIDs, id)
				case "scopes":
					x.ScopeIDs = append(x.ScopeIDs, id)
				}
			}
		}
	}
	// create associated policies before the ones referring to them
	done := map[string]bool{}
	for len(done) < len(created) {
		progress := false
		for _, x := range created {
			if done[x.ID] {
				continue
			}
			ready := true
			for _, a := range x.AssociatedIDs {
				ready = ready && done[a]
			}
			if !ready {
				continue
			}
			links := x.AssociatedIDs
			if err := tx.CreateAuthzPolicy(ctx, x); err != nil {
				return err
			}
			x.AssociatedIDs = links
			done[x.ID], progress = true, true
		}
		if !progress {
			return badRequest("Policies refer to each other in a cycle")
		}
	}
	return nil
}

func (h *Handler) importResourceServer(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, true)
	if err != nil {
		return err
	}
	var s AuthzSettings
	if err := decode(r, &s); err != nil {
		return err
	}
	if err := h.withTx(r.Context(), func(tx *store.Store) error { return h.importSettings(r.Context(), tx, ac.realm, ac.client, &s) }); err != nil {
		return err
	}
	return noContent(w)
}

// ---------------------------------------------------------------- scopes

func (h *Handler) listAuthzScopes(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, false)
	if err != nil {
		return err
	}
	name := strings.ToLower(r.URL.Query().Get("name"))
	out := []authzScopeRep{}
	for _, s := range ac.data.Scopes {
		if name == "" || strings.Contains(strings.ToLower(s.Name), name) {
			out = append(out, scopeToRep(s))
		}
	}
	return ok(w, page(r, out))
}

func (h *Handler) searchAuthzScope(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, false)
	if err != nil {
		return err
	}
	if s := ac.data.ScopeByName(r.URL.Query().Get("name")); s != nil {
		return ok(w, scopeToRep(s))
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (h *Handler) authzScope(r *http.Request, ac *authzCtx) (*model.AuthzScope, error) {
	s := ac.data.Scope(r.PathValue("sid"))
	if s == nil {
		return nil, notFound("Could not find scope")
	}
	return s, nil
}

func (h *Handler) createAuthzScope(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, true)
	if err != nil {
		return err
	}
	var rep authzScopeRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	if strings.TrimSpace(rep.Name) == "" {
		return badRequest("Scope name is required")
	}
	if ac.data.ScopeByName(rep.Name) != nil {
		return conflict("Scope with name [" + rep.Name + "] already exists")
	}
	s := &model.AuthzScope{ID: service.NewID(), ResourceServerID: ac.client.ID, Name: rep.Name, DisplayName: rep.DisplayName, IconURI: rep.IconURI}
	if err := h.Svc.Store.CreateAuthzScope(r.Context(), s); err != nil {
		return err
	}
	w.Header().Set("Location", strings.TrimSuffix(requestURL(r), "/")+"/"+s.ID)
	writeJSON(w, http.StatusCreated, scopeToRep(s))
	return nil
}

func (h *Handler) getAuthzScope(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, false)
	if err != nil {
		return err
	}
	s, err := h.authzScope(r, ac)
	if err != nil {
		return err
	}
	return ok(w, scopeToRep(s))
}

func (h *Handler) updateAuthzScope(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, true)
	if err != nil {
		return err
	}
	s, err := h.authzScope(r, ac)
	if err != nil {
		return err
	}
	var rep authzScopeRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	if rep.Name != "" {
		s.Name = rep.Name
	}
	s.DisplayName, s.IconURI = rep.DisplayName, rep.IconURI
	if err := h.Svc.Store.UpdateAuthzScope(r.Context(), s); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return conflict("Scope with name [" + s.Name + "] already exists")
		}
		return err
	}
	return noContent(w)
}

func (h *Handler) deleteAuthzScope(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, true)
	if err != nil {
		return err
	}
	s, err := h.authzScope(r, ac)
	if err != nil {
		return err
	}
	if err := h.Svc.Store.DeleteAuthzScope(r.Context(), ac.client.ID, s.ID); err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) authzScopeResources(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, false)
	if err != nil {
		return err
	}
	s, err := h.authzScope(r, ac)
	if err != nil {
		return err
	}
	out := []map[string]string{}
	for _, res := range ac.data.Resources {
		if slices.Contains(res.ScopeIDs, s.ID) {
			out = append(out, map[string]string{"_id": res.ID, "name": res.Name})
		}
	}
	return ok(w, out)
}

func (h *Handler) authzScopePermissions(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, false)
	if err != nil {
		return err
	}
	s, err := h.authzScope(r, ac)
	if err != nil {
		return err
	}
	out := []policyRep{}
	for _, x := range ac.data.Policies {
		if authz.IsPermission(x) && slices.Contains(x.ScopeIDs, s.ID) {
			out = append(out, policyToRep(x, false))
		}
	}
	return ok(w, out)
}

// ---------------------------------------------------------------- resources

// buildResource fills a resource from its input; owner defaults to the
// resource server.
func (h *Handler) buildResource(ctx context.Context, tx *store.Store, ac *authzCtx, x *model.AuthzResource, in *authzResourceInput) error {
	if strings.TrimSpace(in.Name) == "" {
		return badRequest("Resource name is required")
	}
	x.Name, x.DisplayName, x.Type, x.OwnerManagedAccess, x.IconURI = in.Name, in.DisplayName, in.Type, in.OwnerManagedAccess, in.IconURI
	x.URIs = in.URIs
	if in.URI != "" && len(x.URIs) == 0 {
		x.URIs = []string{in.URI}
	}
	x.Attributes = in.Attributes
	if x.Owner == "" {
		x.Owner = ac.client.ID
	}
	if o := ownerOf(in.Owner); o != "" && o != ac.client.ID && o != ac.client.ClientID {
		if u, err := tx.GetUser(ctx, ac.realm.ID, o); err == nil {
			x.Owner = u.ID
		} else if u, err := tx.GetUserByUsername(ctx, ac.realm.ID, strings.ToLower(o)); err == nil {
			x.Owner = u.ID
		} else {
			return badRequest("Owner [" + o + "] not found")
		}
	}
	raw := in.Scopes
	if len(in.ResourceScopes) > 0 && string(in.ResourceScopes) != "null" {
		raw = in.ResourceScopes
	}
	names, ids := scopeNames(raw)
	x.ScopeIDs = nil
	for _, id := range ids {
		if s := ac.data.Scope(id); s != nil {
			x.ScopeIDs = append(x.ScopeIDs, s.ID)
		}
	}
	for _, n := range names {
		s := ac.data.ScopeByName(n)
		if s == nil {
			// unknown scopes are created
			s = &model.AuthzScope{ID: service.NewID(), ResourceServerID: ac.client.ID, Name: n}
			if err := tx.CreateAuthzScope(ctx, s); err != nil {
				return err
			}
			ac.data.Scopes = append(ac.data.Scopes, s)
			ac.data.Index()
		}
		x.ScopeIDs = append(x.ScopeIDs, s.ID)
	}
	return nil
}

func (h *Handler) listAuthzResources(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, false)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	deep := q.Get("deep") != "false"
	out := []authzResourceRep{}
	for _, res := range ac.data.Resources {
		if n := strings.ToLower(q.Get("name")); n != "" && !strings.Contains(strings.ToLower(res.Name), n) {
			continue
		}
		if t := q.Get("type"); t != "" && !strings.Contains(res.Type, t) {
			continue
		}
		if u := q.Get("uri"); u != "" && !slices.Contains(res.URIs, u) {
			continue
		}
		if o := q.Get("owner"); o != "" {
			rep := h.ownerRep(r.Context(), ac, res.Owner)
			if rep.ID != o && rep.Name != o {
				continue
			}
		}
		out = append(out, h.resourceToRep(r.Context(), ac, res, deep))
	}
	return ok(w, page(r, out))
}

func (h *Handler) searchAuthzResource(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, false)
	if err != nil {
		return err
	}
	if res := ac.data.ResourceByName(r.URL.Query().Get("name")); res != nil {
		return ok(w, h.resourceToRep(r.Context(), ac, res, true))
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (h *Handler) authzResource(r *http.Request, ac *authzCtx) (*model.AuthzResource, error) {
	res := ac.data.Resource(r.PathValue("rid"))
	if res == nil {
		return nil, notFound("Could not find resource")
	}
	return res, nil
}

func (h *Handler) createAuthzResource(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, true)
	if err != nil {
		return err
	}
	var in authzResourceInput
	if err := decode(r, &in); err != nil {
		return err
	}
	x := &model.AuthzResource{ID: service.NewID(), ResourceServerID: ac.client.ID}
	err = h.withTx(r.Context(), func(tx *store.Store) error {
		if err := h.buildResource(r.Context(), tx, ac, x, &in); err != nil {
			return err
		}
		for _, other := range ac.data.Resources {
			if other.Name == x.Name && other.Owner == x.Owner {
				return conflict("Resource with name [" + x.Name + "] already exists.")
			}
		}
		return tx.CreateAuthzResource(r.Context(), x)
	})
	if err != nil {
		return err
	}
	ac.data.Resources = append(ac.data.Resources, x)
	ac.data.Index()
	w.Header().Set("Location", strings.TrimSuffix(requestURL(r), "/")+"/"+x.ID)
	writeJSON(w, http.StatusCreated, h.resourceToRep(r.Context(), ac, x, true))
	return nil
}

func (h *Handler) getAuthzResource(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, false)
	if err != nil {
		return err
	}
	res, err := h.authzResource(r, ac)
	if err != nil {
		return err
	}
	return ok(w, h.resourceToRep(r.Context(), ac, res, true))
}

func (h *Handler) updateAuthzResource(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, true)
	if err != nil {
		return err
	}
	res, err := h.authzResource(r, ac)
	if err != nil {
		return err
	}
	var in authzResourceInput
	if err := decode(r, &in); err != nil {
		return err
	}
	err = h.withTx(r.Context(), func(tx *store.Store) error {
		if err := h.buildResource(r.Context(), tx, ac, res, &in); err != nil {
			return err
		}
		return tx.UpdateAuthzResource(r.Context(), res)
	})
	if errors.Is(err, store.ErrConflict) {
		return conflict("Resource with name [" + res.Name + "] already exists.")
	}
	if err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) deleteAuthzResource(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, true)
	if err != nil {
		return err
	}
	res, err := h.authzResource(r, ac)
	if err != nil {
		return err
	}
	if err := h.Svc.Store.DeleteAuthzResource(r.Context(), ac.client.ID, res.ID); err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) authzResourceScopes(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, false)
	if err != nil {
		return err
	}
	res, err := h.authzResource(r, ac)
	if err != nil {
		return err
	}
	var scopes []*model.AuthzScope
	for _, sid := range res.ScopeIDs {
		if s := ac.data.Scope(sid); s != nil {
			scopes = append(scopes, s)
		}
	}
	authz.SortScopes(scopes)
	out := []authzScopeRep{}
	for _, s := range scopes {
		out = append(out, scopeToRep(s))
	}
	return ok(w, out)
}

func (h *Handler) authzResourcePermissions(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, false)
	if err != nil {
		return err
	}
	res, err := h.authzResource(r, ac)
	if err != nil {
		return err
	}
	out := []policyRep{}
	for _, x := range ac.data.Policies {
		if !authz.IsPermission(x) {
			continue
		}
		applies := slices.Contains(x.ResourceIDs, res.ID) || (x.Config["defaultResourceType"] != "" && x.Config["defaultResourceType"] == res.Type)
		if !applies && x.Type == authz.TypeScope && len(x.ResourceIDs) == 0 {
			for _, sid := range x.ScopeIDs {
				applies = applies || slices.Contains(res.ScopeIDs, sid)
			}
		}
		if applies {
			out = append(out, policyToRep(x, false))
		}
	}
	return ok(w, out)
}

func (h *Handler) authzResourceAttributes(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, false)
	if err != nil {
		return err
	}
	res, err := h.authzResource(r, ac)
	if err != nil {
		return err
	}
	return ok(w, nonNilListMap(res.Attributes))
}

// ---------------------------------------------------------------- policies

func (h *Handler) authzPolicy(r *http.Request, ac *authzCtx) (*model.AuthzPolicy, error) {
	x := ac.data.Policy(r.PathValue("pid"))
	if x == nil {
		return nil, notFound("Could not find policy")
	}
	return x, nil
}

// listAuthzPolicies implements GET /policy and GET /permission.
func (h *Handler) listAuthzPolicies(permissions bool) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request, p *principal) error {
		ac, err := h.loadAuthz(r, p, false)
		if err != nil {
			return err
		}
		q := r.URL.Query()
		var list []any
		for _, x := range ac.data.Policies {
			isPerm := authz.IsPermission(x)
			if permissions && !isPerm {
				continue
			}
			if !permissions && q.Get("permission") == "false" && isPerm {
				continue
			}
			if !permissions && q.Get("permission") == "true" && !isPerm {
				continue
			}
			if n := strings.ToLower(q.Get("name")); n != "" && !strings.Contains(strings.ToLower(x.Name), n) {
				continue
			}
			if t := q.Get("type"); t != "" && x.Type != t {
				continue
			}
			if rid := q.Get("resource"); rid != "" && !slices.Contains(x.ResourceIDs, rid) {
				if res := ac.data.Resource(rid); res == nil || x.Config["defaultResourceType"] != res.Type {
					continue
				}
			}
			if sid := q.Get("scope"); sid != "" && !slices.Contains(x.ScopeIDs, sid) {
				continue
			}
			if permissions {
				rep := policyToRep(x, false)
				rep.Config = nil
				rep.ResourceType = x.Config["defaultResourceType"]
				list = append(list, rep)
			} else {
				list = append(list, policyToRep(x, true))
			}
		}
		if list == nil {
			list = []any{}
		}
		return ok(w, page(r, list))
	}
}

func (h *Handler) searchAuthzPolicy(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, false)
	if err != nil {
		return err
	}
	for _, x := range ac.data.Policies {
		if x.Name == r.URL.Query().Get("name") {
			return ok(w, policyToRep(x, true))
		}
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (h *Handler) getAuthzPolicy(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, false)
	if err != nil {
		return err
	}
	x, err := h.authzPolicy(r, ac)
	if err != nil {
		return err
	}
	if typ := r.PathValue("type"); typ != "" {
		if typ != x.Type {
			return notFound("Could not find policy")
		}
		return ok(w, typedPolicyRep(x))
	}
	return ok(w, policyToRep(x, true))
}

var policyTypes = map[string]bool{"role": true, "user": true, "group": true, "client": true, "client-scope": true, "time": true,
	"regex": true, "aggregate": true, "js": true, authz.TypeResource: true, authz.TypeScope: true}

func (h *Handler) createAuthzPolicy(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, true)
	if err != nil {
		return err
	}
	in, err := h.readPolicy(r)
	if err != nil {
		return err
	}
	typ := r.PathValue("type")
	if typ == "" {
		typ = in.Type
	}
	if !policyTypes[typ] {
		return badRequest("Unknown policy provider [" + typ + "]")
	}
	if typ == "js" && strings.TrimSpace(in.Code) != strings.TrimSpace(authz.DefaultPolicyCode) {
		return badRequest("JavaScript policies are not supported")
	}
	x := &model.AuthzPolicy{ID: service.NewID(), ResourceServerID: ac.client.ID}
	if err := h.applyPolicyInput(ac, x, typ, in); err != nil {
		return err
	}
	for _, other := range ac.data.Policies {
		if other.Name == x.Name {
			return conflict("Policy with name [" + x.Name + "] already exists")
		}
	}
	if err := h.Svc.Store.CreateAuthzPolicy(r.Context(), x); err != nil {
		return err
	}
	w.Header().Set("Location", strings.TrimSuffix(requestURL(r), "/")+"/"+x.ID)
	rep := typedPolicyRep(x)
	if len(x.AssociatedIDs) > 0 {
		rep["policies"] = x.AssociatedIDs
	}
	if len(x.ResourceIDs) > 0 {
		rep["resources"] = x.ResourceIDs
	}
	if len(x.ScopeIDs) > 0 {
		rep["scopes"] = x.ScopeIDs
	}
	writeJSON(w, http.StatusCreated, rep)
	return nil
}

func (h *Handler) updateAuthzPolicy(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, true)
	if err != nil {
		return err
	}
	x, err := h.authzPolicy(r, ac)
	if err != nil {
		return err
	}
	in, err := h.readPolicy(r)
	if err != nil {
		return err
	}
	typ := x.Type
	if x.Type == "js" && in.Code != "" && strings.TrimSpace(in.Code) != strings.TrimSpace(authz.DefaultPolicyCode) {
		return badRequest("JavaScript policies are not supported")
	}
	if r.PathValue("type") == "" {
		// generic update: config as sent
		in.Config = strMap(nonNilStrMap(in.Config))
		cp := *x
		cp.Config = map[string]string{}
		if err := h.applyGeneric(ac, &cp, in); err != nil {
			return err
		}
		x = &cp
	} else if err := h.applyPolicyInput(ac, x, typ, in); err != nil {
		return err
	}
	if err := h.Svc.Store.UpdateAuthzPolicy(r.Context(), x); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return conflict("Policy with name [" + x.Name + "] already exists")
		}
		return err
	}
	return noContent(w)
}

func nonNilStrMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// applyGeneric applies a generic representation (config as is; resources,
// scopes and applyPolicies in config refer by name).
func (h *Handler) applyGeneric(ac *authzCtx, x *model.AuthzPolicy, in *typedPolicyInput) error {
	if in.Name != "" {
		x.Name = in.Name
	}
	x.Description = in.Description
	if in.Logic != "" {
		x.Logic = in.Logic
	}
	if in.DecisionStrategy != "" {
		x.DecisionStrategy = in.DecisionStrategy
	}
	for k, v := range in.Config {
		x.Config[k] = v
	}
	for key, kind := range map[string]string{"applyPolicies": "policy", "resources": "resource", "scopes": "scope"} {
		raw, ok := x.Config[key]
		if !ok {
			continue
		}
		delete(x.Config, key)
		var names []string
		json.Unmarshal([]byte(raw), &names)
		resolved, err := h.resolveIDs(ac, names, kind)
		if err != nil {
			return err
		}
		switch key {
		case "applyPolicies":
			x.AssociatedIDs = resolved
		case "resources":
			x.ResourceIDs = resolved
		case "scopes":
			x.ScopeIDs = resolved
		}
	}
	return nil
}

func (h *Handler) deleteAuthzPolicy(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, true)
	if err != nil {
		return err
	}
	x, err := h.authzPolicy(r, ac)
	if err != nil {
		return err
	}
	if err := h.Svc.Store.DeleteAuthzPolicy(r.Context(), ac.client.ID, x.ID); err != nil {
		return err
	}
	return noContent(w)
}

// policyLinks serves the associatedPolicies, dependentPolicies, scopes and
// resources of a policy.
func (h *Handler) policyLinks(kind string) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request, p *principal) error {
		ac, err := h.loadAuthz(r, p, false)
		if err != nil {
			return err
		}
		x, err := h.authzPolicy(r, ac)
		if err != nil {
			return err
		}
		d := ac.data
		switch kind {
		case "associated":
			out := []policyRep{}
			for _, id := range x.AssociatedIDs {
				if a := d.Policy(id); a != nil {
					out = append(out, policyToRep(a, false))
				}
			}
			return ok(w, out)
		case "dependent":
			out := []policyRep{}
			for _, other := range d.Policies {
				if slices.Contains(other.AssociatedIDs, x.ID) {
					out = append(out, policyToRep(other, false))
				}
			}
			return ok(w, out)
		case "scopes":
			out := []authzScopeRep{}
			for _, id := range x.ScopeIDs {
				if s := d.Scope(id); s != nil {
					out = append(out, scopeToRep(s))
				}
			}
			return ok(w, out)
		default:
			out := []map[string]string{}
			for _, id := range x.ResourceIDs {
				if res := d.Resource(id); res != nil {
					out = append(out, map[string]string{"_id": res.ID, "name": res.Name})
				}
			}
			return ok(w, out)
		}
	}
}

// policyProviders lists the policy types (/policy/providers and
// /permission/providers).
func (h *Handler) policyProviders(w http.ResponseWriter, r *http.Request, p *principal) error {
	if _, err := h.loadAuthz(r, p, false); err != nil {
		return err
	}
	return ok(w, []map[string]string{
		{"group": "Identity Based", "name": "Regex", "type": "regex"}, {"group": "Identity Based", "name": "Role", "type": "role"},
		{"group": "Permission", "name": "Resource-Based", "type": "resource"}, {"group": "Permission", "name": "Scope-Based", "type": "scope"},
		{"group": "Identity Based", "name": "Client", "type": "client"}, {"group": "Time Based", "name": "Time", "type": "time"},
		{"group": "Identity Based", "name": "User", "type": "user"}, {"group": "Identity Based", "name": "Client Scope", "type": "client-scope"},
		{"group": "Identity Based", "name": "Group", "type": "group"}, {"group": "Others", "name": "Aggregated", "type": "aggregate"},
	})
}

// ---------------------------------------------------------------- evaluation

// evaluatePolicies implements POST /policy/evaluate.
func (h *Handler) evaluatePolicies(w http.ResponseWriter, r *http.Request, p *principal) error {
	ac, err := h.loadAuthz(r, p, false)
	if err != nil {
		return err
	}
	ctx := r.Context()
	var req struct {
		UserID    string `json:"userId"`
		ClientID  string `json:"clientId"`
		RoleIDs   []string
		Resources []struct {
			ID     string            `json:"_id"`
			Name   string            `json:"name"`
			Scopes []json.RawMessage `json:"scopes"`
		} `json:"resources"`
		Context struct {
			Attributes map[string]string `json:"attributes"`
		} `json:"context"`
		Entitlements bool `json:"entitlements"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	var user *model.User
	if req.UserID != "" {
		user, err = h.Svc.Store.GetUser(ctx, ac.realm.ID, req.UserID)
		if err != nil {
			if user, err = h.Svc.Store.GetUserByUsername(ctx, ac.realm.ID, strings.ToLower(req.UserID)); err != nil {
				return badRequest("User [" + req.UserID + "] not found")
			}
		}
	} else {
		if user, err = h.Svc.Store.GetServiceAccountUser(ctx, ac.client.ID); err != nil {
			return badRequest("No user to evaluate")
		}
	}
	clientUUID := ac.client.ID
	if req.ClientID != "" {
		if c, err := h.Svc.Store.GetClient(ctx, ac.realm.ID, req.ClientID); err == nil {
			clientUUID = c.ID
		} else if c, err := h.Svc.Store.GetClientByClientID(ctx, ac.realm.ID, req.ClientID); err == nil {
			clientUUID = c.ID
		}
	}
	evalClient, _ := h.Svc.Store.GetClient(ctx, ac.realm.ID, clientUUID)
	claims, err := oidc.ExampleClaims(ctx, h.Svc, h.URLs.Issuer(r, ac.realm.Name), h.URLs.Base(r), ac.realm, evalClient, user, "", "access")
	if err != nil {
		return err
	}
	id, err := h.Svc.AuthzIdentity(ctx, ac.realm, user, clientUUID, claims)
	if err != nil {
		return err
	}
	for _, rid := range req.RoleIDs {
		id.Roles[rid] = true
	}
	for k, v := range req.Context.Attributes {
		id.Attributes[k] = []string{v}
	}
	var requests []authz.Requested
	for _, res := range req.Resources {
		rq := authz.Requested{ResourceID: res.ID}
		if rq.ResourceID == "" && res.Name != "" {
			if x := ac.data.ResourceByName(res.Name); x != nil {
				rq.ResourceID = x.ID
			}
		}
		names, sids := scopeNames(json.RawMessage(mustJSON(res.Scopes)))
		for _, n := range names {
			if s := ac.data.ScopeByName(n); s != nil {
				rq.Scopes = append(rq.Scopes, s.ID)
			}
		}
		rq.Scopes = append(rq.Scopes, sids...)
		requests = append(requests, rq)
	}
	results := authz.Evaluate(ac.data, id, requests)
	out := []map[string]any{}
	status := "DENY"
	for _, res := range results {
		name := res.Resource.Name
		if len(res.Requested) > 0 {
			var sn []string
			for _, s := range res.Requested {
				sn = append(sn, s.Name)
			}
			name += " with scopes [" + strings.Join(sn, ", ") + "]"
		}
		st := "DENY"
		if res.Allowed {
			st, status = "PERMIT", "PERMIT"
		}
		policies := []map[string]any{}
		for _, dec := range res.Decisions {
			policies = append(policies, h.decisionRep(ac, dec))
		}
		out = append(out, map[string]any{"resource": map[string]string{"_id": res.Resource.ID, "name": name},
			"scopes": scopeReps(res.Requested), "policies": policies, "status": st, "allowedScopes": scopeReps(res.Granted)})
	}
	perms := authz.Permissions(results, true)
	claims["authorization"] = map[string]any{"permissions": perms}
	claims["aud"] = ac.client.ClientID
	return ok(w, map[string]any{"results": out, "entitlements": req.Entitlements, "status": status, "rpt": claims})
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func scopeReps(list []*model.AuthzScope) []authzScopeRep {
	out := []authzScopeRep{}
	for _, s := range list {
		out = append(out, scopeToRep(s))
	}
	return out
}

func (h *Handler) decisionRep(ac *authzCtx, dec *authz.PolicyDecision) map[string]any {
	pol := map[string]any{"id": dec.Policy.ID, "name": dec.Policy.Name, "type": dec.Policy.Type, "logic": dec.Policy.Logic,
		"decisionStrategy": dec.Policy.DecisionStrategy, "config": map[string]string{}, "resources": []string{}, "scopes": []string{}}
	if dec.Policy.Description != "" {
		pol["description"] = dec.Policy.Description
	}
	var resources, scopes []string
	for _, id := range dec.Policy.ResourceIDs {
		if r := ac.data.Resource(id); r != nil {
			resources = append(resources, r.Name)
		}
	}
	for _, id := range dec.Policy.ScopeIDs {
		if s := ac.data.Scope(id); s != nil {
			scopes = append(scopes, s.Name)
		}
	}
	pol["resources"], pol["scopes"] = nonNil(resources), nonNil(scopes)
	assoc := []map[string]any{}
	for _, a := range dec.Associated {
		assoc = append(assoc, h.decisionRep(ac, a))
	}
	status := "DENY"
	if dec.Granted {
		status = "PERMIT"
	}
	return map[string]any{"policy": pol, "status": status, "associatedPolicies": assoc, "scopes": []string{}}
}

// ---------------------------------------------------------------- routes

func (h *Handler) registerAuthzRoutes(R string, add func(string, handlerFunc)) {
	Z := R + "/clients/{id}/authz/resource-server"
	add("GET "+Z, h.getResourceServer)
	add("PUT "+Z, h.updateResourceServer)
	add("GET "+Z+"/settings", h.resourceServerSettings)
	add("POST "+Z+"/import", h.importResourceServer)

	add("GET "+Z+"/scope", h.listAuthzScopes)
	add("POST "+Z+"/scope", h.createAuthzScope)
	add("GET "+Z+"/scope/search", h.searchAuthzScope)
	add("GET "+Z+"/scope/{sid}", h.getAuthzScope)
	add("PUT "+Z+"/scope/{sid}", h.updateAuthzScope)
	add("DELETE "+Z+"/scope/{sid}", h.deleteAuthzScope)
	add("GET "+Z+"/scope/{sid}/resources", h.authzScopeResources)
	add("GET "+Z+"/scope/{sid}/permissions", h.authzScopePermissions)

	add("GET "+Z+"/resource", h.listAuthzResources)
	add("POST "+Z+"/resource", h.createAuthzResource)
	add("GET "+Z+"/resource/search", h.searchAuthzResource)
	add("GET "+Z+"/resource/{rid}", h.getAuthzResource)
	add("PUT "+Z+"/resource/{rid}", h.updateAuthzResource)
	add("DELETE "+Z+"/resource/{rid}", h.deleteAuthzResource)
	add("GET "+Z+"/resource/{rid}/scopes", h.authzResourceScopes)
	add("GET "+Z+"/resource/{rid}/permissions", h.authzResourcePermissions)
	add("GET "+Z+"/resource/{rid}/attributes", h.authzResourceAttributes)

	for _, base := range []string{Z + "/policy", Z + "/permission"} {
		add("GET "+base+"/providers", h.policyProviders)
		add("GET "+base+"/search", h.searchAuthzPolicy)
		add("POST "+base, h.createAuthzPolicy)
		add("POST "+base+"/{type}", h.createAuthzPolicy)
		add("GET "+base+"/{pid}", h.getAuthzPolicy)
		add("PUT "+base+"/{pid}", h.updateAuthzPolicy)
		add("DELETE "+base+"/{pid}", h.deleteAuthzPolicy)
		add("GET "+base+"/{type}/{pid}", h.getAuthzPolicy)
		add("PUT "+base+"/{type}/{pid}", h.updateAuthzPolicy)
		add("DELETE "+base+"/{type}/{pid}", h.deleteAuthzPolicy)
		add("GET "+base+"/{pid}/associatedPolicies", h.policyLinks("associated"))
		add("GET "+base+"/{pid}/dependentPolicies", h.policyLinks("dependent"))
		add("GET "+base+"/{pid}/scopes", h.policyLinks("scopes"))
		add("GET "+base+"/{pid}/resources", h.policyLinks("resources"))
	}
	add("GET "+Z+"/policy", h.listAuthzPolicies(false))
	add("GET "+Z+"/permission", h.listAuthzPolicies(true))
	add("POST "+Z+"/policy/evaluate", h.evaluatePolicies)
}

// applyAuthorization enables or disables a client's authorization services
// as a client representation asks, importing its settings.
func (h *Handler) applyAuthorization(ctx context.Context, tx *store.Store, realm *model.Realm, c *model.Client, rep *ClientRep) error {
	if rep.AuthorizationServicesEnabled == nil {
		return nil
	}
	if !*rep.AuthorizationServicesEnabled {
		return h.Svc.DisableAuthorization(ctx, tx, c)
	}
	if err := h.Svc.EnableAuthorization(ctx, tx, c); err != nil {
		return err
	}
	if len(rep.AuthorizationSettings) == 0 || string(rep.AuthorizationSettings) == "null" {
		return nil
	}
	var s AuthzSettings
	if err := json.Unmarshal(rep.AuthorizationSettings, &s); err != nil {
		return badRequest("Invalid authorizationSettings: " + err.Error())
	}
	return h.importSettings(ctx, tx, realm, c, &s)
}
