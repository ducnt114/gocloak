package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/store"
)

// Identity provider mappers import data of the brokered identity into the
// user (attributes, roles, groups) or the user session (notes).

// IdPMapperProperty describes a config property of a mapper type.
type IdPMapperProperty struct {
	Name         string   `json:"name"`
	Label        string   `json:"label"`
	HelpText     string   `json:"helpText"`
	Type         string   `json:"type"`
	DefaultValue any      `json:"defaultValue,omitempty"`
	Options      []string `json:"options,omitempty"`
	Secret       bool     `json:"secret"`
	Required     bool     `json:"required"`
	ReadOnly     bool     `json:"readOnly"`
}

// IdPMapperType is a mapper type, as listed by the mapper-types endpoint.
type IdPMapperType struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Category   string              `json:"category"`
	HelpText   string              `json:"helpText"`
	Properties []IdPMapperProperty `json:"properties"`

	// providers the mapper works with: "*" (any), "oidc" (OIDC family) or
	// a provider id.
	providers []string
	// preprocess changes the identity before the user is looked up.
	preprocess func(m *model.IdentityProviderMapper, idp *model.IdentityProvider, id *brokeredIdentity)
	// apply imports into the user; update is false for a new user.
	apply func(mc *mapperContext, m *model.IdentityProviderMapper, update bool) error
}

var syncModeProperty = IdPMapperProperty{Name: "syncMode", Label: "Sync mode override", Type: "List", DefaultValue: "INHERIT",
	Options:  []string{"INHERIT", "IMPORT", "LEGACY", "FORCE"},
	HelpText: "Overrides the default sync mode of IDP for this mapper. Values are: 'legacy' to keep the behaviour before this option was introduced, 'import' to only import the user once during first login of the user with this identity provider, 'force' to always update the user during every login with this identity provider and 'inherit' to use the sync mode defined in the identity provider for this mapper."}

func prop(name, label, typ, help string) IdPMapperProperty {
	return IdPMapperProperty{Name: name, Label: label, Type: typ, HelpText: help}
}

var (
	claimProp      = prop("claim", "Claim", "String", "Name of claim to search for in token. You can reference nested claims using a '.', i.e. 'address.locality'. To use dot (.) literally, escape it with backslash (\\.)")
	claimValueProp = prop("claim.value", "Claim Value", "String", "Value the claim must have. If the claim is an array, then the value must be contained in the array.")
	roleProp       = prop("role", "Role", "Role", "Role to grant to user if claim is present. Click 'Select Role' button to browse roles, or just type it in the textbox. To reference a client role the syntax is clientname.clientrole, i.e. myclient.myrole")
	groupProp      = prop("group", "Group", "Group", "Assign the user to the specified group.")
	claimsProp     = prop("claims", "Claims", "ClaimList", "Name and value of the claims to search for in token. You can reference nested claims using a '.', i.e. 'address.locality'. To use dot (.) literally, escape it with backslash (\\.)")
	regexProp      = prop("are.claim.values.regex", "Regex Claim Values", "boolean", "If enabled claim values are interpreted as regular expressions.")
)

// IdPMapperTypes are the supported mapper types, by id.
var IdPMapperTypes = map[string]*IdPMapperType{
	"hardcoded-attribute-idp-mapper": {ID: "hardcoded-attribute-idp-mapper", Name: "Hardcoded Attribute", Category: "Attribute Importer",
		HelpText: "When user is imported from provider, hardcode a value to a specific user attribute.", providers: []string{"*"},
		Properties: []IdPMapperProperty{syncModeProperty, prop("attribute", "User Attribute", "UserProfileAttributeList", "Name of user attribute you want to hardcode"),
			prop("attribute.value", "User Attribute Value", "String", "Value you want to hardcode")},
		apply: hardcodedAttribute},
	"hardcoded-user-session-attribute-idp-mapper": {ID: "hardcoded-user-session-attribute-idp-mapper", Name: "Hardcoded User Session Attribute",
		Category: "Attribute Importer", HelpText: "When user is imported from provider, hardcode a value to a specific user session attribute.",
		providers: []string{"*"},
		Properties: []IdPMapperProperty{syncModeProperty, prop("attribute", "User Session Attribute", "String", "Name of user session attribute you want to hardcode"),
			prop("attribute.value", "User Session Attribute Value", "String", "Value you want to hardcode")},
		apply: hardcodedSessionAttribute},
	"oidc-hardcoded-role-idp-mapper": {ID: "oidc-hardcoded-role-idp-mapper", Name: "Hardcoded Role", Category: "Role Importer",
		HelpText: "When user is imported from provider, hardcode a role mapping for it.", providers: []string{"*"},
		Properties: []IdPMapperProperty{syncModeProperty, roleProp}, apply: hardcodedRole},
	"oidc-hardcoded-group-idp-mapper": {ID: "oidc-hardcoded-group-idp-mapper", Name: "Hardcoded Group", Category: "Group Importer",
		HelpText: "When user is imported from provider, hardcode a group mapping for it.", providers: []string{"*"},
		Properties: []IdPMapperProperty{syncModeProperty, groupProp}, apply: hardcodedGroup},
	"oidc-username-idp-mapper": {ID: "oidc-username-idp-mapper", Name: "Username Template Importer", Category: "Preprocessor",
		HelpText: "Format the username to import.", providers: []string{"*"},
		Properties: []IdPMapperProperty{syncModeProperty,
			{Name: "template", Label: "Template", Type: "String", DefaultValue: "${ALIAS}.${CLAIM.preferred_username}",
				HelpText: "Template to use to format the username to import.  Substitutions are enclosed in ${}.  For example: '${ALIAS}.${CLAIM.sub}'.  ALIAS is the provider alias.  CLAIM.<NAME> references an ID or Access token claim.  The substitution can be converted to upper or lower case by appending |uppercase or |lowercase to the substituted value, e.g. '${CLAIM.sub | lowercase}"},
			{Name: "target", Label: "Target", Type: "List", DefaultValue: "LOCAL", Options: []string{"LOCAL", "BROKER_ID", "BROKER_USERNAME"},
				HelpText: "Destination field for the mapper. LOCAL (default) means that the changes are applied to the username stored in local database upon user import. BROKER_ID and BROKER_USERNAME means that the changes are stored into the ID or username used for federation user lookup, respectively."}},
		preprocess: usernameTemplate},
	"oidc-user-attribute-idp-mapper": {ID: "oidc-user-attribute-idp-mapper", Name: "Attribute Importer", Category: "Attribute Importer",
		HelpText:  "Import declared claim if it exists in ID, access token or the claim set returned by the user profile endpoint into the specified user property or attribute.",
		providers: []string{"oidc"},
		Properties: []IdPMapperProperty{syncModeProperty, claimProp,
			prop("user.attribute", "User Attribute Name", "UserProfileAttributeList", "User attribute name to store claim.  Use email, lastName, and firstName to map to those predefined user properties.")},
		apply: claimToAttribute("claim", "user.attribute")},
	"oidc-role-idp-mapper": {ID: "oidc-role-idp-mapper", Name: "Claim to Role", Category: "Role Importer",
		HelpText: "If a claim exists, grant the user the specified realm or client role.", providers: []string{"oidc"},
		Properties: []IdPMapperProperty{syncModeProperty, claimProp, claimValueProp, roleProp}, apply: claimToRole},
	"oidc-advanced-role-idp-mapper": {ID: "oidc-advanced-role-idp-mapper", Name: "Advanced Claim to Role", Category: "Role Importer",
		HelpText: "If all claims exists, grant the user the specified realm or client role.", providers: []string{"oidc"},
		Properties: []IdPMapperProperty{syncModeProperty, claimsProp, regexProp, roleProp}, apply: advancedClaimToRole},
	"oidc-advanced-group-idp-mapper": {ID: "oidc-advanced-group-idp-mapper", Name: "Advanced Claim to Group", Category: "Group Importer",
		HelpText: "If all claims exists, assign the user to the specified group.", providers: []string{"oidc"},
		Properties: []IdPMapperProperty{syncModeProperty, claimsProp, regexProp, groupProp}, apply: advancedClaimToGroup},
	"oidc-user-session-note-idp-mapper": {ID: "oidc-user-session-note-idp-mapper", Name: "User Session Note Mapper", Category: "User Session",
		HelpText:   "Add every matching claim to the user session note. This can be used together for instance with the User Session Note protocol mapper configured for your client scope or client, so claims for 1st identity provider are available in the token.",
		providers:  []string{"oidc"},
		Properties: []IdPMapperProperty{syncModeProperty, prop("claims", "Claims", "MultivaluedString", "Name of the claims to store as user session notes.")},
		apply:      claimsToSessionNotes},
}

func init() {
	// Social providers have their own JSON field importer.
	for _, p := range []string{"github", "google", "facebook", "gitlab", "microsoft", "apple"} {
		id := p + "-user-attribute-mapper"
		IdPMapperTypes[id] = &IdPMapperType{ID: id, Name: "Attribute Importer", Category: "Attribute Importer",
			HelpText:  "Import user profile information if it exists in Social provider JSON data into the specified user attribute.",
			providers: []string{p},
			Properties: []IdPMapperProperty{syncModeProperty,
				prop("jsonField", "Social Profile JSON Field Path", "String", "Path of field in Social provider User Profile JSON data to get value from. You can use dot notation for nesting and square brackets for array index. Eg. 'contact.address[0].country'."),
				prop("userAttribute", "User Attribute Name", "UserProfileAttributeList", "User attribute name to store information into.")},
			apply: claimToAttribute("jsonField", "userAttribute")}
	}
}

// MapperTypesFor lists the mapper types usable with a provider type.
func MapperTypesFor(providerID string) map[string]*IdPMapperType {
	t := IdPTypes[providerID]
	out := map[string]*IdPMapperType{}
	for id, m := range IdPMapperTypes {
		for _, p := range m.providers {
			if p == "*" || p == providerID || (p == "oidc" && t != nil && t.OIDC && !t.Social) {
				out[id] = m
			}
		}
	}
	return out
}

// mapperContext is the state mappers work on.
type mapperContext struct {
	ctx   context.Context
	st    *store.Store
	realm *model.Realm
	idp   *model.IdentityProvider
	id    *brokeredIdentity
	user  *model.User
	notes map[string]string // user session notes to set
	dirty bool              // user fields changed
}

// syncMode is the effective sync mode of a mapper.
func syncMode(idp *model.IdentityProvider, m *model.IdentityProviderMapper) string {
	mode := m.Config["syncMode"]
	if mode == "" || mode == "INHERIT" {
		mode = idp.Config["syncMode"]
	}
	if mode == "" {
		mode = "LEGACY"
	}
	return mode
}

// preprocessIdentity applies the preprocessors (username template).
func preprocessIdentity(idp *model.IdentityProvider, mappers []*model.IdentityProviderMapper, id *brokeredIdentity) {
	for _, m := range mappers {
		if t := IdPMapperTypes[m.Type]; t != nil && t.preprocess != nil {
			t.preprocess(m, idp, id)
		}
	}
}

// runMappers imports into a new user (update false) or updates an existing
// one at login, honouring the sync mode.
func runMappers(mc *mapperContext, mappers []*model.IdentityProviderMapper, update bool) error {
	for _, m := range mappers {
		t := IdPMapperTypes[m.Type]
		if t == nil || t.apply == nil {
			continue
		}
		if update && syncMode(mc.idp, m) == "IMPORT" && t.Category != "User Session" {
			continue
		}
		if err := t.apply(mc, m, update); err != nil {
			return fmt.Errorf("identity provider mapper %s: %w", m.Name, err)
		}
	}
	if mc.dirty && mc.user.ID != "" {
		return mc.st.UpdateUser(mc.ctx, mc.user)
	}
	return nil
}

// ---------------------------------------------------------------- claims

// claimValue reads a claim by path ("address.locality", "a\.b" for a
// literal dot, "list[0]" for an array element).
func claimValue(claims map[string]any, path string) any {
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(path); i++ {
		switch {
		case path[i] == '\\' && i+1 < len(path) && path[i+1] == '.':
			cur.WriteByte('.')
			i++
		case path[i] == '.':
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(path[i])
		}
	}
	parts = append(parts, cur.String())
	var v any = claims
	for _, p := range parts {
		idx := -1
		if i := strings.IndexByte(p, '['); i > 0 && strings.HasSuffix(p, "]") {
			fmt.Sscan(p[i+1:len(p)-1], &idx)
			p = p[:i]
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[p]
		if idx >= 0 {
			list, ok := v.([]any)
			if !ok || idx >= len(list) {
				return nil
			}
			v = list[idx]
		}
	}
	return v
}

// claimStrings flattens a claim value to strings.
func claimStrings(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case []any:
		var out []string
		for _, x := range t {
			out = append(out, claimStrings(x)...)
		}
		return out
	case string:
		return []string{t}
	case float64:
		return []string{strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%f", t), "0"), ".")}
	case map[string]any:
		b, _ := json.Marshal(t)
		return []string{string(b)}
	default:
		return []string{fmt.Sprint(t)}
	}
}

func hasClaimValue(claims map[string]any, name, value string) bool {
	return slices.Contains(claimStrings(claimValue(claims, name)), value)
}

// claimsMatch checks the "claims" list of the advanced mappers.
func claimsMatch(claims map[string]any, cfg map[string]string) bool {
	var want []struct{ Key, Value string }
	if json.Unmarshal([]byte(cfg["claims"]), &want) != nil || len(want) == 0 {
		return false
	}
	regex := cfg["are.claim.values.regex"] == "true"
	for _, w := range want {
		values := claimStrings(claimValue(claims, w.Key))
		if regex {
			re, err := regexp.Compile("^(?:" + w.Value + ")$")
			if err != nil || !slices.ContainsFunc(values, re.MatchString) {
				return false
			}
		} else if !slices.Contains(values, w.Value) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- attributes

// setAttribute sets a user property or attribute; values nil removes it.
func (mc *mapperContext) setAttribute(name string, values []string) {
	first := ""
	if len(values) > 0 {
		first = values[0]
	}
	u := mc.user
	switch name {
	case "email":
		if !strings.EqualFold(u.Email, first) {
			u.Email, u.EmailVerified = strings.ToLower(first), false
			mc.dirty = true
		}
	case "firstName":
		mc.dirty = mc.dirty || u.FirstName != first
		u.FirstName = first
	case "lastName":
		mc.dirty = mc.dirty || u.LastName != first
		u.LastName = first
	case "username":
		// the username is not changed by mappers
	default:
		if u.Attributes == nil {
			u.Attributes = map[string][]string{}
		}
		if len(values) == 0 {
			if _, ok := u.Attributes[name]; ok {
				delete(u.Attributes, name)
				mc.dirty = true
			}
			return
		}
		if !slices.Equal(u.Attributes[name], values) {
			u.Attributes[name] = values
			mc.dirty = true
		}
	}
}

func hardcodedAttribute(mc *mapperContext, m *model.IdentityProviderMapper, update bool) error {
	if name := m.Config["attribute"]; name != "" {
		mc.setAttribute(name, []string{m.Config["attribute.value"]})
	}
	return nil
}

func claimToAttribute(claimKey, attrKey string) func(*mapperContext, *model.IdentityProviderMapper, bool) error {
	return func(mc *mapperContext, m *model.IdentityProviderMapper, update bool) error {
		name := m.Config[attrKey]
		if name == "" {
			return nil
		}
		values := claimStrings(claimValue(mc.id.Claims, m.Config[claimKey]))
		if len(values) == 0 && !update {
			return nil
		}
		mc.setAttribute(name, values)
		return nil
	}
}

func hardcodedSessionAttribute(mc *mapperContext, m *model.IdentityProviderMapper, update bool) error {
	if name := m.Config["attribute"]; name != "" {
		mc.notes[name] = m.Config["attribute.value"]
	}
	return nil
}

func claimsToSessionNotes(mc *mapperContext, m *model.IdentityProviderMapper, update bool) error {
	for _, name := range strings.FieldsFunc(m.Config["claims"], func(r rune) bool { return r == ',' || r == '#' }) {
		name = strings.TrimSpace(name)
		if v := claimStrings(claimValue(mc.id.Claims, name)); len(v) > 0 {
			mc.notes[name] = strings.Join(v, ",")
		}
	}
	return nil
}

// ---------------------------------------------------------------- roles and groups

// findRoleRef resolves "role" or "clientId.role".
func findRoleRef(ctx context.Context, st *store.Store, realm *model.Realm, ref string) (*model.Role, error) {
	if ref == "" {
		return nil, nil
	}
	if i := strings.Index(ref, "."); i > 0 {
		// the client id may itself contain dots: try the longest prefix first
		for j := strings.LastIndex(ref, "."); j > 0; j = strings.LastIndex(ref[:j], ".") {
			if c, err := st.GetClientByClientID(ctx, realm.ID, ref[:j]); err == nil {
				r, err := st.GetRoleByName(ctx, realm.ID, c.ID, ref[j+1:])
				if err == nil {
					return r, nil
				}
			}
		}
	}
	r, err := st.GetRoleByName(ctx, realm.ID, "", ref)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("role %q not found", ref)
	}
	return r, err
}

func (mc *mapperContext) grantRole(ref string, grant bool) error {
	role, err := findRoleRef(mc.ctx, mc.st, mc.realm, ref)
	if err != nil || role == nil {
		return err
	}
	if grant {
		return mc.st.GrantUserRole(mc.ctx, mc.user.ID, role.ID)
	}
	return mc.st.RevokeUserRole(mc.ctx, mc.user.ID, role.ID)
}

func hardcodedRole(mc *mapperContext, m *model.IdentityProviderMapper, update bool) error {
	return mc.grantRole(m.Config["role"], true)
}

func claimToRole(mc *mapperContext, m *model.IdentityProviderMapper, update bool) error {
	match := hasClaimValue(mc.id.Claims, m.Config["claim"], m.Config["claim.value"])
	if !match && !update {
		return nil
	}
	return mc.grantRole(m.Config["role"], match)
}

func advancedClaimToRole(mc *mapperContext, m *model.IdentityProviderMapper, update bool) error {
	match := claimsMatch(mc.id.Claims, m.Config)
	if !match && !update {
		return nil
	}
	return mc.grantRole(m.Config["role"], match)
}

func (mc *mapperContext) joinGroup(path string, join bool) error {
	g, err := findGroupPath(mc.ctx, mc.st, mc.realm.ID, path)
	if err != nil || g == nil {
		return err
	}
	if join {
		return mc.st.AddUserToGroup(mc.ctx, mc.user.ID, g.ID)
	}
	return mc.st.RemoveUserFromGroup(mc.ctx, mc.user.ID, g.ID)
}

// findGroupPath resolves a group path such as "/staff/editors".
func findGroupPath(ctx context.Context, st *store.Store, realmID, path string) (*model.Group, error) {
	names := strings.FieldsFunc(path, func(r rune) bool { return r == '/' })
	if len(names) == 0 {
		return nil, nil
	}
	all, err := st.ListAllGroups(ctx, realmID)
	if err != nil {
		return nil, err
	}
	parent := ""
	var found *model.Group
	for _, n := range names {
		found = nil
		for _, g := range all {
			if g.ParentID == parent && g.Name == n {
				found = g
				break
			}
		}
		if found == nil {
			return nil, fmt.Errorf("group %q not found", path)
		}
		parent = found.ID
	}
	return found, nil
}

func hardcodedGroup(mc *mapperContext, m *model.IdentityProviderMapper, update bool) error {
	return mc.joinGroup(m.Config["group"], true)
}

func advancedClaimToGroup(mc *mapperContext, m *model.IdentityProviderMapper, update bool) error {
	match := claimsMatch(mc.id.Claims, m.Config)
	if !match && !update {
		return nil
	}
	return mc.joinGroup(m.Config["group"], match)
}

// ---------------------------------------------------------------- username template

var templateVar = regexp.MustCompile(`\$\{([^}]+)\}`)

func usernameTemplate(m *model.IdentityProviderMapper, idp *model.IdentityProvider, id *brokeredIdentity) {
	tmpl := m.Config["template"]
	if tmpl == "" {
		tmpl = "${ALIAS}.${CLAIM.preferred_username}"
	}
	out := templateVar.ReplaceAllStringFunc(tmpl, func(s string) string {
		expr := strings.TrimSpace(s[2 : len(s)-1])
		name, fn, _ := strings.Cut(expr, "|")
		name, fn = strings.TrimSpace(name), strings.TrimSpace(fn)
		var v string
		switch {
		case name == "ALIAS":
			v = idp.Alias
		case strings.HasPrefix(name, "CLAIM."):
			v = strings.Join(claimStrings(claimValue(id.Claims, strings.TrimPrefix(name, "CLAIM."))), ",")
		default:
			return s
		}
		switch fn {
		case "lowercase":
			v = strings.ToLower(v)
		case "uppercase":
			v = strings.ToUpper(v)
		case "localpart":
			v, _, _ = strings.Cut(v, "@")
		}
		return v
	})
	switch m.Config["target"] {
	case "BROKER_ID":
		id.ID = out
	case "BROKER_USERNAME":
		id.BrokerUsername = out
	default:
		id.Username = out
	}
}
