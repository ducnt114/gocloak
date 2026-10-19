package admin

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
)

// The *Rep types mirror Keycloak's JSON representations. Pointer fields let
// PUT requests update only the attributes that are present, as Keycloak does.

type RealmRep struct {
	ID                     *string  `json:"id,omitempty"`
	Realm                  *string  `json:"realm,omitempty"`
	DisplayName            *string  `json:"displayName,omitempty"`
	Enabled                *bool    `json:"enabled,omitempty"`
	AccessTokenLifespan    *int     `json:"accessTokenLifespan,omitempty"`
	AccessCodeLifespan     *int     `json:"accessCodeLifespan,omitempty"`
	SSOSessionIdleTimeout  *int     `json:"ssoSessionIdleTimeout,omitempty"`
	SSOSessionMaxLifespan  *int     `json:"ssoSessionMaxLifespan,omitempty"`
	LoginWithEmailAllowed  *bool    `json:"loginWithEmailAllowed,omitempty"`
	DuplicateEmailsAllowed *bool    `json:"duplicateEmailsAllowed,omitempty"`
	RegistrationAllowed    *bool    `json:"registrationAllowed,omitempty"`
	Attributes             strMap   `json:"attributes,omitempty"`
	DefaultRole            *RoleRep `json:"defaultRole,omitempty"`

	// Settings flatten into the realm JSON, as in Keycloak. PUT requests
	// apply them by decoding the body onto the stored settings, so absent
	// keys keep their value.
	model.RealmSettings

	// Only used for import.
	Roles                       *RolesRep                    `json:"roles,omitempty"`
	Clients                     []ClientRep                  `json:"clients,omitempty"`
	Users                       []UserRep                    `json:"users,omitempty"`
	Groups                      []GroupRep                   `json:"groups,omitempty"`
	ClientScopes                []ClientScopeRep             `json:"clientScopes,omitempty"`
	DefaultDefaultClientScopes  []string                     `json:"defaultDefaultClientScopes,omitempty"`
	DefaultOptionalClientScopes []string                     `json:"defaultOptionalClientScopes,omitempty"`
	ScopeMappings               []ScopeMappingRep            `json:"scopeMappings,omitempty"`
	ClientScopeMappings         map[string][]ScopeMappingRep `json:"clientScopeMappings,omitempty"`
	AuthenticationFlows         []flowRep                    `json:"authenticationFlows,omitempty"`
	AuthenticatorConfig         []authConfigRep              `json:"authenticatorConfig,omitempty"`
	RequiredActions             []requiredActionRep          `json:"requiredActions,omitempty"`
	Components                  map[string][]componentExport `json:"components,omitempty"`
	IdentityProviders           []IdentityProviderRep        `json:"identityProviders,omitempty"`
	DefaultGroups               []string                     `json:"defaultGroups,omitempty"`
	IdentityProviderMappers     []IdPMapperRep               `json:"identityProviderMappers,omitempty"`
}

// componentExport is a component in a realm export (with its secrets).
type componentExport struct {
	ID            string                       `json:"id,omitempty"`
	Name          string                       `json:"name"`
	ProviderID    string                       `json:"providerId"`
	SubType       string                       `json:"subType,omitempty"`
	SubComponents map[string][]componentExport `json:"subComponents"`
	Config        map[string][]string          `json:"config"`
}

type RolesRep struct {
	Realm  []RoleRep            `json:"realm,omitempty"`
	Client map[string][]RoleRep `json:"client,omitempty"`
}

type ClientRep struct {
	ID                                 *string             `json:"id,omitempty"`
	ClientID                           *string             `json:"clientId,omitempty"`
	Name                               *string             `json:"name,omitempty"`
	Description                        *string             `json:"description,omitempty"`
	Enabled                            *bool               `json:"enabled,omitempty"`
	PublicClient                       *bool               `json:"publicClient,omitempty"`
	BearerOnly                         *bool               `json:"bearerOnly,omitempty"`
	ClientAuthenticatorType            *string             `json:"clientAuthenticatorType,omitempty"`
	NotBefore                          *int64              `json:"notBefore,omitempty"`
	Secret                             *string             `json:"secret,omitempty"`
	RootURL                            *string             `json:"rootUrl,omitempty"`
	AdminURL                           *string             `json:"adminUrl,omitempty"`
	BaseURL                            *string             `json:"baseUrl,omitempty"`
	RedirectURIs                       []string            `json:"redirectUris"`
	WebOrigins                         []string            `json:"webOrigins"`
	StandardFlowEnabled                *bool               `json:"standardFlowEnabled,omitempty"`
	ImplicitFlowEnabled                *bool               `json:"implicitFlowEnabled,omitempty"`
	DirectAccessGrantsEnabled          *bool               `json:"directAccessGrantsEnabled,omitempty"`
	ServiceAccountsEnabled             *bool               `json:"serviceAccountsEnabled,omitempty"`
	ConsentRequired                    *bool               `json:"consentRequired,omitempty"`
	FullScopeAllowed                   *bool               `json:"fullScopeAllowed,omitempty"`
	FrontchannelLogout                 *bool               `json:"frontchannelLogout,omitempty"`
	Protocol                           *string             `json:"protocol,omitempty"`
	Attributes                         strMap              `json:"attributes,omitempty"`
	ProtocolMappers                    []ProtocolMapperRep `json:"protocolMappers,omitempty"`
	DefaultClientScopes                []string            `json:"defaultClientScopes,omitempty"`
	AuthenticationFlowBindingOverrides map[string]string   `json:"authenticationFlowBindingOverrides,omitempty"`
	OptionalClientScopes               []string            `json:"optionalClientScopes,omitempty"`
	AuthorizationServicesEnabled       *bool               `json:"authorizationServicesEnabled,omitempty"`
	AuthorizationSettings              json.RawMessage     `json:"authorizationSettings,omitempty"`
}

// ClientConsentRep is a user's consent in realm exports.
type ClientConsentRep struct {
	ClientID            string   `json:"clientId"`
	GrantedClientScopes []string `json:"grantedClientScopes"`
	CreatedDate         int64    `json:"createdDate,omitempty"`
	LastUpdatedDate     int64    `json:"lastUpdatedDate,omitempty"`
}

type CredentialRep struct {
	ID             string `json:"id,omitempty"`
	Type           string `json:"type,omitempty"`
	UserLabel      string `json:"userLabel,omitempty"`
	CreatedDate    int64  `json:"createdDate,omitempty"`
	Value          string `json:"value,omitempty"`
	Temporary      *bool  `json:"temporary,omitempty"`
	SecretData     string `json:"secretData,omitempty"`
	CredentialData string `json:"credentialData,omitempty"`
	Priority       int    `json:"priority,omitempty"`
}

type UserRep struct {
	ID                     *string         `json:"id,omitempty"`
	Username               *string         `json:"username,omitempty"`
	Email                  *string         `json:"email,omitempty"`
	EmailVerified          *bool           `json:"emailVerified,omitempty"`
	FirstName              *string         `json:"firstName,omitempty"`
	LastName               *string         `json:"lastName,omitempty"`
	Enabled                *bool           `json:"enabled,omitempty"`
	CreatedTimestamp       *int64          `json:"createdTimestamp,omitempty"`
	Totp                   *bool           `json:"totp,omitempty"`
	Attributes             listMap         `json:"attributes,omitempty"`
	RequiredActions        []string        `json:"requiredActions"`
	NotBefore              *int64          `json:"notBefore,omitempty"`
	Access                 map[string]bool `json:"access,omitempty"`
	ServiceAccountClientID *string         `json:"serviceAccountClientId,omitempty"`
	DisableableCredTypes   *[]string       `json:"disableableCredentialTypes,omitempty"`
	FederationLink         *string         `json:"federationLink,omitempty"`
	Origin                 *string         `json:"origin,omitempty"`

	UserProfileMetadata *profileMetadata `json:"userProfileMetadata,omitempty"`

	// Only used for create/import.
	Credentials         []CredentialRep        `json:"credentials,omitempty"`
	FederatedIdentities []FederatedIdentityRep `json:"federatedIdentities,omitempty"`
	ClientConsents      []ClientConsentRep     `json:"clientConsents,omitempty"`
	Groups              []string               `json:"groups,omitempty"`
	RealmRoles          []string               `json:"realmRoles,omitempty"`
	ClientRoles         map[string][]string    `json:"clientRoles,omitempty"`
}

type RoleRep struct {
	ID          *string        `json:"id,omitempty"`
	Name        *string        `json:"name,omitempty"`
	Description *string        `json:"description,omitempty"`
	Composite   *bool          `json:"composite,omitempty"`
	ClientRole  *bool          `json:"clientRole,omitempty"`
	ContainerID *string        `json:"containerId,omitempty"`
	Attributes  listMap        `json:"attributes,omitempty"`
	Composites  *CompositesRep `json:"composites,omitempty"`
}

type CompositesRep struct {
	Realm  []string            `json:"realm,omitempty"`
	Client map[string][]string `json:"client,omitempty"`
}

type GroupRep struct {
	ID            *string             `json:"id,omitempty"`
	Name          *string             `json:"name,omitempty"`
	Path          *string             `json:"path,omitempty"`
	ParentID      *string             `json:"parentId,omitempty"`
	SubGroupCount *int                `json:"subGroupCount,omitempty"`
	SubGroups     []GroupRep          `json:"subGroups"`
	Attributes    listMap             `json:"attributes,omitempty"`
	RealmRoles    []string            `json:"realmRoles,omitempty"`
	ClientRoles   map[string][]string `json:"clientRoles,omitempty"`
	Access        map[string]bool     `json:"access,omitempty"`
}

type UserSessionRep struct {
	ID         string            `json:"id"`
	Username   string            `json:"username"`
	UserID     string            `json:"userId"`
	IPAddress  string            `json:"ipAddress"`
	Start      int64             `json:"start"`
	LastAccess int64             `json:"lastAccess"`
	RememberMe bool              `json:"rememberMe"`
	Clients    map[string]string `json:"clients"`
}

type MappingsRep struct {
	RealmMappings  []RoleRep                    `json:"realmMappings,omitempty"`
	ClientMappings map[string]ClientMappingsRep `json:"clientMappings,omitempty"`
}

type ClientMappingsRep struct {
	ID       string    `json:"id"`
	Client   string    `json:"client"`
	Mappings []RoleRep `json:"mappings"`
}

// NewRealmRep returns a realm representation pre-filled with Keycloak's
// default settings; decode a realm JSON into it so absent keys keep them.
func NewRealmRep() RealmRep {
	return RealmRep{RealmSettings: model.DefaultRealmSettings()}
}

func ptr[T any](v T) *T { return &v }

// optional is nil for an empty string (an omitted field).
func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func set[T any](dst *T, src *T) {
	if src != nil {
		*dst = *src
	}
}

// ---------------------------------------------------------------- realm

func realmToRep(r *model.Realm, defaultRole *model.Role) RealmRep {
	rep := RealmRep{
		ID: ptr(r.ID), Realm: ptr(r.Name), DisplayName: ptr(r.DisplayName), Enabled: ptr(r.Enabled),
		AccessTokenLifespan: ptr(r.AccessTokenLifespan), AccessCodeLifespan: ptr(r.AccessCodeLifespan),
		SSOSessionIdleTimeout: ptr(r.SSOSessionIdleTimeout), SSOSessionMaxLifespan: ptr(r.SSOSessionMaxLifespan),
		LoginWithEmailAllowed: ptr(r.LoginWithEmailAllowed), DuplicateEmailsAllowed: ptr(r.DuplicateEmailsAllowed),
		RegistrationAllowed: ptr(r.RegistrationAllowed), Attributes: r.Attributes, RealmSettings: r.Settings,
	}
	if defaultRole != nil {
		dr := roleToRep(defaultRole, r.ID)
		rep.DefaultRole = &dr
	}
	return rep
}

func applyRealmRep(r *model.Realm, rep *RealmRep) {
	set(&r.Name, rep.Realm)
	set(&r.DisplayName, rep.DisplayName)
	set(&r.Enabled, rep.Enabled)
	set(&r.AccessTokenLifespan, rep.AccessTokenLifespan)
	set(&r.AccessCodeLifespan, rep.AccessCodeLifespan)
	set(&r.SSOSessionIdleTimeout, rep.SSOSessionIdleTimeout)
	set(&r.SSOSessionMaxLifespan, rep.SSOSessionMaxLifespan)
	set(&r.LoginWithEmailAllowed, rep.LoginWithEmailAllowed)
	set(&r.DuplicateEmailsAllowed, rep.DuplicateEmailsAllowed)
	set(&r.RegistrationAllowed, rep.RegistrationAllowed)
	if rep.Attributes != nil {
		r.Attributes = rep.Attributes
	}
}

// ---------------------------------------------------------------- client

func clientToRep(c *model.Client) ClientRep {
	return ClientRep{
		ID: ptr(c.ID), ClientID: ptr(c.ClientID), Name: ptr(c.Name), Description: ptr(c.Description),
		Enabled: ptr(c.Enabled), PublicClient: ptr(c.PublicClient), BearerOnly: ptr(c.BearerOnly),
		ClientAuthenticatorType: ptr(authenticatorType(c)), NotBefore: ptr(c.NotBefore),
		AuthenticationFlowBindingOverrides: nonNilMap(c.FlowOverrides),
		RootURL:                            ptr(c.RootURL), BaseURL: ptr(c.BaseURL), RedirectURIs: nonNil(c.RedirectURIs), WebOrigins: nonNil(c.WebOrigins),
		StandardFlowEnabled: ptr(c.StandardFlowEnabled), ImplicitFlowEnabled: ptr(false),
		DirectAccessGrantsEnabled: ptr(c.DirectAccessGrantsEnabled), ServiceAccountsEnabled: ptr(c.ServiceAccountsEnabled),
		ConsentRequired: ptr(c.ConsentRequired), FullScopeAllowed: ptr(c.FullScopeAllowed), Protocol: ptr(c.Protocol),
		Attributes: c.Attributes, FrontchannelLogout: ptr(c.FrontchannelLogout), AdminURL: optional(c.AdminURL),
	}
}

// newClient returns a client with Keycloak's defaults for a created client.
func newClient(realmID string) *model.Client {
	return &model.Client{RealmID: realmID, Enabled: true, StandardFlowEnabled: true, FullScopeAllowed: true,
		Protocol: "openid-connect", Attributes: map[string]string{}}
}

// newClientFromRep builds a client being created. Like Keycloak, a client
// created without webOrigins gets the origins of its http(s) redirect URIs.
func newClientFromRep(realmID string, rep *ClientRep) *model.Client {
	c := newClient(realmID)
	if rep.ID != nil {
		c.ID = *rep.ID
	}
	applyClientRep(c, rep)
	if c.Protocol == service.ProtocolSAML && rep.FrontchannelLogout == nil {
		c.FrontchannelLogout = true
	}
	if rep.WebOrigins == nil {
		seen := map[string]bool{}
		for _, u := range c.RedirectURIs {
			if !strings.HasPrefix(u, "http") {
				continue
			}
			if parsed, err := url.Parse(strings.TrimSuffix(u, "*")); err == nil && parsed.Host != "" {
				o := parsed.Scheme + "://" + parsed.Host
				if !seen[o] {
					seen[o] = true
					c.WebOrigins = append(c.WebOrigins, o)
				}
			}
		}
	}
	return c
}

func applyClientRep(c *model.Client, rep *ClientRep) {
	set(&c.ClientID, rep.ClientID)
	set(&c.Name, rep.Name)
	set(&c.Description, rep.Description)
	set(&c.Enabled, rep.Enabled)
	set(&c.PublicClient, rep.PublicClient)
	set(&c.BearerOnly, rep.BearerOnly)
	if rep.Secret != nil && *rep.Secret != "**********" {
		c.Secret = *rep.Secret
	}
	set(&c.RootURL, rep.RootURL)
	set(&c.AdminURL, rep.AdminURL)
	set(&c.BaseURL, rep.BaseURL)
	set(&c.FrontchannelLogout, rep.FrontchannelLogout)
	set(&c.ConsentRequired, rep.ConsentRequired)
	if rep.RedirectURIs != nil {
		c.RedirectURIs = rep.RedirectURIs
	}
	if rep.WebOrigins != nil {
		c.WebOrigins = rep.WebOrigins
	}
	set(&c.StandardFlowEnabled, rep.StandardFlowEnabled)
	set(&c.DirectAccessGrantsEnabled, rep.DirectAccessGrantsEnabled)
	set(&c.ServiceAccountsEnabled, rep.ServiceAccountsEnabled)
	set(&c.FullScopeAllowed, rep.FullScopeAllowed)
	set(&c.Protocol, rep.Protocol)
	set(&c.ClientAuthenticatorType, rep.ClientAuthenticatorType)
	set(&c.NotBefore, rep.NotBefore)
	if rep.AuthenticationFlowBindingOverrides != nil {
		c.FlowOverrides = rep.AuthenticationFlowBindingOverrides
	}
	// like Keycloak, the given attributes are merged and empty values
	// remove an attribute
	if rep.Attributes != nil {
		if c.Attributes == nil {
			c.Attributes = map[string]string{}
		}
		for k, v := range rep.Attributes {
			if strings.TrimSpace(v) == "" {
				delete(c.Attributes, k)
			} else {
				c.Attributes[k] = v
			}
		}
	}
	if c.PublicClient {
		c.Secret = ""
	}
}

// ---------------------------------------------------------------- user

func userToRep(u *model.User) UserRep {
	rep := UserRep{
		ID: ptr(u.ID), Username: ptr(u.Username), EmailVerified: ptr(u.EmailVerified),
		Enabled: ptr(u.Enabled), CreatedTimestamp: ptr(u.CreatedTimestamp), Totp: ptr(false),
		RequiredActions: nonNil(u.RequiredActions), NotBefore: ptr(u.NotBefore),
		Access:               map[string]bool{"manageGroupMembership": true, "view": true, "mapRoles": true, "impersonate": false, "manage": true},
		DisableableCredTypes: &[]string{},
	}
	if u.Email != "" {
		rep.Email = ptr(u.Email)
	}
	if u.FirstName != "" {
		rep.FirstName = ptr(u.FirstName)
	}
	if u.LastName != "" {
		rep.LastName = ptr(u.LastName)
	}
	if len(u.Attributes) > 0 {
		rep.Attributes = u.Attributes
	}
	if u.FederationLink != "" {
		rep.FederationLink, rep.Origin = ptr(u.FederationLink), ptr(u.FederationLink)
	}
	return rep
}

func applyUserRep(u *model.User, rep *UserRep) {
	set(&u.Username, rep.Username)
	set(&u.Email, rep.Email)
	set(&u.EmailVerified, rep.EmailVerified)
	set(&u.FirstName, rep.FirstName)
	set(&u.LastName, rep.LastName)
	set(&u.Enabled, rep.Enabled)
	set(&u.NotBefore, rep.NotBefore)
	if rep.Attributes != nil {
		u.Attributes = rep.Attributes
	}
	if rep.RequiredActions != nil {
		u.RequiredActions = rep.RequiredActions
	}
}

// ---------------------------------------------------------------- role

func roleToRep(r *model.Role, realmID string) RoleRep {
	container := realmID
	if r.ClientID != "" {
		container = r.ClientID
	}
	rep := RoleRep{ID: ptr(r.ID), Name: ptr(r.Name), Composite: ptr(r.Composite),
		ClientRole: ptr(r.ClientID != ""), ContainerID: ptr(container), Attributes: r.Attributes}
	if r.Description != "" {
		rep.Description = ptr(r.Description)
	}
	return rep
}

func rolesToRep(roles []*model.Role, realmID string) []RoleRep {
	out := make([]RoleRep, 0, len(roles))
	for _, r := range roles {
		out = append(out, roleToRep(r, realmID))
	}
	return out
}

func applyRoleRep(r *model.Role, rep *RoleRep) {
	set(&r.Name, rep.Name)
	set(&r.Description, rep.Description)
	if rep.Attributes != nil {
		r.Attributes = rep.Attributes
	}
}

// ---------------------------------------------------------------- group

func groupToRep(g *model.Group, path string, subCount int) GroupRep {
	rep := GroupRep{ID: ptr(g.ID), Name: ptr(g.Name), Path: ptr(path), SubGroupCount: ptr(subCount),
		SubGroups: []GroupRep{}, Attributes: g.Attributes,
		Access: map[string]bool{"view": true, "viewMembers": true, "manageMembers": true, "manage": true, "manageMembership": true}}
	if g.ParentID != "" {
		rep.ParentID = ptr(g.ParentID)
	}
	return rep
}

// groupPaths computes "/parent/child" paths for every group.
func groupPaths(groups []*model.Group) map[string]string {
	byID := map[string]*model.Group{}
	for _, g := range groups {
		byID[g.ID] = g
	}
	paths := map[string]string{}
	var path func(id string, depth int) string
	path = func(id string, depth int) string {
		if p, ok := paths[id]; ok {
			return p
		}
		g := byID[id]
		if g == nil || depth > 100 {
			return ""
		}
		p := "/" + g.Name
		if g.ParentID != "" {
			p = path(g.ParentID, depth+1) + p
		}
		paths[id] = p
		return p
	}
	for _, g := range groups {
		path(g.ID, 0)
	}
	return paths
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func splitPath(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func authenticatorType(c *model.Client) string {
	if c.ClientAuthenticatorType == "" {
		return "client-secret"
	}
	return c.ClientAuthenticatorType
}

func nonNilMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
