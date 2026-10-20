package service

import (
	"context"
	"errors"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/store"
)

// Protocol mapper types (provider ids) implemented by gocloak.
const (
	MapperUserProperty    = "oidc-usermodel-property-mapper"
	MapperUserAttribute   = "oidc-usermodel-attribute-mapper"
	MapperFullName        = "oidc-full-name-mapper"
	MapperAddress         = "oidc-address-mapper"
	MapperRealmRoles      = "oidc-usermodel-realm-role-mapper"
	MapperClientRoles     = "oidc-usermodel-client-role-mapper"
	MapperGroupMembership = "oidc-group-membership-mapper"
	MapperAudience        = "oidc-audience-mapper"
	MapperAudienceResolve = "oidc-audience-resolve-mapper"
	MapperHardcodedClaim  = "oidc-hardcoded-claim-mapper"
	MapperHardcodedRole   = "oidc-hardcoded-role-mapper"
	MapperRoleName        = "oidc-role-name-mapper"
	MapperAllowedOrigins  = "oidc-allowed-origins-mapper"
	MapperSub             = "oidc-sub-mapper"
	MapperACR             = "oidc-acr-mapper"
	MapperSessionNote     = "oidc-usersessionmodel-note-mapper"
)

// MapperTypes lists the supported mapper types, for validation.
var MapperTypes = map[string]bool{
	MapperUserProperty: true, MapperUserAttribute: true, MapperFullName: true, MapperAddress: true,
	MapperRealmRoles: true, MapperClientRoles: true, MapperGroupMembership: true, MapperAudience: true,
	MapperAudienceResolve: true, MapperHardcodedClaim: true, MapperHardcodedRole: true, MapperRoleName: true,
	MapperAllowedOrigins: true, MapperSub: true, MapperACR: true, MapperSessionNote: true,
}

type builtinMapper struct {
	name, typ string
	config    map[string]string
}

type builtinScope struct {
	name, description string
	protocol          string // openid-connect when empty
	isDefault         bool   // realm default (true) or optional scope
	inTokenScope      bool
	consentText       string
	mappers           []builtinMapper
	scopeRoles        []string // realm roles mapped to the scope
}

// claimFlags returns the include-in-token flags of the built-in mappers:
// access, id, userinfo and introspection.
func claimFlags(access, id, userinfo bool) map[string]string {
	b := func(v bool) string {
		if v {
			return "true"
		}
		return "false"
	}
	return map[string]string{
		"access.token.claim": b(access), "id.token.claim": b(id),
		"userinfo.token.claim": b(userinfo), "introspection.token.claim": "true",
	}
}

func with(base map[string]string, kv ...string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = kv[i+1]
	}
	return out
}

func propertyMapper(name, property, claim, jsonType string) builtinMapper {
	return builtinMapper{name, MapperUserProperty, with(claimFlags(true, true, true),
		"user.attribute", property, "claim.name", claim, "jsonType.label", jsonType)}
}

func attributeMapper(name, attr, claim, jsonType string) builtinMapper {
	return builtinMapper{name, MapperUserAttribute, with(claimFlags(true, true, true),
		"user.attribute", attr, "claim.name", claim, "jsonType.label", jsonType)}
}

// builtinScopes are the client scopes created in every realm.
var builtinScopes = []builtinScope{
	{
		name: "profile", description: "OpenID Connect built-in scope: profile", isDefault: true, inTokenScope: true,
		consentText: "${profileScopeConsentText}",
		mappers: []builtinMapper{
			{"full name", MapperFullName, claimFlags(true, true, true)},
			propertyMapper("username", "username", "preferred_username", "String"),
			propertyMapper("given name", "firstName", "given_name", "String"),
			propertyMapper("family name", "lastName", "family_name", "String"),
			attributeMapper("middle name", "middleName", "middle_name", "String"),
			attributeMapper("nickname", "nickname", "nickname", "String"),
			attributeMapper("profile", "profile", "profile", "String"),
			attributeMapper("picture", "picture", "picture", "String"),
			attributeMapper("website", "website", "website", "String"),
			attributeMapper("gender", "gender", "gender", "String"),
			attributeMapper("birthdate", "birthdate", "birthdate", "String"),
			attributeMapper("zoneinfo", "zoneinfo", "zoneinfo", "String"),
			attributeMapper("locale", "locale", "locale", "String"),
			attributeMapper("updated at", "updatedAt", "updated_at", "long"),
		},
	},
	{
		name: "email", description: "OpenID Connect built-in scope: email", isDefault: true, inTokenScope: true,
		consentText: "${emailScopeConsentText}",
		mappers: []builtinMapper{
			propertyMapper("email", "email", "email", "String"),
			propertyMapper("email verified", "emailVerified", "email_verified", "boolean"),
		},
	},
	{
		name: "roles", description: "OpenID Connect scope for add user roles to the access token", isDefault: true,
		consentText: "${rolesScopeConsentText}",
		mappers: []builtinMapper{
			{"realm roles", MapperRealmRoles, with(claimFlags(true, false, false),
				"claim.name", "realm_access.roles", "jsonType.label", "String", "multivalued", "true")},
			{"client roles", MapperClientRoles, with(claimFlags(true, false, false),
				"claim.name", "resource_access.${client_id}.roles", "jsonType.label", "String", "multivalued", "true")},
			{"audience resolve", MapperAudienceResolve, map[string]string{"access.token.claim": "true", "introspection.token.claim": "true"}},
		},
	},
	{
		name: "web-origins", description: "OpenID Connect scope for add allowed web origins to the access token", isDefault: true,
		mappers: []builtinMapper{
			{"allowed web origins", MapperAllowedOrigins, map[string]string{"access.token.claim": "true", "introspection.token.claim": "true"}},
		},
	},
	{
		name: "acr", description: "OpenID Connect scope for add acr (authentication context class reference) to the token", isDefault: true,
		mappers: []builtinMapper{
			{"acr loa level", MapperACR, map[string]string{"access.token.claim": "true", "id.token.claim": "true", "introspection.token.claim": "true"}},
		},
	},
	{
		name: "basic", description: "OpenID Connect scope for add all basic claims to the token", isDefault: true,
		mappers: []builtinMapper{
			{"sub", MapperSub, map[string]string{"access.token.claim": "true", "introspection.token.claim": "true"}},
			{"auth_time", MapperSessionNote, with(claimFlags(true, true, false),
				"user.session.note", "AUTH_TIME", "claim.name", "auth_time", "jsonType.label", "long")},
		},
	},
	{
		name: "address", description: "OpenID Connect built-in scope: address", inTokenScope: true,
		consentText: "${addressScopeConsentText}",
		mappers: []builtinMapper{
			{"address", MapperAddress, with(claimFlags(true, true, true),
				"user.attribute.formatted", "formatted", "user.attribute.street", "street",
				"user.attribute.locality", "locality", "user.attribute.region", "region",
				"user.attribute.postal_code", "postal_code", "user.attribute.country", "country")},
		},
	},
	{
		name: "phone", description: "OpenID Connect built-in scope: phone", inTokenScope: true,
		consentText: "${phoneScopeConsentText}",
		mappers: []builtinMapper{
			attributeMapper("phone number", "phoneNumber", "phone_number", "String"),
			attributeMapper("phone number verified", "phoneNumberVerified", "phone_number_verified", "boolean"),
		},
	},
	{
		name: "offline_access", description: "OpenID Connect built-in scope: offline_access", inTokenScope: true,
		consentText: "${offlineAccessScopeConsentText}", scopeRoles: []string{OfflineAccessRole},
	},
	{
		name: "microprofile-jwt", description: "Microprofile - JWT built-in scope", inTokenScope: true,
		mappers: []builtinMapper{
			propertyMapper("upn", "username", "upn", "String"),
			{"groups", MapperRealmRoles, with(claimFlags(true, true, true),
				"claim.name", "groups", "jsonType.label", "String", "multivalued", "true")},
		},
	},
	samlRoleListScope,
}

// samlRoleListScope is the default client scope of SAML clients.
var samlRoleListScope = builtinScope{
	name: "role_list", description: "SAML role list", protocol: ProtocolSAML, isDefault: true,
	consentText: "${samlRoleListScopeConsentText}",
	mappers: []builtinMapper{
		{"role list", SAMLMapperRoleList, map[string]string{"attribute.name": "Role", "attribute.nameformat": "Basic", "single": "false"}},
	},
}

// ProvisionClientScopes creates the built-in client scopes in a realm,
// registers them as realm default/optional scopes, and links the realm
// defaults to every existing client.
func (s *Service) ProvisionClientScopes(ctx context.Context, st *store.Store, realm *model.Realm) error {
	for _, b := range builtinScopes {
		if err := provisionScope(ctx, st, realm, b); err != nil {
			return err
		}
	}
	clients, err := st.ListClients(ctx, realm.ID, "", 0, 0)
	if err != nil {
		return err
	}
	for _, c := range clients {
		if err := s.LinkDefaultScopes(ctx, st, c); err != nil {
			return err
		}
	}
	return nil
}

// protocolOf defaults an empty protocol to openid-connect.
func protocolOf(p string) string {
	if p == "" {
		return "openid-connect"
	}
	return p
}

func provisionScope(ctx context.Context, st *store.Store, realm *model.Realm, b builtinScope) error {
	protocol := protocolOf(b.protocol)
	attrs := map[string]string{"display.on.consent.screen": "true"}
	if protocol != ProtocolSAML {
		attrs["include.in.token.scope"] = boolString(b.inTokenScope)
	}
	if b.consentText != "" {
		attrs["consent.screen.text"] = b.consentText
	} else {
		attrs["display.on.consent.screen"] = "false"
	}
	cs := &model.ClientScope{ID: NewID(), RealmID: realm.ID, Name: b.name, Description: b.description,
		Protocol: protocol, Attributes: attrs}
	if err := st.CreateClientScope(ctx, cs); err != nil {
		return err
	}
	for _, bm := range b.mappers {
		if err := st.CreateMapper(ctx, &model.ProtocolMapper{ID: NewID(), RealmID: realm.ID, OwnerID: cs.ID,
			Name: bm.name, Protocol: protocol, Type: bm.typ, Config: bm.config}); err != nil {
			return err
		}
	}
	for _, roleName := range b.scopeRoles {
		role, err := st.GetRoleByName(ctx, realm.ID, "", roleName)
		if err != nil {
			return err
		}
		if err := st.AddScopeMapping(ctx, cs.ID, role.ID); err != nil {
			return err
		}
	}
	return st.SetRealmDefaultScope(ctx, realm.ID, cs.ID, b.isDefault)
}

// LinkDefaultScopes attaches the realm's default and optional client scopes
// of the client's protocol to a client, as done for every new client.
func (s *Service) LinkDefaultScopes(ctx context.Context, st *store.Store, c *model.Client) error {
	links, err := st.ListRealmDefaultScopes(ctx, c.RealmID)
	if err != nil {
		return err
	}
	for _, l := range links {
		cs, err := st.GetClientScope(ctx, c.RealmID, l.ScopeID)
		if err != nil {
			return err
		}
		if protocolOf(cs.Protocol) != protocolOf(c.Protocol) {
			continue
		}
		if err := st.SetClientScopeLink(ctx, c.ID, l.ScopeID, l.Default); err != nil {
			return err
		}
	}
	return nil
}

// UpgradeRealms provisions client scopes and authentication flows in
// realms created before they existed.
func (s *Service) UpgradeRealms(ctx context.Context) error {
	realms, err := s.Store.ListRealms(ctx)
	if err != nil {
		return err
	}
	for _, r := range realms {
		if err := s.ensureBrokerClient(ctx, r); err != nil {
			return err
		}

		n, err := s.Store.CountClientScopes(ctx, r.ID)
		if err != nil {
			return err
		}
		if n == 0 {
			if err := s.Store.WithTx(ctx, func(tx *store.Store) error { return s.ProvisionClientScopes(ctx, tx, r) }); err != nil {
				return err
			}
		}
		if n, err = s.Store.CountFlows(ctx, r.ID); err != nil {
			return err
		}
		if n == 0 {
			if err := s.Store.WithTx(ctx, func(tx *store.Store) error { return s.ProvisionAuthentication(ctx, tx, r) }); err != nil {
				return err
			}
		}
		if err := s.ensureConsoleClient(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

// serviceAccountMappers are the session note mappers added to a
// client when service accounts are enabled.
var serviceAccountMappers = []builtinMapper{
	{"Client ID", MapperSessionNote, with(claimFlags(true, true, false), "user.session.note", "client_id", "claim.name", "client_id", "jsonType.label", "String")},
	{"Client Host", MapperSessionNote, with(claimFlags(true, true, false), "user.session.note", "clientHost", "claim.name", "clientHost", "jsonType.label", "String")},
	{"Client IP Address", MapperSessionNote, with(claimFlags(true, true, false), "user.session.note", "clientAddress", "claim.name", "clientAddress", "jsonType.label", "String")},
}

func (s *Service) addServiceAccountMappers(ctx context.Context, st *store.Store, c *model.Client) error {
	existing, err := st.ListMappers(ctx, c.ID)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, m := range existing {
		have[m.Name] = true
	}
	for _, bm := range serviceAccountMappers {
		if have[bm.name] {
			continue
		}
		err := st.CreateMapper(ctx, &model.ProtocolMapper{ID: NewID(), RealmID: c.RealmID, OwnerID: c.ID,
			Name: bm.name, Protocol: "openid-connect", Type: bm.typ, Config: bm.config})
		if err != nil && !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return nil
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
