package service

import (
	"context"
	"errors"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/store"
)

// AdminConsoleClient is the public client the admin console logs in with.
const AdminConsoleClient = "security-admin-console"

// createConsoleClient adds the security-admin-console client of a realm,
// as Keycloak does.
func (s *Service) createConsoleClient(ctx context.Context, st *store.Store, r *model.Realm, linkScopes bool) error {
	c := &model.Client{ID: NewID(), RealmID: r.ID, ClientID: AdminConsoleClient, Name: "${client_security-admin-console}",
		Enabled: true, PublicClient: true, StandardFlowEnabled: true, FullScopeAllowed: true, Protocol: "openid-connect",
		RootURL: "${authAdminUrl}", BaseURL: "/admin/" + r.Name + "/console/", RedirectURIs: []string{"/admin/" + r.Name + "/console/*"},
		WebOrigins: []string{"+"}, Attributes: map[string]string{"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": "+",
			LightweightAccessToken: "true"}}
	if err := st.CreateClient(ctx, c); err != nil {
		return err
	}
	if linkScopes {
		if err := s.LinkDefaultScopes(ctx, st, c); err != nil {
			return err
		}
	}
	return st.CreateMapper(ctx, &model.ProtocolMapper{ID: NewID(), RealmID: r.ID, OwnerID: c.ID, Name: "locale",
		Protocol: "openid-connect", Type: MapperUserAttribute,
		Config: with(claimFlags(true, true, true), "user.attribute", "locale", "claim.name", "locale", "jsonType.label", "String")})
}

// ensureConsoleClient adds the console client to realms created before M7.
func (s *Service) ensureConsoleClient(ctx context.Context, r *model.Realm) error {
	_, err := s.Store.GetClientByClientID(ctx, r.ID, AdminConsoleClient)
	if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return s.Store.WithTx(ctx, func(tx *store.Store) error { return s.createConsoleClient(ctx, tx, r, true) })
}
