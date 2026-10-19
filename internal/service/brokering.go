package service

import (
	"context"
	"errors"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/store"
)

// The "broker" client holds the role that lets applications read the
// tokens stored for identity provider links.
const (
	BrokerClient  = "broker"
	ReadTokenRole = "read-token"
)

// createBrokerClient adds the broker client of a realm, as Keycloak does.
func (s *Service) createBrokerClient(ctx context.Context, st *store.Store, r *model.Realm) error {
	c := &model.Client{ID: NewID(), RealmID: r.ID, ClientID: BrokerClient, Name: "${client_broker}",
		Enabled: true, BearerOnly: true, StandardFlowEnabled: true, Protocol: "openid-connect"}
	if err := st.CreateClient(ctx, c); err != nil {
		return err
	}
	_, err := s.createClientRoles(ctx, st, c, []string{ReadTokenRole}, nil)
	return err
}

// ensureBrokerClient adds the broker client to realms created before M5.
func (s *Service) ensureBrokerClient(ctx context.Context, r *model.Realm) error {
	_, err := s.Store.GetClientByClientID(ctx, r.ID, BrokerClient)
	if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return s.Store.WithTx(ctx, func(tx *store.Store) error { return s.createBrokerClient(ctx, tx, r) })
}

// FirstBrokerLoginFlow is the alias of the flow run when an identity
// provider account logs in for the first time.
func FirstBrokerLoginFlow(realm *model.Realm, idp *model.IdentityProvider) string {
	switch {
	case idp != nil && idp.FirstBrokerLoginFlowAlias != "":
		return idp.FirstBrokerLoginFlowAlias
	case realm.Settings.FirstBrokerLoginFlow != "":
		return realm.Settings.FirstBrokerLoginFlow
	}
	return "first broker login"
}
