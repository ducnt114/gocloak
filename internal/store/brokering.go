package store

import (
	"context"

	"github.com/ducnt114/gocloak/internal/model"
)

const idpCols = `internal_id, realm_id, alias, display_name, provider_id, enabled, trust_email, store_token,
	add_read_token_role_on_create, link_only, hide_on_login, authenticate_by_default, first_broker_login_flow_alias,
	post_broker_login_flow_alias, gui_order, config`

func scanIdP(sc scanner) (*model.IdentityProvider, error) {
	p := &model.IdentityProvider{Config: map[string]string{}}
	err := sc.Scan(&p.InternalID, &p.RealmID, &p.Alias, &p.DisplayName, &p.ProviderID, &p.Enabled, &p.TrustEmail, &p.StoreToken,
		&p.AddReadTokenRoleOnCreate, &p.LinkOnly, &p.HideOnLogin, &p.AuthenticateByDefault, &p.FirstBrokerLoginFlowAlias,
		&p.PostBrokerLoginFlowAlias, &p.GUIOrder, jsonCol{&p.Config})
	if err != nil {
		return nil, mapErr(err)
	}
	return p, nil
}

func idpArgs(p *model.IdentityProvider) []any {
	if p.Config == nil {
		p.Config = map[string]string{}
	}
	return []any{p.DisplayName, p.ProviderID, p.Enabled, p.TrustEmail, p.StoreToken, p.AddReadTokenRoleOnCreate, p.LinkOnly,
		p.HideOnLogin, p.AuthenticateByDefault, p.FirstBrokerLoginFlowAlias, p.PostBrokerLoginFlowAlias, p.GUIOrder, toJSON(p.Config)}
}

func (s *Store) CreateIdentityProvider(ctx context.Context, p *model.IdentityProvider) error {
	args := append([]any{p.InternalID, p.RealmID, p.Alias}, idpArgs(p)...)
	return s.exec(ctx, `INSERT INTO identity_providers (`+idpCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, args...)
}

func (s *Store) UpdateIdentityProvider(ctx context.Context, p *model.IdentityProvider) error {
	args := append(idpArgs(p), p.InternalID)
	return s.execOne(ctx, `UPDATE identity_providers SET display_name=?, provider_id=?, enabled=?, trust_email=?, store_token=?,
		add_read_token_role_on_create=?, link_only=?, hide_on_login=?, authenticate_by_default=?, first_broker_login_flow_alias=?,
		post_broker_login_flow_alias=?, gui_order=?, config=? WHERE internal_id=?`, args...)
}

// DeleteIdentityProvider removes a provider with its mappers and links.
func (s *Store) DeleteIdentityProvider(ctx context.Context, realmID, alias string) error {
	return s.WithTx(ctx, func(tx *Store) error {
		if err := tx.exec(ctx, `DELETE FROM idp_mappers WHERE realm_id=? AND idp_alias=?`, realmID, alias); err != nil {
			return err
		}
		if err := tx.exec(ctx, `DELETE FROM federated_identities WHERE realm_id=? AND identity_provider=?`, realmID, alias); err != nil {
			return err
		}
		return tx.execOne(ctx, `DELETE FROM identity_providers WHERE realm_id=? AND alias=?`, realmID, alias)
	})
}

func (s *Store) GetIdentityProvider(ctx context.Context, realmID, alias string) (*model.IdentityProvider, error) {
	return scanIdP(s.q.QueryRowContext(ctx, `SELECT `+idpCols+` FROM identity_providers WHERE realm_id=? AND alias=?`, realmID, alias))
}

func (s *Store) ListIdentityProviders(ctx context.Context, realmID string) ([]*model.IdentityProvider, error) {
	return queryList(ctx, s, scanIdP, `SELECT `+idpCols+` FROM identity_providers WHERE realm_id=? ORDER BY gui_order, alias`, realmID)
}

// ---- mappers ----

const idpMapperCols = `id, realm_id, idp_alias, name, mapper_type, config`

func scanIdPMapper(sc scanner) (*model.IdentityProviderMapper, error) {
	m := &model.IdentityProviderMapper{Config: map[string]string{}}
	if err := sc.Scan(&m.ID, &m.RealmID, &m.IdPAlias, &m.Name, &m.Type, jsonCol{&m.Config}); err != nil {
		return nil, mapErr(err)
	}
	return m, nil
}

func (s *Store) CreateIdPMapper(ctx context.Context, m *model.IdentityProviderMapper) error {
	if m.Config == nil {
		m.Config = map[string]string{}
	}
	return s.exec(ctx, `INSERT INTO idp_mappers (`+idpMapperCols+`) VALUES (?,?,?,?,?,?)`, m.ID, m.RealmID, m.IdPAlias, m.Name, m.Type, toJSON(m.Config))
}

func (s *Store) UpdateIdPMapper(ctx context.Context, m *model.IdentityProviderMapper) error {
	return s.execOne(ctx, `UPDATE idp_mappers SET name=?, mapper_type=?, config=? WHERE id=?`, m.Name, m.Type, toJSON(m.Config), m.ID)
}

func (s *Store) DeleteIdPMapper(ctx context.Context, realmID, id string) error {
	return s.execOne(ctx, `DELETE FROM idp_mappers WHERE realm_id=? AND id=?`, realmID, id)
}

func (s *Store) GetIdPMapper(ctx context.Context, realmID, id string) (*model.IdentityProviderMapper, error) {
	return scanIdPMapper(s.q.QueryRowContext(ctx, `SELECT `+idpMapperCols+` FROM idp_mappers WHERE realm_id=? AND id=?`, realmID, id))
}

func (s *Store) ListIdPMappers(ctx context.Context, realmID, alias string) ([]*model.IdentityProviderMapper, error) {
	return queryList(ctx, s, scanIdPMapper, `SELECT `+idpMapperCols+` FROM idp_mappers WHERE realm_id=? AND idp_alias=? ORDER BY name`, realmID, alias)
}

// ---- federated identities ----

const fedCols = `user_id, realm_id, identity_provider, federated_user_id, federated_username, token`

func scanFed(sc scanner) (*model.FederatedIdentity, error) {
	f := &model.FederatedIdentity{}
	if err := sc.Scan(&f.UserID, &f.RealmID, &f.IdentityProvider, &f.FederatedUserID, &f.FederatedUsername, &f.Token); err != nil {
		return nil, mapErr(err)
	}
	return f, nil
}

func (s *Store) CreateFederatedIdentity(ctx context.Context, f *model.FederatedIdentity) error {
	return s.exec(ctx, `INSERT INTO federated_identities (`+fedCols+`) VALUES (?,?,?,?,?,?)`,
		f.UserID, f.RealmID, f.IdentityProvider, f.FederatedUserID, f.FederatedUsername, f.Token)
}

func (s *Store) UpdateFederatedIdentity(ctx context.Context, f *model.FederatedIdentity) error {
	return s.execOne(ctx, `UPDATE federated_identities SET federated_username=?, token=? WHERE user_id=? AND identity_provider=?`,
		f.FederatedUsername, f.Token, f.UserID, f.IdentityProvider)
}

func (s *Store) DeleteFederatedIdentity(ctx context.Context, userID, alias string) error {
	return s.execOne(ctx, `DELETE FROM federated_identities WHERE user_id=? AND identity_provider=?`, userID, alias)
}

// FindFederatedIdentity finds the link of an external account.
func (s *Store) FindFederatedIdentity(ctx context.Context, realmID, alias, federatedUserID string) (*model.FederatedIdentity, error) {
	return scanFed(s.q.QueryRowContext(ctx, `SELECT `+fedCols+` FROM federated_identities
		WHERE realm_id=? AND identity_provider=? AND federated_user_id=?`, realmID, alias, federatedUserID))
}

func (s *Store) GetFederatedIdentity(ctx context.Context, userID, alias string) (*model.FederatedIdentity, error) {
	return scanFed(s.q.QueryRowContext(ctx, `SELECT `+fedCols+` FROM federated_identities WHERE user_id=? AND identity_provider=?`, userID, alias))
}

func (s *Store) ListFederatedIdentities(ctx context.Context, userID string) ([]*model.FederatedIdentity, error) {
	return queryList(ctx, s, scanFed, `SELECT `+fedCols+` FROM federated_identities WHERE user_id=? ORDER BY identity_provider`, userID)
}
