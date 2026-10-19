package store

import (
	"context"

	"github.com/ducnt114/gocloak/internal/model"
)

const clientCols = `id, realm_id, client_id, name, description, enabled, public_client, bearer_only, secret,
	root_url, base_url, redirect_uris, web_origins, standard_flow_enabled, direct_access_grants_enabled,
	service_accounts_enabled, full_scope_allowed, protocol, attributes, client_authenticator_type, not_before, flow_overrides`

func scanClient(sc scanner) (*model.Client, error) {
	c := &model.Client{Attributes: map[string]string{}}
	err := sc.Scan(&c.ID, &c.RealmID, &c.ClientID, &c.Name, &c.Description, &c.Enabled, &c.PublicClient,
		&c.BearerOnly, &c.Secret, &c.RootURL, &c.BaseURL, jsonCol{&c.RedirectURIs}, jsonCol{&c.WebOrigins},
		&c.StandardFlowEnabled, &c.DirectAccessGrantsEnabled, &c.ServiceAccountsEnabled, &c.FullScopeAllowed,
		&c.Protocol, jsonCol{&c.Attributes}, &c.ClientAuthenticatorType, &c.NotBefore, jsonCol{&c.FlowOverrides})
	if err != nil {
		return nil, mapErr(err)
	}
	return c, nil
}

func clientArgs(c *model.Client) []any {
	if c.RedirectURIs == nil {
		c.RedirectURIs = []string{}
	}
	if c.WebOrigins == nil {
		c.WebOrigins = []string{}
	}
	if c.Attributes == nil {
		c.Attributes = map[string]string{}
	}
	if c.ClientAuthenticatorType == "" {
		c.ClientAuthenticatorType = "client-secret"
	}
	if c.FlowOverrides == nil {
		c.FlowOverrides = map[string]string{}
	}
	return []any{c.ClientID, c.Name, c.Description, c.Enabled, c.PublicClient, c.BearerOnly, c.Secret,
		c.RootURL, c.BaseURL, toJSON(c.RedirectURIs), toJSON(c.WebOrigins), c.StandardFlowEnabled,
		c.DirectAccessGrantsEnabled, c.ServiceAccountsEnabled, c.FullScopeAllowed, c.Protocol, toJSON(c.Attributes),
		c.ClientAuthenticatorType, c.NotBefore, toJSON(c.FlowOverrides)}
}

func (s *Store) CreateClient(ctx context.Context, c *model.Client) error {
	args := append([]any{c.ID, c.RealmID}, clientArgs(c)...)
	return s.exec(ctx, `INSERT INTO clients (`+clientCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, args...)
}

func (s *Store) UpdateClient(ctx context.Context, c *model.Client) error {
	args := append(clientArgs(c), c.ID)
	return s.execOne(ctx, `UPDATE clients SET client_id=?, name=?, description=?, enabled=?, public_client=?,
		bearer_only=?, secret=?, root_url=?, base_url=?, redirect_uris=?, web_origins=?, standard_flow_enabled=?,
		direct_access_grants_enabled=?, service_accounts_enabled=?, full_scope_allowed=?, protocol=?, attributes=?,
		client_authenticator_type=?, not_before=?, flow_overrides=? WHERE id=?`, args...)
}

// DeleteClient removes a client together with its roles and service account user.
func (s *Store) DeleteClient(ctx context.Context, id string) error {
	return s.WithTx(ctx, func(tx *Store) error {
		if err := tx.exec(ctx, `DELETE FROM roles WHERE client_id=?`, id); err != nil {
			return err
		}
		if err := tx.exec(ctx, `DELETE FROM users WHERE service_account_client_id=?`, id); err != nil {
			return err
		}
		if err := tx.deleteOwned(ctx, id); err != nil {
			return err
		}
		return tx.execOne(ctx, `DELETE FROM clients WHERE id=?`, id)
	})
}

func (s *Store) GetClient(ctx context.Context, realmID, id string) (*model.Client, error) {
	return scanClient(s.q.QueryRowContext(ctx, `SELECT `+clientCols+` FROM clients WHERE realm_id=? AND id=?`, realmID, id))
}

func (s *Store) GetClientByClientID(ctx context.Context, realmID, clientID string) (*model.Client, error) {
	return scanClient(s.q.QueryRowContext(ctx, `SELECT `+clientCols+` FROM clients WHERE realm_id=? AND client_id=?`, realmID, clientID))
}

// ListClients lists clients of a realm. search does a substring match on clientId.
func (s *Store) ListClients(ctx context.Context, realmID, search string, first, max int) ([]*model.Client, error) {
	q := `SELECT ` + clientCols + ` FROM clients WHERE realm_id=?`
	args := []any{realmID}
	if search != "" {
		q += ` AND lower(client_id) LIKE ? ESCAPE '\'`
		args = append(args, "%"+likeEscape(lower(search))+"%")
	}
	q += ` ORDER BY client_id LIMIT ? OFFSET ?`
	args = append(args, limit(max), first)
	return queryList(ctx, s, scanClient, q, args...)
}
