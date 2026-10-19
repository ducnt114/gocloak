package store

import (
	"context"

	"github.com/ducnt114/gocloak/internal/model"
)

// ---- resource servers ----

const rsCols = `client_id, realm_id, policy_enforcement_mode, decision_strategy, allow_remote_resource_management`

func scanRS(sc scanner) (*model.ResourceServer, error) {
	rs := &model.ResourceServer{}
	if err := sc.Scan(&rs.ClientID, &rs.RealmID, &rs.PolicyEnforcementMode, &rs.DecisionStrategy, &rs.AllowRemoteResourceManagement); err != nil {
		return nil, mapErr(err)
	}
	return rs, nil
}

func (s *Store) CreateResourceServer(ctx context.Context, rs *model.ResourceServer) error {
	return s.exec(ctx, `INSERT INTO resource_servers (`+rsCols+`) VALUES (?,?,?,?,?)`, rs.ClientID, rs.RealmID,
		rs.PolicyEnforcementMode, rs.DecisionStrategy, rs.AllowRemoteResourceManagement)
}

func (s *Store) UpdateResourceServer(ctx context.Context, rs *model.ResourceServer) error {
	return s.execOne(ctx, `UPDATE resource_servers SET policy_enforcement_mode=?, decision_strategy=?, allow_remote_resource_management=?
		WHERE client_id=?`, rs.PolicyEnforcementMode, rs.DecisionStrategy, rs.AllowRemoteResourceManagement, rs.ClientID)
}

func (s *Store) DeleteResourceServer(ctx context.Context, clientID string) error {
	return s.exec(ctx, `DELETE FROM resource_servers WHERE client_id=?`, clientID)
}

func (s *Store) GetResourceServer(ctx context.Context, clientID string) (*model.ResourceServer, error) {
	return scanRS(s.q.QueryRowContext(ctx, `SELECT `+rsCols+` FROM resource_servers WHERE client_id=?`, clientID))
}

// ---- scopes ----

const authzScopeCols = `id, resource_server_id, name, display_name, icon_uri`

func scanAuthzScope(sc scanner) (*model.AuthzScope, error) {
	x := &model.AuthzScope{}
	if err := sc.Scan(&x.ID, &x.ResourceServerID, &x.Name, &x.DisplayName, &x.IconURI); err != nil {
		return nil, mapErr(err)
	}
	return x, nil
}

func (s *Store) CreateAuthzScope(ctx context.Context, x *model.AuthzScope) error {
	return s.exec(ctx, `INSERT INTO authz_scopes (`+authzScopeCols+`) VALUES (?,?,?,?,?)`, x.ID, x.ResourceServerID, x.Name, x.DisplayName, x.IconURI)
}

func (s *Store) UpdateAuthzScope(ctx context.Context, x *model.AuthzScope) error {
	return s.execOne(ctx, `UPDATE authz_scopes SET name=?, display_name=?, icon_uri=? WHERE id=?`, x.Name, x.DisplayName, x.IconURI, x.ID)
}

func (s *Store) DeleteAuthzScope(ctx context.Context, rsID, id string) error {
	return s.execOne(ctx, `DELETE FROM authz_scopes WHERE resource_server_id=? AND id=?`, rsID, id)
}

func (s *Store) ListAuthzScopes(ctx context.Context, rsID string) ([]*model.AuthzScope, error) {
	return queryList(ctx, s, scanAuthzScope, `SELECT `+authzScopeCols+` FROM authz_scopes WHERE resource_server_id=? ORDER BY name`, rsID)
}

// ---- resources ----

const authzResourceCols = `id, resource_server_id, name, display_name, type, owner, owner_managed_access, icon_uri, uris, attributes`

func scanAuthzResource(sc scanner) (*model.AuthzResource, error) {
	x := &model.AuthzResource{Attributes: map[string][]string{}}
	if err := sc.Scan(&x.ID, &x.ResourceServerID, &x.Name, &x.DisplayName, &x.Type, &x.Owner, &x.OwnerManagedAccess, &x.IconURI,
		jsonCol{&x.URIs}, jsonCol{&x.Attributes}); err != nil {
		return nil, mapErr(err)
	}
	return x, nil
}

func (s *Store) setResourceScopes(ctx context.Context, x *model.AuthzResource) error {
	if err := s.exec(ctx, `DELETE FROM authz_resource_scopes WHERE resource_id=?`, x.ID); err != nil {
		return err
	}
	for i, id := range x.ScopeIDs {
		if err := s.exec(ctx, `INSERT INTO authz_resource_scopes (resource_id, scope_id, position) VALUES (?,?,?) ON CONFLICT DO NOTHING`, x.ID, id, i); err != nil {
			return err
		}
	}
	return nil
}

func resourceArgs(x *model.AuthzResource) []any {
	if x.URIs == nil {
		x.URIs = []string{}
	}
	if x.Attributes == nil {
		x.Attributes = map[string][]string{}
	}
	return []any{x.Name, x.DisplayName, x.Type, x.Owner, x.OwnerManagedAccess, x.IconURI, toJSON(x.URIs), toJSON(x.Attributes)}
}

func (s *Store) CreateAuthzResource(ctx context.Context, x *model.AuthzResource) error {
	return s.WithTx(ctx, func(tx *Store) error {
		args := append([]any{x.ID, x.ResourceServerID}, resourceArgs(x)...)
		if err := tx.exec(ctx, `INSERT INTO authz_resources (`+authzResourceCols+`) VALUES (?,?,?,?,?,?,?,?,?,?)`, args...); err != nil {
			return err
		}
		return tx.setResourceScopes(ctx, x)
	})
}

func (s *Store) UpdateAuthzResource(ctx context.Context, x *model.AuthzResource) error {
	return s.WithTx(ctx, func(tx *Store) error {
		args := append(resourceArgs(x), x.ID)
		if err := tx.execOne(ctx, `UPDATE authz_resources SET name=?, display_name=?, type=?, owner=?, owner_managed_access=?,
			icon_uri=?, uris=?, attributes=? WHERE id=?`, args...); err != nil {
			return err
		}
		return tx.setResourceScopes(ctx, x)
	})
}

func (s *Store) DeleteAuthzResource(ctx context.Context, rsID, id string) error {
	return s.execOne(ctx, `DELETE FROM authz_resources WHERE resource_server_id=? AND id=?`, rsID, id)
}

// ListAuthzResources lists a resource server's resources with their scopes.
func (s *Store) ListAuthzResources(ctx context.Context, rsID string) ([]*model.AuthzResource, error) {
	list, err := queryList(ctx, s, scanAuthzResource, `SELECT `+authzResourceCols+` FROM authz_resources WHERE resource_server_id=? ORDER BY name`, rsID)
	if err != nil {
		return nil, err
	}
	links, err := s.pairs(ctx, `SELECT rs.resource_id, rs.scope_id FROM authz_resource_scopes rs JOIN authz_resources r ON r.id=rs.resource_id
		WHERE r.resource_server_id=? ORDER BY rs.position`, rsID)
	if err != nil {
		return nil, err
	}
	byID := map[string]*model.AuthzResource{}
	for _, r := range list {
		byID[r.ID] = r
	}
	for _, l := range links {
		if r := byID[l[0]]; r != nil {
			r.ScopeIDs = append(r.ScopeIDs, l[1])
		}
	}
	return list, nil
}

// pairs runs a query returning two string columns.
func (s *Store) pairs(ctx context.Context, query string, args ...any) ([][2]string, error) {
	return queryList(ctx, s, func(sc scanner) ([2]string, error) {
		var p [2]string
		err := sc.Scan(&p[0], &p[1])
		return p, err
	}, query, args...)
}

// ---- policies ----

const authzPolicyCols = `id, resource_server_id, name, description, type, logic, decision_strategy, owner, config`

func scanAuthzPolicy(sc scanner) (*model.AuthzPolicy, error) {
	x := &model.AuthzPolicy{Config: map[string]string{}}
	if err := sc.Scan(&x.ID, &x.ResourceServerID, &x.Name, &x.Description, &x.Type, &x.Logic, &x.DecisionStrategy, &x.Owner,
		jsonCol{&x.Config}); err != nil {
		return nil, mapErr(err)
	}
	return x, nil
}

func (s *Store) setPolicyLinks(ctx context.Context, x *model.AuthzPolicy) error {
	for _, q := range []string{`DELETE FROM authz_policy_resources WHERE policy_id=?`, `DELETE FROM authz_policy_scopes WHERE policy_id=?`,
		`DELETE FROM authz_associated_policies WHERE policy_id=?`} {
		if err := s.exec(ctx, q, x.ID); err != nil {
			return err
		}
	}
	for _, id := range x.ResourceIDs {
		if err := s.exec(ctx, `INSERT INTO authz_policy_resources (policy_id, resource_id) VALUES (?,?) ON CONFLICT DO NOTHING`, x.ID, id); err != nil {
			return err
		}
	}
	for _, id := range x.ScopeIDs {
		if err := s.exec(ctx, `INSERT INTO authz_policy_scopes (policy_id, scope_id) VALUES (?,?) ON CONFLICT DO NOTHING`, x.ID, id); err != nil {
			return err
		}
	}
	for _, id := range x.AssociatedIDs {
		if err := s.exec(ctx, `INSERT INTO authz_associated_policies (policy_id, associated_id) VALUES (?,?) ON CONFLICT DO NOTHING`, x.ID, id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) CreateAuthzPolicy(ctx context.Context, x *model.AuthzPolicy) error {
	if x.Config == nil {
		x.Config = map[string]string{}
	}
	return s.WithTx(ctx, func(tx *Store) error {
		if err := tx.exec(ctx, `INSERT INTO authz_policies (`+authzPolicyCols+`) VALUES (?,?,?,?,?,?,?,?,?)`, x.ID, x.ResourceServerID,
			x.Name, x.Description, x.Type, x.Logic, x.DecisionStrategy, x.Owner, toJSON(x.Config)); err != nil {
			return err
		}
		return tx.setPolicyLinks(ctx, x)
	})
}

func (s *Store) UpdateAuthzPolicy(ctx context.Context, x *model.AuthzPolicy) error {
	if x.Config == nil {
		x.Config = map[string]string{}
	}
	return s.WithTx(ctx, func(tx *Store) error {
		if err := tx.execOne(ctx, `UPDATE authz_policies SET name=?, description=?, logic=?, decision_strategy=?, owner=?, config=? WHERE id=?`,
			x.Name, x.Description, x.Logic, x.DecisionStrategy, x.Owner, toJSON(x.Config), x.ID); err != nil {
			return err
		}
		return tx.setPolicyLinks(ctx, x)
	})
}

func (s *Store) DeleteAuthzPolicy(ctx context.Context, rsID, id string) error {
	return s.execOne(ctx, `DELETE FROM authz_policies WHERE resource_server_id=? AND id=?`, rsID, id)
}

// ListAuthzPolicies lists a resource server's policies and permissions
// with their resources, scopes and associated policies.
func (s *Store) ListAuthzPolicies(ctx context.Context, rsID string) ([]*model.AuthzPolicy, error) {
	list, err := queryList(ctx, s, scanAuthzPolicy, `SELECT `+authzPolicyCols+` FROM authz_policies WHERE resource_server_id=? ORDER BY name`, rsID)
	if err != nil {
		return nil, err
	}
	byID := map[string]*model.AuthzPolicy{}
	for _, p := range list {
		byID[p.ID] = p
	}
	for _, q := range []struct {
		sql string
		add func(p *model.AuthzPolicy, id string)
	}{
		{`SELECT l.policy_id, l.resource_id FROM authz_policy_resources l JOIN authz_policies p ON p.id=l.policy_id WHERE p.resource_server_id=?`,
			func(p *model.AuthzPolicy, id string) { p.ResourceIDs = append(p.ResourceIDs, id) }},
		{`SELECT l.policy_id, l.scope_id FROM authz_policy_scopes l JOIN authz_policies p ON p.id=l.policy_id WHERE p.resource_server_id=?`,
			func(p *model.AuthzPolicy, id string) { p.ScopeIDs = append(p.ScopeIDs, id) }},
		{`SELECT l.policy_id, l.associated_id FROM authz_associated_policies l JOIN authz_policies p ON p.id=l.policy_id WHERE p.resource_server_id=?`,
			func(p *model.AuthzPolicy, id string) { p.AssociatedIDs = append(p.AssociatedIDs, id) }},
	} {
		links, err := s.pairs(ctx, q.sql, rsID)
		if err != nil {
			return nil, err
		}
		for _, l := range links {
			if p := byID[l[0]]; p != nil {
				q.add(p, l[1])
			}
		}
	}
	return list, nil
}

// ---- permission tickets ----

const ticketCols = `id, resource_server_id, resource_id, scope_id, owner, requester, created_timestamp, granted_timestamp`

func scanTicket(sc scanner) (*model.PermissionTicket, error) {
	t := &model.PermissionTicket{}
	if err := sc.Scan(&t.ID, &t.ResourceServerID, &t.ResourceID, &t.ScopeID, &t.Owner, &t.Requester, &t.CreatedTimestamp, &t.GrantedTimestamp); err != nil {
		return nil, mapErr(err)
	}
	return t, nil
}

func (s *Store) CreatePermissionTicket(ctx context.Context, t *model.PermissionTicket) error {
	return s.exec(ctx, `INSERT INTO authz_permission_tickets (`+ticketCols+`) VALUES (?,?,?,?,?,?,?,?)`, t.ID, t.ResourceServerID,
		t.ResourceID, t.ScopeID, t.Owner, t.Requester, t.CreatedTimestamp, t.GrantedTimestamp)
}

func (s *Store) UpdatePermissionTicket(ctx context.Context, t *model.PermissionTicket) error {
	return s.execOne(ctx, `UPDATE authz_permission_tickets SET granted_timestamp=? WHERE id=?`, t.GrantedTimestamp, t.ID)
}

func (s *Store) DeletePermissionTicket(ctx context.Context, rsID, id string) error {
	return s.execOne(ctx, `DELETE FROM authz_permission_tickets WHERE resource_server_id=? AND id=?`, rsID, id)
}

func (s *Store) ListPermissionTickets(ctx context.Context, rsID string) ([]*model.PermissionTicket, error) {
	return queryList(ctx, s, scanTicket, `SELECT `+ticketCols+` FROM authz_permission_tickets WHERE resource_server_id=? ORDER BY created_timestamp`, rsID)
}
