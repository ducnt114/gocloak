package store

import (
	"context"

	"github.com/ducnt114/gocloak/internal/model"
)

// ---- client scopes ----

const scopeCols = `id, realm_id, name, description, protocol, attributes`

func scanScope(sc scanner) (*model.ClientScope, error) {
	s := &model.ClientScope{Attributes: map[string]string{}}
	if err := sc.Scan(&s.ID, &s.RealmID, &s.Name, &s.Description, &s.Protocol, jsonCol{&s.Attributes}); err != nil {
		return nil, mapErr(err)
	}
	return s, nil
}

func (s *Store) CreateClientScope(ctx context.Context, cs *model.ClientScope) error {
	if cs.Attributes == nil {
		cs.Attributes = map[string]string{}
	}
	return s.exec(ctx, `INSERT INTO client_scopes (`+scopeCols+`) VALUES (?,?,?,?,?,?)`,
		cs.ID, cs.RealmID, cs.Name, cs.Description, cs.Protocol, toJSON(cs.Attributes))
}

func (s *Store) UpdateClientScope(ctx context.Context, cs *model.ClientScope) error {
	if cs.Attributes == nil {
		cs.Attributes = map[string]string{}
	}
	return s.execOne(ctx, `UPDATE client_scopes SET name=?, description=?, protocol=?, attributes=? WHERE id=?`,
		cs.Name, cs.Description, cs.Protocol, toJSON(cs.Attributes), cs.ID)
}

// DeleteClientScope removes a scope with its mappers and scope mappings.
func (s *Store) DeleteClientScope(ctx context.Context, id string) error {
	return s.WithTx(ctx, func(tx *Store) error {
		if err := tx.deleteOwned(ctx, id); err != nil {
			return err
		}
		return tx.execOne(ctx, `DELETE FROM client_scopes WHERE id=?`, id)
	})
}

// deleteOwned removes the mappers and scope mappings of a client or scope.
func (s *Store) deleteOwned(ctx context.Context, ownerID string) error {
	if err := s.exec(ctx, `DELETE FROM protocol_mappers WHERE owner_id=?`, ownerID); err != nil {
		return err
	}
	return s.exec(ctx, `DELETE FROM scope_mappings WHERE owner_id=?`, ownerID)
}

func (s *Store) GetClientScope(ctx context.Context, realmID, id string) (*model.ClientScope, error) {
	return scanScope(s.q.QueryRowContext(ctx, `SELECT `+scopeCols+` FROM client_scopes WHERE realm_id=? AND id=?`, realmID, id))
}

func (s *Store) GetClientScopeByName(ctx context.Context, realmID, name string) (*model.ClientScope, error) {
	return scanScope(s.q.QueryRowContext(ctx, `SELECT `+scopeCols+` FROM client_scopes WHERE realm_id=? AND name=?`, realmID, name))
}

func (s *Store) ListClientScopes(ctx context.Context, realmID string) ([]*model.ClientScope, error) {
	return queryList(ctx, s, scanScope, `SELECT `+scopeCols+` FROM client_scopes WHERE realm_id=? ORDER BY name`, realmID)
}

func (s *Store) CountClientScopes(ctx context.Context, realmID string) (int, error) {
	var n int
	err := s.q.QueryRowContext(ctx, `SELECT count(*) FROM client_scopes WHERE realm_id=?`, realmID).Scan(&n)
	return n, err
}

// ---- protocol mappers ----

const mapperCols = `id, realm_id, owner_id, name, protocol, mapper_type, config`

func scanMapper(sc scanner) (*model.ProtocolMapper, error) {
	m := &model.ProtocolMapper{Config: map[string]string{}}
	if err := sc.Scan(&m.ID, &m.RealmID, &m.OwnerID, &m.Name, &m.Protocol, &m.Type, jsonCol{&m.Config}); err != nil {
		return nil, mapErr(err)
	}
	return m, nil
}

func (s *Store) CreateMapper(ctx context.Context, m *model.ProtocolMapper) error {
	if m.Config == nil {
		m.Config = map[string]string{}
	}
	return s.exec(ctx, `INSERT INTO protocol_mappers (`+mapperCols+`) VALUES (?,?,?,?,?,?,?)`,
		m.ID, m.RealmID, m.OwnerID, m.Name, m.Protocol, m.Type, toJSON(m.Config))
}

func (s *Store) UpdateMapper(ctx context.Context, m *model.ProtocolMapper) error {
	if m.Config == nil {
		m.Config = map[string]string{}
	}
	return s.execOne(ctx, `UPDATE protocol_mappers SET name=?, protocol=?, mapper_type=?, config=? WHERE id=? AND owner_id=?`,
		m.Name, m.Protocol, m.Type, toJSON(m.Config), m.ID, m.OwnerID)
}

func (s *Store) DeleteMapper(ctx context.Context, ownerID, id string) error {
	return s.execOne(ctx, `DELETE FROM protocol_mappers WHERE owner_id=? AND id=?`, ownerID, id)
}

func (s *Store) GetMapper(ctx context.Context, ownerID, id string) (*model.ProtocolMapper, error) {
	return scanMapper(s.q.QueryRowContext(ctx, `SELECT `+mapperCols+` FROM protocol_mappers WHERE owner_id=? AND id=?`, ownerID, id))
}

func (s *Store) ListMappers(ctx context.Context, ownerID string) ([]*model.ProtocolMapper, error) {
	return queryList(ctx, s, scanMapper, `SELECT `+mapperCols+` FROM protocol_mappers WHERE owner_id=? ORDER BY name`, ownerID)
}

// ---- scope links ----

func scanLink(sc scanner) (model.ClientScopeLink, error) {
	var l model.ClientScopeLink
	err := sc.Scan(&l.ScopeID, &l.Default)
	return l, err
}

func (s *Store) SetRealmDefaultScope(ctx context.Context, realmID, scopeID string, isDefault bool) error {
	return s.WithTx(ctx, func(tx *Store) error {
		if err := tx.exec(ctx, `DELETE FROM realm_default_scopes WHERE realm_id=? AND scope_id=?`, realmID, scopeID); err != nil {
			return err
		}
		return tx.exec(ctx, `INSERT INTO realm_default_scopes (realm_id, scope_id, is_default) VALUES (?,?,?)`, realmID, scopeID, isDefault)
	})
}

func (s *Store) RemoveRealmDefaultScope(ctx context.Context, realmID, scopeID string) error {
	return s.exec(ctx, `DELETE FROM realm_default_scopes WHERE realm_id=? AND scope_id=?`, realmID, scopeID)
}

func (s *Store) ListRealmDefaultScopes(ctx context.Context, realmID string) ([]model.ClientScopeLink, error) {
	return queryList(ctx, s, scanLink, `SELECT scope_id, is_default FROM realm_default_scopes WHERE realm_id=?`, realmID)
}

func (s *Store) SetClientScopeLink(ctx context.Context, clientID, scopeID string, isDefault bool) error {
	return s.WithTx(ctx, func(tx *Store) error {
		if err := tx.exec(ctx, `DELETE FROM client_scope_links WHERE client_id=? AND scope_id=?`, clientID, scopeID); err != nil {
			return err
		}
		return tx.exec(ctx, `INSERT INTO client_scope_links (client_id, scope_id, is_default) VALUES (?,?,?)`, clientID, scopeID, isDefault)
	})
}

func (s *Store) RemoveClientScopeLink(ctx context.Context, clientID, scopeID string) error {
	return s.exec(ctx, `DELETE FROM client_scope_links WHERE client_id=? AND scope_id=?`, clientID, scopeID)
}

func (s *Store) ListClientScopeLinks(ctx context.Context, clientID string) ([]model.ClientScopeLink, error) {
	return queryList(ctx, s, scanLink, `SELECT scope_id, is_default FROM client_scope_links WHERE client_id=?`, clientID)
}

// ScopeInUse reports whether a client scope is a realm default or linked to a client.
func (s *Store) ScopeInUse(ctx context.Context, scopeID string) (bool, error) {
	var n int
	err := s.q.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM realm_default_scopes WHERE scope_id=?) +
		(SELECT count(*) FROM client_scope_links WHERE scope_id=?)`, scopeID, scopeID).Scan(&n)
	return n > 0, err
}

// ---- role scope mappings ----

func (s *Store) AddScopeMapping(ctx context.Context, ownerID, roleID string) error {
	return s.exec(ctx, `INSERT INTO scope_mappings (owner_id, role_id) VALUES (?,?) ON CONFLICT DO NOTHING`, ownerID, roleID)
}

func (s *Store) RemoveScopeMapping(ctx context.Context, ownerID, roleID string) error {
	return s.exec(ctx, `DELETE FROM scope_mappings WHERE owner_id=? AND role_id=?`, ownerID, roleID)
}

func (s *Store) ListScopeMappings(ctx context.Context, ownerID string) ([]*model.Role, error) {
	return queryList(ctx, s, scanRole, `SELECT `+prefixed("r", roleCols)+` FROM roles r
		JOIN scope_mappings sm ON sm.role_id=r.id WHERE sm.owner_id=? ORDER BY r.name`, ownerID)
}

// ---- user attribute index ----

// indexUserAttributes rewrites the searchable copy of a user's attributes.
func (s *Store) indexUserAttributes(ctx context.Context, u *model.User) error {
	if err := s.exec(ctx, `DELETE FROM user_attributes WHERE user_id=?`, u.ID); err != nil {
		return err
	}
	for name, values := range u.Attributes {
		for _, v := range values {
			if err := s.exec(ctx, `INSERT INTO user_attributes (user_id, name, value) VALUES (?,?,?)`, u.ID, name, v); err != nil {
				return err
			}
		}
	}
	return nil
}

// backfillUserAttributes indexes users created before the index existed.
func backfillUserAttributes(ctx context.Context, tx *Store) error {
	// only the columns of version 4: later migrations add others
	users, err := queryList(ctx, tx, func(sc scanner) (*model.User, error) {
		u := &model.User{Attributes: map[string][]string{}}
		return u, sc.Scan(&u.ID, jsonCol{&u.Attributes})
	}, `SELECT id, attributes FROM users`)
	if err != nil {
		return err
	}
	for _, u := range users {
		if err := tx.indexUserAttributes(ctx, u); err != nil {
			return err
		}
	}
	return nil
}
