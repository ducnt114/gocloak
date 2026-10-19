package store

import (
	"context"

	"github.com/ducnt114/gocloak/internal/model"
)

const roleCols = `id, realm_id, client_id, name, description, composite, attributes`

func scanRole(sc scanner) (*model.Role, error) {
	r := &model.Role{Attributes: map[string][]string{}}
	err := sc.Scan(&r.ID, &r.RealmID, &r.ClientID, &r.Name, &r.Description, &r.Composite, jsonCol{&r.Attributes})
	if err != nil {
		return nil, mapErr(err)
	}
	return r, nil
}

func (s *Store) CreateRole(ctx context.Context, r *model.Role) error {
	if r.Attributes == nil {
		r.Attributes = map[string][]string{}
	}
	return s.exec(ctx, `INSERT INTO roles (`+roleCols+`) VALUES (?,?,?,?,?,?,?)`,
		r.ID, r.RealmID, r.ClientID, r.Name, r.Description, r.Composite, toJSON(r.Attributes))
}

func (s *Store) UpdateRole(ctx context.Context, r *model.Role) error {
	if r.Attributes == nil {
		r.Attributes = map[string][]string{}
	}
	return s.execOne(ctx, `UPDATE roles SET name=?, description=?, composite=?, attributes=? WHERE id=?`,
		r.Name, r.Description, r.Composite, toJSON(r.Attributes), r.ID)
}

func (s *Store) DeleteRole(ctx context.Context, id string) error {
	return s.execOne(ctx, `DELETE FROM roles WHERE id=?`, id)
}

func (s *Store) GetRole(ctx context.Context, realmID, id string) (*model.Role, error) {
	return scanRole(s.q.QueryRowContext(ctx, `SELECT `+roleCols+` FROM roles WHERE realm_id=? AND id=?`, realmID, id))
}

// GetRoleByName finds a realm role (clientUUID == "") or a client role.
func (s *Store) GetRoleByName(ctx context.Context, realmID, clientUUID, name string) (*model.Role, error) {
	return scanRole(s.q.QueryRowContext(ctx, `SELECT `+roleCols+` FROM roles WHERE realm_id=? AND client_id=? AND name=?`,
		realmID, clientUUID, name))
}

// ListRoles lists realm roles (clientUUID == "") or the roles of a client.
func (s *Store) ListRoles(ctx context.Context, realmID, clientUUID, search string, first, max int) ([]*model.Role, error) {
	q := `SELECT ` + roleCols + ` FROM roles WHERE realm_id=? AND client_id=?`
	args := []any{realmID, clientUUID}
	if search != "" {
		q += ` AND lower(name) LIKE ? ESCAPE '\'`
		args = append(args, "%"+likeEscape(lower(search))+"%")
	}
	q += ` ORDER BY name LIMIT ? OFFSET ?`
	args = append(args, limit(max), first)
	return queryList(ctx, s, scanRole, q, args...)
}

func (s *Store) ListAllRoles(ctx context.Context, realmID string) ([]*model.Role, error) {
	return queryList(ctx, s, scanRole, `SELECT `+roleCols+` FROM roles WHERE realm_id=?`, realmID)
}

// ---- composites ----

func (s *Store) AddComposite(ctx context.Context, parentID, childID string) error {
	return s.WithTx(ctx, func(tx *Store) error {
		if err := tx.exec(ctx, `INSERT INTO composite_roles (parent_id, child_id) VALUES (?,?) ON CONFLICT DO NOTHING`, parentID, childID); err != nil {
			return err
		}
		return tx.exec(ctx, `UPDATE roles SET composite=? WHERE id=?`, true, parentID)
	})
}

func (s *Store) RemoveComposite(ctx context.Context, parentID, childID string) error {
	return s.WithTx(ctx, func(tx *Store) error {
		if err := tx.exec(ctx, `DELETE FROM composite_roles WHERE parent_id=? AND child_id=?`, parentID, childID); err != nil {
			return err
		}
		return tx.exec(ctx, `UPDATE roles SET composite=EXISTS(SELECT 1 FROM composite_roles WHERE parent_id=?) WHERE id=?`, parentID, parentID)
	})
}

// ListComposites returns the direct children of a composite role.
func (s *Store) ListComposites(ctx context.Context, parentID string) ([]*model.Role, error) {
	return queryList(ctx, s, scanRole, `SELECT `+prefixed("r", roleCols)+` FROM roles r
		JOIN composite_roles c ON c.child_id=r.id WHERE c.parent_id=? ORDER BY r.name`, parentID)
}

// CompositeEdges returns every (parent, child) composite edge of a realm.
func (s *Store) CompositeEdges(ctx context.Context, realmID string) (map[string][]string, error) {
	type edge struct{ p, c string }
	edges, err := queryList(ctx, s, func(sc scanner) (edge, error) {
		var e edge
		err := sc.Scan(&e.p, &e.c)
		return e, err
	}, `SELECT c.parent_id, c.child_id FROM composite_roles c JOIN roles r ON r.id=c.parent_id WHERE r.realm_id=?`, realmID)
	if err != nil {
		return nil, err
	}
	m := map[string][]string{}
	for _, e := range edges {
		m[e.p] = append(m[e.p], e.c)
	}
	return m, nil
}

// ---- user role mappings ----

func (s *Store) GrantUserRole(ctx context.Context, userID, roleID string) error {
	return s.exec(ctx, `INSERT INTO user_roles (user_id, role_id) VALUES (?,?) ON CONFLICT DO NOTHING`, userID, roleID)
}

func (s *Store) RevokeUserRole(ctx context.Context, userID, roleID string) error {
	return s.exec(ctx, `DELETE FROM user_roles WHERE user_id=? AND role_id=?`, userID, roleID)
}

// UserRoles returns the roles directly mapped to a user.
func (s *Store) UserRoles(ctx context.Context, userID string) ([]*model.Role, error) {
	return queryList(ctx, s, scanRole, `SELECT `+prefixed("r", roleCols)+` FROM roles r
		JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=? ORDER BY r.name`, userID)
}

// UsersWithRole returns users that have the role directly mapped.
func (s *Store) UsersWithRole(ctx context.Context, roleID string, first, max int) ([]*model.User, error) {
	return queryList(ctx, s, scanUser, `SELECT `+prefixed("u", userCols)+` FROM users u
		JOIN user_roles ur ON ur.user_id=u.id WHERE ur.role_id=? ORDER BY u.username LIMIT ? OFFSET ?`,
		roleID, limit(max), first)
}

// ---- group role mappings ----

func (s *Store) GrantGroupRole(ctx context.Context, groupID, roleID string) error {
	return s.exec(ctx, `INSERT INTO group_roles (group_id, role_id) VALUES (?,?) ON CONFLICT DO NOTHING`, groupID, roleID)
}

func (s *Store) RevokeGroupRole(ctx context.Context, groupID, roleID string) error {
	return s.exec(ctx, `DELETE FROM group_roles WHERE group_id=? AND role_id=?`, groupID, roleID)
}

func (s *Store) GroupRoles(ctx context.Context, groupID string) ([]*model.Role, error) {
	return queryList(ctx, s, scanRole, `SELECT `+prefixed("r", roleCols)+` FROM roles r
		JOIN group_roles gr ON gr.role_id=r.id WHERE gr.group_id=? ORDER BY r.name`, groupID)
}

// prefixed turns "a, b" into "p.a, p.b".
func prefixed(p, cols string) string {
	out := ""
	for i, c := range splitCols(cols) {
		if i > 0 {
			out += ", "
		}
		out += p + "." + c
	}
	return out
}

func splitCols(cols string) []string {
	var out []string
	cur := ""
	for _, ch := range cols {
		switch ch {
		case ',':
			out = append(out, cur)
			cur = ""
		case ' ', '\n', '\t':
		default:
			cur += string(ch)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
