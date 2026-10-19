package store

import (
	"context"

	"github.com/ducnt114/gocloak/internal/model"
)

const groupCols = `id, realm_id, parent_id, name, attributes`

func scanGroup(sc scanner) (*model.Group, error) {
	g := &model.Group{Attributes: map[string][]string{}}
	if err := sc.Scan(&g.ID, &g.RealmID, &g.ParentID, &g.Name, jsonCol{&g.Attributes}); err != nil {
		return nil, mapErr(err)
	}
	return g, nil
}

func (s *Store) CreateGroup(ctx context.Context, g *model.Group) error {
	if g.Attributes == nil {
		g.Attributes = map[string][]string{}
	}
	return s.exec(ctx, `INSERT INTO realm_groups (`+groupCols+`) VALUES (?,?,?,?,?)`,
		g.ID, g.RealmID, g.ParentID, g.Name, toJSON(g.Attributes))
}

func (s *Store) UpdateGroup(ctx context.Context, g *model.Group) error {
	if g.Attributes == nil {
		g.Attributes = map[string][]string{}
	}
	return s.execOne(ctx, `UPDATE realm_groups SET parent_id=?, name=?, attributes=? WHERE id=?`,
		g.ParentID, g.Name, toJSON(g.Attributes), g.ID)
}

// DeleteGroup deletes a group and all of its descendants.
func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	return s.WithTx(ctx, func(tx *Store) error {
		children, err := queryStrings(ctx, tx, `SELECT id FROM realm_groups WHERE parent_id=?`, id)
		if err != nil {
			return err
		}
		for _, c := range children {
			if err := tx.DeleteGroup(ctx, c); err != nil {
				return err
			}
		}
		return tx.execOne(ctx, `DELETE FROM realm_groups WHERE id=?`, id)
	})
}

func (s *Store) GetGroup(ctx context.Context, realmID, id string) (*model.Group, error) {
	return scanGroup(s.q.QueryRowContext(ctx, `SELECT `+groupCols+` FROM realm_groups WHERE realm_id=? AND id=?`, realmID, id))
}

// ListGroups lists the direct children of parentID ("" for top level groups).
// search, when set, matches group names anywhere in the tree instead.
func (s *Store) ListGroups(ctx context.Context, realmID, parentID, search string, first, max int) ([]*model.Group, error) {
	if search != "" {
		return queryList(ctx, s, scanGroup, `SELECT `+groupCols+` FROM realm_groups WHERE realm_id=? AND lower(name) LIKE ? ESCAPE '\'
			ORDER BY name LIMIT ? OFFSET ?`, realmID, "%"+likeEscape(lower(search))+"%", limit(max), first)
	}
	return queryList(ctx, s, scanGroup, `SELECT `+groupCols+` FROM realm_groups WHERE realm_id=? AND parent_id=?
		ORDER BY name LIMIT ? OFFSET ?`, realmID, parentID, limit(max), first)
}

func (s *Store) ListAllGroups(ctx context.Context, realmID string) ([]*model.Group, error) {
	return queryList(ctx, s, scanGroup, `SELECT `+groupCols+` FROM realm_groups WHERE realm_id=? ORDER BY name`, realmID)
}

func (s *Store) CountGroups(ctx context.Context, realmID string, topLevelOnly bool) (int, error) {
	q := `SELECT count(*) FROM realm_groups WHERE realm_id=?`
	if topLevelOnly {
		q += ` AND parent_id=''`
	}
	var n int
	err := s.q.QueryRowContext(ctx, q, realmID).Scan(&n)
	return n, err
}

// ---- membership ----

func (s *Store) AddUserToGroup(ctx context.Context, userID, groupID string) error {
	return s.exec(ctx, `INSERT INTO user_groups (user_id, group_id) VALUES (?,?) ON CONFLICT DO NOTHING`, userID, groupID)
}

func (s *Store) RemoveUserFromGroup(ctx context.Context, userID, groupID string) error {
	return s.exec(ctx, `DELETE FROM user_groups WHERE user_id=? AND group_id=?`, userID, groupID)
}

func (s *Store) UserGroups(ctx context.Context, userID string) ([]*model.Group, error) {
	return queryList(ctx, s, scanGroup, `SELECT `+prefixed("g", groupCols)+` FROM realm_groups g
		JOIN user_groups ug ON ug.group_id=g.id WHERE ug.user_id=? ORDER BY g.name`, userID)
}

func (s *Store) GroupMembers(ctx context.Context, groupID string, first, max int) ([]*model.User, error) {
	return queryList(ctx, s, scanUser, `SELECT `+prefixed("u", userCols)+` FROM users u
		JOIN user_groups ug ON ug.user_id=u.id WHERE ug.group_id=? ORDER BY u.username LIMIT ? OFFSET ?`,
		groupID, limit(max), first)
}
