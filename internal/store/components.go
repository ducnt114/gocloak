package store

import (
	"context"

	"github.com/ducnt114/gocloak/internal/model"
)

const componentCols = `id, realm_id, name, provider_id, provider_type, parent_id, sub_type, config`

func scanComponent(sc scanner) (*model.Component, error) {
	c := &model.Component{Config: map[string][]string{}}
	if err := sc.Scan(&c.ID, &c.RealmID, &c.Name, &c.ProviderID, &c.ProviderType, &c.ParentID, &c.SubType, jsonCol{&c.Config}); err != nil {
		return nil, mapErr(err)
	}
	return c, nil
}

func (s *Store) CreateComponent(ctx context.Context, c *model.Component) error {
	if c.Config == nil {
		c.Config = map[string][]string{}
	}
	return s.exec(ctx, `INSERT INTO components (`+componentCols+`) VALUES (?,?,?,?,?,?,?,?)`,
		c.ID, c.RealmID, c.Name, c.ProviderID, c.ProviderType, c.ParentID, c.SubType, toJSON(c.Config))
}

func (s *Store) UpdateComponent(ctx context.Context, c *model.Component) error {
	if c.Config == nil {
		c.Config = map[string][]string{}
	}
	return s.execOne(ctx, `UPDATE components SET name=?, provider_id=?, provider_type=?, parent_id=?, sub_type=?, config=? WHERE id=?`,
		c.Name, c.ProviderID, c.ProviderType, c.ParentID, c.SubType, toJSON(c.Config), c.ID)
}

func (s *Store) DeleteComponent(ctx context.Context, realmID, id string) error {
	return s.execOne(ctx, `DELETE FROM components WHERE realm_id=? AND id=?`, realmID, id)
}

func (s *Store) GetComponent(ctx context.Context, realmID, id string) (*model.Component, error) {
	return scanComponent(s.q.QueryRowContext(ctx, `SELECT `+componentCols+` FROM components WHERE realm_id=? AND id=?`, realmID, id))
}

// ListComponents lists a realm's components, optionally of one provider type.
func (s *Store) ListComponents(ctx context.Context, realmID, providerType string) ([]*model.Component, error) {
	if providerType == "" {
		return queryList(ctx, s, scanComponent, `SELECT `+componentCols+` FROM components WHERE realm_id=? ORDER BY name, id`, realmID)
	}
	return queryList(ctx, s, scanComponent, `SELECT `+componentCols+` FROM components WHERE realm_id=? AND provider_type=? ORDER BY name, id`,
		realmID, providerType)
}

// DeleteComponentTree deletes a component with its sub components (e.g. an
// LDAP provider and its mappers).
func (s *Store) DeleteComponentTree(ctx context.Context, realmID, id string) error {
	return s.WithTx(ctx, func(tx *Store) error {
		if err := tx.exec(ctx, `DELETE FROM components WHERE realm_id=? AND parent_id=?`, realmID, id); err != nil {
			return err
		}
		return tx.execOne(ctx, `DELETE FROM components WHERE realm_id=? AND id=?`, realmID, id)
	})
}
