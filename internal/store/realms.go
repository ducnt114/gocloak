package store

import (
	"context"
	"time"

	"github.com/ducnt114/gocloak/internal/model"
)

const realmCols = `id, name, display_name, enabled, access_token_lifespan, access_code_lifespan,
	sso_session_idle_timeout, sso_session_max_lifespan, login_with_email_allowed,
	duplicate_emails_allowed, registration_allowed, default_role_id, attributes, settings, created_at`

func scanRealm(sc scanner) (*model.Realm, error) {
	r := &model.Realm{Attributes: map[string]string{}}
	var created int64
	err := sc.Scan(&r.ID, &r.Name, &r.DisplayName, &r.Enabled, &r.AccessTokenLifespan, &r.AccessCodeLifespan,
		&r.SSOSessionIdleTimeout, &r.SSOSessionMaxLifespan, &r.LoginWithEmailAllowed,
		&r.DuplicateEmailsAllowed, &r.RegistrationAllowed, &r.DefaultRoleID, jsonCol{&r.Attributes}, jsonCol{&r.Settings}, &created)
	if err != nil {
		return nil, mapErr(err)
	}
	r.CreatedAt = time.Unix(created, 0)
	return r, nil
}

func (s *Store) CreateRealm(ctx context.Context, r *model.Realm) error {
	return s.exec(ctx, `INSERT INTO realms (`+realmCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.Name, r.DisplayName, r.Enabled, r.AccessTokenLifespan, r.AccessCodeLifespan,
		r.SSOSessionIdleTimeout, r.SSOSessionMaxLifespan, r.LoginWithEmailAllowed,
		r.DuplicateEmailsAllowed, r.RegistrationAllowed, r.DefaultRoleID, toJSON(r.Attributes), toJSON(r.Settings), r.CreatedAt.Unix())
}

func (s *Store) UpdateRealm(ctx context.Context, r *model.Realm) error {
	return s.execOne(ctx, `UPDATE realms SET name=?, display_name=?, enabled=?, access_token_lifespan=?,
		access_code_lifespan=?, sso_session_idle_timeout=?, sso_session_max_lifespan=?,
		login_with_email_allowed=?, duplicate_emails_allowed=?, registration_allowed=?,
		default_role_id=?, attributes=?, settings=? WHERE id=?`,
		r.Name, r.DisplayName, r.Enabled, r.AccessTokenLifespan, r.AccessCodeLifespan,
		r.SSOSessionIdleTimeout, r.SSOSessionMaxLifespan, r.LoginWithEmailAllowed,
		r.DuplicateEmailsAllowed, r.RegistrationAllowed, r.DefaultRoleID, toJSON(r.Attributes), toJSON(r.Settings), r.ID)
}

func (s *Store) DeleteRealm(ctx context.Context, id string) error {
	return s.execOne(ctx, `DELETE FROM realms WHERE id=?`, id)
}

func (s *Store) GetRealmByName(ctx context.Context, name string) (*model.Realm, error) {
	return scanRealm(s.q.QueryRowContext(ctx, `SELECT `+realmCols+` FROM realms WHERE name=?`, name))
}

func (s *Store) GetRealm(ctx context.Context, id string) (*model.Realm, error) {
	return scanRealm(s.q.QueryRowContext(ctx, `SELECT `+realmCols+` FROM realms WHERE id=?`, id))
}

func (s *Store) ListRealms(ctx context.Context) ([]*model.Realm, error) {
	return queryList(ctx, s, scanRealm, `SELECT `+realmCols+` FROM realms ORDER BY name`)
}

// ---- keys ----

func (s *Store) CreateRealmKey(ctx context.Context, k *model.RealmKey) error {
	return s.exec(ctx, `INSERT INTO realm_keys (id, realm_id, algorithm, private_pem, active, priority, created_at)
		VALUES (?,?,?,?,?,?,?)`, k.ID, k.RealmID, k.Algorithm, k.PrivatePEM, k.Active, k.Priority, k.CreatedAt.Unix())
}

func (s *Store) ListRealmKeys(ctx context.Context, realmID string) ([]*model.RealmKey, error) {
	return queryList(ctx, s, func(sc scanner) (*model.RealmKey, error) {
		k := &model.RealmKey{}
		var created int64
		if err := sc.Scan(&k.ID, &k.RealmID, &k.Algorithm, &k.PrivatePEM, &k.Active, &k.Priority, &created); err != nil {
			return nil, err
		}
		k.CreatedAt = time.Unix(created, 0)
		return k, nil
	}, `SELECT id, realm_id, algorithm, private_pem, active, priority, created_at
		FROM realm_keys WHERE realm_id=? ORDER BY priority DESC, created_at DESC`, realmID)
}
