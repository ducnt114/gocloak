package store

import (
	"context"
	"time"

	"github.com/ducnt114/gocloak/internal/model"
)

const sessionCols = `id, realm_id, user_id, ip_address, started, last_refresh, remember_me, clients`

func scanSession(sc scanner) (*model.UserSession, error) {
	us := &model.UserSession{Clients: map[string]bool{}}
	var started, last int64
	if err := sc.Scan(&us.ID, &us.RealmID, &us.UserID, &us.IPAddress, &started, &last, &us.RememberMe, jsonCol{&us.Clients}); err != nil {
		return nil, mapErr(err)
	}
	us.Started = time.Unix(started, 0)
	us.LastRefresh = time.Unix(last, 0)
	return us, nil
}

func (s *Store) CreateUserSession(ctx context.Context, us *model.UserSession) error {
	if us.Clients == nil {
		us.Clients = map[string]bool{}
	}
	return s.exec(ctx, `INSERT INTO user_sessions (`+sessionCols+`) VALUES (?,?,?,?,?,?,?,?)`,
		us.ID, us.RealmID, us.UserID, us.IPAddress, us.Started.Unix(), us.LastRefresh.Unix(), us.RememberMe, toJSON(us.Clients))
}

func (s *Store) UpdateUserSession(ctx context.Context, us *model.UserSession) error {
	return s.execOne(ctx, `UPDATE user_sessions SET last_refresh=?, clients=? WHERE id=?`,
		us.LastRefresh.Unix(), toJSON(us.Clients), us.ID)
}

func (s *Store) GetUserSession(ctx context.Context, id string) (*model.UserSession, error) {
	return scanSession(s.q.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM user_sessions WHERE id=?`, id))
}

func (s *Store) ListUserSessions(ctx context.Context, userID string) ([]*model.UserSession, error) {
	return queryList(ctx, s, scanSession, `SELECT `+sessionCols+` FROM user_sessions WHERE user_id=? ORDER BY started`, userID)
}

func (s *Store) ListRealmSessions(ctx context.Context, realmID string) ([]*model.UserSession, error) {
	return queryList(ctx, s, scanSession, `SELECT `+sessionCols+` FROM user_sessions WHERE realm_id=? ORDER BY started`, realmID)
}

func (s *Store) DeleteUserSession(ctx context.Context, id string) error {
	return s.exec(ctx, `DELETE FROM user_sessions WHERE id=?`, id)
}

func (s *Store) DeleteUserSessionsOfUser(ctx context.Context, userID string) error {
	return s.exec(ctx, `DELETE FROM user_sessions WHERE user_id=?`, userID)
}

func (s *Store) DeleteUserSessionsOfRealm(ctx context.Context, realmID string) error {
	return s.exec(ctx, `DELETE FROM user_sessions WHERE realm_id=?`, realmID)
}

// ---- auth sessions ----

func (s *Store) CreateAuthSession(ctx context.Context, a *model.AuthSession) error {
	return s.exec(ctx, `INSERT INTO auth_sessions (id, realm_id, client_id, params, user_id, expires_at) VALUES (?,?,?,?,?,?)`,
		a.ID, a.RealmID, a.ClientID, toJSON(a.Params), a.UserID, a.ExpiresAt.Unix())
}

func (s *Store) UpdateAuthSession(ctx context.Context, a *model.AuthSession) error {
	return s.execOne(ctx, `UPDATE auth_sessions SET user_id=?, params=? WHERE id=?`, a.UserID, toJSON(a.Params), a.ID)
}

func (s *Store) GetAuthSession(ctx context.Context, id string) (*model.AuthSession, error) {
	a := &model.AuthSession{Params: map[string]string{}}
	var exp int64
	err := s.q.QueryRowContext(ctx, `SELECT id, realm_id, client_id, params, user_id, expires_at FROM auth_sessions WHERE id=?`, id).
		Scan(&a.ID, &a.RealmID, &a.ClientID, jsonCol{&a.Params}, &a.UserID, &exp)
	if err != nil {
		return nil, mapErr(err)
	}
	a.ExpiresAt = time.Unix(exp, 0)
	return a, nil
}

func (s *Store) DeleteAuthSession(ctx context.Context, id string) error {
	return s.exec(ctx, `DELETE FROM auth_sessions WHERE id=?`, id)
}

// ---- authorization codes ----

func (s *Store) CreateAuthCode(ctx context.Context, c *model.AuthCode) error {
	return s.exec(ctx, `INSERT INTO auth_codes (code, realm_id, client_id, user_id, session_id, redirect_uri, scope, nonce,
		code_challenge, code_challenge_method, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		c.Code, c.RealmID, c.ClientID, c.UserID, c.SessionID, c.RedirectURI, c.Scope, c.Nonce,
		c.CodeChallenge, c.CodeChallengeMethod, c.ExpiresAt.Unix())
}

// ConsumeAuthCode atomically fetches and deletes a code, so it can only be used once.
func (s *Store) ConsumeAuthCode(ctx context.Context, code string) (*model.AuthCode, error) {
	var c *model.AuthCode
	err := s.WithTx(ctx, func(tx *Store) error {
		c = &model.AuthCode{}
		var exp int64
		err := tx.q.QueryRowContext(ctx, `SELECT code, realm_id, client_id, user_id, session_id, redirect_uri, scope, nonce,
			code_challenge, code_challenge_method, expires_at FROM auth_codes WHERE code=?`, code).
			Scan(&c.Code, &c.RealmID, &c.ClientID, &c.UserID, &c.SessionID, &c.RedirectURI, &c.Scope, &c.Nonce,
				&c.CodeChallenge, &c.CodeChallengeMethod, &exp)
		if err != nil {
			return mapErr(err)
		}
		c.ExpiresAt = time.Unix(exp, 0)
		return tx.exec(ctx, `DELETE FROM auth_codes WHERE code=?`, code)
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ---- revoked tokens ----

func (s *Store) RevokeToken(ctx context.Context, jti string, expiresAt time.Time) error {
	return s.exec(ctx, `INSERT INTO revoked_tokens (jti, expires_at) VALUES (?,?) ON CONFLICT DO NOTHING`, jti, expiresAt.Unix())
}

func (s *Store) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	var n int
	err := s.q.QueryRowContext(ctx, `SELECT count(*) FROM revoked_tokens WHERE jti=?`, jti).Scan(&n)
	return n > 0, err
}

// PurgeExpired removes expired auth sessions, codes, revocations and SSO sessions.
func (s *Store) PurgeExpired(ctx context.Context, now time.Time) error {
	n := now.Unix()
	for _, q := range []string{
		`DELETE FROM auth_sessions WHERE expires_at < ?`,
		`DELETE FROM auth_codes WHERE expires_at < ?`,
		`DELETE FROM revoked_tokens WHERE expires_at < ?`,
	} {
		if err := s.exec(ctx, q, n); err != nil {
			return err
		}
	}
	// SSO sessions: idle timeout or max lifespan exceeded, per realm settings.
	return s.exec(ctx, `DELETE FROM user_sessions WHERE id IN (
		SELECT us.id FROM user_sessions us JOIN realms r ON r.id=us.realm_id
		WHERE us.last_refresh + r.sso_session_idle_timeout < ? OR us.started + r.sso_session_max_lifespan < ?)`, n, n)
}
