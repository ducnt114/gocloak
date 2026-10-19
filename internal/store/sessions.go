package store

import (
	"context"
	"time"

	"github.com/ducnt114/gocloak/internal/model"
)

const sessionCols = `id, realm_id, user_id, ip_address, started, last_refresh, remember_me, clients, notes`

func scanSession(sc scanner) (*model.UserSession, error) {
	us := &model.UserSession{Clients: map[string]bool{}, Notes: map[string]string{}}
	var started, last int64
	if err := sc.Scan(&us.ID, &us.RealmID, &us.UserID, &us.IPAddress, &started, &last, &us.RememberMe, jsonCol{&us.Clients}, jsonCol{&us.Notes}); err != nil {
		return nil, mapErr(err)
	}
	us.Started = time.Unix(started, 0)
	us.LastRefresh = time.Unix(last, 0)
	return us, nil
}

// sessionTable is user_sessions or offline_sessions.
func sessionTable(offline bool) string {
	if offline {
		return "offline_sessions"
	}
	return "user_sessions"
}

func (s *Store) CreateUserSession(ctx context.Context, us *model.UserSession) error {
	if us.Clients == nil {
		us.Clients = map[string]bool{}
	}
	if us.Notes == nil {
		us.Notes = map[string]string{}
	}
	return s.exec(ctx, `INSERT INTO `+sessionTable(us.Offline)+` (`+sessionCols+`) VALUES (?,?,?,?,?,?,?,?,?)`,
		us.ID, us.RealmID, us.UserID, us.IPAddress, us.Started.Unix(), us.LastRefresh.Unix(), us.RememberMe, toJSON(us.Clients), toJSON(us.Notes))
}

func (s *Store) UpdateUserSession(ctx context.Context, us *model.UserSession) error {
	if us.Notes == nil {
		us.Notes = map[string]string{}
	}
	return s.execOne(ctx, `UPDATE `+sessionTable(us.Offline)+` SET last_refresh=?, clients=?, notes=? WHERE id=?`,
		us.LastRefresh.Unix(), toJSON(us.Clients), toJSON(us.Notes), us.ID)
}

// GetUserSession returns an online session.
func (s *Store) GetUserSession(ctx context.Context, id string) (*model.UserSession, error) {
	return s.GetSession(ctx, id, false)
}

// GetSession returns an online or offline session.
func (s *Store) GetSession(ctx context.Context, id string, offline bool) (*model.UserSession, error) {
	us, err := scanSession(s.q.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM `+sessionTable(offline)+` WHERE id=?`, id))
	if err == nil {
		us.Offline = offline
	}
	return us, err
}

func (s *Store) listSessions(ctx context.Context, offline bool, where string, args ...any) ([]*model.UserSession, error) {
	list, err := queryList(ctx, s, scanSession, `SELECT `+sessionCols+` FROM `+sessionTable(offline)+` WHERE `+where+` ORDER BY started`, args...)
	for _, us := range list {
		us.Offline = offline
	}
	return list, err
}

func (s *Store) ListUserSessions(ctx context.Context, userID string) ([]*model.UserSession, error) {
	return s.listSessions(ctx, false, `user_id=?`, userID)
}

func (s *Store) ListOfflineSessions(ctx context.Context, userID string) ([]*model.UserSession, error) {
	return s.listSessions(ctx, true, `user_id=?`, userID)
}

// ListRealmOfflineSessions lists a realm's offline sessions.
func (s *Store) ListRealmOfflineSessions(ctx context.Context, realmID string) ([]*model.UserSession, error) {
	return s.listSessions(ctx, true, `realm_id=?`, realmID)
}

func (s *Store) ListRealmSessions(ctx context.Context, realmID string) ([]*model.UserSession, error) {
	return s.listSessions(ctx, false, `realm_id=?`, realmID)
}

func (s *Store) SetSessionRememberMe(ctx context.Context, id string) error {
	return s.execOne(ctx, `UPDATE user_sessions SET remember_me=? WHERE id=?`, true, id)
}

func (s *Store) DeleteUserSession(ctx context.Context, id string) error {
	return s.exec(ctx, `DELETE FROM user_sessions WHERE id=?`, id)
}

func (s *Store) DeleteSession(ctx context.Context, us *model.UserSession) error {
	return s.exec(ctx, `DELETE FROM `+sessionTable(us.Offline)+` WHERE id=?`, us.ID)
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

// ConsumeAuthCode atomically fetches and deletes a code, so it can only be
// used once even when two requests race.
func (s *Store) ConsumeAuthCode(ctx context.Context, code string) (*model.AuthCode, error) {
	c := &model.AuthCode{}
	var exp int64
	err := s.q.QueryRowContext(ctx, `DELETE FROM auth_codes WHERE code=? RETURNING code, realm_id, client_id, user_id,
		session_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, expires_at`, code).
		Scan(&c.Code, &c.RealmID, &c.ClientID, &c.UserID, &c.SessionID, &c.RedirectURI, &c.Scope, &c.Nonce,
			&c.CodeChallenge, &c.CodeChallengeMethod, &exp)
	if err != nil {
		return nil, mapErr(err)
	}
	c.ExpiresAt = time.Unix(exp, 0)
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
		`DELETE FROM device_codes WHERE expires_at < ?`,
		`DELETE FROM ciba_requests WHERE expires_at < ?`,
	} {
		if err := s.exec(ctx, q, n); err != nil {
			return err
		}
	}
	// SSO sessions: idle timeout or max lifespan exceeded, per realm settings.
	if err := s.exec(ctx, `DELETE FROM user_sessions WHERE id IN (
		SELECT us.id FROM user_sessions us JOIN realms r ON r.id=us.realm_id
		WHERE us.last_refresh + r.sso_session_idle_timeout < ? OR us.started + r.sso_session_max_lifespan < ?)`, n, n); err != nil {
		return err
	}
	return s.purgeOffline(ctx, now)
}

// purgeOffline removes offline sessions idle for longer than the realm's
// offline idle timeout (or past the optional max lifespan).
func (s *Store) purgeOffline(ctx context.Context, now time.Time) error {
	realms, err := s.ListRealms(ctx)
	if err != nil {
		return err
	}
	for _, r := range realms {
		idle := r.Settings.OfflineSessionIdleTimeout
		if idle <= 0 {
			continue
		}
		q := `DELETE FROM offline_sessions WHERE realm_id=? AND (last_refresh < ?`
		args := []any{r.ID, now.Unix() - int64(idle)}
		if r.Settings.OfflineSessionMaxLifespanEnabled && r.Settings.OfflineSessionMaxLifespan > 0 {
			q += ` OR started < ?`
			args = append(args, now.Unix()-int64(r.Settings.OfflineSessionMaxLifespan))
		}
		if err := s.exec(ctx, q+`)`, args...); err != nil {
			return err
		}
	}
	return nil
}
