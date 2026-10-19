package store

import (
	"context"
	"strings"

	"github.com/ducnt114/gocloak/internal/model"
)

const eventCols = `id, realm_id, type, time, client_id, user_id, session_id, ip_address, error, details`

func (s *Store) AddEvent(ctx context.Context, e *model.Event) error {
	if e.Details == nil {
		e.Details = map[string]string{}
	}
	return s.exec(ctx, `INSERT INTO events (`+eventCols+`) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.RealmID, e.Type, e.Time, e.ClientID, e.UserID, e.SessionID, e.IPAddress, e.Error, toJSON(e.Details))
}

// EventQuery mirrors the parameters of GET /admin/realms/{realm}/events.
type EventQuery struct {
	Types     []string
	ClientID  string
	UserID    string
	IPAddress string
	From, To  int64 // millis, 0 = unbounded
	First     int
	Max       int
}

func (s *Store) ListEvents(ctx context.Context, realmID string, q EventQuery) ([]*model.Event, error) {
	w := ` WHERE realm_id=?`
	args := []any{realmID}
	if len(q.Types) > 0 {
		w += ` AND type IN (` + strings.TrimSuffix(strings.Repeat("?,", len(q.Types)), ",") + `)`
		for _, t := range q.Types {
			args = append(args, t)
		}
	}
	for col, v := range map[string]string{"client_id": q.ClientID, "user_id": q.UserID, "ip_address": q.IPAddress} {
		if v != "" {
			w += ` AND ` + col + `=?`
			args = append(args, v)
		}
	}
	if q.From > 0 {
		w += ` AND time >= ?`
		args = append(args, q.From)
	}
	if q.To > 0 {
		w += ` AND time <= ?`
		args = append(args, q.To)
	}
	args = append(args, limit(q.Max), q.First)
	return queryList(ctx, s, func(sc scanner) (*model.Event, error) {
		e := &model.Event{Details: map[string]string{}}
		err := sc.Scan(&e.ID, &e.RealmID, &e.Type, &e.Time, &e.ClientID, &e.UserID, &e.SessionID, &e.IPAddress, &e.Error, jsonCol{&e.Details})
		return e, err
	}, `SELECT `+eventCols+` FROM events`+w+` ORDER BY time DESC, id LIMIT ? OFFSET ?`, args...)
}

func (s *Store) DeleteEvents(ctx context.Context, realmID string) error {
	return s.exec(ctx, `DELETE FROM events WHERE realm_id=?`, realmID)
}

const adminEventCols = `id, realm_id, time, operation_type, resource_type, resource_path, representation,
	auth_realm_id, auth_client_id, auth_user_id, auth_ip, error`

func (s *Store) AddAdminEvent(ctx context.Context, e *model.AdminEvent) error {
	return s.exec(ctx, `INSERT INTO admin_events (`+adminEventCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.RealmID, e.Time, e.OperationType, e.ResourceType, e.ResourcePath, e.Representation,
		e.AuthRealmID, e.AuthClientID, e.AuthUserID, e.AuthIP, e.Error)
}

// AdminEventQuery mirrors the parameters of GET /admin/realms/{realm}/admin-events.
type AdminEventQuery struct {
	OperationTypes []string
	ResourceTypes  []string
	ResourcePath   string // may end with '*'
	AuthRealm      string
	AuthClient     string
	AuthUser       string
	AuthIP         string
	From, To       int64
	First          int
	Max            int
}

func (s *Store) ListAdminEvents(ctx context.Context, realmID string, q AdminEventQuery) ([]*model.AdminEvent, error) {
	w := ` WHERE realm_id=?`
	args := []any{realmID}
	in := func(col string, values []string) {
		if len(values) == 0 {
			return
		}
		w += ` AND ` + col + ` IN (` + strings.TrimSuffix(strings.Repeat("?,", len(values)), ",") + `)`
		for _, v := range values {
			args = append(args, v)
		}
	}
	in("operation_type", q.OperationTypes)
	in("resource_type", q.ResourceTypes)
	if q.ResourcePath != "" {
		if strings.HasSuffix(q.ResourcePath, "*") {
			w += ` AND resource_path LIKE ? ESCAPE '\'`
			args = append(args, likeEscape(strings.TrimSuffix(q.ResourcePath, "*"))+"%")
		} else {
			w += ` AND resource_path=?`
			args = append(args, q.ResourcePath)
		}
	}
	for col, v := range map[string]string{"auth_realm_id": q.AuthRealm, "auth_client_id": q.AuthClient, "auth_user_id": q.AuthUser, "auth_ip": q.AuthIP} {
		if v != "" {
			w += ` AND ` + col + `=?`
			args = append(args, v)
		}
	}
	if q.From > 0 {
		w += ` AND time >= ?`
		args = append(args, q.From)
	}
	if q.To > 0 {
		w += ` AND time <= ?`
		args = append(args, q.To)
	}
	args = append(args, limit(q.Max), q.First)
	return queryList(ctx, s, func(sc scanner) (*model.AdminEvent, error) {
		e := &model.AdminEvent{}
		err := sc.Scan(&e.ID, &e.RealmID, &e.Time, &e.OperationType, &e.ResourceType, &e.ResourcePath, &e.Representation,
			&e.AuthRealmID, &e.AuthClientID, &e.AuthUserID, &e.AuthIP, &e.Error)
		return e, err
	}, `SELECT `+adminEventCols+` FROM admin_events`+w+` ORDER BY time DESC, id LIMIT ? OFFSET ?`, args...)
}

func (s *Store) DeleteAdminEvents(ctx context.Context, realmID string) error {
	return s.exec(ctx, `DELETE FROM admin_events WHERE realm_id=?`, realmID)
}

// PurgeEvents removes events older than before (millis) in a realm.
func (s *Store) PurgeEvents(ctx context.Context, realmID string, before int64) error {
	return s.exec(ctx, `DELETE FROM events WHERE realm_id=? AND time < ?`, realmID, before)
}

// ---- brute force ----

func (s *Store) GetLoginFailure(ctx context.Context, realmID, userID string) (*model.LoginFailure, error) {
	f := &model.LoginFailure{}
	err := s.q.QueryRowContext(ctx, `SELECT realm_id, user_id, num_failures, num_temporary_lockouts, last_failure, last_ip,
		failed_login_not_before FROM login_failures WHERE realm_id=? AND user_id=?`, realmID, userID).
		Scan(&f.RealmID, &f.UserID, &f.NumFailures, &f.NumTemporaryLockouts, &f.LastFailure, &f.LastIP, &f.FailedLoginNotBefore)
	if err != nil {
		return nil, mapErr(err)
	}
	return f, nil
}

func (s *Store) SaveLoginFailure(ctx context.Context, f *model.LoginFailure) error {
	return s.WithTx(ctx, func(tx *Store) error {
		if err := tx.exec(ctx, `DELETE FROM login_failures WHERE realm_id=? AND user_id=?`, f.RealmID, f.UserID); err != nil {
			return err
		}
		return tx.exec(ctx, `INSERT INTO login_failures (realm_id, user_id, num_failures, num_temporary_lockouts, last_failure,
			last_ip, failed_login_not_before) VALUES (?,?,?,?,?,?,?)`,
			f.RealmID, f.UserID, f.NumFailures, f.NumTemporaryLockouts, f.LastFailure, f.LastIP, f.FailedLoginNotBefore)
	})
}

func (s *Store) DeleteLoginFailure(ctx context.Context, realmID, userID string) error {
	return s.exec(ctx, `DELETE FROM login_failures WHERE realm_id=? AND user_id=?`, realmID, userID)
}

func (s *Store) DeleteLoginFailures(ctx context.Context, realmID string) error {
	return s.exec(ctx, `DELETE FROM login_failures WHERE realm_id=?`, realmID)
}
