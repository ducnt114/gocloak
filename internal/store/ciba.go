package store

import (
	"context"
	"time"

	"github.com/ducnt114/gocloak/internal/model"
)

const cibaCols = `id, realm_id, client_id, user_id, scope, callback_id, notification_token, status, session_id, poll_interval, last_poll, expires_at`

func scanCIBA(sc scanner) (*model.CIBARequest, error) {
	c := &model.CIBARequest{}
	var exp int64
	if err := sc.Scan(&c.ID, &c.RealmID, &c.ClientID, &c.UserID, &c.Scope, &c.CallbackID, &c.NotificationToken, &c.Status,
		&c.SessionID, &c.Interval, &c.LastPoll, &exp); err != nil {
		return nil, mapErr(err)
	}
	c.ExpiresAt = time.Unix(exp, 0)
	return c, nil
}

func (s *Store) CreateCIBARequest(ctx context.Context, c *model.CIBARequest) error {
	return s.exec(ctx, `INSERT INTO ciba_requests (`+cibaCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, c.ID, c.RealmID, c.ClientID,
		c.UserID, c.Scope, c.CallbackID, c.NotificationToken, c.Status, c.SessionID, c.Interval, c.LastPoll, c.ExpiresAt.Unix())
}

func (s *Store) GetCIBARequest(ctx context.Context, id string) (*model.CIBARequest, error) {
	return scanCIBA(s.q.QueryRowContext(ctx, `SELECT `+cibaCols+` FROM ciba_requests WHERE id=?`, id))
}

func (s *Store) GetCIBARequestByCallback(ctx context.Context, callbackID string) (*model.CIBARequest, error) {
	return scanCIBA(s.q.QueryRowContext(ctx, `SELECT `+cibaCols+` FROM ciba_requests WHERE callback_id=?`, callbackID))
}

func (s *Store) UpdateCIBARequest(ctx context.Context, c *model.CIBARequest) error {
	return s.execOne(ctx, `UPDATE ciba_requests SET callback_id=?, status=?, session_id=?, last_poll=? WHERE id=?`,
		c.CallbackID, c.Status, c.SessionID, c.LastPoll, c.ID)
}

// DeleteCIBARequest removes a used request; ErrNotFound when already used.
func (s *Store) DeleteCIBARequest(ctx context.Context, id string) error {
	return s.execOne(ctx, `DELETE FROM ciba_requests WHERE id=?`, id)
}
