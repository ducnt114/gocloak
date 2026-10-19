package store

import (
	"context"
	"time"

	"github.com/ducnt114/gocloak/internal/model"
)

const deviceCols = `device_code, user_code, realm_id, client_id, scope, nonce, status, user_id, session_id, poll_interval, last_poll, expires_at`

func scanDeviceCode(sc scanner) (*model.DeviceCode, error) {
	d := &model.DeviceCode{}
	var exp int64
	if err := sc.Scan(&d.DeviceCode, &d.UserCode, &d.RealmID, &d.ClientID, &d.Scope, &d.Nonce, &d.Status, &d.UserID,
		&d.SessionID, &d.Interval, &d.LastPoll, &exp); err != nil {
		return nil, mapErr(err)
	}
	d.ExpiresAt = time.Unix(exp, 0)
	return d, nil
}

func (s *Store) CreateDeviceCode(ctx context.Context, d *model.DeviceCode) error {
	return s.exec(ctx, `INSERT INTO device_codes (`+deviceCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, d.DeviceCode, d.UserCode,
		d.RealmID, d.ClientID, d.Scope, d.Nonce, d.Status, d.UserID, d.SessionID, d.Interval, d.LastPoll, d.ExpiresAt.Unix())
}

func (s *Store) GetDeviceCode(ctx context.Context, deviceCode string) (*model.DeviceCode, error) {
	return scanDeviceCode(s.q.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM device_codes WHERE device_code=?`, deviceCode))
}

func (s *Store) GetDeviceCodeByUserCode(ctx context.Context, realmID, userCode string) (*model.DeviceCode, error) {
	return scanDeviceCode(s.q.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM device_codes WHERE realm_id=? AND user_code=?`, realmID, userCode))
}

// UpdateDeviceCode stores the state of a device authorization.
func (s *Store) UpdateDeviceCode(ctx context.Context, d *model.DeviceCode) error {
	return s.execOne(ctx, `UPDATE device_codes SET status=?, user_id=?, session_id=?, last_poll=? WHERE device_code=?`,
		d.Status, d.UserID, d.SessionID, d.LastPoll, d.DeviceCode)
}

// DeleteDeviceCode removes a used device code; ErrNotFound when it was
// already used, which makes it single-use under concurrent requests.
func (s *Store) DeleteDeviceCode(ctx context.Context, deviceCode string) error {
	return s.execOne(ctx, `DELETE FROM device_codes WHERE device_code=?`, deviceCode)
}
