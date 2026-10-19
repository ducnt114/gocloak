package store

import (
	"context"

	"github.com/ducnt114/gocloak/internal/model"
)

const consentCols = `user_id, client_id, scopes, created_at, updated_at`

func scanConsent(sc scanner) (*model.UserConsent, error) {
	c := &model.UserConsent{}
	if err := sc.Scan(&c.UserID, &c.ClientID, jsonCol{&c.Scopes}, &c.Created, &c.Updated); err != nil {
		return nil, mapErr(err)
	}
	return c, nil
}

// GetConsent returns what a user granted a client.
func (s *Store) GetConsent(ctx context.Context, userID, clientID string) (*model.UserConsent, error) {
	return scanConsent(s.q.QueryRowContext(ctx, `SELECT `+consentCols+` FROM user_consents WHERE user_id=? AND client_id=?`, userID, clientID))
}

// ListConsents lists the consents of a user.
func (s *Store) ListConsents(ctx context.Context, userID string) ([]*model.UserConsent, error) {
	return queryList(ctx, s, scanConsent, `SELECT `+consentCols+` FROM user_consents WHERE user_id=? ORDER BY created_at`, userID)
}

// SaveConsent creates or replaces a consent.
func (s *Store) SaveConsent(ctx context.Context, realmID string, c *model.UserConsent) error {
	if c.Scopes == nil {
		c.Scopes = []string{}
	}
	return s.WithTx(ctx, func(tx *Store) error {
		if err := tx.exec(ctx, `DELETE FROM user_consents WHERE user_id=? AND client_id=?`, c.UserID, c.ClientID); err != nil {
			return err
		}
		return tx.exec(ctx, `INSERT INTO user_consents (realm_id, `+consentCols+`) VALUES (?,?,?,?,?,?)`,
			realmID, c.UserID, c.ClientID, toJSON(c.Scopes), c.Created, c.Updated)
	})
}

// DeleteConsent removes a consent; ErrNotFound when there was none.
func (s *Store) DeleteConsent(ctx context.Context, userID, clientID string) error {
	return s.execOne(ctx, `DELETE FROM user_consents WHERE user_id=? AND client_id=?`, userID, clientID)
}
