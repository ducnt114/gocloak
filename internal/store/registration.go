package store

import (
	"context"

	"github.com/ducnt114/gocloak/internal/model"
)

const iatCols = `id, realm_id, created_at, expiration, total, remaining`

func scanIAT(sc scanner) (*model.InitialAccessToken, error) {
	t := &model.InitialAccessToken{}
	if err := sc.Scan(&t.ID, &t.RealmID, &t.Created, &t.Expiration, &t.Count, &t.Remaining); err != nil {
		return nil, mapErr(err)
	}
	return t, nil
}

func (s *Store) CreateInitialAccessToken(ctx context.Context, t *model.InitialAccessToken) error {
	return s.exec(ctx, `INSERT INTO client_initial_access (`+iatCols+`) VALUES (?,?,?,?,?,?)`,
		t.ID, t.RealmID, t.Created, t.Expiration, t.Count, t.Remaining)
}

func (s *Store) GetInitialAccessToken(ctx context.Context, realmID, id string) (*model.InitialAccessToken, error) {
	return scanIAT(s.q.QueryRowContext(ctx, `SELECT `+iatCols+` FROM client_initial_access WHERE realm_id=? AND id=?`, realmID, id))
}

func (s *Store) ListInitialAccessTokens(ctx context.Context, realmID string) ([]*model.InitialAccessToken, error) {
	return queryList(ctx, s, scanIAT, `SELECT `+iatCols+` FROM client_initial_access WHERE realm_id=? ORDER BY created_at, id`, realmID)
}

func (s *Store) DeleteInitialAccessToken(ctx context.Context, realmID, id string) error {
	return s.execOne(ctx, `DELETE FROM client_initial_access WHERE realm_id=? AND id=?`, realmID, id)
}

// UseInitialAccessToken takes one use of a token; ErrNotFound when none is left.
func (s *Store) UseInitialAccessToken(ctx context.Context, realmID, id string) error {
	return s.execOne(ctx, `UPDATE client_initial_access SET remaining=remaining-1 WHERE realm_id=? AND id=? AND remaining>0`, realmID, id)
}

// RegistrationTokenID returns the id of the current registration access
// token of a client ("" without one).
func (s *Store) RegistrationTokenID(ctx context.Context, clientID string) (string, error) {
	var id string
	err := s.q.QueryRowContext(ctx, `SELECT token_id FROM client_registration_tokens WHERE client_id=?`, clientID).Scan(&id)
	if err != nil {
		if err = mapErr(err); err == ErrNotFound {
			return "", nil
		}
		return "", err
	}
	return id, nil
}

// SetRegistrationTokenID records the current registration access token.
func (s *Store) SetRegistrationTokenID(ctx context.Context, clientID, tokenID string) error {
	return s.WithTx(ctx, func(tx *Store) error {
		if err := tx.exec(ctx, `DELETE FROM client_registration_tokens WHERE client_id=?`, clientID); err != nil {
			return err
		}
		return tx.exec(ctx, `INSERT INTO client_registration_tokens (client_id, token_id) VALUES (?,?)`, clientID, tokenID)
	})
}
