package store

import (
	"context"
	"strings"

	"github.com/ducnt114/gocloak/internal/model"
)

const userCols = `id, realm_id, username, email, email_verified, first_name, last_name, enabled,
	created_timestamp, attributes, required_actions, service_account_client_id, not_before, federation_link`

func scanUser(sc scanner) (*model.User, error) {
	u := &model.User{Attributes: map[string][]string{}}
	err := sc.Scan(&u.ID, &u.RealmID, &u.Username, &u.Email, &u.EmailVerified, &u.FirstName, &u.LastName,
		&u.Enabled, &u.CreatedTimestamp, jsonCol{&u.Attributes}, jsonCol{&u.RequiredActions},
		&u.ServiceAccountClientID, &u.NotBefore, &u.FederationLink)
	if err != nil {
		return nil, mapErr(err)
	}
	return u, nil
}

func userArgs(u *model.User) []any {
	if u.Attributes == nil {
		u.Attributes = map[string][]string{}
	}
	if u.RequiredActions == nil {
		u.RequiredActions = []string{}
	}
	return []any{u.Username, u.Email, u.EmailVerified, u.FirstName, u.LastName, u.Enabled,
		u.CreatedTimestamp, toJSON(u.Attributes), toJSON(u.RequiredActions), u.ServiceAccountClientID, u.NotBefore, u.FederationLink}
}

func (s *Store) CreateUser(ctx context.Context, u *model.User) error {
	args := append([]any{u.ID, u.RealmID}, userArgs(u)...)
	return s.WithTx(ctx, func(tx *Store) error {
		if err := tx.exec(ctx, `INSERT INTO users (`+userCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, args...); err != nil {
			return err
		}
		return tx.indexUserAttributes(ctx, u)
	})
}

func (s *Store) UpdateUser(ctx context.Context, u *model.User) error {
	args := append(userArgs(u), u.ID)
	return s.WithTx(ctx, func(tx *Store) error {
		if err := tx.execOne(ctx, `UPDATE users SET username=?, email=?, email_verified=?, first_name=?, last_name=?,
			enabled=?, created_timestamp=?, attributes=?, required_actions=?, service_account_client_id=?, not_before=?,
			federation_link=? WHERE id=?`, args...); err != nil {
			return err
		}
		return tx.indexUserAttributes(ctx, u)
	})
}

func (s *Store) DeleteUser(ctx context.Context, realmID, id string) error {
	return s.execOne(ctx, `DELETE FROM users WHERE realm_id=? AND id=?`, realmID, id)
}

func (s *Store) GetUser(ctx context.Context, realmID, id string) (*model.User, error) {
	return scanUser(s.q.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE realm_id=? AND id=?`, realmID, id))
}

func (s *Store) GetUserByUsername(ctx context.Context, realmID, username string) (*model.User, error) {
	return scanUser(s.q.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE realm_id=? AND username=?`,
		realmID, strings.ToLower(username)))
}

// GetUserByEmail returns the first user with the given email (case-insensitive).
func (s *Store) GetUserByEmail(ctx context.Context, realmID, email string) (*model.User, error) {
	return scanUser(s.q.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE realm_id=? AND email=? ORDER BY created_timestamp LIMIT 1`,
		realmID, strings.ToLower(email)))
}

func (s *Store) GetServiceAccountUser(ctx context.Context, clientUUID string) (*model.User, error) {
	return scanUser(s.q.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE service_account_client_id=?`, clientUUID))
}

// ListAllUsers returns every user of a realm, service accounts included.
func (s *Store) ListAllUsers(ctx context.Context, realmID string) ([]*model.User, error) {
	return queryList(ctx, s, scanUser, `SELECT `+userCols+` FROM users WHERE realm_id=? ORDER BY username`, realmID)
}

// UserQuery mirrors the query parameters of GET /admin/realms/{realm}/users.
type UserQuery struct {
	Search    string
	Username  string
	Email     string
	FirstName string
	LastName  string
	Enabled   *bool
	// Attributes requires exact attribute values (the "q" parameter).
	Attributes map[string]string
	IdPAlias   string // linked to this identity provider
	IdPUserID  string // with this user id at the provider
	Exact      bool
	First      int
	Max        int
}

func (q UserQuery) where(realmID string) (string, []any) {
	// Service account users are hidden from user listings.
	w := ` WHERE realm_id=? AND service_account_client_id=''`
	args := []any{realmID}
	if q.Search != "" {
		s := strings.ToLower(strings.Trim(q.Search, "*"))
		if q.Exact {
			w += ` AND (username=? OR email=? OR lower(first_name)=? OR lower(last_name)=?)`
			args = append(args, s, s, s, s)
		} else {
			p := "%" + likeEscape(s) + "%"
			w += ` AND (username LIKE ? ESCAPE '\' OR email LIKE ? ESCAPE '\' OR lower(first_name) LIKE ? ESCAPE '\' OR lower(last_name) LIKE ? ESCAPE '\')`
			args = append(args, p, p, p, p)
		}
	}
	add := func(col, v string) {
		if v == "" {
			return
		}
		v = strings.ToLower(v)
		if q.Exact {
			w += ` AND lower(` + col + `)=?`
			args = append(args, v)
		} else {
			w += ` AND lower(` + col + `) LIKE ? ESCAPE '\'`
			args = append(args, "%"+likeEscape(v)+"%")
		}
	}
	add("username", q.Username)
	add("email", q.Email)
	add("first_name", q.FirstName)
	add("last_name", q.LastName)
	if q.Enabled != nil {
		w += ` AND enabled=?`
		args = append(args, *q.Enabled)
	}
	for name, value := range q.Attributes {
		w += ` AND EXISTS (SELECT 1 FROM user_attributes ua WHERE ua.user_id=users.id AND ua.name=? AND ua.value=?)`
		args = append(args, name, value)
	}
	if q.IdPAlias != "" || q.IdPUserID != "" {
		w += ` AND EXISTS (SELECT 1 FROM federated_identities fi WHERE fi.user_id=users.id`
		if q.IdPAlias != "" {
			w += ` AND fi.identity_provider=?`
			args = append(args, q.IdPAlias)
		}
		if q.IdPUserID != "" {
			w += ` AND fi.federated_user_id=?`
			args = append(args, q.IdPUserID)
		}
		w += `)`
	}
	return w, args
}

func (s *Store) SearchUsers(ctx context.Context, realmID string, q UserQuery) ([]*model.User, error) {
	w, args := q.where(realmID)
	args = append(args, limit(q.Max), q.First)
	return queryList(ctx, s, scanUser, `SELECT `+userCols+` FROM users`+w+` ORDER BY username LIMIT ? OFFSET ?`, args...)
}

func (s *Store) CountUsers(ctx context.Context, realmID string, q UserQuery) (int, error) {
	w, args := q.where(realmID)
	var n int
	err := s.q.QueryRowContext(ctx, `SELECT count(*) FROM users`+w, args...).Scan(&n)
	return n, err
}

// ---- credentials ----

func (s *Store) CreateCredential(ctx context.Context, c *model.Credential) error {
	return s.exec(ctx, `INSERT INTO credentials (id, user_id, type, user_label, secret_data, credential_data, created_date, priority)
		VALUES (?,?,?,?,?,?,?,?)`, c.ID, c.UserID, c.Type, c.UserLabel, c.SecretData, c.CredentialData, c.CreatedDate, c.Priority)
}

func (s *Store) ListCredentials(ctx context.Context, userID string) ([]*model.Credential, error) {
	return queryList(ctx, s, func(sc scanner) (*model.Credential, error) {
		c := &model.Credential{}
		err := sc.Scan(&c.ID, &c.UserID, &c.Type, &c.UserLabel, &c.SecretData, &c.CredentialData, &c.CreatedDate, &c.Priority)
		return c, err
	}, `SELECT id, user_id, type, user_label, secret_data, credential_data, created_date, priority
		FROM credentials WHERE user_id=? ORDER BY priority, created_date`, userID)
}

func (s *Store) UpdateCredentialSecret(ctx context.Context, id, secretData, credentialData string) error {
	return s.execOne(ctx, `UPDATE credentials SET secret_data=?, credential_data=? WHERE id=?`, secretData, credentialData, id)
}

func (s *Store) UpdateCredentialLabel(ctx context.Context, userID, id, label string) error {
	return s.execOne(ctx, `UPDATE credentials SET user_label=? WHERE user_id=? AND id=?`, label, userID, id)
}

func (s *Store) DeleteCredential(ctx context.Context, userID, id string) error {
	return s.execOne(ctx, `DELETE FROM credentials WHERE user_id=? AND id=?`, userID, id)
}

func (s *Store) DeleteCredentialsOfType(ctx context.Context, userID, typ string) error {
	return s.exec(ctx, `DELETE FROM credentials WHERE user_id=? AND type=?`, userID, typ)
}

// ListFederatedUsers lists the users imported from a user storage component.
func (s *Store) ListFederatedUsers(ctx context.Context, realmID, componentID string) ([]*model.User, error) {
	return queryList(ctx, s, scanUser, `SELECT `+userCols+` FROM users WHERE realm_id=? AND federation_link=? ORDER BY username`, realmID, componentID)
}

// FindUserByAttribute returns the user with an attribute value (e.g. LDAP_ID).
func (s *Store) FindUserByAttribute(ctx context.Context, realmID, name, value string) (*model.User, error) {
	return scanUser(s.q.QueryRowContext(ctx, `SELECT `+prefixed("users", userCols)+` FROM users
		JOIN user_attributes ua ON ua.user_id=users.id WHERE users.realm_id=? AND ua.name=? AND ua.value=? LIMIT 1`, realmID, name, value))
}
