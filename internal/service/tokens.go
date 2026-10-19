package service

import (
	"context"
	"crypto/rsa"
	"errors"

	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/store"
)

// Token types, as written in the "typ" claim by Keycloak.
const (
	TokenBearer  = "Bearer"
	TokenID      = "ID"
	TokenRefresh = "Refresh"
	TokenCookie  = "Serialized-ID"
)

// ErrInvalidToken is returned by VerifyToken for any token that is not
// currently acceptable.
var ErrInvalidToken = errors.New("invalid token")

// VerifiedToken is a token that passed VerifyToken.
type VerifiedToken struct {
	Claims  jwt.Claims
	User    *model.User        // nil if the subject no longer exists
	Session *model.UserSession // nil for session-less tokens (client credentials)
}

// VerifyToken checks signature, issuer, type, expiry and revocation of a
// token issued by realm, and that its user and SSO session are still valid.
func (s *Service) VerifyToken(ctx context.Context, realm *model.Realm, token, issuer, typ string) (*VerifiedToken, error) {
	keys, err := s.PublicKeys(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	claims, err := jwt.Verify(token, func(kid string) *rsa.PublicKey { return keys[kid] })
	if err != nil {
		return nil, ErrInvalidToken
	}
	now := s.Now().Unix()
	if claims.String("iss") != issuer || claims.Int("exp") < now {
		return nil, ErrInvalidToken
	}
	if typ != "" && claims.String("typ") != typ {
		return nil, ErrInvalidToken
	}
	if jti := claims.String("jti"); jti != "" {
		revoked, err := s.Store.IsTokenRevoked(ctx, jti)
		if err != nil {
			return nil, err
		}
		if revoked {
			return nil, ErrInvalidToken
		}
	}
	vt := &VerifiedToken{Claims: claims}
	if sub := claims.String("sub"); sub != "" {
		u, err := s.Store.GetUser(ctx, realm.ID, sub)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, ErrInvalidToken
			}
			return nil, err
		}
		if !u.Enabled || (u.NotBefore > 0 && claims.Int("iat") < u.NotBefore) {
			return nil, ErrInvalidToken
		}
		vt.User = u
	}
	if sid := claims.String("sid"); sid != "" {
		us, err := s.Store.GetUserSession(ctx, sid)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, ErrInvalidToken
			}
			return nil, err
		}
		if us.RealmID != realm.ID || !s.SessionValid(realm, us) {
			return nil, ErrInvalidToken
		}
		vt.Session = us
	}
	return vt, nil
}
