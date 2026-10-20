package service

import (
	"context"
	"errors"

	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/store"
)

// Token types, as written in the "typ" claim.
const (
	TokenBearer  = "Bearer"
	TokenID      = "ID"
	TokenRefresh = "Refresh"
	TokenOffline = "Offline"
	TokenCookie  = "Serialized-ID"
)

// LightweightAccessToken is the client attribute making access tokens
// lightweight: only the core claims and the mappers marked for them
// (lightweight.claim), the rest being available through introspection.
const LightweightAccessToken = "client.use.lightweight.access.token.enabled"

// ErrInvalidToken is returned by VerifyToken for any token that is not
// currently acceptable.
var ErrInvalidToken = errors.New("invalid token")

// VerifiedToken is a token that passed VerifyToken.
type VerifiedToken struct {
	Claims  jwt.Claims
	User    *model.User        // nil if the token has no subject
	Session *model.UserSession // nil for session-less tokens (client credentials)
}

// VerifyToken checks signature, issuer, type, expiry, not-before policies
// and revocation of a token issued by realm, and that its user and session
// are still valid. typs lists the accepted "typ" values (any when empty).
func (s *Service) VerifyToken(ctx context.Context, realm *model.Realm, token, issuer string, typs ...string) (*VerifiedToken, error) {
	claims, err := jwt.Verify(token, func(kid, alg string) *jwt.Key { return s.VerificationKey(ctx, realm.ID, kid, alg) })
	if err != nil {
		return nil, ErrInvalidToken
	}
	typ := claims.String("typ")
	if len(typs) > 0 {
		ok := false
		for _, t := range typs {
			ok = ok || t == typ
		}
		if !ok {
			return nil, ErrInvalidToken
		}
	}
	now := s.Now().Unix()
	if claims.String("iss") != issuer {
		return nil, ErrInvalidToken
	}
	// Offline tokens have no expiry unless the realm sets a max lifespan.
	if _, hasExp := claims["exp"]; hasExp || typ != TokenOffline {
		if claims.Int("exp") < now {
			return nil, ErrInvalidToken
		}
	}
	iat := claims.Int("iat")
	if iat < realm.Settings.NotBefore {
		return nil, ErrInvalidToken
	}
	if azp := claims.String("azp"); azp != "" {
		if c, err := s.Store.GetClientByClientID(ctx, realm.ID, azp); err == nil && iat < c.NotBefore {
			return nil, ErrInvalidToken
		}
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
		if !u.Enabled || (u.NotBefore > 0 && iat < u.NotBefore) {
			return nil, ErrInvalidToken
		}
		vt.User = u
	}
	if sid := claims.String("sid"); sid != "" {
		us, err := s.tokenSession(ctx, sid, typ)
		if err != nil {
			return nil, err
		}
		if us == nil || us.RealmID != realm.ID || !s.SessionValid(realm, us) {
			return nil, ErrInvalidToken
		}
		vt.Session = us
	}
	if vt.User == nil && vt.Session != nil && typ != TokenCookie {
		// lightweight access tokens have no subject: the session tells the user
		u, err := s.Store.GetUser(ctx, realm.ID, vt.Session.UserID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, ErrInvalidToken
			}
			return nil, err
		}
		if !u.Enabled || (u.NotBefore > 0 && iat < u.NotBefore) {
			return nil, ErrInvalidToken
		}
		vt.User = u
	}
	return vt, nil
}

// tokenSession finds the session a token belongs to: offline tokens use
// offline sessions, cookies online ones, and access/ID tokens either.
func (s *Service) tokenSession(ctx context.Context, sid, typ string) (*model.UserSession, error) {
	order := []bool{false, true}
	switch typ {
	case TokenOffline:
		order = []bool{true}
	case TokenRefresh, TokenCookie:
		order = []bool{false}
	}
	for _, offline := range order {
		us, err := s.Store.GetSession(ctx, sid, offline)
		if err == nil {
			return us, nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	return nil, nil
}
