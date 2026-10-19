package service

import (
	"context"
	"net/http"
	"strings"

	"github.com/ducnt114/gocloak/internal/dpop"
	"github.com/ducnt114/gocloak/internal/jwt"
)

// AccessToken returns the access token of a request and its authorization
// scheme: "Bearer" or "DPoP" (empty when there is none).
func AccessToken(r *http.Request) (token, scheme string) {
	a := r.Header.Get("Authorization")
	switch {
	case len(a) > 7 && strings.EqualFold(a[:7], "bearer "):
		return strings.TrimSpace(a[7:]), "Bearer"
	case len(a) > 5 && strings.EqualFold(a[:5], "dpop "):
		return strings.TrimSpace(a[5:]), "DPoP"
	}
	return "", ""
}

// CheckDPoP verifies the DPoP proof of a request (none: nil, nil),
// rejecting proofs seen before. token is the access token the request
// presents to a resource, "" at the token endpoint.
func (s *Service) CheckDPoP(ctx context.Context, r *http.Request, requestURL, token string) (*dpop.Proof, error) {
	proofs := r.Header.Values("DPoP")
	switch len(proofs) {
	case 0:
		return nil, nil
	case 1:
	default:
		return nil, &dpop.Error{Msg: "Multiple DPoP headers"}
	}
	p, err := dpop.Verify(proofs[0], r.Method, requestURL, token, s.Now())
	if err != nil {
		return nil, err
	}
	key := "dpop:" + p.JKT + ":" + p.JTI
	used, err := s.Store.IsTokenRevoked(ctx, key)
	if err != nil {
		return nil, err
	}
	if used {
		return nil, &dpop.Error{Msg: "DPoP proof has already been used"}
	}
	if err := s.Store.RevokeToken(ctx, key, p.IAT.Add(dpop.MaxAge+dpop.MaxSkew)); err != nil {
		return nil, err
	}
	return p, nil
}

// BoundKey is the thumbprint a DPoP-bound token is bound to ("" if none).
func BoundKey(claims jwt.Claims) string {
	if cnf, ok := claims["cnf"].(map[string]any); ok {
		if jkt, ok := cnf["jkt"].(string); ok {
			return jkt
		}
	}
	return ""
}

// CheckTokenBinding makes sure a DPoP-bound access token is presented with
// the DPoP scheme and a proof of its key, and that plain tokens are not
// presented as DPoP ones.
func (s *Service) CheckTokenBinding(ctx context.Context, r *http.Request, requestURL, token, scheme string, claims jwt.Claims) error {
	jkt := BoundKey(claims)
	if jkt == "" {
		if scheme == "DPoP" {
			return &dpop.Error{Msg: "Token is not DPoP bound"}
		}
		return nil
	}
	if scheme != "DPoP" {
		return &dpop.Error{Msg: "DPoP-bound token used as a bearer token"}
	}
	p, err := s.CheckDPoP(ctx, r, requestURL, token)
	if err != nil {
		return err
	}
	if p == nil || p.JKT != jkt {
		return &dpop.Error{Msg: "DPoP proof and token binding verification failed"}
	}
	return nil
}
