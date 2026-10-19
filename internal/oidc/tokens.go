package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
)

func hasScope(scope, s string) bool {
	for _, x := range strings.Fields(scope) {
		if x == s {
			return true
		}
	}
	return false
}

// tokenResponse is the JSON returned by the token endpoint.
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	TokenType        string `json:"token_type"`
	IDToken          string `json:"id_token,omitempty"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state,omitempty"`
	Scope            string `json:"scope"`
}

// issueRequest gathers everything needed to mint tokens.
type issueRequest struct {
	realm   *model.Realm
	client  *model.Client
	user    *model.User
	session *model.UserSession // nil for client credentials
	scope   string             // requested scope parameter
	strict  bool               // reject unknown scopes (invalid_scope)
	nonce   string
	refresh bool
}

func atHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func allowedOrigins(base string, c *model.Client) []string {
	var out []string
	for _, o := range c.WebOrigins {
		if o == "+" {
			for _, ru := range c.RedirectURIs {
				if or := originOf(resolveURI(base, c, ru)); or != "" {
					out = append(out, or)
				}
			}
			continue
		}
		out = append(out, o)
	}
	return out
}

// issue mints the access, ID and refresh tokens. Claims beyond the core
// ones come from the protocol mappers of the applied client scopes.
func (h *Handler) issue(r *http.Request, ir *issueRequest) (*tokenResponse, error) {
	ctx := r.Context()
	base := h.URLs.Base(r)
	tc, scope, err := newTokenContext(ctx, h.Svc, base, ir.realm, ir.client, ir.user, ir.session, ir.scope, ir.strict)
	if err != nil {
		var se *scopeError
		if errors.As(err, &se) {
			return nil, &oauthError{http.StatusBadRequest, "invalid_scope", se.Error()}
		}
		return nil, err
	}
	if ir.session == nil {
		ip := clientIP(r)
		tc.notes["client_id"], tc.notes["clientHost"], tc.notes["clientAddress"] = ir.client.ClientID, ip, ip
	}
	kid, key, err := h.Svc.SigningKey(ctx, ir.realm.ID)
	if err != nil {
		return nil, err
	}
	now := h.Svc.Now()
	iss := h.URLs.Issuer(r, ir.realm.Name)
	exp := now.Add(time.Duration(ir.realm.AccessTokenLifespan) * time.Second)
	if ir.session != nil {
		// An access token never outlives its SSO session.
		if max := ir.session.Started.Add(time.Duration(ir.realm.SSOSessionMaxLifespan) * time.Second); exp.After(max) {
			exp = max
		}
	}

	at := jwt.Claims{
		"exp": exp.Unix(), "iat": now.Unix(), "jti": service.NewID(), "iss": iss,
		"sub": ir.user.ID, "typ": service.TokenBearer, "azp": ir.client.ClientID, "scope": scope,
	}
	if ir.session != nil {
		at["sid"] = ir.session.ID
	}
	if err := tc.apply(ctx, at, kindAccess); err != nil {
		return nil, err
	}
	access, err := jwt.Sign(at, kid, key)
	if err != nil {
		return nil, err
	}
	resp := &tokenResponse{
		AccessToken: access, ExpiresIn: int(exp.Sub(now).Seconds()), TokenType: "Bearer", Scope: scope,
	}

	if hasScope(scope, "openid") {
		idc := jwt.Claims{
			"exp": exp.Unix(), "iat": now.Unix(), "jti": service.NewID(), "iss": iss,
			"aud": ir.client.ClientID, "sub": ir.user.ID, "typ": service.TokenID, "azp": ir.client.ClientID,
			"at_hash": atHash(access),
		}
		if ir.nonce != "" {
			idc["nonce"] = ir.nonce
		}
		if ir.session != nil {
			idc["sid"] = ir.session.ID
		}
		if err := tc.apply(ctx, idc, kindID); err != nil {
			return nil, err
		}
		if resp.IDToken, err = jwt.Sign(idc, kid, key); err != nil {
			return nil, err
		}
	}

	if ir.refresh && ir.session != nil {
		rexp := now.Add(time.Duration(ir.realm.SSOSessionIdleTimeout) * time.Second)
		if max := ir.session.Started.Add(time.Duration(ir.realm.SSOSessionMaxLifespan) * time.Second); rexp.After(max) {
			rexp = max
		}
		rc := jwt.Claims{
			"exp": rexp.Unix(), "iat": now.Unix(), "jti": service.NewID(), "iss": iss, "aud": iss,
			"sub": ir.user.ID, "typ": service.TokenRefresh, "azp": ir.client.ClientID, "sid": ir.session.ID,
			"scope": scope,
		}
		if ir.nonce != "" {
			rc["nonce"] = ir.nonce
		}
		if resp.RefreshToken, err = jwt.Sign(rc, kid, key); err != nil {
			return nil, err
		}
		resp.RefreshExpiresIn = int(rexp.Sub(now).Seconds())
		resp.SessionState = ir.session.ID
	}
	return resp, nil
}

func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}
