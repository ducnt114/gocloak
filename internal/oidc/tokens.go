package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/dpop"
	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
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
	IssuedTokenType  string `json:"issued_token_type,omitempty"` // token exchange

	accessJTI, refreshJTI, refreshTyp string // for events
}

// eventDetails adds the token ids Keycloak records in login events.
func (t *tokenResponse) eventDetails(ev *eventInfo) {
	ev.details["token_id"] = t.accessJTI
	ev.details["refresh_token_id"] = t.refreshJTI
	ev.details["refresh_token_type"] = t.refreshTyp
	ev.details["scope"] = t.Scope
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
	extra   jwt.Claims // claims added to the access token (RPT permissions)
	// audience restricts the "aud" of the access token (token exchange);
	// each value must be an audience the token would have anyway.
	audience []string
}

// errAudience reports a requested audience the token cannot have.
type errAudience struct{ aud string }

func (e *errAudience) Error() string { return "Requested audience not available: " + e.aud }

// atHash is the left half of the access token's hash, using the hash of
// the ID token's signature algorithm.
func atHash(token, alg string) string {
	var sum []byte
	switch alg[len(alg)-3:] {
	case "384":
		s := sha512.Sum384([]byte(token))
		sum = s[:]
	case "512":
		s := sha512.Sum512([]byte(token))
		sum = s[:]
	default:
		s := sha256.Sum256([]byte(token))
		sum = s[:]
	}
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
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
	accessKey, err := h.Svc.SigningKey(ctx, ir.realm, ir.client.Attributes["access.token.signed.response.alg"])
	if err != nil {
		return nil, err
	}
	now := h.Svc.Now()
	iss := h.URLs.Issuer(r, ir.realm.Name)
	exp := now.Add(time.Duration(ir.realm.AccessTokenLifespan) * time.Second)
	if ir.session != nil && !ir.session.Offline {
		// An access token never outlives its SSO session.
		if max := ir.session.Started.Add(time.Duration(ir.realm.SSOSessionMaxLifespan) * time.Second); exp.After(max) {
			exp = max
		}
	}

	// offline_access turns the refresh token into an offline token, backed
	// by an offline session that survives logout.
	session := ir.session
	offline := ir.refresh && session != nil && (session.Offline || hasScope(scope, "offline_access"))
	if offline && !session.Offline {
		if !slices.Contains(tc.realmRoles, service.OfflineAccessRole) {
			return nil, &oauthError{http.StatusBadRequest, "not_allowed", "Offline tokens not allowed for the user or client"}
		}
		if session, err = h.offlineSession(ctx, session, ir.client); err != nil {
			return nil, err
		}
	}

	at := jwt.Claims{
		"exp": exp.Unix(), "iat": now.Unix(), "jti": service.NewID(), "iss": iss,
		"sub": ir.user.ID, "typ": service.TokenBearer, "azp": ir.client.ClientID, "scope": scope,
	}
	if ir.session != nil {
		at["sid"] = ir.session.ID
	}
	proof := dpopProof(r)
	if proof != nil {
		at["cnf"] = map[string]any{"jkt": proof.JKT}
	}
	kind := kindAccess
	if ir.client.Attributes[service.LightweightAccessToken] == "true" && ir.session != nil {
		// a lightweight token: the user is found through its session
		delete(at, "sub")
		kind = kindLightweight
	}
	if err := tc.apply(ctx, at, kind); err != nil {
		return nil, err
	}
	if len(ir.audience) > 0 {
		have := at.Audience()
		for _, a := range ir.audience {
			if !slices.Contains(have, a) && a != ir.client.ClientID {
				return nil, &errAudience{a}
			}
		}
		at["aud"] = append([]string{}, ir.audience...)
		finalizeAudience(at)
	}
	for k, v := range ir.extra {
		at[k] = v
	}
	access, err := jwt.Sign(at, accessKey)
	if err != nil {
		return nil, err
	}
	tokenType := "Bearer"
	if proof != nil {
		tokenType = "DPoP"
	}
	resp := &tokenResponse{
		AccessToken: access, ExpiresIn: int(exp.Sub(now).Seconds()), TokenType: tokenType, Scope: scope,
		NotBeforePolicy: int(ir.realm.Settings.NotBefore), accessJTI: at.String("jti"),
	}

	if hasScope(scope, "openid") {
		idKey, err := h.Svc.SigningKey(ctx, ir.realm, ir.client.Attributes["id.token.signed.response.alg"])
		if err != nil {
			return nil, err
		}
		idc := jwt.Claims{
			"exp": exp.Unix(), "iat": now.Unix(), "jti": service.NewID(), "iss": iss,
			"aud": ir.client.ClientID, "sub": ir.user.ID, "typ": service.TokenID, "azp": ir.client.ClientID,
			"at_hash": atHash(access, idKey.Alg),
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
		if resp.IDToken, err = jwt.Sign(idc, idKey); err != nil {
			return nil, err
		}
	}

	if ir.refresh && session != nil {
		refreshKey, err := h.Svc.SigningKey(ctx, ir.realm, "HS512")
		if err != nil {
			return nil, err
		}
		rc := jwt.Claims{
			"iat": now.Unix(), "jti": service.NewID(), "iss": iss, "aud": iss,
			"sub": ir.user.ID, "typ": service.TokenRefresh, "azp": ir.client.ClientID, "sid": session.ID,
			"scope": tc.allScopes(hasScope(scope, "openid")),
		}
		if ir.realm.Settings.RevokeRefreshToken {
			rc["reuse_id"] = service.NewID()
		}
		if proof != nil && ir.client.PublicClient {
			// public clients cannot authenticate: their refresh tokens are bound
			rc["cnf"] = map[string]any{"jkt": proof.JKT}
		}
		if offline {
			rc["typ"] = service.TokenOffline
			if ir.realm.Settings.OfflineSessionMaxLifespanEnabled {
				rexp := session.Started.Add(time.Duration(ir.realm.Settings.OfflineSessionMaxLifespan) * time.Second)
				rc["exp"] = rexp.Unix()
				resp.RefreshExpiresIn = int(rexp.Sub(now).Seconds())
			}
		} else {
			rexp := now.Add(time.Duration(ir.realm.SSOSessionIdleTimeout) * time.Second)
			if max := session.Started.Add(time.Duration(ir.realm.SSOSessionMaxLifespan) * time.Second); rexp.After(max) {
				rexp = max
			}
			rc["exp"] = rexp.Unix()
			resp.RefreshExpiresIn = int(rexp.Sub(now).Seconds())
		}
		if ir.nonce != "" {
			rc["nonce"] = ir.nonce
		}
		if resp.RefreshToken, err = jwt.Sign(rc, refreshKey); err != nil {
			return nil, err
		}
		resp.SessionState = session.ID
		resp.refreshJTI, resp.refreshTyp = rc.String("jti"), rc.String("typ")
	}
	return resp, nil
}

// attrDPoPBound requires DPoP proofs at the token endpoint.
const attrDPoPBound = "dpop.bound.access.tokens"

type dpopProofKey struct{}

// dpopProof is the verified DPoP proof of a token request, if any.
func dpopProof(r *http.Request) *dpop.Proof {
	p, _ := r.Context().Value(dpopProofKey{}).(*dpop.Proof)
	return p
}

// offlineSession returns the offline copy of an SSO session (same id, as
// in Keycloak), creating it or attaching client to it.
func (h *Handler) offlineSession(ctx context.Context, us *model.UserSession, client *model.Client) (*model.UserSession, error) {
	off, err := h.Svc.Store.GetSession(ctx, us.ID, true)
	switch {
	case errors.Is(err, store.ErrNotFound):
		off = &model.UserSession{ID: us.ID, RealmID: us.RealmID, UserID: us.UserID, IPAddress: us.IPAddress,
			Started: h.Svc.Now(), LastRefresh: h.Svc.Now(), Clients: map[string]bool{client.ID: true}, Notes: map[string]string{}, Offline: true}
		for k, v := range us.Notes {
			off.Notes[k] = v
		}
		return off, h.Svc.Store.CreateUserSession(ctx, off)
	case err != nil:
		return nil, err
	}
	if !off.Clients[client.ID] {
		off.Clients[client.ID] = true
		off.LastRefresh = h.Svc.Now()
		if err := h.Svc.Store.UpdateUserSession(ctx, off); err != nil {
			return nil, err
		}
	}
	return off, nil
}

func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}
