package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
)

// Scopes that are always granted (Keycloak's default client scopes that
// show up in the "scope" claim) and the optional ones a client may request.
var (
	defaultScopes  = []string{"profile", "email"}
	optionalScopes = map[string]bool{"address": true, "phone": true, "offline_access": true, "microprofile-jwt": true}
)

// grantedScope computes the scope string of issued tokens.
func grantedScope(requested string) string {
	set := map[string]bool{}
	var out []string
	add := func(s string) {
		if !set[s] {
			set[s] = true
			out = append(out, s)
		}
	}
	req := strings.Fields(requested)
	for _, s := range req {
		if s == "openid" {
			add(s)
		}
	}
	for _, s := range defaultScopes {
		add(s)
	}
	for _, s := range req {
		if optionalScopes[s] {
			add(s)
		}
	}
	return strings.Join(out, " ")
}

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
	scope   string             // already granted scope
	nonce   string
	refresh bool
}

// userClaims adds the profile and email claims of the default scopes.
func userClaims(c jwt.Claims, u *model.User) {
	c["preferred_username"] = u.Username
	if name := strings.TrimSpace(u.FirstName + " " + u.LastName); name != "" {
		c["name"] = name
	}
	if u.FirstName != "" {
		c["given_name"] = u.FirstName
	}
	if u.LastName != "" {
		c["family_name"] = u.LastName
	}
	if u.Email != "" {
		c["email"] = u.Email
	}
	c["email_verified"] = u.EmailVerified
}

// roleClaims returns realm_access, resource_access and the audience derived
// from the client roles present in the token.
func (h *Handler) roleClaims(ctx context.Context, ir *issueRequest) (realmAccess map[string]any, resourceAccess map[string]any, aud []string, err error) {
	roles, err := h.Svc.EffectiveRoles(ctx, ir.realm.ID, ir.user.ID)
	if err != nil {
		return nil, nil, nil, err
	}
	clients := map[string]string{} // uuid -> clientId
	var realmRoles []string
	byClient := map[string][]string{}
	for _, r := range roles {
		// Without full scope a client only sees its own roles (Keycloak's
		// scope mappings are not implemented).
		if !ir.client.FullScopeAllowed && r.ClientID != ir.client.ID {
			continue
		}
		if r.ClientID == "" {
			realmRoles = append(realmRoles, r.Name)
			continue
		}
		cid, ok := clients[r.ClientID]
		if !ok {
			c, err := h.Svc.Store.GetClient(ctx, ir.realm.ID, r.ClientID)
			if err != nil {
				return nil, nil, nil, err
			}
			cid = c.ClientID
			clients[r.ClientID] = cid
		}
		byClient[cid] = append(byClient[cid], r.Name)
	}
	if len(realmRoles) > 0 {
		sort.Strings(realmRoles)
		realmAccess = map[string]any{"roles": realmRoles}
	}
	if len(byClient) > 0 {
		resourceAccess = map[string]any{}
		for cid, rs := range byClient {
			sort.Strings(rs)
			resourceAccess[cid] = map[string]any{"roles": rs}
			if cid != ir.client.ClientID {
				aud = append(aud, cid)
			}
		}
		sort.Strings(aud)
	}
	return realmAccess, resourceAccess, aud, nil
}

func audienceClaim(aud []string) any {
	if len(aud) == 1 {
		return aud[0]
	}
	return aud
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

// issue mints the access, ID and refresh tokens.
func (h *Handler) issue(r *http.Request, ir *issueRequest) (*tokenResponse, error) {
	ctx := r.Context()
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

	realmAccess, resourceAccess, aud, err := h.roleClaims(ctx, ir)
	if err != nil {
		return nil, err
	}
	at := jwt.Claims{
		"exp": exp.Unix(), "iat": now.Unix(), "jti": service.NewID(), "iss": iss,
		"sub": ir.user.ID, "typ": service.TokenBearer, "azp": ir.client.ClientID, "scope": ir.scope, "acr": "1",
	}
	if len(aud) > 0 {
		at["aud"] = audienceClaim(aud)
	}
	if realmAccess != nil {
		at["realm_access"] = realmAccess
	}
	if resourceAccess != nil {
		at["resource_access"] = resourceAccess
	}
	if origins := allowedOrigins(h.URLs.Base(r), ir.client); len(origins) > 0 {
		at["allowed-origins"] = origins
	}
	if ir.session != nil {
		at["sid"] = ir.session.ID
		at["auth_time"] = ir.session.Started.Unix()
	} else {
		at["client_id"] = ir.client.ClientID
		at["clientHost"] = clientIP(r)
		at["clientAddress"] = clientIP(r)
	}
	userClaims(at, ir.user)
	access, err := jwt.Sign(at, kid, key)
	if err != nil {
		return nil, err
	}
	resp := &tokenResponse{
		AccessToken: access, ExpiresIn: int(exp.Sub(now).Seconds()), TokenType: "Bearer", Scope: ir.scope,
	}

	if hasScope(ir.scope, "openid") {
		idc := jwt.Claims{
			"exp": exp.Unix(), "iat": now.Unix(), "jti": service.NewID(), "iss": iss,
			"aud": ir.client.ClientID, "sub": ir.user.ID, "typ": service.TokenID, "azp": ir.client.ClientID,
			"at_hash": atHash(access), "acr": "1",
		}
		if ir.nonce != "" {
			idc["nonce"] = ir.nonce
		}
		if ir.session != nil {
			idc["sid"] = ir.session.ID
			idc["auth_time"] = ir.session.Started.Unix()
		}
		userClaims(idc, ir.user)
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
			"scope": ir.scope,
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
