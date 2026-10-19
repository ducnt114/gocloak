package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// ---------------------------------------------------------------- metadata

func (h *Handler) realmInfo(w http.ResponseWriter, r *http.Request) {
	realm, err := h.realm(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	_, key, err := h.Svc.SigningKey(r.Context(), realm.ID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	iss := h.URLs.Issuer(r, realm.Name)
	writeJSON(w, http.StatusOK, map[string]any{
		"realm":             realm.Name,
		"public_key":        jwt.PublicKeyBase64(&key.PublicKey),
		"token-service":     iss + "/protocol/openid-connect",
		"account-service":   iss + "/account",
		"tokens-not-before": 0,
	})
}

func (h *Handler) discovery(w http.ResponseWriter, r *http.Request) {
	realm, err := h.realm(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	iss := h.URLs.Issuer(r, realm.Name)
	p := iss + "/protocol/openid-connect"
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                        iss,
		"authorization_endpoint":                        p + "/auth",
		"token_endpoint":                                p + "/token",
		"introspection_endpoint":                        p + "/token/introspect",
		"userinfo_endpoint":                             p + "/userinfo",
		"end_session_endpoint":                          p + "/logout",
		"revocation_endpoint":                           p + "/revoke",
		"jwks_uri":                                      p + "/certs",
		"frontchannel_logout_session_supported":         false,
		"backchannel_logout_supported":                  false,
		"grant_types_supported":                         []string{"authorization_code", "client_credentials", "password", "refresh_token"},
		"response_types_supported":                      []string{"code"},
		"response_modes_supported":                      []string{"query", "fragment", "form_post"},
		"subject_types_supported":                       []string{"public"},
		"id_token_signing_alg_values_supported":         []string{"RS256"},
		"userinfo_signing_alg_values_supported":         []string{"none"},
		"code_challenge_methods_supported":              []string{"plain", "S256"},
		"token_endpoint_auth_methods_supported":         []string{"client_secret_basic", "client_secret_post"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"revocation_endpoint_auth_methods_supported":    []string{"client_secret_basic", "client_secret_post"},
		"scopes_supported":                              []string{"openid", "profile", "email", "roles", "web-origins", "address", "phone", "offline_access", "microprofile-jwt"},
		"claims_supported":                              []string{"aud", "sub", "iss", "auth_time", "name", "given_name", "family_name", "preferred_username", "email", "email_verified", "acr", "sid"},
		"claims_parameter_supported":                    false,
		"request_parameter_supported":                   false,
		"request_uri_parameter_supported":               false,
		"tls_client_certificate_bound_access_tokens":    false,
	})
}

func (h *Handler) certs(w http.ResponseWriter, r *http.Request) {
	realm, err := h.realm(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	keys, err := h.Svc.PublicKeys(r.Context(), realm.ID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	jwks := make([]jwt.JWK, 0, len(keys))
	for kid, k := range keys {
		jwks = append(jwks, jwt.PublicJWK(kid, k))
	}
	sort.Slice(jwks, func(i, j int) bool { return jwks[i].Kid < jwks[j].Kid })
	writeJSON(w, http.StatusOK, map[string]any{"keys": jwks})
}

// ---------------------------------------------------------------- token

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	resp, err := h.tokenGrant(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) tokenGrant(r *http.Request) (*tokenResponse, error) {
	realm, err := h.realm(r)
	if err != nil {
		return nil, err
	}
	if err := r.ParseForm(); err != nil {
		return nil, errInvalidRequest("Invalid form body")
	}
	grant := r.PostFormValue("grant_type")
	if grant == "" {
		return nil, errInvalidRequest("Missing form parameter: grant_type")
	}
	client, err := h.authenticateClient(r, realm)
	if err != nil {
		return nil, err
	}
	switch grant {
	case "authorization_code":
		return h.grantAuthorizationCode(r, realm, client)
	case "password":
		return h.grantPassword(r, realm, client)
	case "client_credentials":
		return h.grantClientCredentials(r, realm, client)
	case "refresh_token":
		return h.grantRefreshToken(r, realm, client)
	}
	return nil, &oauthError{http.StatusBadRequest, "unsupported_grant_type", "Unsupported grant_type"}
}

func (h *Handler) grantAuthorizationCode(r *http.Request, realm *model.Realm, client *model.Client) (*tokenResponse, error) {
	ctx := r.Context()
	if !client.StandardFlowEnabled {
		return nil, errUnauthorizedClient("Client not allowed to exchange code")
	}
	code := r.PostFormValue("code")
	if code == "" {
		return nil, errInvalidRequest("Missing parameter: code")
	}
	ac, err := h.Svc.Store.ConsumeAuthCode(ctx, code)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errInvalidGrant("Code not valid")
		}
		return nil, err
	}
	if ac.RealmID != realm.ID || ac.ClientID != client.ID {
		return nil, errInvalidGrant("Code not valid")
	}
	if h.Svc.Now().After(ac.ExpiresAt) {
		return nil, errInvalidGrant("Code not valid")
	}
	if ac.RedirectURI != r.PostFormValue("redirect_uri") {
		return nil, errInvalidGrant("Incorrect redirect_uri")
	}
	if err := verifyPKCE(ac, r.PostFormValue("code_verifier")); err != nil {
		return nil, err
	}
	session, err := h.Svc.Store.GetUserSession(ctx, ac.SessionID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errInvalidGrant("Session not active")
		}
		return nil, err
	}
	if !h.Svc.SessionValid(realm, session) {
		return nil, errInvalidGrant("Session not active")
	}
	user, err := h.Svc.Store.GetUser(ctx, realm.ID, ac.UserID)
	if err != nil {
		return nil, errInvalidGrant("User not found")
	}
	if !user.Enabled {
		return nil, errInvalidGrant("User disabled")
	}
	return h.issue(r, &issueRequest{realm: realm, client: client, user: user, session: session,
		scope: ac.Scope, nonce: ac.Nonce, refresh: true})
}

func verifyPKCE(ac *model.AuthCode, verifier string) error {
	if ac.CodeChallenge == "" {
		if verifier != "" {
			return errInvalidGrant("PKCE code verifier specified but challenge not present in authorization")
		}
		return nil
	}
	if verifier == "" {
		return errInvalidGrant("PKCE code verifier not specified")
	}
	if len(verifier) < 43 || len(verifier) > 128 {
		return errInvalidGrant("Invalid code verifier")
	}
	computed := verifier
	if ac.CodeChallengeMethod == "S256" {
		sum := sha256.Sum256([]byte(verifier))
		computed = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	if subtle.ConstantTimeCompare([]byte(computed), []byte(ac.CodeChallenge)) != 1 {
		return errInvalidGrant("PKCE verification failed")
	}
	return nil
}

func (h *Handler) grantPassword(r *http.Request, realm *model.Realm, client *model.Client) (*tokenResponse, error) {
	ctx := r.Context()
	if !client.DirectAccessGrantsEnabled {
		return nil, errUnauthorizedClient("Client not allowed for direct access grants")
	}
	username, pw := r.PostFormValue("username"), r.PostFormValue("password")
	user, err := h.Svc.FindLoginUser(ctx, realm, username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errInvalidGrant("Invalid user credentials")
		}
		return nil, err
	}
	ok, err := h.Svc.CheckPassword(ctx, user, pw)
	if err != nil {
		return nil, err
	}
	if !ok {
		h.Log.Info("login failed", "realm", realm.Name, "username", username, "client", client.ClientID)
		return nil, errInvalidGrant("Invalid user credentials")
	}
	if !user.Enabled {
		return nil, errInvalidGrant("Account disabled")
	}
	if len(user.RequiredActions) > 0 {
		return nil, errInvalidGrant("Account is not fully set up")
	}
	session, err := h.newSession(r, realm, user, client)
	if err != nil {
		return nil, err
	}
	return h.issue(r, &issueRequest{realm: realm, client: client, user: user, session: session,
		scope: grantedScope(r.PostFormValue("scope")), refresh: true})
}

func (h *Handler) grantClientCredentials(r *http.Request, realm *model.Realm, client *model.Client) (*tokenResponse, error) {
	ctx := r.Context()
	if client.PublicClient {
		return nil, errUnauthorizedClient("Public client not allowed to retrieve service account")
	}
	if !client.ServiceAccountsEnabled {
		return nil, errUnauthorizedClient("Client not enabled to retrieve service account")
	}
	user, err := h.Svc.Store.GetServiceAccountUser(ctx, client.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errInvalidRequest("Service account user not found")
		}
		return nil, err
	}
	if !user.Enabled {
		return nil, errInvalidRequest("User disabled")
	}
	return h.issue(r, &issueRequest{realm: realm, client: client, user: user, scope: grantedScope(r.PostFormValue("scope"))})
}

func (h *Handler) grantRefreshToken(r *http.Request, realm *model.Realm, client *model.Client) (*tokenResponse, error) {
	ctx := r.Context()
	raw := r.PostFormValue("refresh_token")
	if raw == "" {
		return nil, errInvalidRequest("Missing parameter: refresh_token")
	}
	vt, err := h.Svc.VerifyToken(ctx, realm, raw, h.URLs.Issuer(r, realm.Name), service.TokenRefresh)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) {
			return nil, errInvalidGrant("Invalid refresh token")
		}
		return nil, err
	}
	if vt.Claims.String("azp") != client.ClientID {
		return nil, errInvalidGrant("Invalid refresh token. Token client and authorized client don't match")
	}
	if vt.Session == nil || vt.User == nil || !vt.Session.Clients[client.ID] {
		return nil, errInvalidGrant("Session not active")
	}
	vt.Session.LastRefresh = h.Svc.Now()
	if err := h.Svc.Store.UpdateUserSession(ctx, vt.Session); err != nil {
		return nil, err
	}
	return h.issue(r, &issueRequest{realm: realm, client: client, user: vt.User, session: vt.Session,
		scope: vt.Claims.String("scope"), nonce: vt.Claims.String("nonce"), refresh: true})
}

// newSession starts an SSO session for user with client attached.
func (h *Handler) newSession(r *http.Request, realm *model.Realm, user *model.User, client *model.Client) (*model.UserSession, error) {
	now := h.Svc.Now()
	us := &model.UserSession{ID: service.NewID(), RealmID: realm.ID, UserID: user.ID, IPAddress: clientIP(r),
		Started: now, LastRefresh: now, Clients: map[string]bool{client.ID: true}}
	if err := h.Svc.Store.CreateUserSession(r.Context(), us); err != nil {
		return nil, err
	}
	h.Log.Info("login", "realm", realm.Name, "user", user.Username, "client", client.ClientID, "session", us.ID)
	return us, nil
}

// ---------------------------------------------------------------- userinfo

func (h *Handler) userinfo(w http.ResponseWriter, r *http.Request) {
	realm, err := h.realm(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	tok := bearerToken(r)
	if tok == "" && r.Method == http.MethodPost {
		tok = r.PostFormValue("access_token")
	}
	unauthorized := func(desc string) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+realm.Name+`", error="invalid_token", error_description="`+desc+`"`)
		writeJSON(w, http.StatusUnauthorized, &oauthError{Code: "invalid_token", Description: desc})
	}
	if tok == "" {
		unauthorized("Token not provided")
		return
	}
	vt, err := h.Svc.VerifyToken(r.Context(), realm, tok, h.URLs.Issuer(r, realm.Name), service.TokenBearer)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) {
			unauthorized("Token verification failed")
			return
		}
		h.writeError(w, err)
		return
	}
	if vt.User == nil {
		unauthorized("User not found")
		return
	}
	out := jwt.Claims{"sub": vt.User.ID}
	userClaims(out, vt.User)
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------- introspection

func (h *Handler) introspect(w http.ResponseWriter, r *http.Request) {
	realm, err := h.realm(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	client, err := h.authenticateClient(r, realm)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if client.PublicClient {
		h.writeError(w, errUnauthorizedClient("Public client is not allowed to introspect tokens"))
		return
	}
	tok := r.PostFormValue("token")
	if tok == "" {
		h.writeError(w, errInvalidRequest("Token not provided"))
		return
	}
	vt, err := h.Svc.VerifyToken(r.Context(), realm, tok, h.URLs.Issuer(r, realm.Name), "")
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) {
			writeJSON(w, http.StatusOK, map[string]any{"active": false})
			return
		}
		h.writeError(w, err)
		return
	}
	out := jwt.Claims{}
	for k, v := range vt.Claims {
		out[k] = v
	}
	out["active"] = true
	out["client_id"] = vt.Claims.String("azp")
	out["token_type"] = vt.Claims.String("typ")
	if vt.User != nil {
		out["username"] = vt.User.Username
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------- revocation

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	realm, err := h.realm(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	client, err := h.authenticateClient(r, realm)
	if err != nil {
		h.writeError(w, err)
		return
	}
	tok := r.PostFormValue("token")
	if tok == "" {
		h.writeError(w, errInvalidRequest("Token not provided"))
		return
	}
	ctx := r.Context()
	vt, err := h.Svc.VerifyToken(ctx, realm, tok, h.URLs.Issuer(r, realm.Name), "")
	if err != nil {
		// RFC 7009: invalid tokens do not cause an error response.
		if errors.Is(err, service.ErrInvalidToken) {
			w.WriteHeader(http.StatusOK)
			return
		}
		h.writeError(w, err)
		return
	}
	if vt.Claims.String("azp") != client.ClientID {
		h.writeError(w, errUnauthorizedClient("Unmatching clients"))
		return
	}
	switch vt.Claims.String("typ") {
	case service.TokenRefresh:
		// Revoking a refresh token ends the client's part of the session.
		if s := vt.Session; s != nil {
			delete(s.Clients, client.ID)
			if len(s.Clients) == 0 {
				err = h.Svc.Store.DeleteUserSession(ctx, s.ID)
			} else {
				err = h.Svc.Store.UpdateUserSession(ctx, s)
			}
		}
	default:
		err = h.Svc.Store.RevokeToken(ctx, vt.Claims.String("jti"), time.Unix(vt.Claims.Int("exp"), 0))
	}
	if err != nil {
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}
