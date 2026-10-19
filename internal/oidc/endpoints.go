package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/ducnt114/gocloak/internal/dpop"
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
	key, err := h.Svc.SigningKey(r.Context(), realm, "RS256")
	if err != nil {
		h.writeError(w, err)
		return
	}
	iss := h.URLs.Issuer(r, realm.Name)
	writeJSON(w, http.StatusOK, map[string]any{
		"realm":             realm.Name,
		"public_key":        jwt.PublicKeyBase64(key.Public),
		"token-service":     iss + "/protocol/openid-connect",
		"account-service":   iss + "/account",
		"tokens-not-before": realm.Settings.NotBefore,
	})
}

var asymmetricAlgs = []string{"PS384", "ES384", "RS384", "ES256", "RS256", "ES512", "PS256", "PS512", "RS512"}

func (h *Handler) discovery(w http.ResponseWriter, r *http.Request) {
	realm, err := h.realm(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	iss := h.URLs.Issuer(r, realm.Name)
	p := iss + "/protocol/openid-connect"
	authMethods := []string{"private_key_jwt", "client_secret_basic", "client_secret_post", "client_secret_jwt"}
	authAlgs := append(append([]string{}, asymmetricAlgs...), "HS256", "HS512", "HS384")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                                   iss,
		"authorization_endpoint":                                   p + "/auth",
		"token_endpoint":                                           p + "/token",
		"introspection_endpoint":                                   p + "/token/introspect",
		"userinfo_endpoint":                                        p + "/userinfo",
		"end_session_endpoint":                                     p + "/logout",
		"revocation_endpoint":                                      p + "/revoke",
		"jwks_uri":                                                 p + "/certs",
		"frontchannel_logout_supported":                            true,
		"frontchannel_logout_session_supported":                    true,
		"backchannel_logout_supported":                             true,
		"backchannel_logout_session_supported":                     true,
		"grant_types_supported":                                    []string{"authorization_code", "client_credentials", "password", "refresh_token", grantDeviceCode, grantTokenExchange},
		"device_authorization_endpoint":                            p + "/auth/device",
		"response_types_supported":                                 []string{"code"},
		"response_modes_supported":                                 []string{"query", "fragment", "form_post"},
		"subject_types_supported":                                  []string{"public"},
		"id_token_signing_alg_values_supported":                    asymmetricAlgs,
		"userinfo_signing_alg_values_supported":                    []string{"none"},
		"code_challenge_methods_supported":                         []string{"plain", "S256"},
		"token_endpoint_auth_methods_supported":                    authMethods,
		"token_endpoint_auth_signing_alg_values_supported":         authAlgs,
		"introspection_endpoint_auth_methods_supported":            authMethods,
		"introspection_endpoint_auth_signing_alg_values_supported": authAlgs,
		"revocation_endpoint_auth_methods_supported":               authMethods,
		"revocation_endpoint_auth_signing_alg_values_supported":    authAlgs,
		"scopes_supported":                                         []string{"openid", "profile", "email", "roles", "web-origins", "acr", "basic", "address", "phone", "offline_access", "microprofile-jwt"},
		"claims_supported":                                         []string{"aud", "sub", "iss", "auth_time", "name", "given_name", "family_name", "preferred_username", "email", "email_verified", "acr", "sid"},
		"claims_parameter_supported":                               true,
		"request_parameter_supported":                              true,
		"request_uri_parameter_supported":                          true,
		"require_request_uri_registration":                         true,
		"request_object_signing_alg_values_supported":              append(append([]string{}, authAlgs...), "none"),
		"pushed_authorization_request_endpoint":                    p + "/ext/par/request",
		"require_pushed_authorization_requests":                    false,
		"authorization_response_iss_parameter_supported":           true,
		"tls_client_certificate_bound_access_tokens":               false,
		"dpop_signing_alg_values_supported":                        asymmetricAlgs,
	})
}

func (h *Handler) certs(w http.ResponseWriter, r *http.Request) {
	realm, err := h.realm(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	keys, err := h.Svc.RealmKeys(r.Context(), realm.ID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	jwks := []jwt.JWK{}
	for _, k := range keys {
		if !k.Enabled {
			continue
		}
		if j, ok := k.JWK(); ok {
			jwks = append(jwks, j)
		}
	}
	sort.SliceStable(jwks, func(i, j int) bool { return jwks[i].Kid < jwks[j].Kid })
	writeJSON(w, http.StatusOK, map[string]any{"keys": jwks})
}

// ---------------------------------------------------------------- token

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	if r.PostFormValue("grant_type") == grantUMATicket {
		realm, err := h.realm(r)
		if err != nil {
			h.writeError(w, err)
			return
		}
		// the client may authenticate, but the bearer token is what counts
		if bearerToken(r) == "" || r.PostFormValue("client_id") != "" {
			if _, err := h.authenticateClient(r, realm); err != nil {
				h.writeError(w, err)
				return
			}
		}
		h.grantUMA(w, r, realm)
		return
	}
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
		typ := map[string]string{"authorization_code": "CODE_TO_TOKEN_ERROR", "password": "LOGIN_ERROR",
			"client_credentials": "CLIENT_LOGIN_ERROR", "refresh_token": "REFRESH_TOKEN_ERROR"}[grant]
		if typ != "" {
			h.event(r, realm, typ, &eventInfo{clientID: clientIDParam(r), err: "invalid_client_credentials",
				details: map[string]string{"grant_type": grant}})
		}
		return nil, err
	}
	// a DPoP proof binds the issued tokens to the client's key
	proof, err := h.Svc.CheckDPoP(r.Context(), r, h.URLs.Issuer(r, realm.Name)+"/protocol/openid-connect/token", "")
	if err != nil {
		if dpop.IsError(err) {
			return nil, &oauthError{http.StatusBadRequest, "invalid_dpop_proof", err.Error()}
		}
		return nil, err
	}
	if proof == nil && client.Attributes[attrDPoPBound] == "true" {
		return nil, &oauthError{http.StatusBadRequest, "invalid_dpop_proof", "DPoP proof is missing"}
	}
	if proof != nil {
		r = r.WithContext(context.WithValue(r.Context(), dpopProofKey{}, proof))
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
	case grantDeviceCode:
		return h.grantDevice(r, realm, client)
	case grantTokenExchange:
		return h.grantTokenExchange(r, realm, client)
	}
	return nil, &oauthError{http.StatusBadRequest, "unsupported_grant_type", "Unsupported grant_type"}
}

func (h *Handler) grantAuthorizationCode(r *http.Request, realm *model.Realm, client *model.Client) (*tokenResponse, error) {
	ctx := r.Context()
	ev := &eventInfo{client: client, details: map[string]string{"grant_type": "authorization_code"}}
	fail := func(code string, e error) (*tokenResponse, error) {
		ev.err = code
		h.event(r, realm, "CODE_TO_TOKEN_ERROR", ev)
		return nil, e
	}
	if !client.StandardFlowEnabled {
		return fail("not_allowed", errUnauthorizedClient("Client not allowed to exchange code"))
	}
	code := r.PostFormValue("code")
	if code == "" {
		return fail("invalid_code", errInvalidRequest("Missing parameter: code"))
	}
	ac, err := h.Svc.Store.ConsumeAuthCode(ctx, code)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fail("invalid_code", errInvalidGrant("Code not valid"))
		}
		return nil, err
	}
	ev.sessionID, ev.userID = ac.SessionID, ac.UserID
	if ac.RealmID != realm.ID || ac.ClientID != client.ID {
		return fail("invalid_code", errInvalidGrant("Code not valid"))
	}
	if h.Svc.Now().After(ac.ExpiresAt) {
		return fail("expired_code", errInvalidGrant("Code not valid"))
	}
	if ac.RedirectURI != r.PostFormValue("redirect_uri") {
		return fail("invalid_code", errInvalidGrant("Incorrect redirect_uri"))
	}
	if err := verifyPKCE(ac, r.PostFormValue("code_verifier")); err != nil {
		return fail("invalid_code_verifier", err)
	}
	session, err := h.Svc.Store.GetUserSession(ctx, ac.SessionID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fail("user_session_not_found", errInvalidGrant("Session not active"))
		}
		return nil, err
	}
	if !h.Svc.SessionValid(realm, session) {
		return fail("user_session_not_found", errInvalidGrant("Session not active"))
	}
	user, err := h.Svc.Store.GetUser(ctx, realm.ID, ac.UserID)
	if err != nil {
		return fail("user_not_found", errInvalidGrant("User not found"))
	}
	if !user.Enabled {
		return fail("user_disabled", errInvalidGrant("User disabled"))
	}
	resp, err := h.issue(r, &issueRequest{realm: realm, client: client, user: user, session: session,
		scope: ac.Scope, nonce: ac.Nonce, refresh: true})
	if err != nil {
		return fail(errorCode(err), err)
	}
	ev.details["code_id"] = ac.SessionID
	resp.eventDetails(ev)
	h.event(r, realm, "CODE_TO_TOKEN", ev)
	return resp, nil
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

// errInvalidCredentials is Keycloak's response to a failed password grant.
func errInvalidCredentials() *oauthError {
	return &oauthError{http.StatusUnauthorized, "invalid_grant", "Invalid user credentials"}
}

func (h *Handler) grantPassword(r *http.Request, realm *model.Realm, client *model.Client) (*tokenResponse, error) {
	ev := &eventInfo{client: client, details: map[string]string{"grant_type": "password", "auth_method": "openid-connect",
		"username": r.PostFormValue("username")}}
	fail := func(code string, e error) (*tokenResponse, error) {
		ev.err = code
		h.event(r, realm, "LOGIN_ERROR", ev)
		return nil, e
	}
	if !client.DirectAccessGrantsEnabled {
		return fail("not_allowed", errUnauthorizedClient("Client not allowed for direct access grants"))
	}
	// The direct grant flow authenticates the user (and records its own errors).
	user, err := h.runDirectGrant(r, realm, client)
	if err != nil {
		return nil, err
	}
	ev.userID = user.ID
	if err := h.checkPasswordExpiry(r, realm, user); err != nil {
		return nil, err
	}
	pending, err := h.pendingActions(&flowContext{h: h, r: r, realm: realm, client: client, user: user,
		as: &model.AuthSession{Params: map[string]string{}}})
	if err != nil {
		return nil, err
	}
	if len(pending) > 0 {
		return fail("resolve_required_actions", errInvalidGrant("Account is not fully set up"))
	}
	if client.ConsentRequired {
		// no page to ask for consent in a direct grant
		return fail("consent_denied", errInvalidClient400("Client requires user consent"))
	}
	session, err := h.newSession(r, realm, user, client, nil)
	if err != nil {
		return nil, err
	}
	ev.sessionID = session.ID
	resp, err := h.issue(r, &issueRequest{realm: realm, client: client, user: user, session: session,
		scope: r.PostFormValue("scope"), strict: true, refresh: true})
	if err != nil {
		return fail(errorCode(err), err)
	}
	resp.eventDetails(ev)
	h.event(r, realm, "LOGIN", ev)
	return resp, nil
}

// checkPasswordExpiry adds UPDATE_PASSWORD when the forceExpiredPasswordChange
// policy says the user's password is too old.
func (h *Handler) checkPasswordExpiry(r *http.Request, realm *model.Realm, user *model.User) error {
	expired, err := h.Svc.PasswordExpired(r.Context(), realm, user)
	if err != nil || !expired {
		return err
	}
	for _, a := range user.RequiredActions {
		if a == service.ActionUpdatePassword {
			return nil
		}
	}
	user.RequiredActions = append(user.RequiredActions, service.ActionUpdatePassword)
	return h.Svc.Store.UpdateUser(r.Context(), user)
}

func (h *Handler) grantClientCredentials(r *http.Request, realm *model.Realm, client *model.Client) (*tokenResponse, error) {
	ctx := r.Context()
	ev := &eventInfo{client: client, details: map[string]string{"grant_type": "client_credentials"}}
	fail := func(code string, e error) (*tokenResponse, error) {
		ev.err = code
		h.event(r, realm, "CLIENT_LOGIN_ERROR", ev)
		return nil, e
	}
	if client.PublicClient {
		return fail("invalid_client", errUnauthorizedClient("Public client not allowed to retrieve service account"))
	}
	if !client.ServiceAccountsEnabled {
		return fail("invalid_client", errUnauthorizedClient("Client not enabled to retrieve service account"))
	}
	user, err := h.Svc.Store.GetServiceAccountUser(ctx, client.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fail("user_not_found", errInvalidRequest("Service account user not found"))
		}
		return nil, err
	}
	ev.userID = user.ID
	ev.details["username"] = user.Username
	if !user.Enabled {
		return fail("user_disabled", errInvalidRequest("User disabled"))
	}
	resp, err := h.issue(r, &issueRequest{realm: realm, client: client, user: user, scope: r.PostFormValue("scope"), strict: true})
	if err != nil {
		return fail(errorCode(err), err)
	}
	resp.eventDetails(ev)
	h.event(r, realm, "CLIENT_LOGIN", ev)
	return resp, nil
}

func (h *Handler) grantRefreshToken(r *http.Request, realm *model.Realm, client *model.Client) (*tokenResponse, error) {
	ctx := r.Context()
	ev := &eventInfo{client: client, details: map[string]string{"grant_type": "refresh_token"}}
	fail := func(code string, e error) (*tokenResponse, error) {
		ev.err = code
		h.event(r, realm, "REFRESH_TOKEN_ERROR", ev)
		return nil, e
	}
	raw := r.PostFormValue("refresh_token")
	if raw == "" {
		return fail("invalid_token", errInvalidRequest("Missing parameter: refresh_token"))
	}
	vt, err := h.Svc.VerifyToken(ctx, realm, raw, h.URLs.Issuer(r, realm.Name), service.TokenRefresh, service.TokenOffline)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) {
			return fail("invalid_token", errInvalidGrant("Invalid refresh token"))
		}
		return nil, err
	}
	if vt.User != nil {
		ev.userID = vt.User.ID
	}
	if vt.Claims.String("azp") != client.ClientID {
		return fail("invalid_token", errInvalidGrant("Invalid refresh token. Token client and authorized client don't match"))
	}
	if jkt := service.BoundKey(vt.Claims); jkt != "" {
		if p := dpopProof(r); p == nil || p.JKT != jkt {
			return fail("invalid_token", &oauthError{http.StatusBadRequest, "invalid_dpop_proof", "DPoP proof and token binding verification failed"})
		}
	}
	if vt.Session == nil || vt.User == nil {
		return fail("invalid_token", errInvalidGrant("Session not active"))
	}
	ev.sessionID = vt.Session.ID
	if !vt.Session.Clients[client.ID] {
		return fail("invalid_token", errInvalidGrant("Session doesn't have required client"))
	}
	if realm.Settings.RevokeRefreshToken {
		if err := h.checkRefreshReuse(r, realm, client, vt); err != nil {
			return fail("invalid_token", err)
		}
	}
	vt.Session.LastRefresh = h.Svc.Now()
	if err := h.Svc.Store.UpdateUserSession(ctx, vt.Session); err != nil {
		return nil, err
	}
	resp, err := h.issue(r, &issueRequest{realm: realm, client: client, user: vt.User, session: vt.Session,
		scope: vt.Claims.String("scope"), nonce: vt.Claims.String("nonce"), refresh: true})
	if err != nil {
		return fail(errorCode(err), err)
	}
	resp.eventDetails(ev)
	ev.details["updated_refresh_token_id"] = resp.refreshJTI
	ev.details["refresh_token_id"] = vt.Claims.String("jti")
	h.event(r, realm, "REFRESH_TOKEN", ev)
	return resp, nil
}

// checkRefreshReuse implements revokeRefreshToken: each refresh token may
// be used refreshTokenMaxReuse+1 times; exceeding that removes the client
// from the session, which invalidates every refresh token it holds.
func (h *Handler) checkRefreshReuse(r *http.Request, realm *model.Realm, client *model.Client, vt *service.VerifiedToken) error {
	us := vt.Session
	if us.Notes == nil {
		us.Notes = map[string]string{}
	}
	key, countKey := "refresh."+client.ID, "refresh_count."+client.ID
	jti := vt.Claims.String("jti")
	if us.Notes[key] != jti {
		us.Notes[key], us.Notes[countKey] = jti, "0"
	}
	count, _ := strconv.Atoi(us.Notes[countKey])
	if count > realm.Settings.RefreshTokenMaxReuse {
		delete(us.Clients, client.ID)
		delete(us.Notes, key)
		delete(us.Notes, countKey)
		if err := h.Svc.Store.UpdateUserSession(r.Context(), us); err != nil {
			return err
		}
		return errInvalidGrant("Maximum allowed refresh token reuse exceeded")
	}
	us.Notes[countKey] = strconv.Itoa(count + 1)
	return nil
}

// newSession starts an SSO session for user with client attached.
func (h *Handler) newSession(r *http.Request, realm *model.Realm, user *model.User, client *model.Client, notes map[string]string) (*model.UserSession, error) {
	now := h.Svc.Now()
	if notes == nil {
		notes = map[string]string{}
	}
	if ua := r.UserAgent(); ua != "" {
		notes["userAgent"] = ua
	}
	us := &model.UserSession{ID: service.NewID(), RealmID: realm.ID, UserID: user.ID, IPAddress: clientIP(r),
		Started: now, LastRefresh: now, Clients: map[string]bool{client.ID: true}, Notes: notes}
	if err := h.Svc.Store.CreateUserSession(r.Context(), us); err != nil {
		return nil, err
	}
	return us, nil
}

// ---------------------------------------------------------------- userinfo

func (h *Handler) userinfo(w http.ResponseWriter, r *http.Request) {
	realm, err := h.realm(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	tok, scheme := service.AccessToken(r)
	if tok == "" && r.Method == http.MethodPost {
		tok, scheme = r.PostFormValue("access_token"), "Bearer"
	}
	unauthorized := func(desc string) {
		h.event(r, realm, "USER_INFO_REQUEST_ERROR", &eventInfo{err: "invalid_token"})
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
	if err := h.Svc.CheckTokenBinding(r.Context(), r, h.URLs.Base(r)+r.URL.Path, tok, scheme, vt.Claims); err != nil {
		if dpop.IsError(err) {
			unauthorized(err.Error())
			return
		}
		h.writeError(w, err)
		return
	}
	if !hasScope(vt.Claims.String("scope"), "openid") {
		// Keycloak refuses userinfo for tokens issued without "openid".
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+realm.Name+`", error="insufficient_scope", error_description="Missing openid scope"`)
		writeJSON(w, http.StatusForbidden, &oauthError{Code: "insufficient_scope", Description: "Missing openid scope"})
		return
	}
	client, err := h.Svc.Store.GetClientByClientID(r.Context(), realm.ID, vt.Claims.String("azp"))
	if err != nil {
		unauthorized("Client not found")
		return
	}
	tc, _, err := newTokenContext(r.Context(), h.Svc, h.URLs.Base(r), realm, client, vt.User, vt.Session, vt.Claims.String("scope"), false)
	if err != nil {
		h.writeError(w, err)
		return
	}
	out := jwt.Claims{"sub": vt.User.ID}
	if err := tc.apply(r.Context(), out, kindUserinfo); err != nil {
		h.writeError(w, err)
		return
	}
	ev := &eventInfo{client: client, userID: vt.User.ID, details: map[string]string{"auth_method": "validate_access_token", "username": vt.User.Username}}
	if vt.Session != nil {
		ev.sessionID = vt.Session.ID
	}
	h.event(r, realm, "USER_INFO_REQUEST", ev)
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
		h.event(r, realm, "INTROSPECT_TOKEN_ERROR", &eventInfo{clientID: clientIDParam(r), err: "invalid_client_credentials"})
		h.writeError(w, err)
		return
	}
	if client.PublicClient {
		h.writeError(w, &oauthError{http.StatusForbidden, "invalid_request", "Client not allowed."})
		return
	}
	tok := r.PostFormValue("token")
	if tok == "" {
		h.writeError(w, errInvalidRequest("Token not provided"))
		return
	}
	vt, err := h.Svc.VerifyToken(r.Context(), realm, tok, h.URLs.Issuer(r, realm.Name))
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
	if _, hasSub := vt.Claims["sub"]; !hasSub && vt.User != nil && vt.Session != nil && vt.Claims.String("typ") == service.TokenBearer {
		// a lightweight access token: introspection returns the claims the
		// mappers give to introspection
		if err := h.lightweightClaims(r, realm, vt, out); err != nil {
			h.writeError(w, err)
			return
		}
	}
	out["active"] = true
	out["client_id"] = vt.Claims.String("azp")
	out["token_type"] = vt.Claims.String("typ")
	if vt.User != nil {
		out["username"] = vt.User.Username
	}
	h.event(r, realm, "INTROSPECT_TOKEN", &eventInfo{client: client})
	writeJSON(w, http.StatusOK, out)
}

// lightweightClaims adds the claims left out of a lightweight access token.
func (h *Handler) lightweightClaims(r *http.Request, realm *model.Realm, vt *service.VerifiedToken, out jwt.Claims) error {
	ctx := r.Context()
	client, err := h.Svc.Store.GetClientByClientID(ctx, realm.ID, vt.Claims.String("azp"))
	if err != nil {
		return nil
	}
	tc, _, err := newTokenContext(ctx, h.Svc, h.URLs.Base(r), realm, client, vt.User, vt.Session, vt.Claims.String("scope"), false)
	if err != nil {
		return err
	}
	out["sub"] = vt.User.ID
	return tc.apply(ctx, out, kindIntrospection)
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
	vt, err := h.Svc.VerifyToken(ctx, realm, tok, h.URLs.Issuer(r, realm.Name))
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
	case service.TokenRefresh, service.TokenOffline:
		// Revoking a refresh token ends the client's part of the session.
		if s := vt.Session; s != nil {
			delete(s.Clients, client.ID)
			if len(s.Clients) == 0 {
				err = h.Svc.Store.DeleteSession(ctx, s)
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
	ev := &eventInfo{client: client}
	if vt.User != nil {
		ev.userID = vt.User.ID
	}
	h.event(r, realm, "REVOKE_GRANT", ev)
	w.WriteHeader(http.StatusOK)
}
