package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

const (
	identityCookie    = "KEYCLOAK_IDENTITY"
	sessionCookie     = "KEYCLOAK_SESSION"
	authSessionCookie = "AUTH_SESSION_ID"
	authSessionTTL    = 30 * time.Minute
)

// authorize handles /protocol/openid-connect/auth.
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	h.authorizeWith(w, r, "browser")
}

// registrations handles /protocol/openid-connect/registrations, which
// starts a login on the registration form.
func (h *Handler) registrations(w http.ResponseWriter, r *http.Request) {
	h.authorizeWith(w, r, "registration")
}

func (h *Handler) authorizeWith(w http.ResponseWriter, r *http.Request, binding string) {
	ctx := r.Context()
	realm, err := h.realm(r)
	if err != nil {
		h.errorPage(w, r, http.StatusNotFound, "realmNotFoundMessage")
		return
	}
	if binding == "registration" && !realm.RegistrationAllowed {
		h.errorPage(w, r, http.StatusBadRequest, "registrationNotAllowedMessage")
		return
	}
	q := func(k string) string { return r.FormValue(k) }

	client, err := h.Svc.Store.GetClientByClientID(ctx, realm.ID, q("client_id"))
	if err != nil {
		h.errorPage(w, r, http.StatusBadRequest, "clientNotFoundMessage")
		return
	}
	if !client.Enabled {
		h.errorPage(w, r, http.StatusBadRequest, "clientDisabledMessage")
		return
	}
	if client.BearerOnly {
		h.errorPage(w, r, http.StatusBadRequest, "bearerOnlyMessage")
		return
	}
	redirectURI := q("redirect_uri")
	if redirectURI == "" {
		redirectURI = soleRedirectURI(h.URLs.Base(r), client)
	}
	if redirectURI == "" || !matchRedirectURI(h.URLs.Base(r), client, redirectURI) {
		h.errorPage(w, r, http.StatusBadRequest, "invalidRedirectUriMessage")
		return
	}

	// From here on errors are reported to the client via redirect.
	mode := q("response_mode")
	switch mode {
	case "", "query", "fragment", "form_post":
	default:
		h.errorPage(w, r, http.StatusBadRequest, "invalidResponseModeMessage")
		return
	}
	fail := func(code, desc string) {
		h.redirectResult(w, r, redirectURI, mode, url.Values{"error": {code}, "error_description": {desc}, "state": {q("state")}})
	}
	if q("response_type") != "code" {
		fail("unsupported_response_type", "Client is not allowed to initiate browser login with given response_type. Only the authorization code flow is supported.")
		return
	}
	if !client.StandardFlowEnabled {
		fail("unauthorized_client", "Client is not allowed to initiate browser login with given response_type. Standard flow is disabled for the client.")
		return
	}
	method := q("code_challenge_method")
	if q("code_challenge") != "" && method == "" {
		method = "plain"
	}
	if method != "" && method != "plain" && method != "S256" {
		fail("invalid_request", "Invalid parameter: code challenge method is not supported")
		return
	}
	if req := client.Attributes["pkce.code.challenge.method"]; req != "" {
		if q("code_challenge") == "" {
			fail("invalid_request", "Missing parameter: code_challenge")
			return
		}
		if method != req {
			fail("invalid_request", "Invalid parameter: code challenge method is not matching the configured one")
			return
		}
	}

	if _, _, invalid, err := resolveScopes(ctx, h.Svc.Store, realm, client, q("scope")); err != nil {
		h.serverErrorPage(w, r, err)
		return
	} else if len(invalid) > 0 {
		fail("invalid_scope", "Invalid scopes: "+strings.Join(invalid, " "))
		return
	}

	params := map[string]string{
		"client_id":             client.ClientID,
		"redirect_uri":          redirectURI,
		"response_mode":         mode,
		"scope":                 q("scope"),
		"state":                 q("state"),
		"nonce":                 q("nonce"),
		"code_challenge":        q("code_challenge"),
		"code_challenge_method": method,
		"login_hint":            q("login_hint"),
		"prompt":                q("prompt"),
		"max_age":               q("max_age"),
		"kc_action":             q("kc_action"),
		"kc_idp_hint":           q("kc_idp_hint"),
	}

	if strings.Contains(q("prompt"), "none") {
		// Only an existing SSO session can answer without user interaction.
		us, user := h.ssoSession(r, realm)
		if us == nil {
			fail("login_required", "Login required")
			return
		}
		if len(user.RequiredActions) > 0 {
			fail("interaction_required", "Interaction required")
			return
		}
		h.finishLogin(w, r, realm, client, user, us, params)
		return
	}

	as, err := h.newAuthSession(w, r, realm, client, params)
	if err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	h.startFlow(w, r, realm, client, as, binding)
}

func soleRedirectURI(base string, c *model.Client) string {
	if len(c.RedirectURIs) == 1 && !strings.Contains(c.RedirectURIs[0], "*") {
		return resolveURI(base, c, c.RedirectURIs[0])
	}
	return ""
}

// loadAuthSession returns the in-flight login referenced by session_code,
// which must also match the browser's AUTH_SESSION_ID cookie.
func (h *Handler) loadAuthSession(r *http.Request, realm *model.Realm) (*model.AuthSession, *model.Client, error) {
	id := r.URL.Query().Get("session_code")
	ck, err := r.Cookie(authSessionCookie)
	if id == "" || err != nil || subtle.ConstantTimeCompare([]byte(ck.Value), []byte(id)) != 1 {
		return nil, nil, store.ErrNotFound
	}
	as, err := h.Svc.Store.GetAuthSession(r.Context(), id)
	if err != nil {
		return nil, nil, err
	}
	if as.RealmID != realm.ID || h.Svc.Now().After(as.ExpiresAt) {
		return nil, nil, store.ErrNotFound
	}
	client, err := h.Svc.Store.GetClient(r.Context(), realm.ID, as.ClientID)
	if err != nil {
		return nil, nil, err
	}
	return as, client, nil
}

// authenticateEndpoint serves /login-actions/authenticate: the forms of
// the flow's executions post here (?execution=<id>).
func (h *Handler) authenticateEndpoint(w http.ResponseWriter, r *http.Request) {
	realm, as, client, ok := h.authSessionOf(w, r)
	if !ok {
		return
	}
	posted := ""
	if r.Method == http.MethodPost {
		posted = r.URL.Query().Get("execution")
	}
	h.continueFlow(w, r, realm, client, as, posted)
}

// authSessionOf loads the realm and auth session of a login-actions request.
func (h *Handler) authSessionOf(w http.ResponseWriter, r *http.Request) (*model.Realm, *model.AuthSession, *model.Client, bool) {
	realm, err := h.realm(r)
	if err != nil {
		h.errorPage(w, r, http.StatusNotFound, "realmNotFoundMessage")
		return nil, nil, nil, false
	}
	as, client, err := h.loadAuthSession(r, realm)
	if err != nil {
		h.errorPage(w, r, http.StatusBadRequest, "loginTimeout")
		return nil, nil, nil, false
	}
	return realm, as, client, true
}

// registrationEndpoint switches the login to the registration flow.
func (h *Handler) registrationEndpoint(w http.ResponseWriter, r *http.Request) {
	realm, as, client, ok := h.authSessionOf(w, r)
	if !ok {
		return
	}
	if !realm.RegistrationAllowed {
		h.errorPage(w, r, http.StatusBadRequest, "registrationNotAllowedMessage")
		return
	}
	as.UserID = ""
	h.startFlow(w, r, realm, client, as, "registration")
}

// resetCredentialsEndpoint switches the login to the reset credentials flow.
func (h *Handler) resetCredentialsEndpoint(w http.ResponseWriter, r *http.Request) {
	realm, as, client, ok := h.authSessionOf(w, r)
	if !ok {
		return
	}
	if !realm.Settings.ResetPasswordAllowed {
		h.errorPage(w, r, http.StatusBadRequest, "resetCredentialNotAllowedMessage")
		return
	}
	as.UserID = ""
	h.startFlow(w, r, realm, client, as, "reset_credentials")
}

// restartEndpoint starts the login over ("Back to login", "Try another way").
func (h *Handler) restartEndpoint(w http.ResponseWriter, r *http.Request) {
	realm, as, client, ok := h.authSessionOf(w, r)
	if !ok {
		return
	}
	as.UserID = ""
	h.startFlow(w, r, realm, client, as, "browser")
}

// finishLogin attaches the client to an SSO session (creating one if
// needed), issues the authorization code and redirects back to the client.
func (h *Handler) finishLogin(w http.ResponseWriter, r *http.Request, realm *model.Realm, client *model.Client, user *model.User, us *model.UserSession, params map[string]string) {
	ctx := r.Context()
	var err error
	if us == nil {
		notes := map[string]string{"AUTH_TIME": strconv.FormatInt(h.Svc.Now().Unix(), 10)}
		for k, v := range params {
			if strings.HasPrefix(k, notePrefix) {
				notes[strings.TrimPrefix(k, notePrefix)] = v
			}
		}
		if us, err = h.newSession(r, realm, user, client, notes); err != nil {
			h.serverErrorPage(w, r, err)
			return
		}
		if params[keyRemember] == "true" {
			us.RememberMe = true
			if err := h.Svc.Store.SetSessionRememberMe(ctx, us.ID); err != nil {
				h.serverErrorPage(w, r, err)
				return
			}
		}
	} else if !us.Clients[client.ID] {
		us.Clients[client.ID] = true
		if err := h.Svc.Store.UpdateUserSession(ctx, us); err != nil {
			h.serverErrorPage(w, r, err)
			return
		}
	}
	if err := h.setIdentityCookie(w, r, realm, user, us); err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	code := &model.AuthCode{
		Code: service.RandomToken(32), RealmID: realm.ID, ClientID: client.ID, UserID: user.ID, SessionID: us.ID,
		RedirectURI: params["redirect_uri"], Scope: params["scope"], Nonce: params["nonce"],
		CodeChallenge: params["code_challenge"], CodeChallengeMethod: params["code_challenge_method"],
		ExpiresAt: h.Svc.Now().Add(time.Duration(realm.AccessCodeLifespan) * time.Second),
	}
	if err := h.Svc.Store.CreateAuthCode(ctx, code); err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	h.event(r, realm, "LOGIN", &eventInfo{client: client, userID: user.ID, sessionID: us.ID, details: map[string]string{
		"auth_method": "openid-connect", "auth_type": "code", "redirect_uri": params["redirect_uri"],
		"consent": "no_consent_required", "code_id": us.ID, "username": user.Username}})
	h.redirectResult(w, r, params["redirect_uri"], params["response_mode"], url.Values{
		"code": {code.Code}, "state": {params["state"]}, "session_state": {us.ID}, "iss": {h.URLs.Issuer(r, realm.Name)},
	})
}

// redirectResult sends authorization response parameters to the client.
func (h *Handler) redirectResult(w http.ResponseWriter, r *http.Request, redirectURI, mode string, v url.Values) {
	for k, vals := range v {
		if len(vals) == 0 || vals[0] == "" {
			delete(v, k)
		}
	}
	switch mode {
	case "form_post":
		h.render(w, http.StatusOK, "form-post", pageData{Action: redirectURI, Fields: v, r: r})
	case "fragment":
		http.Redirect(w, r, redirectURI+"#"+v.Encode(), http.StatusFound)
	default:
		sep := "?"
		if strings.Contains(redirectURI, "?") {
			sep = "&"
		}
		if len(v) == 0 {
			sep = ""
		}
		http.Redirect(w, r, redirectURI+sep+v.Encode(), http.StatusFound)
	}
}

// ---------------------------------------------------------------- SSO cookie

func (h *Handler) cookiePath(realm *model.Realm) string { return "/realms/" + realm.Name + "/" }

func (h *Handler) setCookie(w http.ResponseWriter, r *http.Request, realm *model.Realm, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: h.cookiePath(realm), MaxAge: maxAge, HttpOnly: true,
		Secure: strings.HasPrefix(h.URLs.Base(r), "https://"), SameSite: http.SameSiteLaxMode,
	})
}

func (h *Handler) clearCookie(w http.ResponseWriter, r *http.Request, realm *model.Realm, name string) {
	h.setCookie(w, r, realm, name, "", -1)
}

// setIdentityCookie stores a signed reference to the SSO session. The cookie
// is signed so that knowing a session id (the "sid" claim) is not enough to
// hijack a session.
func (h *Handler) setIdentityCookie(w http.ResponseWriter, r *http.Request, realm *model.Realm, user *model.User, us *model.UserSession) error {
	key, err := h.Svc.SigningKey(r.Context(), realm, "HS512")
	if err != nil {
		return err
	}
	exp := us.Started.Add(time.Duration(h.Svc.SessionMaxLifespan(realm, us)) * time.Second)
	tok, err := jwt.Sign(jwt.Claims{
		"typ": service.TokenCookie, "iss": h.URLs.Issuer(r, realm.Name), "sub": user.ID, "sid": us.ID,
		"exp": exp.Unix(), "iat": h.Svc.Now().Unix(), "jti": service.NewID(),
	}, key)
	if err != nil {
		return err
	}
	maxAge := 0 // a session cookie, unless "remember me" was checked
	if us.RememberMe {
		maxAge = int(time.Until(exp).Seconds())
	}
	h.setCookie(w, r, realm, identityCookie, tok, maxAge)
	// readable by the login status iframe of keycloak-js applications
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: realm.Name + "/" + user.ID + "/" + us.ID, Path: h.cookiePath(realm),
		MaxAge: maxAge, Secure: strings.HasPrefix(h.URLs.Base(r), "https://"), SameSite: http.SameSiteLaxMode})
	return nil
}

// ssoSession returns the valid SSO session of the browser, if any.
func (h *Handler) ssoSession(r *http.Request, realm *model.Realm) (*model.UserSession, *model.User) {
	ck, err := r.Cookie(identityCookie)
	if err != nil || ck.Value == "" {
		return nil, nil
	}
	vt, err := h.Svc.VerifyToken(r.Context(), realm, ck.Value, h.URLs.Issuer(r, realm.Name), service.TokenCookie)
	if err != nil || vt.Session == nil || vt.User == nil {
		return nil, nil
	}
	return vt.Session, vt.User
}

// ---------------------------------------------------------------- logout

// logout implements RP-initiated logout, and Keycloak's legacy back-channel
// logout (POST with refresh_token and client credentials).
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	realm, err := h.realm(r)
	if err != nil {
		h.errorPage(w, r, http.StatusNotFound, "realmNotFoundMessage")
		return
	}
	if r.Method == http.MethodPost && r.PostFormValue("refresh_token") != "" {
		h.backchannelLogout(w, r, realm)
		return
	}

	var client *model.Client
	hintSession := ""
	if hint := r.FormValue("id_token_hint"); hint != "" {
		// Expired ID tokens are acceptable as hints, so only the signature is checked.
		claims, err := jwt.Verify(hint, func(kid, alg string) *jwt.Key { return h.Svc.VerificationKey(ctx, realm.ID, kid, alg) })
		if err != nil || claims.String("iss") != h.URLs.Issuer(r, realm.Name) {
			h.errorPage(w, r, http.StatusBadRequest, "invalidIdTokenHintMessage")
			return
		}
		if client, err = h.Svc.Store.GetClientByClientID(ctx, realm.ID, claims.String("azp")); err != nil {
			h.errorPage(w, r, http.StatusBadRequest, "invalidIdTokenHintMessage")
			return
		}
		hintSession = claims.String("sid")
		if hintSession != "" {
			// without the SSO cookie (e.g. a broker's back-channel logout),
			// the session of the hint is logged out, as Keycloak does
			if s, err := h.Svc.Store.GetUserSession(ctx, hintSession); err != nil || s.UserID != claims.String("sub") {
				hintSession = ""
			}
		}
	}
	if cid := r.FormValue("client_id"); cid != "" {
		c, err := h.Svc.Store.GetClientByClientID(ctx, realm.ID, cid)
		if err != nil || (client != nil && c.ID != client.ID) {
			h.errorPage(w, r, http.StatusBadRequest, "invalidClientIdMessage")
			return
		}
		client = c
	}
	redirect := r.FormValue("post_logout_redirect_uri")
	if redirect != "" && (client == nil || !postLogoutRedirectAllowed(h.URLs.Base(r), client, redirect)) {
		h.errorPage(w, r, http.StatusBadRequest, "invalidPostLogoutRedirectMessage")
		return
	}

	us, _ := h.ssoSession(r, realm)
	if us == nil && hintSession != "" {
		us, _ = h.Svc.Store.GetUserSession(ctx, hintSession)
	}
	// Without an id_token_hint the user must confirm, which also protects
	// against cross-site logout requests.
	if us != nil && r.FormValue("id_token_hint") == "" && !h.logoutConfirmed(r) {
		ck, _ := r.Cookie(identityCookie)
		fields := url.Values{"confirm": {confirmToken(ck.Value)}}
		for _, k := range []string{"post_logout_redirect_uri", "state", "client_id"} {
			if v := r.FormValue(k); v != "" {
				fields.Set(k, v)
			}
		}
		h.render(w, http.StatusOK, "logout-confirm", pageData{realm: realm, r: r, Title: "logoutConfirmTitle",
			Action: h.URLs.Issuer(r, realm.Name) + "/protocol/openid-connect/logout", Fields: fields})
		return
	}
	front := ""
	if us != nil {
		front = h.idpLogout(r, realm, us, true, redirect, r.FormValue("state"))
		if err := h.Svc.Store.DeleteUserSession(ctx, us.ID); err != nil {
			h.serverErrorPage(w, r, err)
			return
		}
		h.event(r, realm, "LOGOUT", &eventInfo{client: client, userID: us.UserID, sessionID: us.ID,
			details: map[string]string{"redirect_uri": redirect}})
	}
	h.clearCookie(w, r, realm, identityCookie)
	h.clearCookie(w, r, realm, sessionCookie)
	if front != "" {
		http.Redirect(w, r, front, http.StatusFound)
		return
	}
	if redirect != "" {
		v := url.Values{}
		if s := r.FormValue("state"); s != "" {
			v.Set("state", s)
		}
		h.redirectResult(w, r, redirect, "query", v)
		return
	}
	h.render(w, http.StatusOK, "info", pageData{realm: realm, r: r, Title: "loggedOut"})
}

func confirmToken(cookie string) string {
	sum := sha256.Sum256([]byte("logout:" + cookie))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (h *Handler) logoutConfirmed(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	ck, err := r.Cookie(identityCookie)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(r.PostFormValue("confirm")), []byte(confirmToken(ck.Value))) == 1
}

func (h *Handler) backchannelLogout(w http.ResponseWriter, r *http.Request, realm *model.Realm) {
	client, err := h.authenticateClient(r, realm)
	if err != nil {
		h.writeError(w, err)
		return
	}
	vt, err := h.Svc.VerifyToken(r.Context(), realm, r.PostFormValue("refresh_token"), h.URLs.Issuer(r, realm.Name), service.TokenRefresh, service.TokenOffline)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) {
			h.writeError(w, errInvalidGrant("Invalid refresh token"))
			return
		}
		h.writeError(w, err)
		return
	}
	if vt.Claims.String("azp") != client.ClientID {
		h.writeError(w, errInvalidGrant("Invalid refresh token"))
		return
	}
	if vt.Session != nil {
		h.idpLogout(r, realm, vt.Session, false, "", "")
		if err := h.Svc.Store.DeleteSession(r.Context(), vt.Session); err != nil {
			h.writeError(w, err)
			return
		}
		h.event(r, realm, "LOGOUT", &eventInfo{client: client, userID: vt.Session.UserID, sessionID: vt.Session.ID})
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) loginActionURL(r *http.Request, realm *model.Realm, action, sessionCode string) string {
	return h.URLs.Issuer(r, realm.Name) + "/login-actions/" + action + "?session_code=" + url.QueryEscape(sessionCode)
}

func realmTitle(r *model.Realm) string {
	if r.DisplayName != "" {
		return r.DisplayName
	}
	return r.Name
}

// SSOSession returns the browser's valid SSO session and its user, if any.
func (h *Handler) SSOSession(r *http.Request, realm *model.Realm) (*model.UserSession, *model.User) {
	return h.ssoSession(r, realm)
}

// StateChecker is a CSRF token bound to the browser's SSO cookie, for forms
// of pages served to logged in users (the account console).
func StateChecker(r *http.Request) string {
	ck, err := r.Cookie(identityCookie)
	if err != nil {
		return ""
	}
	return confirmToken("state:" + ck.Value)
}
