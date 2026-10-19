package oidc

import (
	"crypto/rsa"
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
	authSessionCookie = "AUTH_SESSION_ID"
	authSessionTTL    = 30 * time.Minute
)

// authorize handles /protocol/openid-connect/auth.
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	realm, err := h.realm(r)
	if err != nil {
		h.errorPage(w, r, http.StatusNotFound, "Realm does not exist.")
		return
	}
	q := func(k string) string { return r.FormValue(k) }

	client, err := h.Svc.Store.GetClientByClientID(ctx, realm.ID, q("client_id"))
	if err != nil {
		h.errorPage(w, r, http.StatusBadRequest, "Client not found.")
		return
	}
	if !client.Enabled {
		h.errorPage(w, r, http.StatusBadRequest, "Client disabled.")
		return
	}
	if client.BearerOnly {
		h.errorPage(w, r, http.StatusBadRequest, "Bearer-only applications are not allowed to initiate browser login.")
		return
	}
	redirectURI := q("redirect_uri")
	if redirectURI == "" {
		redirectURI = soleRedirectURI(h.URLs.Base(r), client)
	}
	if redirectURI == "" || !matchRedirectURI(h.URLs.Base(r), client, redirectURI) {
		h.errorPage(w, r, http.StatusBadRequest, "Invalid parameter: redirect_uri")
		return
	}

	// From here on errors are reported to the client via redirect.
	mode := q("response_mode")
	switch mode {
	case "", "query", "fragment", "form_post":
	default:
		h.errorPage(w, r, http.StatusBadRequest, "Invalid parameter: response_mode")
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

	params := map[string]string{
		"client_id":             client.ClientID,
		"redirect_uri":          redirectURI,
		"response_mode":         mode,
		"scope":                 grantedScope(q("scope")),
		"state":                 q("state"),
		"nonce":                 q("nonce"),
		"code_challenge":        q("code_challenge"),
		"code_challenge_method": method,
		"login_hint":            q("login_hint"),
	}
	prompt := q("prompt")

	// Reuse an existing SSO session unless a fresh login is required.
	if us, user := h.ssoSession(r, realm); us != nil && !strings.Contains(prompt, "login") {
		fresh := true
		if ma := q("max_age"); ma != "" {
			if n, err := strconv.Atoi(ma); err == nil && h.Svc.Now().Sub(us.Started) > time.Duration(n)*time.Second {
				fresh = false
			}
		}
		if fresh && len(user.RequiredActions) == 0 {
			h.finishLogin(w, r, realm, client, user, us, params)
			return
		}
	}
	if strings.Contains(prompt, "none") {
		fail("login_required", "Login required")
		return
	}

	as := &model.AuthSession{ID: service.RandomToken(24), RealmID: realm.ID, ClientID: client.ID,
		Params: params, ExpiresAt: h.Svc.Now().Add(authSessionTTL)}
	if err := h.Svc.Store.CreateAuthSession(ctx, as); err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	h.setCookie(w, r, realm, authSessionCookie, as.ID, 0)
	h.renderLogin(w, r, realm, as, params["login_hint"], "", http.StatusOK)
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

// loginAction handles the username/password form.
func (h *Handler) loginAction(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	realm, err := h.realm(r)
	if err != nil {
		h.errorPage(w, r, http.StatusNotFound, "Realm does not exist.")
		return
	}
	as, client, err := h.loadAuthSession(r, realm)
	if err != nil {
		h.errorPage(w, r, http.StatusBadRequest, "Your login attempt timed out. Login will start from the beginning.")
		return
	}
	username, pw := strings.TrimSpace(r.PostFormValue("username")), r.PostFormValue("password")
	user, err := h.Svc.FindLoginUser(ctx, realm, username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		h.serverErrorPage(w, r, err)
		return
	}
	ok := false
	if user != nil {
		if ok, err = h.Svc.CheckPassword(ctx, user, pw); err != nil {
			h.serverErrorPage(w, r, err)
			return
		}
	}
	if !ok {
		h.Log.Info("login failed", "realm", realm.Name, "username", username, "client", client.ClientID)
		h.renderLogin(w, r, realm, as, username, "Invalid username or password.", http.StatusUnauthorized)
		return
	}
	if !user.Enabled {
		h.renderLogin(w, r, realm, as, username, "Account is disabled, contact your administrator.", http.StatusUnauthorized)
		return
	}
	as.UserID = user.ID
	if err := h.Svc.Store.UpdateAuthSession(ctx, as); err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	h.continueLogin(w, r, realm, client, user, as)
}

// continueLogin runs pending required actions, then completes the login.
func (h *Handler) continueLogin(w http.ResponseWriter, r *http.Request, realm *model.Realm, client *model.Client, user *model.User, as *model.AuthSession) {
	for _, a := range user.RequiredActions {
		if a == service.ActionUpdatePassword {
			h.render(w, http.StatusOK, "update-password", pageData{
				Realm: realmTitle(realm), Title: "Update password",
				Action:  h.loginActionURL(r, realm, "required-action", as.ID),
				Message: "You need to change your password to activate your account.",
			})
			return
		}
	}
	if err := h.Svc.Store.DeleteAuthSession(r.Context(), as.ID); err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	h.clearCookie(w, r, realm, authSessionCookie)
	h.finishLogin(w, r, realm, client, user, nil, as.Params)
}

// requiredAction handles the update password form.
func (h *Handler) requiredAction(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	realm, err := h.realm(r)
	if err != nil {
		h.errorPage(w, r, http.StatusNotFound, "Realm does not exist.")
		return
	}
	as, client, err := h.loadAuthSession(r, realm)
	if err != nil || as.UserID == "" {
		h.errorPage(w, r, http.StatusBadRequest, "Your login attempt timed out. Login will start from the beginning.")
		return
	}
	user, err := h.Svc.Store.GetUser(ctx, realm.ID, as.UserID)
	if err != nil {
		h.errorPage(w, r, http.StatusBadRequest, "User not found.")
		return
	}
	pw, confirm := r.PostFormValue("password-new"), r.PostFormValue("password-confirm")
	errMsg := ""
	switch {
	case pw == "":
		errMsg = "Please specify password."
	case pw != confirm:
		errMsg = "Passwords don't match."
	}
	if errMsg != "" {
		h.render(w, http.StatusBadRequest, "update-password", pageData{
			Realm: realmTitle(realm), Title: "Update password", Error: errMsg,
			Action: h.loginActionURL(r, realm, "required-action", as.ID),
		})
		return
	}
	if err := h.Svc.SetPassword(ctx, h.Svc.Store, user, pw, false); err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	h.continueLogin(w, r, realm, client, user, as)
}

// finishLogin attaches the client to an SSO session (creating one if
// needed), issues the authorization code and redirects back to the client.
func (h *Handler) finishLogin(w http.ResponseWriter, r *http.Request, realm *model.Realm, client *model.Client, user *model.User, us *model.UserSession, params map[string]string) {
	ctx := r.Context()
	var err error
	if us == nil {
		if us, err = h.newSession(r, realm, user, client); err != nil {
			h.serverErrorPage(w, r, err)
			return
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
		h.render(w, http.StatusOK, "form-post", pageData{Action: redirectURI, Fields: v})
	case "fragment":
		http.Redirect(w, r, redirectURI+"#"+v.Encode(), http.StatusFound)
	default:
		sep := "?"
		if strings.Contains(redirectURI, "?") {
			sep = "&"
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
	kid, key, err := h.Svc.SigningKey(r.Context(), realm.ID)
	if err != nil {
		return err
	}
	exp := us.Started.Add(time.Duration(realm.SSOSessionMaxLifespan) * time.Second)
	tok, err := jwt.Sign(jwt.Claims{
		"typ": service.TokenCookie, "iss": h.URLs.Issuer(r, realm.Name), "sub": user.ID, "sid": us.ID,
		"exp": exp.Unix(), "iat": h.Svc.Now().Unix(), "jti": service.NewID(),
	}, kid, key)
	if err != nil {
		return err
	}
	h.setCookie(w, r, realm, identityCookie, tok, 0)
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
		h.errorPage(w, r, http.StatusNotFound, "Realm does not exist.")
		return
	}
	if r.Method == http.MethodPost && r.PostFormValue("refresh_token") != "" {
		h.backchannelLogout(w, r, realm)
		return
	}

	var client *model.Client
	if hint := r.FormValue("id_token_hint"); hint != "" {
		// Expired ID tokens are acceptable as hints, so only the signature is checked.
		keys, err := h.Svc.PublicKeys(ctx, realm.ID)
		if err != nil {
			h.serverErrorPage(w, r, err)
			return
		}
		claims, err := jwt.Verify(hint, func(kid string) *rsa.PublicKey { return keys[kid] })
		if err != nil || claims.String("iss") != h.URLs.Issuer(r, realm.Name) {
			h.errorPage(w, r, http.StatusBadRequest, "Invalid parameter: id_token_hint")
			return
		}
		if client, err = h.Svc.Store.GetClientByClientID(ctx, realm.ID, claims.String("azp")); err != nil {
			h.errorPage(w, r, http.StatusBadRequest, "Invalid parameter: id_token_hint")
			return
		}
	}
	if cid := r.FormValue("client_id"); cid != "" {
		c, err := h.Svc.Store.GetClientByClientID(ctx, realm.ID, cid)
		if err != nil || (client != nil && c.ID != client.ID) {
			h.errorPage(w, r, http.StatusBadRequest, "Invalid parameter: client_id")
			return
		}
		client = c
	}
	redirect := r.FormValue("post_logout_redirect_uri")
	if redirect != "" && (client == nil || !postLogoutRedirectAllowed(h.URLs.Base(r), client, redirect)) {
		h.errorPage(w, r, http.StatusBadRequest, "Invalid redirect uri")
		return
	}

	us, _ := h.ssoSession(r, realm)
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
		h.render(w, http.StatusOK, "logout-confirm", pageData{Realm: realmTitle(realm), Title: "Logging out",
			Action: h.URLs.Issuer(r, realm.Name) + "/protocol/openid-connect/logout", Fields: fields})
		return
	}
	if us != nil {
		if err := h.Svc.Store.DeleteUserSession(ctx, us.ID); err != nil {
			h.serverErrorPage(w, r, err)
			return
		}
		h.Log.Info("logout", "realm", realm.Name, "session", us.ID)
	}
	h.clearCookie(w, r, realm, identityCookie)
	if redirect != "" {
		v := url.Values{}
		if s := r.FormValue("state"); s != "" {
			v.Set("state", s)
		}
		h.redirectResult(w, r, redirect, "query", v)
		return
	}
	h.render(w, http.StatusOK, "info", pageData{Realm: realmTitle(realm), Title: "You are logged out"})
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
	vt, err := h.Svc.VerifyToken(r.Context(), realm, r.PostFormValue("refresh_token"), h.URLs.Issuer(r, realm.Name), service.TokenRefresh)
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
		if err := h.Svc.Store.DeleteUserSession(r.Context(), vt.Session.ID); err != nil {
			h.writeError(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) loginActionURL(r *http.Request, realm *model.Realm, action, sessionCode string) string {
	return h.URLs.Issuer(r, realm.Name) + "/login-actions/" + action + "?session_code=" + url.QueryEscape(sessionCode)
}

func (h *Handler) renderLogin(w http.ResponseWriter, r *http.Request, realm *model.Realm, as *model.AuthSession, username, errMsg string, status int) {
	label := "Username"
	if realm.LoginWithEmailAllowed {
		label = "Username or email"
	}
	h.render(w, status, "login", pageData{
		Realm: realmTitle(realm), Title: "Sign in to your account", Error: errMsg, Username: username,
		UsernameLabel: label, Action: h.loginActionURL(r, realm, "authenticate", as.ID),
	})
}

func realmTitle(r *model.Realm) string {
	if r.DisplayName != "" {
		return r.DisplayName
	}
	return r.Name
}
