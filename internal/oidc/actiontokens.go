package oidc

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
)

// Action token types, as in Keycloak.
const (
	tokenVerifyEmail      = "verify-email"
	tokenResetCredentials = "reset-credentials"
	tokenExecuteActions   = "execute-actions"
	keyResetVerified      = "_reset_verified"
)

type actionTokenClaims struct {
	typ         string
	authSession string
	email       string
	redirect    string
	actions     []string
	lifespan    int // seconds
}

// ActionTokenLink builds a signed, single-use link for an emailed action
// (verify email, reset credentials, execute actions).
func ActionTokenLink(ctx context.Context, svc *service.Service, issuer string, realm *model.Realm, clientID string,
	user *model.User, typ string, actions []string, redirect string, lifespan int) (string, error) {
	key, err := svc.SigningKey(ctx, realm, "HS512")
	if err != nil {
		return "", err
	}
	now := svc.Now()
	claims := jwt.Claims{"typ": typ, "iss": issuer, "aud": issuer, "sub": user.ID, "azp": clientID,
		"iat": now.Unix(), "exp": now.Add(time.Duration(lifespan) * time.Second).Unix(), "jti": service.NewID()}
	if len(actions) > 0 {
		claims["rqac"] = actions
	}
	if redirect != "" {
		claims["reduri"] = redirect
	}
	if typ == tokenVerifyEmail {
		claims["eml"] = user.Email
	}
	return signedLink(issuer, clientID, claims, key)
}

func signedLink(issuer, clientID string, claims jwt.Claims, key *jwt.Key) (string, error) {
	tok, err := jwt.Sign(claims, key)
	if err != nil {
		return "", err
	}
	return issuer + "/login-actions/action-token?" + url.Values{"key": {tok}, "client_id": {clientID}}.Encode(), nil
}

// actionTokenLink creates a link for an action of the current login.
func (h *Handler) actionTokenLink(r *http.Request, realm *model.Realm, client *model.Client, user *model.User, c actionTokenClaims) (string, error) {
	key, err := h.Svc.SigningKey(r.Context(), realm, "HS512")
	if err != nil {
		return "", err
	}
	iss := h.URLs.Issuer(r, realm.Name)
	now := h.Svc.Now()
	claims := jwt.Claims{"typ": c.typ, "iss": iss, "aud": iss, "sub": user.ID, "azp": client.ClientID,
		"iat": now.Unix(), "exp": now.Add(time.Duration(c.lifespan) * time.Second).Unix(), "jti": service.NewID(),
		"asid": c.authSession}
	if c.email != "" {
		claims["eml"] = c.email
	}
	return signedLink(iss, client.ClientID, claims, key)
}

// actionToken handles /login-actions/action-token.
func (h *Handler) actionToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	realm, err := h.realm(r)
	if err != nil {
		h.errorPage(w, r, http.StatusNotFound, "Realm does not exist.")
		return
	}
	expired := func() {
		h.render(w, http.StatusBadRequest, "error", pageData{Realm: realmTitle(realm), Title: "We are sorry...",
			Error: "The link you clicked is no longer valid. It may have expired."})
	}
	iss := h.URLs.Issuer(r, realm.Name)
	claims, err := jwt.Verify(r.URL.Query().Get("key"), func(kid, alg string) *jwt.Key { return h.Svc.VerificationKey(ctx, realm.ID, kid, alg) })
	if err != nil || claims.String("iss") != iss || claims.Int("exp") < h.Svc.Now().Unix() {
		expired()
		return
	}
	typ := claims.String("typ")
	if !slices.Contains([]string{tokenVerifyEmail, tokenResetCredentials, tokenExecuteActions}, typ) {
		expired()
		return
	}
	jti := claims.String("jti")
	if used, err := h.Svc.Store.IsTokenRevoked(ctx, "action:"+jti); err != nil || used {
		expired()
		return
	}
	user, err := h.Svc.Store.GetUser(ctx, realm.ID, claims.String("sub"))
	if err != nil || !user.Enabled {
		expired()
		return
	}
	client, err := h.Svc.Store.GetClientByClientID(ctx, realm.ID, claims.String("azp"))
	if err != nil || !client.Enabled {
		h.errorPage(w, r, http.StatusBadRequest, "Client not found.")
		return
	}
	if err := h.Svc.Store.RevokeToken(ctx, "action:"+jti, time.Unix(claims.Int("exp"), 0)); err != nil {
		h.serverErrorPage(w, r, err)
		return
	}

	// The auth session of the login that sent the email, if this is the same browser.
	var as *model.AuthSession
	if asid := claims.String("asid"); asid != "" {
		if ck, err := r.Cookie(authSessionCookie); err == nil && ck.Value == asid {
			if s, err := h.Svc.Store.GetAuthSession(ctx, asid); err == nil && s.RealmID == realm.ID && h.Svc.Now().Before(s.ExpiresAt) {
				as = s
			}
		}
	}

	switch typ {
	case tokenVerifyEmail:
		if !strings.EqualFold(claims.String("eml"), user.Email) {
			expired()
			return
		}
		user.EmailVerified = true
		user.RequiredActions = slices.DeleteFunc(user.RequiredActions, func(a string) bool { return a == service.ActionVerifyEmail })
		if err := h.Svc.Store.UpdateUser(ctx, user); err != nil {
			h.serverErrorPage(w, r, err)
			return
		}
		h.event(r, realm, "VERIFY_EMAIL", &eventInfo{client: client, userID: user.ID, details: map[string]string{"email": user.Email}})
		if as != nil && as.UserID == user.ID {
			h.continueFlow(w, r, realm, client, as, "")
			return
		}
		d := pageData{Realm: realmTitle(realm), Title: "Your email address has been verified."}
		if reduri := claims.String("reduri"); reduri != "" {
			d.LinkURL, d.LinkText = reduri, "« Back to Application"
		}
		h.render(w, http.StatusOK, "info", d)

	case tokenResetCredentials:
		if as == nil {
			// another browser: start a new login of the client for this user
			if as, err = h.newAuthSession(w, r, realm, client, map[string]string{"client_id": client.ClientID,
				"redirect_uri": clientHome(h.URLs.Base(r), client), keyFlow: "reset_credentials"}); err != nil {
				h.serverErrorPage(w, r, err)
				return
			}
		}
		as.UserID = user.ID
		as.Params[keyResetVerified] = "true"
		if err := h.Svc.Store.UpdateAuthSession(ctx, as); err != nil {
			h.serverErrorPage(w, r, err)
			return
		}
		h.continueFlow(w, r, realm, client, as, "")

	case tokenExecuteActions:
		var actions []string
		if list, ok := claims["rqac"].([]any); ok {
			for _, a := range list {
				if s, ok := a.(string); ok {
					actions = append(actions, s)
				}
			}
		}
		as, err := h.newAuthSession(w, r, realm, client, map[string]string{"client_id": client.ClientID,
			"redirect_uri": claims.String("reduri"), keyMode: modeExecution, keyActions: strings.Join(append([]string{"-"}, actions...), " ")})
		if err != nil {
			h.serverErrorPage(w, r, err)
			return
		}
		as.UserID = user.ID
		if err := h.Svc.Store.UpdateAuthSession(ctx, as); err != nil {
			h.serverErrorPage(w, r, err)
			return
		}
		h.event(r, realm, "EXECUTE_ACTION_TOKEN", &eventInfo{client: client, userID: user.ID})
		names := make([]string, len(actions))
		for i, a := range actions {
			names[i] = actionNames[a]
			if names[i] == "" {
				names[i] = a
			}
		}
		h.render(w, http.StatusOK, "info", pageData{Realm: realmTitle(realm), Title: "Perform the following action(s)",
			Message: strings.Join(names, ", "), LinkURL: h.loginActionURL(r, realm, "required-action", as.ID),
			LinkText: "» Click here to proceed"})
	}
}

var actionNames = map[string]string{
	service.ActionUpdatePassword: "Update Password", service.ActionUpdateProfile: "Update Profile",
	service.ActionVerifyEmail: "Verify Email", service.ActionConfigureTOTP: "Configure OTP",
	service.ActionTermsAndConditions: "Terms and Conditions", service.ActionUpdateEmail: "Update Email",
	service.ActionWebAuthnRegister: "Webauthn Register", service.ActionWebAuthnPasswordles: "Webauthn Register Passwordless",
}

// clientHome is where a login started from an email returns to.
func clientHome(base string, c *model.Client) string {
	if c.BaseURL != "" {
		return resolveURI(base, c, c.BaseURL)
	}
	if c.RootURL != "" {
		return resolveURI(base, c, "/")
	}
	return soleRedirectURI(base, c)
}

// newAuthSession starts a login for client and sets the browser cookie.
func (h *Handler) newAuthSession(w http.ResponseWriter, r *http.Request, realm *model.Realm, client *model.Client, params map[string]string) (*model.AuthSession, error) {
	as := &model.AuthSession{ID: service.RandomToken(24), RealmID: realm.ID, ClientID: client.ID, Params: params,
		ExpiresAt: h.Svc.Now().Add(authSessionTTL)}
	if err := h.Svc.Store.CreateAuthSession(r.Context(), as); err != nil {
		return nil, err
	}
	h.setCookie(w, r, realm, authSessionCookie, as.ID, 0)
	return as, nil
}
