package oidc

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/otp"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// authenticatorDef is an authenticator implementation. authenticate runs
// when the flow reaches the execution, action when its form is submitted,
// direct in the direct grant flow; configuredFor backs
// conditional-user-configured.
type authenticatorDef struct {
	requiresUser  bool
	authenticate  func(*flowContext) (result, error)
	action        func(*flowContext) (result, error)
	direct        func(*flowContext) (result, error)
	configuredFor func(*flowContext, *model.User) (bool, error)
}

var authenticators map[string]*authenticatorDef

func attempted(*flowContext) (result, error)        { return resAttempted, nil }
func never(*flowContext, *model.User) (bool, error) { return false, nil }
func succeed(*flowContext) (result, error)          { return resSuccess, nil }

func init() {
	authenticators = map[string]*authenticatorDef{
		"auth-cookie":                     {authenticate: cookieAuthenticate},
		"auth-spnego":                     {authenticate: attempted},
		"identity-provider-redirector":    {authenticate: idpRedirector},
		"idp-review-profile":              {authenticate: idpReviewProfile, action: idpReviewProfileAction},
		"idp-create-user-if-unique":       {authenticate: idpCreateUserIfUnique},
		"idp-detect-existing-broker-user": {authenticate: idpDetectExistingUser},
		"idp-auto-link":                   {authenticate: idpAutoLink},
		"idp-confirm-link":                {authenticate: idpConfirmLink, action: idpConfirmLinkAction},
		"idp-email-verification":          {authenticate: idpEmailVerification},
		"idp-username-password-form": {authenticate: idpPasswordForm, action: idpPasswordAction,
			configuredFor: hasCredential(model.CredentialPassword)},
		"idp-add-organization-member": {authenticate: succeed, configuredFor: never},
		"organization":                {authenticate: attempted},
		"auth-username-password-form": {authenticate: usernamePasswordForm, action: usernamePasswordAction,
			configuredFor: hasCredential(model.CredentialPassword)},
		"auth-username-form": {authenticate: usernameForm, action: usernameAction},
		"auth-password-form": {requiresUser: true, authenticate: passwordForm, action: passwordAction,
			configuredFor: hasCredential(model.CredentialPassword)},
		"auth-otp-form":                  {requiresUser: true, authenticate: otpForm, action: otpAction, configuredFor: hasCredential(credentialOTP)},
		"direct-grant-validate-username": {direct: directUsername},
		"direct-grant-validate-password": {requiresUser: true, direct: directPassword, configuredFor: hasCredential(model.CredentialPassword)},
		"direct-grant-validate-otp":      {requiresUser: true, direct: directOTP, configuredFor: hasCredential(credentialOTP)},
		"reset-credentials-choose-user":  {authenticate: resetChooseUserForm, action: resetChooseUserAction},
		"reset-credential-email":         {authenticate: resetSendEmail},
		"reset-password":                 {requiresUser: true, authenticate: resetPasswordForm, action: resetPasswordAction},
		"reset-otp":                      {requiresUser: true, authenticate: resetOTP, configuredFor: hasCredential(credentialOTP)},
		"webauthn-authenticator": {requiresUser: true, authenticate: webauthnForm(false), action: webauthnAction(false),
			configuredFor: hasCredential(credentialWebAuthn)},
		"webauthn-authenticator-passwordless": {authenticate: webauthnForm(true), action: webauthnAction(true),
			configuredFor: hasCredential(credentialWebAuthnPasswordless)},
		"deny-access-authenticator":  {authenticate: denyAccess},
		"allow-access-authenticator": {authenticate: succeed, direct: succeed},
	}
}

const (
	credentialOTP                  = "otp"
	credentialWebAuthn             = "webauthn"
	credentialWebAuthnPasswordless = "webauthn-passwordless"
)

func hasCredential(typ string) func(*flowContext, *model.User) (bool, error) {
	return func(fc *flowContext, u *model.User) (bool, error) {
		if u == nil {
			return false, nil
		}
		creds, err := fc.h.Svc.Store.ListCredentials(fc.ctx(), u.ID)
		if err != nil {
			return false, err
		}
		for _, c := range creds {
			if c.Type == typ {
				return true, nil
			}
		}
		return false, nil
	}
}

// evalCondition evaluates a conditional-* execution of a sub flow.
func (h *Handler) evalCondition(fc *flowContext, authenticator string, cfg map[string]string, siblings []*model.AuthExecution) (bool, error) {
	if fc.user == nil {
		return false, nil
	}
	negate := cfg["negate"] == "true" || cfg["not"] == "true"
	var ok bool
	switch authenticator {
	case "conditional-user-configured":
		var err error
		if ok, err = h.configured(fc, siblings); err != nil {
			return false, err
		}
	case "conditional-user-role":
		roles, err := h.Svc.EffectiveRoles(fc.ctx(), fc.realm.ID, fc.user.ID)
		if err != nil {
			return false, err
		}
		want := cfg["condUserRole"]
		for _, r := range roles {
			name := r.Name
			if r.ClientID != "" {
				if c, err := h.Svc.Store.GetClient(fc.ctx(), fc.realm.ID, r.ClientID); err == nil {
					name = c.ClientID + "." + r.Name
				}
			}
			ok = ok || name == want
		}
	case "conditional-user-attribute":
		for _, v := range fc.user.Attributes[cfg["attribute_name"]] {
			ok = ok || v == cfg["attribute_expected_value"]
		}
	default:
		return false, nil
	}
	return ok != negate, nil
}

// ---------------------------------------------------------------- cookie

func cookieAuthenticate(fc *flowContext) (result, error) {
	if strings.Contains(fc.as.Params["prompt"], "login") {
		return resAttempted, nil
	}
	us, user := fc.h.ssoSession(fc.r, fc.realm)
	if us == nil {
		return resAttempted, nil
	}
	if ma := fc.as.Params["max_age"]; ma != "" {
		if n, err := strconv.Atoi(ma); err == nil && fc.h.Svc.Now().Sub(us.Started) > time.Duration(n)*time.Second {
			return resAttempted, nil
		}
	}
	fc.user, fc.sso = user, us
	return resSuccess, nil
}

// ---------------------------------------------------------------- username / password

func (fc *flowContext) loginEvent(username string) *eventInfo {
	return &eventInfo{client: fc.client, details: map[string]string{"auth_method": "openid-connect", "auth_type": "code",
		"redirect_uri": fc.as.Params["redirect_uri"], "username": username}}
}

func (fc *flowContext) renderLogin(page, username, errMsg string, status int) (result, error) {
	label := "username"
	if fc.realm.LoginWithEmailAllowed {
		label = "usernameOrEmail"
	}
	if fc.realm.Settings.RegistrationEmailAsUsername {
		label = "email"
	}
	if errMsg == "" && fc.as.Params[keyFlashError] != "" {
		errMsg = fc.as.Params[keyFlashError]
	}
	delete(fc.as.Params, keyFlashError)
	d := pageData{realm: fc.realm, r: fc.r, user: fc.user, Title: "loginAccountTitle", Error: errMsg, Username: username,
		UsernameLabel: label, Action: fc.actionURL(), RememberMe: fc.realm.Settings.RememberMe,
		Remembered: fc.as.Params[keyRemember] == "true", Message: fc.message, MessageArgs: fc.messageArgs}
	if page == "login" || page == "login-username" {
		d.Providers = fc.h.loginProviders(fc.r, fc.realm, fc.as)
	}
	if fc.realm.RegistrationAllowed {
		d.RegisterURL = fc.h.loginActionURL(fc.r, fc.realm, "registration", fc.as.ID)
	}
	if fc.realm.Settings.ResetPasswordAllowed {
		d.ResetURL = fc.h.loginActionURL(fc.r, fc.realm, "reset-credentials", fc.as.ID)
	}
	if fc.user != nil && page == "login-password" {
		d.Username = fc.user.Username
		d.RestartURL = fc.h.loginActionURL(fc.r, fc.realm, "restart", fc.as.ID)
	}
	fc.h.render(fc.w, status, page, d)
	return resChallenge, nil
}

func usernamePasswordForm(fc *flowContext) (result, error) {
	return fc.renderLogin("login", fc.as.Params["login_hint"], "", http.StatusOK)
}

// identify resolves the username field of a login form and checks that the
// user may log in; it renders the form again on failure.
func (fc *flowContext) identify(page, username string) (*model.User, result, error) {
	ev := fc.loginEvent(username)
	fail := func(code, msg string) (*model.User, result, error) {
		ev.err = code
		fc.h.event(fc.r, fc.realm, "LOGIN_ERROR", ev)
		res, err := fc.renderLogin(page, username, msg, http.StatusUnauthorized)
		return nil, res, err
	}
	user, err := fc.h.Svc.FindLoginUser(fc.ctx(), fc.realm, username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, 0, err
	}
	if user == nil {
		return fail("user_not_found", "invalidUserMessage")
	}
	ev.userID = user.ID
	if !user.Enabled {
		return fail("user_disabled", "accountDisabledMessage")
	}
	locked, err := fc.h.Svc.TemporarilyLocked(fc.ctx(), fc.realm, user)
	if err != nil {
		return nil, 0, err
	}
	if locked {
		return fail("user_temporarily_disabled", "invalidUserMessage")
	}
	return user, resSuccess, nil
}

// checkPassword verifies a password with brute force accounting and
// renders page with an error on failure.
func (fc *flowContext) checkPassword(page string, user *model.User, pw string) (result, error) {
	ok, err := fc.h.Svc.CheckPassword(fc.ctx(), user, pw)
	if err != nil {
		return 0, err
	}
	if !ok {
		if err := fc.h.Svc.LoginFailed(fc.ctx(), fc.realm, user, clientIP(fc.r)); err != nil {
			return 0, err
		}
		ev := fc.loginEvent(user.Username)
		ev.userID, ev.err = user.ID, "invalid_user_credentials"
		fc.h.event(fc.r, fc.realm, "LOGIN_ERROR", ev)
		return fc.renderLogin(page, user.Username, "invalidUserMessage", http.StatusUnauthorized)
	}
	if err := fc.h.Svc.LoginSucceeded(fc.ctx(), fc.realm, user); err != nil {
		return 0, err
	}
	return resSuccess, fc.h.checkPasswordExpiry(fc.r, fc.realm, user)
}

func (fc *flowContext) rememberMe() {
	if fc.realm.Settings.RememberMe && fc.r.PostFormValue("rememberMe") == "on" {
		fc.as.Params[keyRemember] = "true"
	} else {
		delete(fc.as.Params, keyRemember)
	}
}

func usernamePasswordAction(fc *flowContext) (result, error) {
	username := strings.TrimSpace(fc.r.PostFormValue("username"))
	user, res, err := fc.identify("login", username)
	if user == nil {
		return res, err
	}
	if res, err := fc.checkPassword("login", user, fc.r.PostFormValue("password")); res != resSuccess || err != nil {
		return res, err
	}
	fc.rememberMe()
	fc.user = user
	return resSuccess, nil
}

func usernameForm(fc *flowContext) (result, error) {
	return fc.renderLogin("login-username", fc.as.Params["login_hint"], "", http.StatusOK)
}

func usernameAction(fc *flowContext) (result, error) {
	user, res, err := fc.identify("login-username", strings.TrimSpace(fc.r.PostFormValue("username")))
	if user == nil {
		return res, err
	}
	fc.rememberMe()
	fc.user = user
	return resSuccess, nil
}

func passwordForm(fc *flowContext) (result, error) {
	return fc.renderLogin("login-password", "", "", http.StatusOK)
}

func passwordAction(fc *flowContext) (result, error) {
	locked, err := fc.h.Svc.TemporarilyLocked(fc.ctx(), fc.realm, fc.user)
	if err != nil {
		return 0, err
	}
	if locked || !fc.user.Enabled {
		return fc.renderLogin("login-password", "", "invalidUserMessage", http.StatusUnauthorized)
	}
	return fc.checkPassword("login-password", fc.user, fc.r.PostFormValue("password"))
}

// ---------------------------------------------------------------- OTP

func otpCredentials(fc *flowContext, u *model.User) ([]*model.Credential, error) {
	creds, err := fc.h.Svc.Store.ListCredentials(fc.ctx(), u.ID)
	if err != nil {
		return nil, err
	}
	var out []*model.Credential
	for _, c := range creds {
		if c.Type == credentialOTP {
			out = append(out, c)
		}
	}
	return out, nil
}

func otpForm(fc *flowContext) (result, error) {
	ok, err := hasCredential(credentialOTP)(fc, fc.user)
	if err != nil {
		return 0, err
	}
	if !ok {
		if fc.exec.Requirement == model.Required {
			// a required OTP the user has not set up yet: ask for it
			return resSuccess, fc.h.addRequiredAction(fc, service.ActionConfigureTOTP)
		}
		return resAttempted, nil
	}
	return fc.renderOTP("", http.StatusOK)
}

func (fc *flowContext) renderOTP(errMsg string, status int) (result, error) {
	fc.h.render(fc.w, status, "login-otp", pageData{realm: fc.realm, r: fc.r, user: fc.user, Title: "loginAccountTitle",
		Error: errMsg, Action: fc.actionURL()})
	return resChallenge, nil
}

// verifyOTP checks a code against the user's OTP credentials, enforcing the
// realm's code reuse policy.
func (h *Handler) verifyOTP(fc *flowContext, u *model.User, code string) (bool, error) {
	creds, err := otpCredentials(fc, u)
	if err != nil || code == "" {
		return false, err
	}
	policy := fc.realm.Settings
	for _, c := range creds {
		var sd otp.SecretData
		var cd otp.CredentialData
		if jsonUnmarshal(c.SecretData, &sd) != nil || jsonUnmarshal(c.CredentialData, &cd) != nil {
			continue
		}
		if cd.SubType == "hotp" {
			next, ok := otp.ValidateHOTP(code, sd.Value, cd, policy.OTPPolicyLookAheadWindow)
			if !ok {
				continue
			}
			cd.Counter = next
			return true, h.Svc.Store.UpdateCredentialSecret(fc.ctx(), c.ID, c.SecretData, jsonString(cd))
		}
		if !otp.ValidateTOTP(code, sd.Value, cd, policy.OTPPolicyLookAheadWindow, h.Svc.Now()) {
			continue
		}
		if !policy.OTPPolicyCodeReusable {
			key := "otp:" + c.ID + ":" + code
			used, err := h.Svc.Store.IsTokenRevoked(fc.ctx(), key)
			if err != nil || used {
				return false, err
			}
			period := cd.Period
			if period <= 0 {
				period = 30
			}
			ttl := time.Duration(period*(2*policy.OTPPolicyLookAheadWindow+1)) * time.Second
			if err := h.Svc.Store.RevokeToken(fc.ctx(), key, h.Svc.Now().Add(ttl)); err != nil {
				return false, err
			}
		}
		return true, nil
	}
	return false, nil
}

func otpAction(fc *flowContext) (result, error) {
	ok, err := fc.h.verifyOTP(fc, fc.user, strings.TrimSpace(fc.r.PostFormValue("otp")))
	if err != nil {
		return 0, err
	}
	if !ok {
		if err := fc.h.Svc.LoginFailed(fc.ctx(), fc.realm, fc.user, clientIP(fc.r)); err != nil {
			return 0, err
		}
		ev := fc.loginEvent(fc.user.Username)
		ev.userID, ev.err = fc.user.ID, "invalid_user_credentials"
		fc.h.event(fc.r, fc.realm, "LOGIN_ERROR", ev)
		return fc.renderOTP("invalidTotpMessage", http.StatusUnauthorized)
	}
	return resSuccess, nil
}

// ---------------------------------------------------------------- direct grant

func (fc *flowContext) directFail(code string, err *oauthError) (result, error) {
	ev := &eventInfo{client: fc.client, err: code, details: map[string]string{"grant_type": "password", "auth_method": "openid-connect",
		"username": fc.r.PostFormValue("username")}}
	if fc.user != nil {
		ev.userID = fc.user.ID
	}
	fc.h.event(fc.r, fc.realm, "LOGIN_ERROR", ev)
	fc.directErr = err
	return resFailed, nil
}

func directUsername(fc *flowContext) (result, error) {
	username := fc.r.PostFormValue("username")
	if username == "" {
		return fc.directFail("user_not_found", &oauthError{http.StatusUnauthorized, "invalid_request", "Missing parameter: username"})
	}
	user, err := fc.h.Svc.FindLoginUser(fc.ctx(), fc.realm, username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fc.directFail("user_not_found", errInvalidCredentials())
		}
		return 0, err
	}
	fc.user = user
	if !user.Enabled {
		return fc.directFail("user_disabled", errInvalidGrant("Account disabled"))
	}
	locked, err := fc.h.Svc.TemporarilyLocked(fc.ctx(), fc.realm, user)
	if err != nil {
		return 0, err
	}
	if locked {
		return fc.directFail("user_temporarily_disabled", errInvalidCredentials())
	}
	return resSuccess, nil
}

func directPassword(fc *flowContext) (result, error) {
	ok, err := fc.h.Svc.CheckPassword(fc.ctx(), fc.user, fc.r.PostFormValue("password"))
	if err != nil {
		return 0, err
	}
	if !ok {
		if err := fc.h.Svc.LoginFailed(fc.ctx(), fc.realm, fc.user, clientIP(fc.r)); err != nil {
			return 0, err
		}
		return fc.directFail("invalid_user_credentials", errInvalidCredentials())
	}
	return resSuccess, fc.h.Svc.LoginSucceeded(fc.ctx(), fc.realm, fc.user)
}

func directOTP(fc *flowContext) (result, error) {
	ok, err := fc.h.verifyOTP(fc, fc.user, strings.TrimSpace(fc.r.PostFormValue("totp")))
	if err != nil {
		return 0, err
	}
	if !ok {
		if err := fc.h.Svc.LoginFailed(fc.ctx(), fc.realm, fc.user, clientIP(fc.r)); err != nil {
			return 0, err
		}
		return fc.directFail("invalid_user_credentials", errInvalidCredentials())
	}
	return resSuccess, nil
}

// ---------------------------------------------------------------- reset credentials

func (fc *flowContext) renderReset(errMsg string, status int) (result, error) {
	label := "usernameOrEmail"
	if fc.realm.Settings.RegistrationEmailAsUsername {
		label = "email"
	}
	fc.h.render(fc.w, status, "login-reset-password", pageData{realm: fc.realm, r: fc.r, user: fc.user, Title: "emailForgotTitle",
		Error: errMsg, UsernameLabel: label, Action: fc.actionURL(),
		Message:  "emailInstruction",
		LoginURL: fc.h.loginActionURL(fc.r, fc.realm, "restart", fc.as.ID)})
	return resChallenge, nil
}

func resetChooseUserForm(fc *flowContext) (result, error) {
	if fc.user != nil || fc.as.Params[keyNoUser] == "true" {
		return resSuccess, nil
	}
	return fc.renderReset("", http.StatusOK)
}

func resetChooseUserAction(fc *flowContext) (result, error) {
	ident := strings.TrimSpace(fc.r.PostFormValue("username"))
	if ident == "" {
		return fc.renderReset("missingUsernameMessage", http.StatusBadRequest)
	}
	user, err := fc.h.Svc.Store.GetUserByUsername(fc.ctx(), fc.realm.ID, ident)
	if errors.Is(err, store.ErrNotFound) {
		user, err = fc.h.Svc.Store.GetUserByEmail(fc.ctx(), fc.realm.ID, ident)
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return 0, err
	}
	if user == nil || !user.Enabled || user.ServiceAccountClientID != "" {
		// Keycloak does not reveal whether the account exists.
		fc.h.event(fc.r, fc.realm, "SEND_RESET_PASSWORD_ERROR", &eventInfo{client: fc.client, err: "user_not_found",
			details: map[string]string{"username": ident}})
		fc.as.Params[keyNoUser] = "true"
		return resSuccess, nil
	}
	fc.user = user
	return resSuccess, nil
}

func (fc *flowContext) emailSentPage() (result, error) {
	fc.h.render(fc.w, http.StatusOK, "info", pageData{realm: fc.realm, r: fc.r, user: fc.user, Title: "emailForgotTitle",
		Message: "emailSentMessage",
		LinkURL: fc.h.loginActionURL(fc.r, fc.realm, "restart", fc.as.ID), LinkText: "backToLogin"})
	return resChallenge, nil
}

func resetSendEmail(fc *flowContext) (result, error) {
	if fc.user != nil && fc.as.Params[keyResetVerified] == "true" {
		return resSuccess, nil // the emailed link was followed
	}
	if fc.user == nil {
		return fc.emailSentPage()
	}
	if fc.as.Params[keyEmailSent] == "true" {
		return fc.emailSentPage()
	}
	if fc.user.Email == "" {
		return fc.fail(errInvalidRequest("no email"), "emailSendErrorMessage")
	}
	lifespan := fc.realm.Settings.ActionTokenGeneratedByUser
	link, err := fc.h.actionTokenLink(fc.r, fc.realm, fc.client, fc.user, actionTokenClaims{typ: tokenResetCredentials,
		authSession: fc.as.ID, lifespan: lifespan})
	if err != nil {
		return 0, err
	}
	msg, err := fc.h.Svc.EmailMessage(fc.realm, fc.user, service.PasswordReset, link, lifespan, nil)
	if err != nil {
		return 0, err
	}
	if err := fc.h.Svc.SendEmail(fc.ctx(), fc.realm, msg); err != nil {
		fc.h.Log.Warn("send reset password email", "realm", fc.realm.Name, "err", err)
		fc.h.event(fc.r, fc.realm, "SEND_RESET_PASSWORD_ERROR", &eventInfo{client: fc.client, userID: fc.user.ID, err: "email_send_failed"})
		return fc.fail(errInvalidRequest("email"), "emailSendErrorMessage")
	}
	fc.as.Params[keyEmailSent] = "true"
	fc.h.event(fc.r, fc.realm, "SEND_RESET_PASSWORD", &eventInfo{client: fc.client, userID: fc.user.ID,
		details: map[string]string{"email": fc.user.Email, "username": fc.user.Username}})
	return fc.emailSentPage()
}

func resetPasswordForm(fc *flowContext) (result, error) {
	return fc.renderUpdatePassword("", nil, http.StatusOK)
}

func (fc *flowContext) renderUpdatePassword(errMsg string, errArgs []any, status int) (result, error) {
	fc.h.render(fc.w, status, "update-password", pageData{realm: fc.realm, r: fc.r, user: fc.user, Title: "updatePasswordTitle",
		Error: errMsg, ErrorArgs: errArgs, Action: fc.actionURL()})
	return resChallenge, nil
}

func resetPasswordAction(fc *flowContext) (result, error) {
	msg, args, err := fc.h.updatePassword(fc)
	if err != nil {
		return 0, err
	}
	if msg != "" {
		return fc.renderUpdatePassword(msg, args, http.StatusBadRequest)
	}
	return resSuccess, nil
}

func resetOTP(fc *flowContext) (result, error) {
	creds, err := otpCredentials(fc, fc.user)
	if err != nil {
		return 0, err
	}
	for _, c := range creds {
		if err := fc.h.Svc.Store.DeleteCredential(fc.ctx(), fc.user.ID, c.ID); err != nil {
			return 0, err
		}
	}
	return resSuccess, fc.h.addRequiredAction(fc, service.ActionConfigureTOTP)
}

// ---------------------------------------------------------------- access

func denyAccess(fc *flowContext) (result, error) {
	msg := fc.config["denyErrorMessage"]
	if msg == "" {
		return fc.fail(&oauthError{http.StatusUnauthorized, "access_denied", "Access denied"}, "accessDeniedMessage")
	}
	return fc.fail(&oauthError{http.StatusUnauthorized, "access_denied", msg}, msg)
}
