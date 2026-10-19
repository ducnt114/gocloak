package oidc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"image/png"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"rsc.io/qr"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/otp"
	"github.com/ducnt114/gocloak/internal/policy"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
	"github.com/ducnt114/gocloak/internal/userprofile"
)

func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// requiredActionURL is where a required action page posts to.
func (fc *flowContext) requiredActionURL(alias string) string {
	return fc.h.loginActionURL(fc.r, fc.realm, "required-action", fc.as.ID) + "&execution=" + alias
}

// addRequiredAction adds a required action to the user, persistently.
func (h *Handler) addRequiredAction(fc *flowContext, alias string) error {
	if !slices.Contains(fc.user.RequiredActions, alias) {
		fc.user.RequiredActions = append(fc.user.RequiredActions, alias)
		if err := h.Svc.Store.UpdateUser(fc.ctx(), fc.user); err != nil {
			return err
		}
	}
	if fc.as.Params[keyActions] != "" && !slices.Contains(strings.Fields(fc.as.Params[keyActions]), alias) {
		fc.as.Params[keyActions] += " " + alias
	}
	return nil
}

// pendingActions computes the required actions of the login: the user's
// own, plus those triggered by the realm (incomplete profile, unverified
// email, application initiated kc_action), ordered by provider priority.
// Disabled providers are ignored, as in Keycloak.
func (h *Handler) pendingActions(fc *flowContext) ([]string, error) {
	providers, err := h.Svc.Store.ListRequiredActions(fc.ctx(), fc.realm.ID)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, a := range fc.user.RequiredActions {
		want[a] = true
	}
	if incomplete, err := h.Svc.ProfileIncomplete(fc.ctx(), fc.realm, fc.user); err != nil {
		return nil, err
	} else if incomplete {
		want[service.ActionVerifyProfile] = true
	}
	if fc.realm.Settings.VerifyEmail && !fc.user.EmailVerified && fc.user.Email != "" {
		want[service.ActionVerifyEmail] = true
	}
	if a := fc.as.Params["kc_action"]; a != "" {
		want[a] = true
	}
	var out []string
	for _, p := range providers {
		if want[p.Alias] && p.Enabled {
			out = append(out, p.Alias)
		}
	}
	return out, nil
}

// afterAuthentication runs once the flow identified and authenticated the
// user: required actions first, then the redirect back to the client.
func (h *Handler) afterAuthentication(fc *flowContext) {
	if fc.user == nil {
		h.errorPage(fc.w, fc.r, http.StatusBadRequest, "invalidFlowMessage")
		return
	}
	if !fc.user.Enabled {
		h.errorPage(fc.w, fc.r, http.StatusBadRequest, "accountDisabledMessage")
		return
	}
	if fc.as.Params[keyActions] == "" {
		pending, err := h.pendingActions(fc)
		if err != nil {
			h.serverErrorPage(fc.w, fc.r, err)
			return
		}
		fc.as.Params[keyActions] = strings.Join(append([]string{"-"}, pending...), " ")
		if err := fc.save(); err != nil {
			h.serverErrorPage(fc.w, fc.r, err)
			return
		}
	}
	h.processRequiredActions(fc, "")
}

// processRequiredActions renders the next pending required action, or
// processes the submitted one (posted), and finishes the login when none is left.
func (h *Handler) processRequiredActions(fc *flowContext, posted string) {
	for {
		pending := strings.Fields(fc.as.Params[keyActions])
		next := ""
		for _, a := range pending {
			if a != "-" {
				next = a
				break
			}
		}
		if next == "" {
			break
		}
		ra := requiredActions[next]
		var res result
		var err error
		switch {
		case ra == nil:
			res = resSuccess // not implemented: skip it, as Keycloak does for unknown providers
		case posted == next && fc.r.Method == http.MethodPost:
			posted = ""
			res, err = ra.action(fc)
		default:
			res, err = ra.challenge(fc)
		}
		if err != nil {
			h.serverErrorPage(fc.w, fc.r, err)
			return
		}
		if res != resSuccess {
			if err := fc.save(); err != nil {
				h.serverErrorPage(fc.w, fc.r, err)
			}
			return
		}
		if err := h.completeAction(fc, next); err != nil {
			h.serverErrorPage(fc.w, fc.r, err)
			return
		}
	}
	h.finishAuthentication(fc)
}

// completeAction removes a done action from the login and from the user.
func (h *Handler) completeAction(fc *flowContext, alias string) error {
	pending := strings.Fields(fc.as.Params[keyActions])
	fc.as.Params[keyActions] = strings.Join(slices.DeleteFunc(pending, func(a string) bool { return a == alias }), " ")
	if fc.as.Params[keyActions] == "" {
		fc.as.Params[keyActions] = "-"
	}
	if slices.Contains(fc.user.RequiredActions, alias) {
		fc.user.RequiredActions = slices.DeleteFunc(fc.user.RequiredActions, func(a string) bool { return a == alias })
		if err := h.Svc.Store.UpdateUser(fc.ctx(), fc.user); err != nil {
			return err
		}
	}
	delete(fc.as.Params, "kc_action")
	return fc.save()
}

// finishAuthentication completes the login: back to the client with a
// code, or, for admin requested actions, to the given redirect or a page.
func (h *Handler) finishAuthentication(fc *flowContext) {
	ctx := fc.ctx()
	if err := h.Svc.Store.DeleteAuthSession(ctx, fc.as.ID); err != nil {
		h.serverErrorPage(fc.w, fc.r, err)
		return
	}
	h.clearCookie(fc.w, fc.r, fc.realm, authSessionCookie)
	if fc.as.Params[keyMode] == modeExecution {
		if redirect := fc.as.Params["redirect_uri"]; redirect != "" {
			http.Redirect(fc.w, fc.r, redirect, http.StatusFound)
			return
		}
		h.render(fc.w, http.StatusOK, "info", pageData{realm: fc.realm, r: fc.r, user: fc.user, Title: "accountUpdatedMessage"})
		return
	}
	h.finishLogin(fc.w, fc.r, fc.realm, fc.client, fc.user, fc.sso, fc.as.Params)
}

// requiredActionEndpoint serves /login-actions/required-action.
func (h *Handler) requiredActionEndpoint(w http.ResponseWriter, r *http.Request) {
	realm, err := h.realm(r)
	if err != nil {
		h.errorPage(w, r, http.StatusNotFound, "realmNotFoundMessage")
		return
	}
	as, client, err := h.loadAuthSession(r, realm)
	if err != nil || as.UserID == "" {
		h.errorPage(w, r, http.StatusBadRequest, "loginTimeout")
		return
	}
	user, err := h.Svc.Store.GetUser(r.Context(), realm.ID, as.UserID)
	if err != nil {
		h.errorPage(w, r, http.StatusBadRequest, "userNotFoundMessage")
		return
	}
	fc := &flowContext{h: h, w: w, r: r, realm: realm, client: client, as: as, user: user}
	if as.Params[keyFlow] == "browser" || as.Params[keyFlow] == "" {
		fc.sso, _ = h.ssoSession(r, realm)
	}
	if as.Params[keyActions] == "" {
		h.afterAuthentication(fc)
		return
	}
	h.processRequiredActions(fc, r.URL.Query().Get("execution"))
}

// ---------------------------------------------------------------- actions

type requiredActionDef struct {
	challenge func(*flowContext) (result, error)
	action    func(*flowContext) (result, error)
}

var requiredActions map[string]*requiredActionDef

func init() {
	requiredActions = map[string]*requiredActionDef{
		service.ActionUpdatePassword:      {challenge: updatePasswordPage, action: updatePasswordAction},
		service.ActionUpdateProfile:       {challenge: profilePage(false), action: profileAction},
		service.ActionVerifyProfile:       {challenge: profilePage(true), action: profileAction},
		service.ActionVerifyEmail:         {challenge: verifyEmailPage, action: verifyEmailPage},
		service.ActionConfigureTOTP:       {challenge: configureTOTPPage, action: configureTOTPAction},
		service.ActionTermsAndConditions:  {challenge: termsPage, action: termsAction},
		service.ActionUpdateEmail:         {challenge: updateEmailPage, action: updateEmailAction},
		service.ActionWebAuthnRegister:    {challenge: webauthnRegisterPage(false), action: webauthnRegisterAction(false)},
		service.ActionWebAuthnPasswordles: {challenge: webauthnRegisterPage(true), action: webauthnRegisterAction(true)},
	}
}

// updatePassword applies the password-new / password-confirm form and
// returns the message key (and arguments) to show when it is rejected.
func (h *Handler) updatePassword(fc *flowContext) (string, []any, error) {
	pw, confirm := fc.r.PostFormValue("password-new"), fc.r.PostFormValue("password-confirm")
	switch {
	case pw == "":
		return "missingPasswordMessage", nil, nil
	case pw != confirm:
		return "notMatchPasswordMessage", nil, nil
	}
	if err := h.Svc.SetPassword(fc.ctx(), h.Svc.Store, fc.user, pw, false); err != nil {
		var pe *policy.Error
		if errors.As(err, &pe) {
			h.event(fc.r, fc.realm, "UPDATE_PASSWORD_ERROR", &eventInfo{client: fc.client, userID: fc.user.ID, err: "password_rejected"})
			return pe.Key, pe.Args, nil
		}
		return "", nil, err
	}
	h.event(fc.r, fc.realm, "UPDATE_PASSWORD", &eventInfo{client: fc.client, userID: fc.user.ID})
	return "", nil, nil
}

func updatePasswordPage(fc *flowContext) (result, error) {
	fc.h.render(fc.w, http.StatusOK, "update-password", pageData{realm: fc.realm, r: fc.r, user: fc.user, Title: "updatePasswordTitle",
		Message: "updatePasswordMessage", Action: fc.requiredActionURL(service.ActionUpdatePassword)})
	return resChallenge, nil
}

func updatePasswordAction(fc *flowContext) (result, error) {
	msg, args, err := fc.h.updatePassword(fc)
	if err != nil {
		return 0, err
	}
	if msg != "" {
		fc.h.render(fc.w, http.StatusBadRequest, "update-password", pageData{realm: fc.realm, r: fc.r, user: fc.user, Title: "updatePasswordTitle",
			Error: msg, ErrorArgs: args, Action: fc.requiredActionURL(service.ActionUpdatePassword)})
		return resChallenge, nil
	}
	return resSuccess, nil
}

// ---------------------------------------------------------------- profile

// coreLabels are the message keys of the core attributes.
var coreLabels = map[string]string{"username": "username", "email": "email", "firstName": "firstName", "lastName": "lastName"}

// profileFields builds the form fields of the user profile in the user
// context; values come from the user or a submitted form.
func (h *Handler) profileFields(fc *flowContext, cfg *userprofile.Config, values map[string][]string, errs userprofile.Errors, registration bool) []profileField {
	var fields []profileField
	errBy := map[string]userprofile.FieldError{}
	for _, e := range errs {
		if _, ok := errBy[e.Field]; !ok {
			errBy[e.Field] = e
		}
	}
	for _, a := range cfg.Attributes {
		if !cfg.CanView(a.Name, userprofile.ContextUser) {
			continue
		}
		if a.Name == "username" && fc.realm.Settings.RegistrationEmailAsUsername {
			continue
		}
		label := coreLabels[a.Name]
		if label == "" {
			label = a.DisplayName
			if strings.HasPrefix(label, "${") && strings.HasSuffix(label, "}") {
				label = label[2 : len(label)-1] // a message key
			} else if label == "" {
				label = a.Name
			}
		}
		readOnly := !cfg.CanEdit(a.Name, userprofile.ContextUser) ||
			(a.Name == "username" && !registration && !fc.realm.Settings.EditUsernameAllowed)
		typ := "text"
		if a.Name == "email" {
			typ = "email"
		}
		required := a.Required != nil && (len(a.Required.Roles) == 0 || slices.Contains(a.Required.Roles, userprofile.ContextUser))
		val := ""
		if v := values[a.Name]; len(v) > 0 {
			val = v[0]
		}
		fe := errBy[a.Name]
		fields = append(fields, profileField{Name: a.Name, Label: label, Type: typ, Value: val, Error: fe.ErrorMessage, ErrorArgs: fe.Params,
			Required: required || a.Name == "username", ReadOnly: readOnly})
	}
	return fields
}

func profilePage(verify bool) func(*flowContext) (result, error) {
	return func(fc *flowContext) (result, error) {
		cfg, err := fc.h.Svc.UserProfile(fc.ctx(), fc.h.Svc.Store, fc.realm)
		if err != nil {
			return 0, err
		}
		values := service.ProfileValues(fc.user)
		errs := cfg.Validate(values, userprofile.ContextUser, nil)
		if verify && len(errs) == 0 {
			return resSuccess, nil
		}
		alias := service.ActionUpdateProfile
		if verify {
			alias = service.ActionVerifyProfile
			errs = nil // do not show errors before the user edits the form
		}
		fc.h.render(fc.w, http.StatusOK, "update-profile", pageData{realm: fc.realm, r: fc.r, user: fc.user, Title: "loginProfileTitle",
			Message: "updateProfileMessage", Action: fc.requiredActionURL(alias),
			Profile: fc.h.profileFields(fc, cfg, values, errs, false)})
		return resChallenge, nil
	}
}

// formProfileValues reads the submitted profile fields.
func formProfileValues(r *http.Request, cfg *userprofile.Config, base map[string][]string) map[string][]string {
	r.ParseForm()
	values := map[string][]string{}
	for k, v := range base {
		values[k] = v
	}
	for _, a := range cfg.Attributes {
		if !cfg.CanEdit(a.Name, userprofile.ContextUser) {
			continue
		}
		if v, ok := r.PostForm[a.Name]; ok {
			values[a.Name] = []string{strings.TrimSpace(v[0])}
		}
	}
	return values
}

// applyProfile writes profile values to a user (core attributes to their
// fields, others to attributes), keeping attributes the profile does not manage.
func applyProfile(u *model.User, cfg *userprofile.Config, values map[string][]string, allowUsername bool) {
	first := func(k string) string {
		if v := values[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	if allowUsername && first("username") != "" {
		u.Username = first("username")
	}
	u.Email, u.FirstName, u.LastName = strings.ToLower(first("email")), first("firstName"), first("lastName")
	if u.Attributes == nil {
		u.Attributes = map[string][]string{}
	}
	for _, a := range cfg.Attributes {
		if userprofile.IsCore(a.Name) || !cfg.CanEdit(a.Name, userprofile.ContextUser) {
			continue
		}
		if v := values[a.Name]; len(v) > 0 && v[0] != "" {
			u.Attributes[a.Name] = v
		} else {
			delete(u.Attributes, a.Name)
		}
	}
}

func profileAction(fc *flowContext) (result, error) {
	cfg, err := fc.h.Svc.UserProfile(fc.ctx(), fc.h.Svc.Store, fc.realm)
	if err != nil {
		return 0, err
	}
	values := formProfileValues(fc.r, cfg, service.ProfileValues(fc.user))
	if !fc.realm.Settings.EditUsernameAllowed {
		values["username"] = []string{fc.user.Username}
	}
	errs := cfg.Validate(values, userprofile.ContextUser, nil)
	u := *fc.user
	oldEmail := u.Email
	applyProfile(&u, cfg, values, fc.realm.Settings.EditUsernameAllowed)
	if len(errs) == 0 {
		if u.Email != oldEmail {
			u.EmailVerified = false
		}
		err := fc.h.Svc.UpdateUser(fc.ctx(), fc.h.Svc.Store, &u)
		var conflict bool
		if errors.Is(err, store.ErrConflict) {
			field, key := "username", "usernameExistsMessage"
			if strings.Contains(err.Error(), "email") {
				field, key = "email", "emailExistsMessage"
			}
			errs = append(errs, userprofile.FieldError{Field: field, ErrorMessage: key})
			conflict = true
		} else if err != nil {
			return 0, err
		}
		if !conflict {
			*fc.user = u
			fc.h.event(fc.r, fc.realm, "UPDATE_PROFILE", &eventInfo{client: fc.client, userID: u.ID})
			return resSuccess, nil
		}
	}
	alias := fc.r.URL.Query().Get("execution")
	fc.h.render(fc.w, http.StatusBadRequest, "update-profile", pageData{realm: fc.realm, r: fc.r, user: fc.user, Title: "loginProfileTitle",
		Action: fc.requiredActionURL(alias), Profile: fc.h.profileFields(fc, cfg, values, errs, false)})
	return resChallenge, nil
}

// ---------------------------------------------------------------- verify email

func verifyEmailPage(fc *flowContext) (result, error) {
	if fc.user.EmailVerified || fc.user.Email == "" {
		return resSuccess, nil
	}
	resend := fc.r.URL.Query().Get("resend") == "true"
	if fc.as.Params[keyEmailSent] != "verify" || resend {
		lifespan := fc.realm.Settings.ActionTokenGeneratedByUser
		link, err := fc.h.actionTokenLink(fc.r, fc.realm, fc.client, fc.user, actionTokenClaims{typ: tokenVerifyEmail,
			authSession: fc.as.ID, email: fc.user.Email, lifespan: lifespan})
		if err != nil {
			return 0, err
		}
		msg, err := fc.h.Svc.EmailMessage(fc.realm, fc.user, service.EmailVerification, link, lifespan, nil)
		if err != nil {
			return 0, err
		}
		if err := fc.h.Svc.SendEmail(fc.ctx(), fc.realm, msg); err != nil {
			fc.h.Log.Warn("send verification email", "realm", fc.realm.Name, "err", err)
			fc.h.event(fc.r, fc.realm, "SEND_VERIFY_EMAIL_ERROR", &eventInfo{client: fc.client, userID: fc.user.ID, err: "email_send_failed"})
			return fc.fail(errInvalidRequest("email"), "emailSendErrorMessage")
		}
		fc.as.Params[keyEmailSent] = "verify"
		fc.h.event(fc.r, fc.realm, "SEND_VERIFY_EMAIL", &eventInfo{client: fc.client, userID: fc.user.ID,
			details: map[string]string{"email": fc.user.Email}})
	}
	fc.h.render(fc.w, http.StatusOK, "info", pageData{realm: fc.realm, r: fc.r, user: fc.user, Title: "emailVerifyTitle",
		Message:  "emailVerifyInstruction1",
		LinkURL:  fc.requiredActionURL(service.ActionVerifyEmail) + "&resend=true",
		LinkText: "emailVerifyResend"})
	return resChallenge, nil
}

// ---------------------------------------------------------------- OTP

func (fc *flowContext) otpPolicy() otp.Policy {
	s := fc.realm.Settings
	return otp.Policy{Type: s.OTPPolicyType, Algorithm: s.OTPPolicyAlgorithm, Digits: s.OTPPolicyDigits,
		Period: s.OTPPolicyPeriod, LookAhead: s.OTPPolicyLookAheadWindow, Counter: s.OTPPolicyInitialCounter}
}

func qrDataURI(content string) (string, error) {
	code, err := qr.Encode(content, qr.M)
	if err != nil {
		return "", err
	}
	code.Scale = 4
	var buf bytes.Buffer
	if err := png.Encode(&buf, code.Image()); err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func (fc *flowContext) renderConfigureTOTP(errMsg string, status int) (result, error) {
	secret := fc.as.Params[keyOTPSecret]
	if secret == "" {
		secret = otp.GenerateSecret()
		fc.as.Params[keyOTPSecret] = secret
	}
	p := fc.otpPolicy()
	uri := otp.KeyURI(secret, realmTitle(fc.realm), fc.user.Username, p)
	img, err := qrDataURI(uri)
	if err != nil {
		return 0, err
	}
	fc.h.render(fc.w, status, "configure-totp", pageData{realm: fc.realm, r: fc.r, user: fc.user, Title: "loginTotpTitle",
		Error: errMsg, Action: fc.requiredActionURL(service.ActionConfigureTOTP),
		OTP: &otpSetup{QR: template.URL(img), Secret: spaced(otp.Base32(secret)), Type: p.Type, Algorithm: strings.TrimPrefix(p.Algorithm, "Hmac"),
			Digits: p.Digits, Period: p.Period, Counter: p.Counter}})
	return resChallenge, nil
}

func spaced(s string) string {
	var parts []string
	for len(s) > 4 {
		parts = append(parts, s[:4])
		s = s[4:]
	}
	return strings.Join(append(parts, s), " ")
}

func configureTOTPPage(fc *flowContext) (result, error) {
	return fc.renderConfigureTOTP("", http.StatusOK)
}

func configureTOTPAction(fc *flowContext) (result, error) {
	secret := fc.as.Params[keyOTPSecret]
	code := strings.TrimSpace(fc.r.PostFormValue("totp"))
	if secret == "" {
		return fc.renderConfigureTOTP("", http.StatusOK)
	}
	if code == "" {
		return fc.renderConfigureTOTP("missingTotpMessage", http.StatusBadRequest)
	}
	p := fc.otpPolicy()
	cd := otp.CredentialData{SubType: p.Type, Digits: p.Digits, Counter: p.Counter, Period: p.Period, Algorithm: p.Algorithm}
	ok := false
	if p.Type == "hotp" {
		var next int
		if next, ok = otp.ValidateHOTP(code, secret, cd, p.LookAhead); ok {
			p.Counter = next
		}
	} else {
		ok = otp.ValidateTOTP(code, secret, cd, p.LookAhead, fc.h.Svc.Now())
	}
	if !ok {
		fc.h.event(fc.r, fc.realm, "UPDATE_TOTP_ERROR", &eventInfo{client: fc.client, userID: fc.user.ID, err: "invalid_totp"})
		return fc.renderConfigureTOTP("invalidTotpMessage", http.StatusBadRequest)
	}
	sd, cdJSON := otp.Credential(secret, p)
	if err := fc.h.Svc.Store.CreateCredential(fc.ctx(), &model.Credential{ID: service.NewID(), UserID: fc.user.ID, Type: credentialOTP,
		UserLabel: strings.TrimSpace(fc.r.PostFormValue("userLabel")), SecretData: sd, CredentialData: cdJSON,
		CreatedDate: fc.h.Svc.Now().UnixMilli(), Priority: 20}); err != nil {
		return 0, err
	}
	delete(fc.as.Params, keyOTPSecret)
	fc.h.event(fc.r, fc.realm, "UPDATE_TOTP", &eventInfo{client: fc.client, userID: fc.user.ID})
	return resSuccess, nil
}

// ---------------------------------------------------------------- terms

func termsPage(fc *flowContext) (result, error) {
	fc.h.render(fc.w, http.StatusOK, "terms", pageData{realm: fc.realm, r: fc.r, user: fc.user, Title: "termsTitle",
		Message: "termsText", Action: fc.requiredActionURL(service.ActionTermsAndConditions)})
	return resChallenge, nil
}

func termsAction(fc *flowContext) (result, error) {
	if fc.r.PostFormValue("cancel") != "" {
		return fc.fail(&oauthError{http.StatusBadRequest, "access_denied", "terms declined"}, "termsDeclinedMessage")
	}
	if fc.user.Attributes == nil {
		fc.user.Attributes = map[string][]string{}
	}
	fc.user.Attributes["terms_and_conditions"] = []string{strconv.FormatInt(fc.h.Svc.Now().Unix(), 10)}
	return resSuccess, fc.h.Svc.Store.UpdateUser(fc.ctx(), fc.user)
}

// ---------------------------------------------------------------- update email

func updateEmailPage(fc *flowContext) (result, error) {
	fc.h.render(fc.w, http.StatusOK, "update-email", pageData{realm: fc.realm, r: fc.r, user: fc.user, Title: "emailUpdateTitle",
		Username: fc.user.Email, Action: fc.requiredActionURL(service.ActionUpdateEmail)})
	return resChallenge, nil
}

func updateEmailAction(fc *flowContext) (result, error) {
	email := strings.ToLower(strings.TrimSpace(fc.r.PostFormValue("email")))
	cfg, err := fc.h.Svc.UserProfile(fc.ctx(), fc.h.Svc.Store, fc.realm)
	if err != nil {
		return 0, err
	}
	values := service.ProfileValues(fc.user)
	values["email"] = []string{email}
	errs := cfg.Validate(values, userprofile.ContextUser, nil)
	msg, var_args := "", []any(nil)
	for _, e := range errs {
		if e.Field == "email" {
			msg, var_args = e.ErrorMessage, e.Params
		}
	}
	if email == "" {
		msg = "missingEmailMessage"
	}
	if msg == "" {
		u := *fc.user
		u.Email, u.EmailVerified = email, false
		if err := fc.h.Svc.UpdateUser(fc.ctx(), fc.h.Svc.Store, &u); errors.Is(err, store.ErrConflict) {
			msg = "emailExistsMessage"
		} else if err != nil {
			return 0, err
		} else {
			*fc.user = u
			fc.h.event(fc.r, fc.realm, "UPDATE_EMAIL", &eventInfo{client: fc.client, userID: u.ID, details: map[string]string{"updated_email": email}})
			if fc.realm.Settings.VerifyEmail {
				return resSuccess, fc.h.addRequiredAction(fc, service.ActionVerifyEmail)
			}
			return resSuccess, nil
		}
	}
	fc.h.render(fc.w, http.StatusBadRequest, "update-email", pageData{realm: fc.realm, r: fc.r, user: fc.user, Title: "emailUpdateTitle",
		Username: email, Error: msg, ErrorArgs: var_args, Action: fc.requiredActionURL(service.ActionUpdateEmail)})
	return resChallenge, nil
}

// ---------------------------------------------------------------- registration

// renderRegistration renders the registration form of the form flow.
func (h *Handler) renderRegistration(fc *flowContext, actions []string, values map[string][]string, errs userprofile.Errors) (result, error) {
	cfg, err := h.Svc.UserProfile(fc.ctx(), h.Svc.Store, fc.realm)
	if err != nil {
		return 0, err
	}
	d := pageData{realm: fc.realm, r: fc.r, user: fc.user, Title: "registerTitle", Action: fc.actionURL(),
		Profile:     h.profileFields(fc, cfg, values, errs, true),
		LoginURL:    h.loginActionURL(fc.r, fc.realm, "restart", fc.as.ID),
		Password:    slices.Contains(actions, "registration-password-action"),
		Terms:       slices.Contains(actions, "registration-terms-and-conditions"),
		FieldErrors: map[string]profileField{}}
	for _, e := range errs {
		if e.Field == "password" || e.Field == "password-confirm" || e.Field == "termsAccepted" {
			d.FieldErrors[e.Field] = profileField{Error: e.ErrorMessage, ErrorArgs: e.Params}
		}
	}
	status := http.StatusOK
	if len(errs) > 0 {
		status = http.StatusBadRequest
	}
	h.render(fc.w, status, "register", d)
	return resChallenge, nil
}

// register validates the registration form with every enabled form action
// and creates the user.
func (h *Handler) register(fc *flowContext, actions []string) (result, error) {
	ctx := fc.ctx()
	cfg, err := h.Svc.UserProfile(ctx, h.Svc.Store, fc.realm)
	if err != nil {
		return 0, err
	}
	values := formProfileValues(fc.r, cfg, map[string][]string{})
	if fc.realm.Settings.RegistrationEmailAsUsername {
		values["username"] = values["email"]
	}
	var errs userprofile.Errors
	if slices.Contains(actions, "registration-user-creation") {
		errs = cfg.Validate(values, userprofile.ContextUser, nil)
		username := strings.ToLower(first(values["username"]))
		if _, err := h.Svc.Store.GetUserByUsername(ctx, fc.realm.ID, username); err == nil {
			field := "username"
			if fc.realm.Settings.RegistrationEmailAsUsername {
				field = "email"
			}
			errs = append(errs, userprofile.FieldError{Field: field, ErrorMessage: "usernameExistsMessage"})
		}
		if email := first(values["email"]); email != "" && !fc.realm.DuplicateEmailsAllowed {
			if _, err := h.Svc.Store.GetUserByEmail(ctx, fc.realm.ID, email); err == nil {
				errs = append(errs, userprofile.FieldError{Field: "email", ErrorMessage: "emailExistsMessage"})
			}
		}
	}
	pw := fc.r.PostFormValue("password")
	if slices.Contains(actions, "registration-password-action") {
		switch {
		case pw == "":
			errs = append(errs, userprofile.FieldError{Field: "password", ErrorMessage: "missingPasswordMessage"})
		case pw != fc.r.PostFormValue("password-confirm"):
			errs = append(errs, userprofile.FieldError{Field: "password-confirm", ErrorMessage: "invalidPasswordConfirmMessage"})
		default:
			pol, err := policy.Parse(fc.realm.Settings.PasswordPolicy)
			if err == nil {
				if pe := pol.Validate(pw, policy.Subject{Username: first(values["username"]), Email: first(values["email"])}); pe != nil {
					errs = append(errs, userprofile.FieldError{Field: "password", ErrorMessage: pe.Key, Params: pe.Args})
				}
			}
		}
	}
	terms := slices.Contains(actions, "registration-terms-and-conditions")
	if terms && fc.r.PostFormValue("termsAccepted") != "on" {
		errs = append(errs, userprofile.FieldError{Field: "termsAccepted", ErrorMessage: "termsAcceptanceRequired"})
	}
	if len(errs) > 0 {
		h.event(fc.r, fc.realm, "REGISTER_ERROR", &eventInfo{client: fc.client, err: "invalid_registration",
			details: map[string]string{"username": first(values["username"]), "email": first(values["email"])}})
		return h.renderRegistration(fc, actions, values, errs)
	}
	u := &model.User{RealmID: fc.realm.ID, Enabled: true}
	applyProfile(u, cfg, values, true)
	if terms {
		u.Attributes["terms_and_conditions"] = []string{strconv.FormatInt(h.Svc.Now().Unix(), 10)}
	}
	err = h.Svc.Store.WithTx(ctx, func(tx *store.Store) error {
		if err := h.Svc.CreateUser(ctx, tx, u); err != nil {
			return err
		}
		if pw != "" {
			return h.Svc.SetPassword(ctx, tx, u, pw, false)
		}
		return nil
	})
	if errors.Is(err, store.ErrConflict) {
		return h.renderRegistration(fc, actions, values, userprofile.Errors{{Field: "username", ErrorMessage: "usernameExistsMessage"}})
	}
	if err != nil {
		return 0, err
	}
	fc.user = u
	h.event(fc.r, fc.realm, "REGISTER", &eventInfo{client: fc.client, userID: u.ID, details: map[string]string{
		"username": u.Username, "email": u.Email, "register_method": "form", "redirect_uri": fc.as.Params["redirect_uri"]}})
	return resSuccess, nil
}

func first(v []string) string {
	if len(v) > 0 {
		return v[0]
	}
	return ""
}
