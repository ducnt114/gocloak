package oidc

import (
	"errors"
	"net/http"
	"strings"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
	"github.com/ducnt114/gocloak/internal/userprofile"
)

// Authenticators of the browser flow (identity-provider-redirector) and of
// the first broker login flow.

// idpRedirector sends the browser to the provider named by kc_idp_hint, or
// to the default provider of its configuration.
func idpRedirector(fc *flowContext) (result, error) {
	alias := fc.as.Params["kc_idp_hint"]
	if alias == "" {
		alias = fc.config["defaultProvider"]
	}
	if alias == "" {
		return resAttempted, nil
	}
	idp, err := fc.h.enabledIdP(fc.r, fc.realm, alias)
	if errors.Is(err, store.ErrNotFound) {
		fc.h.Log.Warn("identity provider of kc_idp_hint not found", "realm", fc.realm.Name, "alias", alias)
		return resAttempted, nil
	}
	if err != nil {
		return 0, err
	}
	fc.h.redirectToIdP(fc.w, fc.r, fc.realm, fc.as, idp)
	return resChallenge, nil
}

// brokerUser is the would-be user of a brokered identity.
func brokerUser(realm *model.Realm, id *brokeredIdentity) *model.User {
	u := &model.User{RealmID: realm.ID, Username: id.Username, Email: id.Email, FirstName: id.FirstName, LastName: id.LastName,
		Attributes: map[string][]string{}}
	for k, v := range id.Attributes {
		u.Attributes[k] = v
	}
	if realm.Settings.RegistrationEmailAsUsername {
		u.Username = id.Email
	}
	return u
}

// ---------------------------------------------------------------- review profile

// idpReviewProfile shows the profile from the provider for review
// (update.profile.on.first.login: on, missing or off).
func idpReviewProfile(fc *flowContext) (result, error) {
	_, id, err := fc.brokerState()
	if err != nil {
		return 0, err
	}
	cfg, err := fc.h.Svc.UserProfile(fc.ctx(), fc.h.Svc.Store, fc.realm)
	if err != nil {
		return 0, err
	}
	values := service.ProfileValues(brokerUser(fc.realm, id))
	mode := fc.config["update.profile.on.first.login"]
	if mode == "" {
		mode = "missing"
	}
	if fc.as.Params[keyIdPReview] == "force" {
		mode = "on"
	}
	if mode == "off" || (mode == "missing" && len(cfg.Validate(values, userprofile.ContextUser, nil)) == 0) {
		return resSuccess, nil
	}
	fc.h.render(fc.w, http.StatusOK, "update-profile", pageData{realm: fc.realm, r: fc.r, Title: "loginIdpReviewProfileTitle",
		Action: fc.actionURL(), Profile: fc.h.profileFields(fc, cfg, values, nil, true)})
	return resChallenge, nil
}

func idpReviewProfileAction(fc *flowContext) (result, error) {
	_, id, err := fc.brokerState()
	if err != nil {
		return 0, err
	}
	cfg, err := fc.h.Svc.UserProfile(fc.ctx(), fc.h.Svc.Store, fc.realm)
	if err != nil {
		return 0, err
	}
	u := brokerUser(fc.realm, id)
	values := formProfileValues(fc.r, cfg, service.ProfileValues(u))
	if fc.realm.Settings.RegistrationEmailAsUsername {
		values["username"] = values["email"]
	}
	if errs := cfg.Validate(values, userprofile.ContextUser, nil); len(errs) > 0 {
		fc.h.render(fc.w, http.StatusBadRequest, "update-profile", pageData{realm: fc.realm, r: fc.r, Title: "loginIdpReviewProfileTitle",
			Action: fc.actionURL(), Profile: fc.h.profileFields(fc, cfg, values, errs, true)})
		return resChallenge, nil
	}
	applyProfile(u, cfg, values, true)
	if !strings.EqualFold(u.Email, id.Email) {
		// a changed email is not verified by the provider
		fc.as.Params[keyIdPReview] = "changed"
	} else if fc.as.Params[keyIdPReview] == "force" {
		delete(fc.as.Params, keyIdPReview)
	}
	id.Username, id.Email, id.FirstName, id.LastName, id.Attributes = u.Username, u.Email, u.FirstName, u.LastName, u.Attributes
	fc.saveIdentity(id)
	return resSuccess, nil
}

// ---------------------------------------------------------------- create or find the user

// duplicateUser finds the user an identity collides with, by email (unless
// duplicate emails are allowed) or username.
func (fc *flowContext) duplicateUser(id *brokeredIdentity) (*model.User, string, string, error) {
	u := brokerUser(fc.realm, id)
	if u.Email != "" && !fc.realm.DuplicateEmailsAllowed {
		dup, err := fc.h.Svc.Store.GetUserByEmail(fc.ctx(), fc.realm.ID, strings.ToLower(u.Email))
		if err == nil {
			return dup, "email", u.Email, nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return nil, "", "", err
		}
	}
	if u.Username != "" {
		dup, err := fc.h.Svc.Store.GetUserByUsername(fc.ctx(), fc.realm.ID, strings.ToLower(u.Username))
		if err == nil {
			return dup, "username", u.Username, nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return nil, "", "", err
		}
	}
	return nil, "", "", nil
}

// idpCreateUserIfUnique creates the user, unless one with the same email or
// username exists: then the existing account is handled by the next steps.
func idpCreateUserIfUnique(fc *flowContext) (result, error) {
	ctx := fc.ctx()
	idp, id, err := fc.brokerState()
	if err != nil {
		return 0, err
	}
	dup, attr, value, err := fc.duplicateUser(id)
	if err != nil {
		return 0, err
	}
	if dup != nil {
		fc.as.Params[keyIdPExisting] = dup.ID
		fc.as.Params[keyIdPDuplicate] = attr + " " + value
		return resAttempted, nil
	}
	u := brokerUser(fc.realm, id)
	if strings.TrimSpace(u.Username) == "" {
		return fc.fail(errInvalidRequest("missing username"), "missingUsernameMessage")
	}
	u.Enabled = true
	u.EmailVerified = idp.TrustEmail && u.Email != "" && fc.as.Params[keyIdPReview] != "changed"
	notes := map[string]string{}
	err = fc.h.Svc.Store.WithTx(ctx, func(tx *store.Store) error {
		if err := fc.h.Svc.CreateUser(ctx, tx, u); err != nil {
			return err
		}
		if err := tx.CreateFederatedIdentity(ctx, &model.FederatedIdentity{UserID: u.ID, RealmID: fc.realm.ID,
			IdentityProvider: idp.Alias, FederatedUserID: id.ID, FederatedUsername: id.BrokerUsername, Token: id.Token}); err != nil {
			return err
		}
		mappers, err := tx.ListIdPMappers(ctx, fc.realm.ID, idp.Alias)
		if err != nil {
			return err
		}
		if err := runMappers(&mapperContext{ctx: ctx, st: tx, realm: fc.realm, idp: idp, id: id, user: u, notes: notes}, mappers, false); err != nil {
			return err
		}
		if idp.AddReadTokenRoleOnCreate {
			if b, err := tx.GetClientByClientID(ctx, fc.realm.ID, service.BrokerClient); err == nil {
				if role, err := tx.GetRoleByName(ctx, fc.realm.ID, b.ID, service.ReadTokenRole); err == nil {
					if err := tx.GrantUserRole(ctx, u.ID, role.ID); err != nil {
						return err
					}
				}
			}
		}
		if fc.config["require.password.update.after.registration"] == "true" {
			u.RequiredActions = append(u.RequiredActions, service.ActionUpdatePassword)
			return tx.UpdateUser(ctx, u)
		}
		return nil
	})
	if errors.Is(err, store.ErrConflict) {
		return fc.fail(errInvalidRequest("user exists"), "usernameExistsMessage")
	}
	if err != nil {
		return 0, err
	}
	for k, v := range notes {
		fc.as.Params[notePrefix+k] = v
	}
	fc.as.Params[keyIdPNewUser] = "true"
	fc.user = u
	fc.h.event(fc.r, fc.realm, "REGISTER", &eventInfo{client: fc.client, userID: u.ID, details: map[string]string{
		"identity_provider": idp.Alias, "identity_provider_identity": id.BrokerUsername, "username": u.Username,
		"email": u.Email, "register_method": "broker"}})
	return resSuccess, nil
}

// existingUser is the account found by idp-create-user-if-unique.
func (fc *flowContext) existingUser() (*model.User, error) {
	id := fc.as.Params[keyIdPExisting]
	if id == "" {
		return nil, store.ErrNotFound
	}
	return fc.h.Svc.Store.GetUser(fc.ctx(), fc.realm.ID, id)
}

// idpDetectExistingUser requires an existing account with the same email or
// username, and sets it as the user.
func idpDetectExistingUser(fc *flowContext) (result, error) {
	_, id, err := fc.brokerState()
	if err != nil {
		return 0, err
	}
	dup, attr, value, err := fc.duplicateUser(id)
	if err != nil {
		return 0, err
	}
	if dup == nil {
		return fc.fail(errInvalidRequest("no existing user"), "invalidUserMessage")
	}
	fc.as.Params[keyIdPExisting] = dup.ID
	fc.as.Params[keyIdPDuplicate] = attr + " " + value
	fc.user = dup
	return resSuccess, nil
}

// idpAutoLink links the existing account without confirmation.
func idpAutoLink(fc *flowContext) (result, error) {
	u, err := fc.existingUser()
	if errors.Is(err, store.ErrNotFound) {
		return fc.fail(errInvalidRequest("no existing user"), "invalidFlowMessage")
	}
	if err != nil {
		return 0, err
	}
	fc.user = u
	return resSuccess, nil
}

// ---------------------------------------------------------------- confirm link

func idpConfirmLink(fc *flowContext) (result, error) {
	if fc.as.Params[keyIdPExisting] == "" {
		return fc.fail(errInvalidRequest("no existing user"), "invalidFlowMessage")
	}
	return fc.renderConfirmLink(http.StatusOK)
}

func (fc *flowContext) renderConfirmLink(status int) (result, error) {
	attr, value, _ := strings.Cut(fc.as.Params[keyIdPDuplicate], " ")
	fc.h.render(fc.w, status, "login-idp-link-confirm", pageData{realm: fc.realm, r: fc.r, Title: "confirmLinkIdpTitle",
		Message: "federatedIdentityConfirmLinkMessage", MessageArgs: []any{attr, value}, Action: fc.actionURL()})
	return resChallenge, nil
}

func idpConfirmLinkAction(fc *flowContext) (result, error) {
	switch fc.r.PostFormValue("submitAction") {
	case "linkAccount":
		return resSuccess, nil
	case "updateProfile":
		// back to the review form, then look for the user again
		fc.as.Params[keyIdPReview] = "force"
		delete(fc.as.Params, keyIdPExisting)
		delete(fc.as.Params, keyIdPDuplicate)
		delete(fc.as.Params, keyDone)
		if err := fc.save(); err != nil {
			return 0, err
		}
		http.Redirect(fc.w, fc.r, fc.h.loginActionURL(fc.r, fc.realm, "authenticate", fc.as.ID), http.StatusFound)
		return resChallenge, nil
	}
	return fc.renderConfirmLink(http.StatusBadRequest)
}

// ---------------------------------------------------------------- verify the existing account

// idpEmailVerification verifies the existing account by email before it is
// linked; it does not apply when the realm cannot send email.
func idpEmailVerification(fc *flowContext) (result, error) {
	u, err := fc.existingUser()
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fc.fail(errInvalidRequest("no existing user"), "invalidFlowMessage")
		}
		return 0, err
	}
	if fc.as.Params[keyIdPEmailOK] == "true" {
		fc.user = u
		return resSuccess, nil
	}
	if fc.realm.Settings.SMTPServer["host"] == "" || u.Email == "" {
		return resAttempted, nil
	}
	idp, id, err := fc.brokerState()
	if err != nil {
		return 0, err
	}
	providerName := idp.DisplayName
	if providerName == "" {
		providerName = idp.Alias
	}
	if fc.as.Params[keyEmailSent] != "idp-link" || fc.r.URL.Query().Get("resend") == "true" {
		lifespan := fc.realm.Settings.ActionTokenGeneratedByUser
		link, err := fc.h.actionTokenLink(fc.r, fc.realm, fc.client, u, actionTokenClaims{typ: tokenIdPVerifyAccount,
			authSession: fc.as.ID, email: u.Email, lifespan: lifespan, extra: map[string]any{"idpa": idp.Alias, "idpu": id.BrokerUsername}})
		if err != nil {
			return 0, err
		}
		msg, err := fc.h.Svc.IdPLinkEmail(fc.realm, u, providerName, id.BrokerUsername, link, lifespan)
		if err != nil {
			return 0, err
		}
		if err := fc.h.Svc.SendEmail(fc.ctx(), fc.realm, msg); err != nil {
			fc.h.Log.Warn("send identity provider link email", "realm", fc.realm.Name, "err", err)
			return fc.fail(errInvalidRequest("email"), "emailSendErrorMessage")
		}
		fc.h.event(fc.r, fc.realm, "SEND_IDENTITY_PROVIDER_LINK", &eventInfo{client: fc.client, userID: u.ID, details: map[string]string{
			"identity_provider": idp.Alias, "identity_provider_identity": id.BrokerUsername, "email": u.Email}})
		fc.as.Params[keyEmailSent] = "idp-link"
	}
	fc.h.render(fc.w, http.StatusOK, "login-idp-link-email", pageData{realm: fc.realm, r: fc.r, Title: "emailLinkIdpTitle",
		TitleArgs: []any{providerName}, Message: "emailLinkIdp1", MessageArgs: []any{providerName, id.BrokerUsername, realmTitle(fc.realm)},
		LinkURL: fc.h.loginActionURL(fc.r, fc.realm, "authenticate", fc.as.ID)})
	return resChallenge, nil
}

// idpPasswordForm verifies the existing account by its password.
func idpPasswordForm(fc *flowContext) (result, error) {
	u, err := fc.existingUser()
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fc.fail(errInvalidRequest("no existing user"), "invalidFlowMessage")
		}
		return 0, err
	}
	return fc.renderReauthenticate(u, "", http.StatusOK)
}

func (fc *flowContext) renderReauthenticate(u *model.User, errMsg string, status int) (result, error) {
	alias := fc.as.Params[keyIdP]
	if idp, err := fc.h.Svc.Store.GetIdentityProvider(fc.ctx(), fc.realm.ID, alias); err == nil && idp.DisplayName != "" {
		alias = idp.DisplayName
	}
	fc.message, fc.messageArgs = "federatedIdentityConfirmReauthenticateMessage", []any{alias}
	saved := fc.user
	fc.user = u // shows the username; the user is set only once authenticated
	res, err := fc.renderLogin("login-password", u.Username, errMsg, status)
	fc.user = saved
	return res, err
}

func idpPasswordAction(fc *flowContext) (result, error) {
	u, err := fc.existingUser()
	if err != nil {
		return 0, err
	}
	locked, err := fc.h.Svc.TemporarilyLocked(fc.ctx(), fc.realm, u)
	if err != nil {
		return 0, err
	}
	if locked || !u.Enabled {
		return fc.renderReauthenticate(u, "invalidUserMessage", http.StatusUnauthorized)
	}
	ok, err := fc.h.Svc.CheckPassword(fc.ctx(), u, fc.r.PostFormValue("password"))
	if err != nil {
		return 0, err
	}
	if !ok {
		if err := fc.h.Svc.LoginFailed(fc.ctx(), fc.realm, u, clientIP(fc.r)); err != nil {
			return 0, err
		}
		ev := fc.loginEvent(u.Username)
		ev.userID, ev.err = u.ID, "invalid_user_credentials"
		fc.h.event(fc.r, fc.realm, "LOGIN_ERROR", ev)
		return fc.renderReauthenticate(u, "invalidUserMessage", http.StatusUnauthorized)
	}
	if err := fc.h.Svc.LoginSucceeded(fc.ctx(), fc.realm, u); err != nil {
		return 0, err
	}
	fc.user = u
	return resSuccess, nil
}
