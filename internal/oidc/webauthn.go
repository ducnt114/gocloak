package oidc

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
)

// webauthnCredentialData is the credentialData JSON stored for
// webauthn and webauthn-passwordless credentials.
type webauthnCredentialData struct {
	AAGUID                     string   `json:"aaguid"`
	CredentialID               string   `json:"credentialId"`
	CredentialPublicKey        string   `json:"credentialPublicKey"`
	Counter                    uint32   `json:"counter"`
	AttestationStatementFormat string   `json:"attestationStatementFormat"`
	Transports                 []string `json:"transports,omitempty"`
	// Backup flags must stay consistent between registration and logins.
	BackupEligible bool `json:"backupEligible,omitempty"`
	BackupState    bool `json:"backupState,omitempty"`
}

// waUser adapts a user and its WebAuthn credentials to go-webauthn.
type waUser struct {
	u     *model.User
	creds []webauthn.Credential
	ids   []string // credential row ids, parallel to creds
}

func (w *waUser) WebAuthnID() []byte   { return []byte(w.u.ID) }
func (w *waUser) WebAuthnName() string { return w.u.Username }
func (w *waUser) WebAuthnDisplayName() string {
	return strings.TrimSpace(w.u.FirstName + " " + w.u.LastName)
}
func (w *waUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

func credentialType(passwordless bool) string {
	if passwordless {
		return credentialWebAuthnPasswordless
	}
	return credentialWebAuthn
}

func (h *Handler) loadWAUser(fc *flowContext, u *model.User, passwordless bool) (*waUser, error) {
	all, err := h.Svc.Store.ListCredentials(fc.ctx(), u.ID)
	if err != nil {
		return nil, err
	}
	w := &waUser{u: u}
	for _, c := range all {
		if c.Type != credentialType(passwordless) {
			continue
		}
		var cd webauthnCredentialData
		if jsonUnmarshal(c.CredentialData, &cd) != nil {
			continue
		}
		id, err1 := base64.StdEncoding.DecodeString(cd.CredentialID)
		pub, err2 := base64.StdEncoding.DecodeString(cd.CredentialPublicKey)
		if err1 != nil || err2 != nil {
			continue
		}
		cred := webauthn.Credential{ID: id, PublicKey: pub, AttestationType: cd.AttestationStatementFormat,
			Flags: webauthn.CredentialFlags{BackupEligible: cd.BackupEligible, BackupState: cd.BackupState}}
		cred.Authenticator.SignCount = cd.Counter
		if a, err := uuid.Parse(cd.AAGUID); err == nil {
			cred.Authenticator.AAGUID = a[:]
		}
		for _, t := range cd.Transports {
			cred.Transport = append(cred.Transport, protocol.AuthenticatorTransport(t))
		}
		w.creds = append(w.creds, cred)
		w.ids = append(w.ids, c.ID)
	}
	return w, nil
}

// relyingParty configures go-webauthn from the realm's WebAuthn policy.
func (h *Handler) relyingParty(fc *flowContext, passwordless bool) (*webauthn.WebAuthn, error) {
	p := fc.realm.Settings.WebAuthn(passwordless)
	base := h.URLs.Base(fc.r)
	u, _ := url.Parse(base)
	rpID := p.RpID
	if rpID == "" {
		rpID = u.Hostname()
	}
	timeout := 60 * time.Second
	if p.CreateTimeout > 0 {
		timeout = time.Duration(p.CreateTimeout) * time.Second
	}
	return webauthn.New(&webauthn.Config{
		RPID: rpID, RPDisplayName: p.RpEntityName, RPOrigins: append([]string{base}, p.ExtraOrigins...),
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: timeout},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: timeout},
		},
	})
}

func userVerification(v string) protocol.UserVerificationRequirement {
	switch v {
	case "required":
		return protocol.VerificationRequired
	case "discouraged":
		return protocol.VerificationDiscouraged
	}
	return protocol.VerificationPreferred
}

func (fc *flowContext) saveSession(key string, s *webauthn.SessionData) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	fc.as.Params[key] = string(b)
	return nil
}

func (fc *flowContext) loadSession(key string) (*webauthn.SessionData, bool) {
	var s webauthn.SessionData
	if json.Unmarshal([]byte(fc.as.Params[key]), &s) != nil {
		return nil, false
	}
	return &s, true
}

// ---------------------------------------------------------------- authentication

func webauthnForm(passwordless bool) func(*flowContext) (result, error) {
	return func(fc *flowContext) (result, error) {
		return fc.h.renderWebAuthnLogin(fc, passwordless, "", http.StatusOK)
	}
}

func (h *Handler) renderWebAuthnLogin(fc *flowContext, passwordless bool, errMsg string, status int) (result, error) {
	rp, err := h.relyingParty(fc, passwordless)
	if err != nil {
		return 0, err
	}
	p := fc.realm.Settings.WebAuthn(passwordless)
	opts := []webauthn.LoginOption{webauthn.WithUserVerification(userVerification(p.UserVerificationRequirement))}
	var assertion *protocol.CredentialAssertion
	var session *webauthn.SessionData
	if passwordless && fc.user == nil {
		assertion, session, err = rp.BeginDiscoverableLogin(opts...)
	} else {
		w, lerr := h.loadWAUser(fc, fc.user, passwordless)
		if lerr != nil {
			return 0, lerr
		}
		if len(w.creds) == 0 {
			if fc.exec.Requirement == model.Required {
				alias := service.ActionWebAuthnRegister
				if passwordless {
					alias = service.ActionWebAuthnPasswordles
				}
				return resSuccess, h.addRequiredAction(fc, alias)
			}
			return resAttempted, nil
		}
		assertion, session, err = rp.BeginLogin(w, opts...)
	}
	if err != nil {
		return 0, err
	}
	if err := fc.saveSession(keyChallenge, session); err != nil {
		return 0, err
	}
	options, _ := json.Marshal(assertion.Response)
	h.render(fc.w, status, "webauthn-authenticate", pageData{realm: fc.realm, r: fc.r, user: fc.user, Title: "webauthn-login-title", Error: errMsg,
		Action: fc.actionURL(), WebAuthn: &webauthnPage{Options: string(options)}})
	if err := fc.save(); err != nil {
		return 0, err
	}
	return resChallenge, nil
}

func webauthnAction(passwordless bool) func(*flowContext) (result, error) {
	return func(fc *flowContext) (result, error) {
		h := fc.h
		fail := func() (result, error) {
			ev := fc.loginEvent("")
			if fc.user != nil {
				ev.userID = fc.user.ID
			}
			ev.err = "invalid_user_credentials"
			h.event(fc.r, fc.realm, "LOGIN_ERROR", ev)
			return h.renderWebAuthnLogin(fc, passwordless, "webauthn-error-auth-verification", http.StatusUnauthorized)
		}
		session, ok := fc.loadSession(keyChallenge)
		if !ok {
			return fail()
		}
		parsed, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(fc.r.PostFormValue("credential")))
		if err != nil {
			return fail()
		}
		rp, err := h.relyingParty(fc, passwordless)
		if err != nil {
			return 0, err
		}
		var w *waUser
		var cred *webauthn.Credential
		if passwordless && fc.user == nil {
			var found webauthn.User
			found, cred, err = rp.ValidatePasskeyLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
				u, err := h.Svc.Store.GetUser(fc.ctx(), fc.realm.ID, string(userHandle))
				if err != nil {
					return nil, err
				}
				w, err = h.loadWAUser(fc, u, true)
				return w, err
			}, *session, parsed)
			if err == nil {
				w = found.(*waUser)
			}
		} else {
			if w, err = h.loadWAUser(fc, fc.user, passwordless); err != nil {
				return 0, err
			}
			cred, err = rp.ValidateLogin(w, *session, parsed)
		}
		if err != nil || cred == nil {
			return fail()
		}
		if !w.u.Enabled {
			return fail()
		}
		delete(fc.as.Params, keyChallenge)
		fc.user = w.u
		for i, c := range w.creds {
			if string(c.ID) == string(cred.ID) {
				if err := h.storeWebAuthnCounter(fc, w.ids[i], cred.Authenticator.SignCount); err != nil {
					return 0, err
				}
			}
		}
		return resSuccess, nil
	}
}

func (h *Handler) storeWebAuthnCounter(fc *flowContext, credID string, counter uint32) error {
	creds, err := h.Svc.Store.ListCredentials(fc.ctx(), fc.user.ID)
	if err != nil {
		return err
	}
	for _, c := range creds {
		if c.ID != credID {
			continue
		}
		var cd webauthnCredentialData
		if jsonUnmarshal(c.CredentialData, &cd) != nil {
			return nil
		}
		cd.Counter = counter
		return h.Svc.Store.UpdateCredentialSecret(fc.ctx(), c.ID, c.SecretData, jsonString(cd))
	}
	return nil
}

// ---------------------------------------------------------------- registration

func webauthnRegisterPage(passwordless bool) func(*flowContext) (result, error) {
	return func(fc *flowContext) (result, error) {
		return fc.h.renderWebAuthnRegister(fc, passwordless, "", http.StatusOK)
	}
}

func (h *Handler) renderWebAuthnRegister(fc *flowContext, passwordless bool, errMsg string, status int) (result, error) {
	rp, err := h.relyingParty(fc, passwordless)
	if err != nil {
		return 0, err
	}
	w, err := h.loadWAUser(fc, fc.user, passwordless)
	if err != nil {
		return 0, err
	}
	p := fc.realm.Settings.WebAuthn(passwordless)
	sel := protocol.AuthenticatorSelection{UserVerification: userVerification(p.UserVerificationRequirement)}
	switch p.AuthenticatorAttachment {
	case "platform":
		sel.AuthenticatorAttachment = protocol.Platform
	case "cross-platform":
		sel.AuthenticatorAttachment = protocol.CrossPlatform
	}
	resident := passwordless || p.RequireResidentKey == "Yes"
	sel.RequireResidentKey = protocol.ResidentKeyRequired()
	if !resident {
		sel.RequireResidentKey = protocol.ResidentKeyNotRequired()
		sel.ResidentKey = protocol.ResidentKeyRequirementDiscouraged
	} else {
		sel.ResidentKey = protocol.ResidentKeyRequirementRequired
	}
	conveyance := protocol.PreferNoAttestation
	switch p.AttestationConveyancePreference {
	case "direct":
		conveyance = protocol.PreferDirectAttestation
	case "indirect":
		conveyance = protocol.PreferIndirectAttestation
	}
	var exclude []protocol.CredentialDescriptor
	for _, c := range w.creds {
		exclude = append(exclude, c.Descriptor())
	}
	creation, session, err := rp.BeginRegistration(w, webauthn.WithAuthenticatorSelection(sel),
		webauthn.WithConveyancePreference(conveyance), webauthn.WithExclusions(exclude))
	if err != nil {
		return 0, err
	}
	if err := fc.saveSession(keyChallenge, session); err != nil {
		return 0, err
	}
	options, _ := json.Marshal(creation.Response)
	alias := service.ActionWebAuthnRegister
	if passwordless {
		alias = service.ActionWebAuthnPasswordles
	}
	h.render(fc.w, status, "webauthn-register", pageData{realm: fc.realm, r: fc.r, user: fc.user, Title: "webauthn-registration-title",
		Error: errMsg, Action: fc.requiredActionURL(alias), WebAuthn: &webauthnPage{Options: string(options)}})
	return resChallenge, nil
}

func webauthnRegisterAction(passwordless bool) func(*flowContext) (result, error) {
	return func(fc *flowContext) (result, error) {
		h := fc.h
		fail := func() (result, error) {
			h.event(fc.r, fc.realm, "UPDATE_CREDENTIAL_ERROR", &eventInfo{client: fc.client, userID: fc.user.ID, err: "invalid_registration",
				details: map[string]string{"credential_type": credentialType(passwordless)}})
			return h.renderWebAuthnRegister(fc, passwordless, "webauthn-error-registration", http.StatusBadRequest)
		}
		session, ok := fc.loadSession(keyChallenge)
		if !ok {
			return fail()
		}
		parsed, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(fc.r.PostFormValue("credential")))
		if err != nil {
			return fail()
		}
		rp, err := h.relyingParty(fc, passwordless)
		if err != nil {
			return 0, err
		}
		w, err := h.loadWAUser(fc, fc.user, passwordless)
		if err != nil {
			return 0, err
		}
		cred, err := rp.CreateCredential(w, *session, parsed)
		if err != nil {
			return fail()
		}
		aaguid := ""
		if a, err := uuid.FromBytes(cred.Authenticator.AAGUID); err == nil {
			aaguid = a.String()
		}
		cd := webauthnCredentialData{AAGUID: aaguid, CredentialID: base64.StdEncoding.EncodeToString(cred.ID),
			CredentialPublicKey: base64.StdEncoding.EncodeToString(cred.PublicKey), Counter: cred.Authenticator.SignCount,
			AttestationStatementFormat: cred.AttestationType,
			BackupEligible:             cred.Flags.BackupEligible, BackupState: cred.Flags.BackupState}
		if cd.AttestationStatementFormat == "" {
			cd.AttestationStatementFormat = "none"
		}
		for _, t := range cred.Transport {
			cd.Transports = append(cd.Transports, string(t))
		}
		label := strings.TrimSpace(fc.r.PostFormValue("authenticatorLabel"))
		if label == "" {
			label = "Passkey"
		}
		if err := h.Svc.Store.CreateCredential(fc.ctx(), &model.Credential{ID: service.NewID(), UserID: fc.user.ID,
			Type: credentialType(passwordless), UserLabel: label, SecretData: "{}", CredentialData: jsonString(cd),
			CreatedDate: h.Svc.Now().UnixMilli(), Priority: 30}); err != nil {
			return 0, err
		}
		delete(fc.as.Params, keyChallenge)
		h.event(fc.r, fc.realm, "UPDATE_CREDENTIAL", &eventInfo{client: fc.client, userID: fc.user.ID,
			details: map[string]string{"credential_type": credentialType(passwordless)}})
		return resSuccess, nil
	}
}
