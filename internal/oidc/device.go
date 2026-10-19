package oidc

import (
	"crypto/rand"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// OAuth 2.0 Device Authorization Grant (RFC 8628).

const (
	grantDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"
	attrDeviceGrant = "oauth2.device.authorization.grant.enabled"
	keyDevice       = "_device" // the device code a login approves
)

const (
	deviceStatusPending  = "pending"
	deviceStatusApproved = "approved"
	deviceStatusDenied   = "denied"
)

// deviceSettings returns the lifespan and polling interval of device codes:
// the client's settings, else the realm's.
func deviceSettings(realm *model.Realm, c *model.Client) (lifespan, interval int) {
	get := func(clientAttr, realmAttr string, def int) int {
		if n, err := strconv.Atoi(c.Attributes[clientAttr]); err == nil && n > 0 {
			return n
		}
		if n, err := strconv.Atoi(realm.Attributes[realmAttr]); err == nil && n > 0 {
			return n
		}
		return def
	}
	return get("oauth2.device.code.lifespan", "oauth2DeviceCodeLifespan", 600),
		get("oauth2.device.polling.interval", "oauth2DevicePollingInterval", 5)
}

// newUserCode returns a code for people to type: 8 letters, XXXX-XXXX.
func newUserCode() string {
	const letters = "BCDFGHJKLMNPQRSTVWXZ"
	b := make([]byte, 9)
	for i := range b {
		if i == 4 {
			b[i] = '-'
			continue
		}
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		b[i] = letters[n.Int64()]
	}
	return string(b)
}

// deviceAuthorization serves /protocol/openid-connect/auth/device.
func (h *Handler) deviceAuthorization(w http.ResponseWriter, r *http.Request) {
	realm, err := h.realm(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	client, err := h.authenticateClient(r, realm)
	if err != nil {
		h.event(r, realm, "OAUTH2_DEVICE_AUTH_ERROR", &eventInfo{clientID: clientIDParam(r), err: "invalid_client_credentials"})
		writeJSON(w, http.StatusUnauthorized, &oauthError{Code: "unauthorized_client", Description: "Invalid client or Invalid client credentials"})
		return
	}
	if client.Attributes[attrDeviceGrant] != "true" {
		h.event(r, realm, "OAUTH2_DEVICE_AUTH_ERROR", &eventInfo{client: client, err: "not_allowed"})
		writeJSON(w, http.StatusBadRequest, &oauthError{Code: "unauthorized_client",
			Description: "Client is not allowed to initiate OAuth 2.0 Device Authorization Grant. The flow is disabled for the client."})
		return
	}
	lifespan, interval := deviceSettings(realm, client)
	d := &model.DeviceCode{DeviceCode: service.RandomToken(32), RealmID: realm.ID, ClientID: client.ID,
		Scope: r.PostFormValue("scope"), Nonce: r.PostFormValue("nonce"), Status: deviceStatusPending, Interval: interval,
		ExpiresAt: h.Svc.Now().Add(time.Duration(lifespan) * time.Second)}
	for i := 0; ; i++ {
		d.UserCode = newUserCode()
		err = h.Svc.Store.CreateDeviceCode(r.Context(), d)
		if !errors.Is(err, store.ErrConflict) || i > 5 {
			break
		}
	}
	if err != nil {
		h.writeError(w, err)
		return
	}
	verify := h.URLs.Issuer(r, realm.Name) + "/device"
	h.event(r, realm, "OAUTH2_DEVICE_AUTH", &eventInfo{client: client})
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code": d.DeviceCode, "user_code": d.UserCode, "verification_uri": verify,
		"verification_uri_complete": verify + "?user_code=" + url.QueryEscape(d.UserCode),
		"expires_in":                lifespan, "interval": interval,
	})
}

// deviceVerification serves /realms/{realm}/device: the page where users
// enter the code shown by their device, then log in to approve it.
func (h *Handler) deviceVerification(w http.ResponseWriter, r *http.Request) {
	realm, err := h.realm(r)
	if err != nil {
		h.errorPage(w, r, http.StatusNotFound, "realmNotFoundMessage")
		return
	}
	ctx := r.Context()
	code := strings.ToUpper(strings.TrimSpace(r.FormValue("user_code")))
	if code == "" {
		code = strings.ToUpper(strings.TrimSpace(r.PostFormValue("device_user_code")))
	}
	page := func(status int, msg string) {
		h.render(w, status, "login-oauth2-device-verify-user-code", pageData{realm: realm, r: r, Title: "oauth2DeviceVerificationTitle",
			Error: msg, Action: h.URLs.Issuer(r, realm.Name) + "/device"})
	}
	if code == "" {
		page(http.StatusOK, "")
		return
	}
	if len(code) == 8 {
		code = code[:4] + "-" + code[4:]
	}
	d, err := h.Svc.Store.GetDeviceCodeByUserCode(ctx, realm.ID, code)
	if err != nil || d.Status != deviceStatusPending {
		h.event(r, realm, "OAUTH2_DEVICE_VERIFY_USER_CODE_ERROR", &eventInfo{err: "invalid_oauth2_user_code"})
		page(http.StatusBadRequest, "oauth2DeviceInvalidUserCodeMessage")
		return
	}
	if h.Svc.Now().After(d.ExpiresAt) {
		h.event(r, realm, "OAUTH2_DEVICE_VERIFY_USER_CODE_ERROR", &eventInfo{err: "expired_oauth2_user_code"})
		page(http.StatusBadRequest, "oauth2DeviceExpiredUserCodeMessage")
		return
	}
	client, err := h.Svc.Store.GetClient(ctx, realm.ID, d.ClientID)
	if err != nil || !client.Enabled {
		page(http.StatusBadRequest, "oauth2DeviceInvalidUserCodeMessage")
		return
	}
	h.event(r, realm, "OAUTH2_DEVICE_VERIFY_USER_CODE", &eventInfo{client: client})
	as, err := h.newAuthSession(w, r, realm, client, map[string]string{"client_id": client.ClientID, "scope": d.Scope,
		"nonce": d.Nonce, keyDevice: d.DeviceCode})
	if err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	h.startFlow(w, r, realm, client, as, "browser")
}

// finishDeviceLogin approves the device code once the user logged in and
// consented, instead of redirecting to the client.
func (h *Handler) finishDeviceLogin(w http.ResponseWriter, r *http.Request, realm *model.Realm, client *model.Client, user *model.User, us *model.UserSession, params map[string]string) {
	ctx := r.Context()
	d, err := h.Svc.Store.GetDeviceCode(ctx, params[keyDevice])
	if err != nil || d.Status != deviceStatusPending || d.ClientID != client.ID || h.Svc.Now().After(d.ExpiresAt) {
		h.render(w, http.StatusBadRequest, "info", pageData{realm: realm, r: r, user: user,
			Title: "oauth2DeviceVerificationFailedHeader", Message: "oauth2DeviceExpiredUserCodeMessage"})
		return
	}
	d.Status, d.UserID, d.SessionID = deviceStatusApproved, user.ID, us.ID
	if err := h.Svc.Store.UpdateDeviceCode(ctx, d); err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	h.event(r, realm, "LOGIN", &eventInfo{client: client, userID: user.ID, sessionID: us.ID, details: map[string]string{
		"auth_method": "openid-connect", "consent": consentDetail(client, params), "code_id": us.ID, "username": user.Username}})
	h.render(w, http.StatusOK, "info", pageData{realm: realm, r: r, user: user,
		Title: "oauth2DeviceVerificationCompleteHeader", Message: "oauth2DeviceVerificationCompleteMessage"})
}

// denyDevice marks a device code denied when the user refuses the consent.
func (h *Handler) denyDevice(w http.ResponseWriter, r *http.Request, realm *model.Realm, params map[string]string) {
	if d, err := h.Svc.Store.GetDeviceCode(r.Context(), params[keyDevice]); err == nil && d.Status == deviceStatusPending {
		d.Status = deviceStatusDenied
		if err := h.Svc.Store.UpdateDeviceCode(r.Context(), d); err != nil {
			h.serverErrorPage(w, r, err)
			return
		}
	}
	h.render(w, http.StatusOK, "info", pageData{realm: realm, r: r,
		Title: "oauth2DeviceVerificationFailedHeader", Message: "oauth2DeviceConsentDeniedMessage"})
}

// grantDevice exchanges an approved device code for tokens.
func (h *Handler) grantDevice(r *http.Request, realm *model.Realm, client *model.Client) (*tokenResponse, error) {
	ctx := r.Context()
	ev := &eventInfo{client: client, details: map[string]string{"grant_type": grantDeviceCode}}
	fail := func(code string, e error) (*tokenResponse, error) {
		ev.err = code
		h.event(r, realm, "OAUTH2_DEVICE_CODE_TO_TOKEN_ERROR", ev)
		return nil, e
	}
	if client.Attributes[attrDeviceGrant] != "true" {
		return fail("not_allowed", errInvalidGrant("Client not allowed OAuth 2.0 Device Authorization Grant"))
	}
	code := r.PostFormValue("device_code")
	if code == "" {
		return fail("invalid_request", errInvalidRequest("Missing parameter: device_code"))
	}
	d, err := h.Svc.Store.GetDeviceCode(ctx, code)
	if errors.Is(err, store.ErrNotFound) || err == nil && (d.RealmID != realm.ID || d.ClientID != client.ID) {
		return fail("invalid_oauth2_device_code", errInvalidGrant("Device code not valid"))
	}
	if err != nil {
		return nil, err
	}
	now := h.Svc.Now()
	if now.After(d.ExpiresAt) {
		_ = h.Svc.Store.DeleteDeviceCode(ctx, d.DeviceCode)
		return fail("expired_oauth2_device_code", &oauthError{http.StatusBadRequest, "expired_token", "Device code is expired"})
	}
	switch d.Status {
	case deviceStatusDenied:
		_ = h.Svc.Store.DeleteDeviceCode(ctx, d.DeviceCode)
		ev.details["reason"] = "The end user denied the authorization request"
		return fail("access_denied", &oauthError{http.StatusBadRequest, "access_denied", "The end user denied the authorization request"})
	case deviceStatusPending:
		slow := d.LastPoll > 0 && now.Unix()-d.LastPoll < int64(d.Interval)
		d.LastPoll = now.Unix()
		if err := h.Svc.Store.UpdateDeviceCode(ctx, d); err != nil {
			return nil, err
		}
		if slow {
			return fail("slow_down", &oauthError{http.StatusBadRequest, "slow_down", "Slow down"})
		}
		return fail("authorization_pending", &oauthError{http.StatusBadRequest, "authorization_pending", "The authorization request is still pending"})
	}
	// approved: the code is used once
	if err := h.Svc.Store.DeleteDeviceCode(ctx, d.DeviceCode); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fail("invalid_oauth2_device_code", errInvalidGrant("Device code not valid"))
		}
		return nil, err
	}
	ev.userID, ev.sessionID = d.UserID, d.SessionID
	session, err := h.Svc.Store.GetUserSession(ctx, d.SessionID)
	if err != nil || !h.Svc.SessionValid(realm, session) {
		return fail("user_session_not_found", errInvalidGrant("Session not active"))
	}
	user, err := h.Svc.Store.GetUser(ctx, realm.ID, d.UserID)
	if err != nil || !user.Enabled {
		return fail("user_not_found", errInvalidGrant("User not found"))
	}
	resp, err := h.issue(r, &issueRequest{realm: realm, client: client, user: user, session: session,
		scope: d.Scope, nonce: d.Nonce, refresh: true})
	if err != nil {
		return fail(errorCode(err), err)
	}
	ev.details["code_id"] = session.ID
	resp.eventDetails(ev)
	h.event(r, realm, "OAUTH2_DEVICE_CODE_TO_TOKEN", ev)
	return resp, nil
}
