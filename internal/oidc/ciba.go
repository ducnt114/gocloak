package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// OpenID Connect Client-Initiated Backchannel Authentication (CIBA), poll
// and ping modes, with Keycloak's HTTP authentication channel: the request
// is posted to the configured channel URI with a bearer token, and the
// authentication device answers on /ext/ciba/auth/callback with that token.

const (
	grantCIBA       = "urn:openid:params:grant-type:ciba"
	attrCIBA        = "oidc.ciba.grant.enabled"
	attrCIBAMode    = "ciba.backchannel.token.delivery.mode"
	attrCIBANotify  = "ciba.backchannel.client.notification.endpoint"
	cibaUnavailable = "Unexpected response from authentication device"
)

func cibaSettings(realm *model.Realm) (expires, interval int) {
	expires, interval = 120, 5
	if n, err := strconv.Atoi(realm.Attributes["cibaExpiresIn"]); err == nil && n > 0 {
		expires = n
	}
	if n, err := strconv.Atoi(realm.Attributes["cibaInterval"]); err == nil && n >= 0 {
		interval = n
	}
	return expires, interval
}

// cibaAuth serves /protocol/openid-connect/ext/ciba/auth.
func (h *Handler) cibaAuth(w http.ResponseWriter, r *http.Request) {
	realm, err := h.realm(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	ctx := r.Context()
	client, err := h.authenticateClient(r, realm)
	if err != nil {
		h.writeError(w, err)
		return
	}
	fail := func(status int, code, desc string) {
		h.event(r, realm, "LOGIN_ERROR", &eventInfo{client: client, err: code, details: map[string]string{"grant_type": grantCIBA}})
		writeJSON(w, status, &oauthError{Code: code, Description: desc})
	}
	if client.Attributes[attrCIBA] != "true" {
		fail(http.StatusUnauthorized, "invalid_grant", "Client not allowed OIDC CIBA Grant")
		return
	}
	hint := r.PostFormValue("login_hint")
	if hint == "" {
		fail(http.StatusBadRequest, "invalid_request", "missing parameter : login_hint")
		return
	}
	user, err := h.Svc.Store.GetUserByUsername(ctx, realm.ID, hint)
	if err != nil || !user.Enabled {
		fail(http.StatusBadRequest, "invalid_request", "invalid user")
		return
	}
	notifyToken := r.PostFormValue("client_notification_token")
	if client.Attributes[attrCIBAMode] == "ping" && notifyToken == "" {
		fail(http.StatusBadRequest, "invalid_request", "missing parameter : client_notification_token")
		return
	}
	_, scope, invalid, err := resolveScopes(ctx, h.Svc.Store, realm, client, r.PostFormValue("scope"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	if len(invalid) > 0 {
		fail(http.StatusBadRequest, "invalid_scope", "Invalid scopes: "+strings.Join(invalid, " "))
		return
	}
	expires, interval := cibaSettings(realm)
	now := h.Svc.Now()
	req := &model.CIBARequest{ID: service.RandomToken(32), RealmID: realm.ID, ClientID: client.ID, UserID: user.ID,
		Scope: r.PostFormValue("scope"), CallbackID: service.NewID(), NotificationToken: notifyToken, Status: deviceStatusPending,
		Interval: interval, ExpiresAt: now.Add(time.Duration(expires) * time.Second)}
	key, err := h.Svc.SigningKey(ctx, realm, "")
	if err != nil {
		h.writeError(w, err)
		return
	}
	iss := h.URLs.Issuer(r, realm.Name)
	bearer, err := jwt.Sign(jwt.Claims{"exp": req.ExpiresAt.Unix(), "iat": now.Unix(), "jti": req.CallbackID, "iss": iss, "aud": iss,
		"sub": user.ID, "typ": service.TokenBearer, "azp": client.ClientID}, key)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if err := h.Svc.Store.CreateCIBARequest(ctx, req); err != nil {
		h.writeError(w, err)
		return
	}
	body, _ := json.Marshal(map[string]any{"scope": scope, "binding_message": r.PostFormValue("binding_message"),
		"login_hint": hint, "is_consent_required": client.ConsentRequired})
	if h.Svc.CIBAChannelURI == "" || !h.postChannel(ctx, h.Svc.CIBAChannelURI, bearer, body) {
		_ = h.Svc.Store.DeleteCIBARequest(ctx, req.ID)
		fail(http.StatusServiceUnavailable, "server_error", cibaUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"auth_req_id": req.ID, "expires_in": expires, "interval": interval})
}

func (h *Handler) postChannel(ctx context.Context, uri, bearer string, body []byte) bool {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := brokerHTTP.Do(req)
	if err != nil {
		h.Log.Warn("CIBA authentication channel", "err", err)
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusCreated
}

// cibaCallback receives the user's decision from the authentication device.
func (h *Handler) cibaCallback(w http.ResponseWriter, r *http.Request) {
	realm, err := h.realm(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	ctx := r.Context()
	invalid := func(status int) {
		writeJSON(w, status, &oauthError{Code: "invalid_token", Description: "Invalid token"})
	}
	tok, _ := service.AccessToken(r)
	if tok == "" {
		invalid(http.StatusUnauthorized)
		return
	}
	claims, err := jwt.Verify(tok, func(kid, alg string) *jwt.Key { return h.Svc.VerificationKey(ctx, realm.ID, kid, alg) })
	if err != nil || claims.String("iss") != h.URLs.Issuer(r, realm.Name) || claims.Int("exp") < h.Svc.Now().Unix() {
		invalid(http.StatusUnauthorized)
		return
	}
	req, err := h.Svc.Store.GetCIBARequestByCallback(ctx, claims.String("jti"))
	if err != nil || req.Status != deviceStatusPending || req.RealmID != realm.ID {
		invalid(http.StatusForbidden)
		return
	}
	var in struct {
		Status string `json:"status"`
	}
	b, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if json.Unmarshal(b, &in) != nil || (in.Status != "SUCCEED" && in.Status != "UNAUTHORIZED" && in.Status != "CANCELLED") {
		writeJSON(w, http.StatusBadRequest, &oauthError{Code: "unknown_error", Description: "Cannot parse the JSON"})
		return
	}
	client, err := h.Svc.Store.GetClient(ctx, realm.ID, req.ClientID)
	if err != nil {
		invalid(http.StatusForbidden)
		return
	}
	req.CallbackID = service.NewID() // the callback token is used once
	if in.Status == "SUCCEED" {
		user, err := h.Svc.Store.GetUser(ctx, realm.ID, req.UserID)
		if err != nil || !user.Enabled {
			req.Status = deviceStatusDenied
		} else {
			us, err := h.newSession(r, realm, user, client, map[string]string{"AUTH_TIME": strconv.FormatInt(h.Svc.Now().Unix(), 10)})
			if err != nil {
				h.writeError(w, err)
				return
			}
			req.Status, req.SessionID = deviceStatusApproved, us.ID
			h.event(r, realm, "LOGIN", &eventInfo{client: client, userID: user.ID, sessionID: us.ID,
				details: map[string]string{"auth_method": "openid-connect", "grant_type": grantCIBA}})
		}
	} else {
		req.Status = deviceStatusDenied
	}
	if err := h.Svc.Store.UpdateCIBARequest(ctx, req); err != nil {
		h.writeError(w, err)
		return
	}
	if client.Attributes[attrCIBAMode] == "ping" && client.Attributes[attrCIBANotify] != "" {
		body, _ := json.Marshal(map[string]string{"auth_req_id": req.ID})
		go func() {
			nr, err := http.NewRequest(http.MethodPost, client.Attributes[attrCIBANotify], bytes.NewReader(body))
			if err != nil {
				return
			}
			nr.Header.Set("Content-Type", "application/json")
			nr.Header.Set("Authorization", "Bearer "+req.NotificationToken)
			if resp, err := brokerHTTP.Do(nr); err == nil {
				resp.Body.Close()
			}
		}()
	}
	w.WriteHeader(http.StatusOK)
}

// grantCIBA exchanges an authorized auth_req_id for tokens.
func (h *Handler) grantCIBA(r *http.Request, realm *model.Realm, client *model.Client) (*tokenResponse, error) {
	ctx := r.Context()
	ev := &eventInfo{client: client, details: map[string]string{"grant_type": grantCIBA}}
	fail := func(code string, e error) (*tokenResponse, error) {
		ev.err = code
		h.event(r, realm, "AUTHREQID_TO_TOKEN_ERROR", ev)
		return nil, e
	}
	if client.Attributes[attrCIBA] != "true" {
		return fail("not_allowed", errInvalidGrant("Client not allowed OIDC CIBA Grant"))
	}
	req, err := h.Svc.Store.GetCIBARequest(ctx, r.PostFormValue("auth_req_id"))
	if errors.Is(err, store.ErrNotFound) || err == nil && (req.RealmID != realm.ID || req.ClientID != client.ID) {
		return fail("invalid_grant", errInvalidGrant("Invalid Auth Req ID"))
	}
	if err != nil {
		return nil, err
	}
	now := h.Svc.Now()
	if now.After(req.ExpiresAt) {
		_ = h.Svc.Store.DeleteCIBARequest(ctx, req.ID)
		return fail("expired_token", &oauthError{http.StatusBadRequest, "expired_token", "authentication timed out"})
	}
	switch req.Status {
	case deviceStatusDenied:
		_ = h.Svc.Store.DeleteCIBARequest(ctx, req.ID)
		return fail("access_denied", &oauthError{http.StatusBadRequest, "access_denied", "not authorized"})
	case deviceStatusPending:
		slow := req.LastPoll > 0 && now.Unix()-req.LastPoll < int64(req.Interval)
		req.LastPoll = now.Unix()
		if err := h.Svc.Store.UpdateCIBARequest(ctx, req); err != nil {
			return nil, err
		}
		if slow {
			return fail("slow_down", &oauthError{http.StatusBadRequest, "slow_down", "too early to access"})
		}
		return fail("authorization_pending", &oauthError{http.StatusBadRequest, "authorization_pending",
			"The authorization request is still pending as the end-user hasn't yet been authenticated."})
	}
	if err := h.Svc.Store.DeleteCIBARequest(ctx, req.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fail("invalid_grant", errInvalidGrant("Invalid Auth Req ID"))
		}
		return nil, err
	}
	session, err := h.Svc.Store.GetUserSession(ctx, req.SessionID)
	if err != nil || !h.Svc.SessionValid(realm, session) {
		return fail("user_session_not_found", errInvalidGrant("Session not active"))
	}
	user, err := h.Svc.Store.GetUser(ctx, realm.ID, req.UserID)
	if err != nil || !user.Enabled {
		return fail("user_not_found", errInvalidGrant("User not found"))
	}
	ev.userID, ev.sessionID = user.ID, session.ID
	resp, err := h.issue(r, &issueRequest{realm: realm, client: client, user: user, session: session, scope: req.Scope, refresh: true})
	if err != nil {
		return fail(errorCode(err), err)
	}
	resp.eventDetails(ev)
	h.event(r, realm, "AUTHREQID_TO_TOKEN", ev)
	return resp, nil
}
