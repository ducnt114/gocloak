package oidc

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/ducnt114/gocloak/internal/model"
)

// eventInfo collects the fields of a login event as a request proceeds.
type eventInfo struct {
	client    *model.Client
	clientID  string // when the client could not be resolved
	userID    string
	sessionID string
	err       string
	details   map[string]string
}

// event records a login event for the realm.
func (h *Handler) event(r *http.Request, realm *model.Realm, typ string, ev *eventInfo) {
	e := &model.Event{Type: typ, UserID: ev.userID, SessionID: ev.sessionID, IPAddress: clientIP(r), Error: ev.err, Details: map[string]string{}}
	e.ClientID = ev.clientID
	if ev.client != nil {
		e.ClientID = ev.client.ClientID
		e.Details["client_auth_method"] = ev.client.ClientAuthenticatorType
	}
	for k, v := range ev.details {
		if v != "" {
			e.Details[k] = v
		}
	}
	h.Svc.RecordEvent(r.Context(), realm, e)
}

// clientIDParam is the client id a request claims, for error events.
func clientIDParam(r *http.Request) string {
	if id, _, ok := r.BasicAuth(); ok {
		if v, err := url.QueryUnescape(id); err == nil {
			return v
		}
	}
	return r.FormValue("client_id")
}

// errorCode maps an OAuth error to the error string of an event.
func errorCode(err error) string {
	var oe *oauthError
	if errors.As(err, &oe) {
		return oe.Code
	}
	return "server_error"
}
