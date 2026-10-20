package oidc

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
)

// OAuth 2.0 Token Exchange (RFC 8693) between clients of a realm, following
// the "standard token exchange": a confidential client with
// standard.token.exchange.enabled exchanges an access token issued to a user
// for it (the client must be in the token's audience) for a new token,
// possibly narrowed to some audiences and scopes.

const (
	grantTokenExchange   = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeAccess      = "urn:ietf:params:oauth:token-type:access_token"
	tokenTypeRefresh     = "urn:ietf:params:oauth:token-type:refresh_token"
	attrTokenExchange    = "standard.token.exchange.enabled"
	attrExchangeRefresh  = "standard.token.exchange.enableRefreshRequestedTokenType"
	exchangeRefreshAllow = "SAME_SESSION"
)

func (h *Handler) grantTokenExchange(r *http.Request, realm *model.Realm, client *model.Client) (*tokenResponse, error) {
	ctx := r.Context()
	ev := &eventInfo{client: client, details: map[string]string{"grant_type": grantTokenExchange}}
	fail := func(code string, e error) (*tokenResponse, error) {
		ev.err = code
		h.event(r, realm, "TOKEN_EXCHANGE_ERROR", ev)
		return nil, e
	}
	if client.PublicClient {
		return fail("invalid_client", &oauthError{http.StatusBadRequest, "invalid_client", "Public client is not allowed to exchange token"})
	}
	if client.Attributes[attrTokenExchange] != "true" {
		return fail("not_allowed", &oauthError{http.StatusBadRequest, "unauthorized_client", "Standard token exchange is not enabled for the requested client"})
	}
	subject := r.PostFormValue("subject_token")
	if subject == "" {
		return fail("invalid_request", errInvalidRequest("Parameter 'subject_token' is required"))
	}
	if t := r.PostFormValue("subject_token_type"); t != "" && t != tokenTypeAccess {
		return fail("invalid_request", errInvalidRequest("Parameter 'subject_token' supports access tokens only"))
	}
	requested := r.PostFormValue("requested_token_type")
	switch requested {
	case "", tokenTypeAccess:
		requested = tokenTypeAccess
	case tokenTypeRefresh:
		if client.Attributes[attrExchangeRefresh] != exchangeRefreshAllow {
			return fail("invalid_request", errInvalidRequest("requested_token_type unsupported"))
		}
	default:
		return fail("invalid_request", errInvalidRequest("requested_token_type unsupported"))
	}
	vt, err := h.Svc.VerifyToken(ctx, realm, subject, h.URLs.Issuer(r, realm.Name), service.TokenBearer)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) {
			return fail("invalid_token", &oauthError{http.StatusBadRequest, "invalid_token", "Invalid token"})
		}
		return nil, err
	}
	if vt.User == nil {
		return fail("invalid_token", &oauthError{http.StatusBadRequest, "invalid_token", "Invalid token"})
	}
	ev.userID = vt.User.ID
	if !slices.Contains(vt.Claims.Audience(), client.ClientID) {
		return fail("not_allowed", &oauthError{http.StatusForbidden, "access_denied", "Client is not within the token audience"})
	}
	if requested == tokenTypeRefresh && vt.Session == nil {
		return fail("invalid_request", errInvalidRequest("requested_token_type unsupported"))
	}
	var audience []string
	for _, a := range r.PostForm["audience"] {
		for _, v := range strings.Fields(a) {
			if _, err := h.Svc.Store.GetClientByClientID(ctx, realm.ID, v); err != nil {
				return fail("invalid_request", errInvalidRequest("Audience not found"))
			}
			audience = append(audience, v)
		}
	}
	session := vt.Session
	if session != nil {
		ev.sessionID = session.ID
		if !session.Clients[client.ID] && !session.Offline {
			session.Clients[client.ID] = true
			if err := h.Svc.Store.UpdateUserSession(ctx, session); err != nil {
				return nil, err
			}
		}
	}
	resp, err := h.issue(r, &issueRequest{realm: realm, client: client, user: vt.User, session: session,
		scope: r.PostFormValue("scope"), strict: true, refresh: requested == tokenTypeRefresh, audience: audience})
	var ae *errAudience
	if errors.As(err, &ae) {
		return fail("invalid_request", errInvalidRequest(ae.Error()))
	}
	if err != nil {
		return fail(errorCode(err), err)
	}
	resp.IssuedTokenType = requested
	if requested == tokenTypeAccess {
		resp.SessionState = ""
		resp.RefreshExpiresIn = 0
	}
	ev.details["subject_token_client_id"] = vt.Claims.String("azp")
	ev.details["requested_token_type"] = requested
	ev.details["audience"] = strings.Join(audience, " ")
	resp.eventDetails(ev)
	h.event(r, realm, "TOKEN_EXCHANGE", ev)
	return resp, nil
}
