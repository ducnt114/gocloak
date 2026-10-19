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

// OpenID Connect front-channel and back-channel logout of the clients of a
// session (OIDC Front-Channel Logout 1.0, Back-Channel Logout 1.0).

// Client attributes of OIDC client logout, as named by Keycloak.
const (
	attrFrontchannelURL      = "frontchannel.logout.url"
	attrFrontchannelSession  = "frontchannel.logout.session.required"
	attrBackchannelURL       = "backchannel.logout.url"
	attrBackchannelSession   = "backchannel.logout.session.required"
	attrBackchannelRevokeOff = "backchannel.logout.revoke.offline.tokens"
)

const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// sessionOIDCClients returns the enabled OIDC clients of a session.
func (h *Handler) sessionOIDCClients(ctx context.Context, realm *model.Realm, us *model.UserSession) []*model.Client {
	ids := make([]string, 0, len(us.Clients))
	for id := range us.Clients {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var out []*model.Client
	for _, id := range ids {
		c, err := h.Svc.Store.GetClient(ctx, realm.ID, id)
		if err != nil || !c.Enabled || c.Protocol == service.ProtocolSAML {
			continue
		}
		out = append(out, c)
	}
	return out
}

// logoutOIDCClients sends logout tokens to the back-channel logout URLs of
// the session's clients, and returns the front-channel logout URLs (with
// the client names) for the browser to load.
func (h *Handler) logoutOIDCClients(ctx context.Context, issuer string, realm *model.Realm, us *model.UserSession) (frames, names []string) {
	for _, c := range h.sessionOIDCClients(ctx, realm, us) {
		if u := c.Attributes[attrBackchannelURL]; u != "" {
			h.sendLogoutToken(ctx, issuer, realm, us, c, u)
		}
		if u := c.Attributes[attrFrontchannelURL]; c.FrontchannelLogout && u != "" {
			if c.Attributes[attrFrontchannelSession] != "false" {
				u = appendQuery(u, url.Values{"sid": {us.ID}, "iss": {issuer}})
			}
			frames = append(frames, u)
			name := c.Name
			if name == "" || strings.HasPrefix(name, "${") {
				name = c.ClientID
			}
			names = append(names, name)
		}
	}
	return frames, names
}

// sendLogoutToken posts a Back-Channel Logout token to a client.
func (h *Handler) sendLogoutToken(ctx context.Context, issuer string, realm *model.Realm, us *model.UserSession, c *model.Client, target string) {
	key, err := h.Svc.SigningKey(ctx, realm, "")
	if err != nil {
		h.Log.Warn("back-channel logout", "client", c.ClientID, "err", err)
		return
	}
	now := h.Svc.Now()
	claims := jwt.Claims{
		"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": service.NewID(), "iss": issuer,
		"aud": c.ClientID, "sub": us.UserID, "typ": "Logout",
		"events": map[string]any{backchannelLogoutEvent: map[string]any{}},
	}
	if c.Attributes[attrBackchannelSession] != "false" {
		claims["sid"] = us.ID
	}
	if c.Attributes[attrBackchannelRevokeOff] == "true" {
		claims["revoke_offline_access"] = true
	}
	tok, err := jwt.SignTyped(claims, key, "logout+jwt")
	if err != nil {
		h.Log.Warn("back-channel logout", "client", c.ClientID, "err", err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(url.Values{"logout_token": {tok}}.Encode()))
	if err != nil {
		h.Log.Warn("back-channel logout", "client", c.ClientID, "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := brokerHTTP.Do(req)
	if err != nil {
		h.Log.Warn("back-channel logout", "client", c.ClientID, "err", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		h.Log.Warn("back-channel logout", "client", c.ClientID, "status", resp.StatusCode)
	}
}

// renderFrontchannelLogout shows the page loading the clients' front-channel
// logout URLs, then going on to redirect (or showing that the user is
// logged out).
func (h *Handler) renderFrontchannelLogout(w http.ResponseWriter, r *http.Request, realm *model.Realm, frames, names []string, redirect string) {
	h.render(w, http.StatusOK, "frontchannel-logout", pageData{realm: realm, r: r, Title: "frontchannel-logout.title",
		Frames: frames, Items: names, LinkURL: redirect})
}
