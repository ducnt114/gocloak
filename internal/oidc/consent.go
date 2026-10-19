package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/saml"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// keyConsented marks a login whose consent page was accepted.
const keyConsented = "_consented"

// pendingConsent returns what the user still has to consent to for a login
// (nothing when the client does not require consent).
func (h *Handler) pendingConsent(ctx context.Context, realm *model.Realm, client *model.Client, user *model.User, params map[string]string) ([]service.ConsentItem, error) {
	if !client.ConsentRequired {
		return nil, nil
	}
	scopes, _, _, err := resolveScopes(ctx, h.Svc.Store, realm, client, params["scope"])
	if err != nil {
		return nil, err
	}
	items := service.ConsentItems(client, scopes)
	if strings.Contains(params["prompt"], "consent") {
		return items, nil
	}
	consent, err := h.Svc.Store.GetConsent(ctx, user.ID, client.ID)
	if errors.Is(err, store.ErrNotFound) {
		return items, nil
	}
	if err != nil {
		return nil, err
	}
	var out []service.ConsentItem
	for _, it := range items {
		if !slicesContains(consent.Scopes, it.ID) {
			out = append(out, it)
		}
	}
	return out, nil
}

func slicesContains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// consentDetail is the "consent" detail of LOGIN events.
func consentDetail(c *model.Client, params map[string]string) string {
	switch {
	case !c.ConsentRequired:
		return "no_consent_required"
	case params[keyConsented] != "":
		return "consent_granted"
	}
	return "persistent_consent"
}

func clientDisplayName(c *model.Client) string {
	if c.Name != "" && !strings.HasPrefix(c.Name, "${") {
		return c.Name
	}
	return c.ClientID
}

// askConsent renders the consent page of a login when the user has
// something to grant; it reports whether it did.
func (h *Handler) askConsent(fc *flowContext) (bool, error) {
	if fc.as.Params[keyConsented] != "" {
		return false, nil
	}
	items, err := h.pendingConsent(fc.ctx(), fc.realm, fc.client, fc.user, fc.as.Params)
	if err != nil || len(items) == 0 {
		return false, err
	}
	var texts []string
	for _, it := range items {
		if key := service.MessageRef(it.Text); key != "" {
			texts = append(texts, key)
		} else {
			texts = append(texts, it.Text)
		}
	}
	h.render(fc.w, http.StatusOK, "login-oauth-grant", pageData{realm: fc.realm, r: fc.r, user: fc.user,
		Title: "oauthGrantTitle", TitleArgs: []any{clientDisplayName(fc.client)}, Items: texts,
		Action: h.loginActionURL(fc.r, fc.realm, "consent", fc.as.ID)})
	return true, nil
}

// consentEndpoint receives the consent page (/login-actions/consent).
func (h *Handler) consentEndpoint(w http.ResponseWriter, r *http.Request) {
	realm, as, client, ok := h.authSessionOf(w, r)
	if !ok {
		return
	}
	if as.UserID == "" {
		h.errorPage(w, r, http.StatusBadRequest, "invalidFlowMessage")
		return
	}
	ctx := r.Context()
	user, err := h.Svc.Store.GetUser(ctx, realm.ID, as.UserID)
	if err != nil {
		h.errorPage(w, r, http.StatusBadRequest, "invalidFlowMessage")
		return
	}
	if r.PostFormValue("accept") == "" {
		h.event(r, realm, "LOGIN_ERROR", &eventInfo{client: client, userID: user.ID, err: "rejected_by_user"})
		_ = h.Svc.Store.DeleteAuthSession(ctx, as.ID)
		h.clearCookie(w, r, realm, authSessionCookie)
		if client.Protocol == service.ProtocolSAML {
			h.samlSendStatus(w, r, realm, client, as.Params, saml.StatusRequester, saml.StatusRequestDenied)
			return
		}
		h.redirectResult(w, r, as.Params["redirect_uri"], as.Params["response_mode"], url.Values{
			"error": {"access_denied"}, "state": {as.Params["state"]}, "iss": {h.URLs.Issuer(r, realm.Name)}})
		return
	}
	items, err := h.pendingConsent(ctx, realm, client, user, as.Params)
	if err == nil {
		err = h.Svc.GrantConsent(ctx, h.Svc.Store, realm.ID, user.ID, client, items)
	}
	if err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	as.Params[keyConsented] = "true"
	if err := h.Svc.Store.UpdateAuthSession(ctx, as); err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	fc := &flowContext{h: h, w: w, r: r, realm: realm, client: client, as: as, user: user}
	if as.Params[keyFlow] == "browser" || as.Params[keyFlow] == "" {
		if us, _ := h.ssoSession(r, realm); us != nil && us.UserID == user.ID {
			fc.sso = us
		}
	}
	h.processRequiredActions(fc, "")
}
