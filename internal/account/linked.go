package account

import (
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/oidc"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// linkedAccountRep is Keycloak's LinkedAccountRepresentation.
type linkedAccountRep struct {
	Connected      bool   `json:"connected"`
	Social         bool   `json:"social"`
	ProviderAlias  string `json:"providerAlias"`
	ProviderName   string `json:"providerName"`
	DisplayName    string `json:"displayName"`
	GUIOrder       string `json:"guiOrder,omitempty"`
	LinkedUsername string `json:"linkedUsername,omitempty"`
}

// linkedAccounts lists the realm's enabled identity providers with the
// user's links.
func (h *Handler) linkedAccounts(r *http.Request, c *caller) ([]linkedAccountRep, error) {
	idps, err := h.Svc.Store.ListIdentityProviders(r.Context(), c.realm.ID)
	if err != nil {
		return nil, err
	}
	links, err := h.Svc.Store.ListFederatedIdentities(r.Context(), c.user.ID)
	if err != nil {
		return nil, err
	}
	linked := map[string]*model.FederatedIdentity{}
	for _, l := range links {
		linked[l.IdentityProvider] = l
	}
	out := []linkedAccountRep{}
	for _, idp := range idps {
		t := oidc.IdPTypes[idp.ProviderID]
		if !idp.Enabled || t == nil {
			continue
		}
		rep := linkedAccountRep{Social: t.Social, ProviderAlias: idp.Alias, ProviderName: idp.ProviderID,
			DisplayName: idp.DisplayName, GUIOrder: idp.GUIOrder}
		if rep.DisplayName == "" {
			rep.DisplayName = idp.Alias
		}
		if l := linked[idp.Alias]; l != nil {
			rep.Connected, rep.LinkedUsername = true, l.FederatedUsername
		}
		out = append(out, rep)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, aerr := strconv.Atoi(out[i].GUIOrder)
		b, berr := strconv.Atoi(out[j].GUIOrder)
		if aerr == nil && berr == nil && a != b {
			return a < b
		}
		return out[i].DisplayName < out[j].DisplayName
	})
	return out, nil
}

func (h *Handler) apiLinkedAccounts(w http.ResponseWriter, r *http.Request, c *caller) error {
	list, err := h.linkedAccounts(r, c)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	search := strings.ToLower(strings.Trim(q.Get("search"), "*"))
	filtered := []linkedAccountRep{}
	for _, a := range list {
		if q.Get("linked") != "" && strconv.FormatBool(a.Connected) != q.Get("linked") {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(a.DisplayName), search) && !strings.Contains(strings.ToLower(a.ProviderAlias), search) {
			continue
		}
		filtered = append(filtered, a)
	}
	return writeJSON(w, http.StatusOK, filtered)
}

// unlink removes a link, keeping at least one way to log in.
func (h *Handler) unlink(r *http.Request, c *caller, alias string) error {
	ctx := r.Context()
	links, err := h.Svc.Store.ListFederatedIdentities(ctx, c.user.ID)
	if err != nil {
		return err
	}
	found := false
	for _, l := range links {
		found = found || l.IdentityProvider == alias
	}
	if !found {
		return &apiError{http.StatusBadRequest, map[string]string{"errorMessage": "federatedIdentityNotActiveMessage"}}
	}
	if len(links) == 1 {
		creds, err := h.Svc.Store.ListCredentials(ctx, c.user.ID)
		if err != nil {
			return err
		}
		hasPassword := false
		for _, cr := range creds {
			hasPassword = hasPassword || cr.Type == model.CredentialPassword
		}
		if !hasPassword {
			return &apiError{http.StatusBadRequest, map[string]string{"errorMessage": "federatedIdentityRemovingLastProviderMessage"}}
		}
	}
	if err := h.Svc.Store.DeleteFederatedIdentity(ctx, c.user.ID, alias); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	h.Svc.RecordEvent(ctx, c.realm, &model.Event{Type: "REMOVE_FEDERATED_IDENTITY", ClientID: service.AccountClient,
		UserID: c.user.ID, Details: map[string]string{"identity_provider": alias}})
	return nil
}

func (h *Handler) apiUnlink(w http.ResponseWriter, r *http.Request, c *caller) error {
	if err := h.unlink(r, c, r.PathValue("alias")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// linkURL is where the browser goes to link a provider account, for the
// client the user is logged in with.
func (h *Handler) linkURL(r *http.Request, c *caller, clientID, alias, redirect string) (string, string, string) {
	nonce := service.RandomToken(16)
	hash := oidc.LinkHash(nonce, c.session.ID, clientID, alias)
	u := h.URLs.Issuer(r, c.realm.Name) + "/broker/" + url.PathEscape(alias) + "/link?" + url.Values{
		"client_id": {clientID}, "redirect_uri": {redirect}, "nonce": {nonce}, "hash": {hash}}.Encode()
	return u, nonce, hash
}

// apiLinkURI returns the link URL for the account console application:
// GET /account/linked-accounts/{alias}?providerId=&redirectUri=.
func (h *Handler) apiLinkURI(w http.ResponseWriter, r *http.Request, c *caller) error {
	alias := r.PathValue("alias")
	if _, err := h.Svc.Store.GetIdentityProvider(r.Context(), c.realm.ID, alias); err != nil {
		return &apiError{http.StatusBadRequest, map[string]string{"errorMessage": "Invalid identity provider"}}
	}
	if c.session == nil {
		return &apiError{http.StatusBadRequest, map[string]string{"errorMessage": "Invalid session"}}
	}
	redirect := r.URL.Query().Get("redirectUri")
	if redirect == "" {
		return &apiError{http.StatusBadRequest, map[string]string{"errorMessage": "missing redirectUri"}}
	}
	u, nonce, hash := h.linkURL(r, c, c.clientID, alias, redirect)
	return writeJSON(w, http.StatusOK, map[string]string{"accountLinkUri": u, "nonce": nonce, "hash": hash})
}

// ---------------------------------------------------------------- pages

func (h *Handler) linkedAccountsPage(w http.ResponseWriter, r *http.Request, c *caller) error {
	list, err := h.linkedAccounts(r, c)
	if err != nil {
		return err
	}
	p := accountPage{Section: "linked-accounts", Title: "linkedAccounts", LinkedAccounts: list}
	switch {
	case r.URL.Query().Get("linkError") != "":
		p.Error = r.URL.Query().Get("linkError")
	case r.URL.Query().Get("removed") == "true":
		p.Message = "identityProviderRemovedMessage"
	}
	h.render(w, r, c, http.StatusOK, "linked-accounts", p)
	return nil
}

func (h *Handler) linkPage(w http.ResponseWriter, r *http.Request, c *caller) error {
	iss := h.URLs.Issuer(r, c.realm.Name)
	u, _, _ := h.linkURL(r, c, service.AccountClient, r.PathValue("alias"), iss+"/account/linked-accounts")
	http.Redirect(w, r, u, http.StatusSeeOther)
	return nil
}

func (h *Handler) unlinkPage(w http.ResponseWriter, r *http.Request, c *caller) error {
	iss := h.URLs.Issuer(r, c.realm.Name)
	err := h.unlink(r, c, r.PathValue("alias"))
	var ae *apiError
	if errors.As(err, &ae) {
		body, _ := ae.body.(map[string]string)
		http.Redirect(w, r, iss+"/account/linked-accounts?linkError="+url.QueryEscape(body["errorMessage"]), http.StatusSeeOther)
		return nil
	}
	if err != nil {
		return err
	}
	http.Redirect(w, r, iss+"/account/linked-accounts?removed=true", http.StatusSeeOther)
	return nil
}
