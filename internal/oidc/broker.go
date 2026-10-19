package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// Identity brokering: users log in with an external identity provider.
// The browser is sent to the provider from the login page (or by
// kc_idp_hint), comes back to /broker/{alias}/endpoint, and the brokered
// identity is then either a known link (login), or goes through the first
// broker login flow (create or link a user).

// Auth session keys of a brokered login.
const (
	keyIdP             = "_idp"              // alias of the provider
	keyIdPState        = "_idp_state"        // state sent to the provider
	keyIdPNonce        = "_idp_nonce"        // nonce sent to the provider
	keyIdPVerifier     = "_idp_verifier"     // PKCE code verifier
	keyIdPIdentity     = "_idp_identity"     // brokeredIdentity JSON
	keyIdPExisting     = "_idp_existing"     // id of the existing user with the same email/username
	keyIdPDuplicate    = "_idp_duplicate"    // "attribute value" that matched the existing user
	keyIdPNewUser      = "_idp_new_user"     // the first broker login created the user
	keyIdPReview       = "_idp_review"       // "force": review the profile again
	keyIdPEmailOK      = "_idp_email_ok"     // the existing account was verified by email
	keyIdPLinkUser     = "_idp_link_user"    // client initiated account linking: the user
	keyIdPLinkSession  = "_idp_link_session" // and the SSO session
	keyFlashError      = "_flash_error"      // error shown on the next login page
	notePrefix         = "_note."            // user session notes to set
	bindingFirstBroker = "first_broker_login"
	bindingPostBroker  = "post_broker_login"
)

func (h *Handler) registerBroker(mux *http.ServeMux) {
	const b = "/realms/{realm}/broker/{alias}"
	mux.HandleFunc("GET "+b+"/login", h.brokerLogin)
	mux.HandleFunc("GET "+b+"/endpoint", h.brokerCallback)
	mux.HandleFunc("POST "+b+"/endpoint", h.brokerCallback)
	mux.HandleFunc("GET "+b+"/endpoint/logout_response", h.brokerLogoutResponse)
	mux.HandleFunc("GET "+b+"/link", h.brokerLink)
	mux.HandleFunc("GET "+b+"/token", h.cors(h.brokerToken))
	mux.HandleFunc("OPTIONS "+b+"/token", h.preflight)
}

// enabledIdP loads an enabled identity provider of a known type.
func (h *Handler) enabledIdP(r *http.Request, realm *model.Realm, alias string) (*model.IdentityProvider, error) {
	idp, err := h.Svc.Store.GetIdentityProvider(r.Context(), realm.ID, alias)
	if err != nil {
		return nil, err
	}
	if !idp.Enabled || IdPTypes[idp.ProviderID] == nil {
		return nil, store.ErrNotFound
	}
	return idp, nil
}

// brokerLoginURL is the link of a provider on the login page.
func (h *Handler) brokerLoginURL(r *http.Request, realm *model.Realm, alias, sessionCode string) string {
	return h.URLs.Issuer(r, realm.Name) + "/broker/" + url.PathEscape(alias) + "/login?session_code=" + url.QueryEscape(sessionCode)
}

// brokerLogin handles /broker/{alias}/login: the provider buttons of the
// login page.
func (h *Handler) brokerLogin(w http.ResponseWriter, r *http.Request) {
	realm, as, _, ok := h.authSessionOf(w, r)
	if !ok {
		return
	}
	idp, err := h.enabledIdP(r, realm, r.PathValue("alias"))
	if err != nil || idp.LinkOnly {
		h.errorPage(w, r, http.StatusBadRequest, "identityProviderNotFoundMessage")
		return
	}
	h.redirectToIdP(w, r, realm, as, idp)
}

// redirectToIdP sends the browser to the provider's authorization endpoint.
func (h *Handler) redirectToIdP(w http.ResponseWriter, r *http.Request, realm *model.Realm, as *model.AuthSession, idp *model.IdentityProvider) {
	state := service.RandomToken(16)
	as.Params[keyIdP] = idp.Alias
	as.Params[keyIdPState] = state
	as.Params[keyIdPNonce] = service.RandomToken(16)
	delete(as.Params, keyIdPVerifier)
	if idp.Config["pkceEnabled"] == "true" {
		as.Params[keyIdPVerifier] = service.RandomToken(32)
	}
	u, err := h.authorizationURL(r, realm, idp, as, as.ID+"."+state, as.Params[keyIdPNonce], as.Params[keyIdPVerifier])
	if err == nil {
		err = h.Svc.Store.UpdateAuthSession(r.Context(), as)
	}
	if err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}

// brokerFail ends a brokered login with an error: back to the login page
// (or to the client, when linking an account).
func (h *Handler) brokerFail(w http.ResponseWriter, r *http.Request, realm *model.Realm, client *model.Client, as *model.AuthSession,
	idp *model.IdentityProvider, code, msg string) {
	h.event(r, realm, "IDENTITY_PROVIDER_LOGIN_ERROR", &eventInfo{client: client, err: code,
		details: map[string]string{"identity_provider": idp.Alias}})
	if as.Params[keyIdPLinkUser] != "" {
		h.linkResult(w, r, realm, as, msg)
		return
	}
	// do not send the browser to the provider again (kc_idp_hint)
	delete(as.Params, "kc_idp_hint")
	if msg != "" {
		as.Params[keyFlashError] = msg
	}
	as.UserID = ""
	h.startFlow(w, r, realm, client, as, "browser")
}

// brokerCallback handles /broker/{alias}/endpoint, where the provider
// returns the browser.
func (h *Handler) brokerCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	realm, err := h.realm(r)
	if err != nil {
		h.errorPage(w, r, http.StatusNotFound, "realmNotFoundMessage")
		return
	}
	idp, err := h.enabledIdP(r, realm, r.PathValue("alias"))
	if err != nil {
		h.errorPage(w, r, http.StatusBadRequest, "identityProviderNotFoundMessage")
		return
	}
	asID, state, _ := strings.Cut(r.FormValue("state"), ".")
	if asID == "" || state == "" {
		h.errorPage(w, r, http.StatusBadRequest, "identityProviderMissingStateMessage")
		return
	}
	as, err := h.Svc.Store.GetAuthSession(ctx, asID)
	if err != nil || as.RealmID != realm.ID || h.Svc.Now().After(as.ExpiresAt) || as.Params[keyIdP] != idp.Alias ||
		subtle.ConstantTimeCompare([]byte(as.Params[keyIdPState]), []byte(state)) != 1 {
		h.errorPage(w, r, http.StatusBadRequest, "loginTimeout")
		return
	}
	// The response must come back to the browser that started the login.
	// Only a form_post response (Apple), a cross-site POST, comes without
	// the SameSite=Lax cookie; it is bound by the state alone.
	if ck, err := r.Cookie(authSessionCookie); (err != nil && r.Method != http.MethodPost) || (err == nil && ck.Value != as.ID) {
		h.errorPage(w, r, http.StatusBadRequest, "loginTimeout")
		return
	}
	delete(as.Params, keyIdPState) // the state is single use
	client, err := h.Svc.Store.GetClient(ctx, realm.ID, as.ClientID)
	if err != nil {
		h.errorPage(w, r, http.StatusBadRequest, "clientNotFoundMessage")
		return
	}
	if e := r.FormValue("error"); e != "" {
		msg := "identityProviderUnexpectedErrorMessage"
		if e == "access_denied" {
			msg = "" // cancelled by the user: back to the login page
		}
		h.brokerFail(w, r, realm, client, as, idp, e, msg)
		return
	}
	code := r.FormValue("code")
	if code == "" {
		h.brokerFail(w, r, realm, client, as, idp, "invalid_code", "identityProviderMissingCodeOrErrorMessage")
		return
	}
	call := &brokerCall{h: h, r: r, realm: realm, idp: idp, typ: IdPTypes[idp.ProviderID], nonce: as.Params[keyIdPNonce]}
	if err := call.exchangeCode(code, as.Params[keyIdPVerifier]); err != nil {
		h.Log.Warn("identity provider token request", "alias", idp.Alias, "err", err)
		h.brokerFail(w, r, realm, client, as, idp, "invalid_code", "identityProviderUnexpectedErrorMessage")
		return
	}
	id, err := call.typ.profile(ctx, call)
	if err == nil && id.ID == "" {
		err = errors.New("the provider returned no user id")
	}
	if err != nil {
		h.Log.Warn("identity provider profile", "alias", idp.Alias, "err", err)
		h.brokerFail(w, r, realm, client, as, idp, "invalid_token", "identityProviderInvalidResponseMessage")
		return
	}
	if idp.StoreToken {
		id.Token = string(call.tokenJSON)
	}
	id.IDToken = call.idToken
	id.BrokerUsername = id.Username
	mappers, err := h.Svc.Store.ListIdPMappers(ctx, realm.ID, idp.Alias)
	if err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	preprocessIdentity(idp, mappers, id)

	if as.Params[keyIdPLinkUser] != "" {
		h.linkAccount(w, r, realm, client, as, idp, id)
		return
	}
	link, err := h.Svc.Store.FindFederatedIdentity(ctx, realm.ID, idp.Alias, id.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		h.serverErrorPage(w, r, err)
		return
	}
	if link == nil {
		if idp.LinkOnly {
			h.brokerFail(w, r, realm, client, as, idp, "identity_provider_link_only", "identityProviderLinkOnlyMessage")
			return
		}
		h.startFirstBrokerLogin(w, r, realm, client, as, id)
		return
	}

	// A known account: log the linked user in.
	user, err := h.Svc.Store.GetUser(ctx, realm.ID, link.UserID)
	if err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	fc := &flowContext{h: h, w: w, r: r, realm: realm, client: client, as: as, user: user}
	if !user.Enabled {
		h.event(r, realm, "IDENTITY_PROVIDER_LOGIN_ERROR", &eventInfo{client: client, userID: user.ID, err: "user_disabled",
			details: map[string]string{"identity_provider": idp.Alias}})
		h.errorPage(w, r, http.StatusBadRequest, "accountDisabledMessage")
		return
	}
	if locked, err := h.Svc.TemporarilyLocked(ctx, realm, user); err != nil || locked {
		h.errorPage(w, r, http.StatusBadRequest, "accountTemporarilyDisabledMessage")
		return
	}
	if link.FederatedUsername != id.BrokerUsername || (idp.StoreToken && link.Token != id.Token) {
		link.FederatedUsername = id.BrokerUsername
		if idp.StoreToken {
			link.Token = id.Token
		}
		if err := h.Svc.Store.UpdateFederatedIdentity(ctx, link); err != nil {
			h.serverErrorPage(w, r, err)
			return
		}
	}
	notes := map[string]string{}
	mc := &mapperContext{ctx: ctx, st: h.Svc.Store, realm: realm, idp: idp, id: id, user: user, notes: notes}
	if err := runMappers(mc, mappers, true); err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	h.event(r, realm, "IDENTITY_PROVIDER_LOGIN", &eventInfo{client: client, userID: user.ID, details: map[string]string{
		"identity_provider": idp.Alias, "identity_provider_identity": id.BrokerUsername}})
	h.brokerIdentified(fc, idp, id, notes)
}

// brokerIdentified continues a login whose user is known: the post broker
// login flow if the provider has one, then required actions.
func (h *Handler) brokerIdentified(fc *flowContext, idp *model.IdentityProvider, id *brokeredIdentity, notes map[string]string) {
	notes[noteIdP] = idp.Alias
	notes[noteIdPIdentity] = id.BrokerUsername
	if id.IDToken != "" {
		notes[noteFederatedIDT] = id.IDToken
	}
	for k, v := range notes {
		fc.as.Params[notePrefix+k] = v
	}
	fc.as.UserID = fc.user.ID
	delete(fc.as.Params, keyActions)
	if idp.PostBrokerLoginFlowAlias != "" && fc.as.Params[keyFlow] != bindingPostBroker {
		h.startFlow(fc.w, fc.r, fc.realm, fc.client, fc.as, bindingPostBroker)
		return
	}
	h.afterAuthentication(fc)
}

// startFirstBrokerLogin runs the first broker login flow for an identity
// that is not linked yet.
func (h *Handler) startFirstBrokerLogin(w http.ResponseWriter, r *http.Request, realm *model.Realm, client *model.Client, as *model.AuthSession, id *brokeredIdentity) {
	b, _ := json.Marshal(id)
	as.Params[keyIdPIdentity] = string(b)
	for _, k := range []string{keyIdPExisting, keyIdPDuplicate, keyIdPNewUser, keyIdPReview, keyIdPEmailOK} {
		delete(as.Params, k)
	}
	as.UserID = ""
	as.Params[keyFlow] = bindingFirstBroker
	delete(as.Params, keyDone)
	if err := h.Svc.Store.UpdateAuthSession(r.Context(), as); err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	// The flow runs on our own URL, so that the auth session cookie is
	// sent even when the provider posted the response (Apple).
	http.Redirect(w, r, h.loginActionURL(r, realm, "authenticate", as.ID), http.StatusFound)
}

// brokerFlow returns the flow of a broker binding.
func (h *Handler) brokerFlow(r *http.Request, realm *model.Realm, as *model.AuthSession, binding string) (*model.AuthFlow, error) {
	idp, err := h.Svc.Store.GetIdentityProvider(r.Context(), realm.ID, as.Params[keyIdP])
	if err != nil {
		return nil, err
	}
	alias := service.FirstBrokerLoginFlow(realm, idp)
	if binding == bindingPostBroker {
		alias = idp.PostBrokerLoginFlowAlias
	}
	return h.Svc.Store.GetFlowByAlias(r.Context(), realm.ID, alias)
}

// brokerState loads the provider and identity of a first broker login.
func (fc *flowContext) brokerState() (*model.IdentityProvider, *brokeredIdentity, error) {
	idp, err := fc.h.Svc.Store.GetIdentityProvider(fc.ctx(), fc.realm.ID, fc.as.Params[keyIdP])
	if err != nil {
		return nil, nil, err
	}
	var id brokeredIdentity
	if err := json.Unmarshal([]byte(fc.as.Params[keyIdPIdentity]), &id); err != nil {
		return nil, nil, errors.New("no brokered identity in the login")
	}
	return idp, &id, nil
}

func (fc *flowContext) saveIdentity(id *brokeredIdentity) {
	b, _ := json.Marshal(id)
	fc.as.Params[keyIdPIdentity] = string(b)
}

// afterFirstBrokerLogin links the user the first broker login flow created
// or confirmed, then finishes the login.
func (h *Handler) afterFirstBrokerLogin(fc *flowContext) {
	ctx := fc.ctx()
	idp, id, err := fc.brokerState()
	if err != nil || fc.user == nil {
		h.errorPage(fc.w, fc.r, http.StatusBadRequest, "invalidFlowMessage")
		return
	}
	notes := map[string]string{}
	if fc.as.Params[keyIdPNewUser] != "true" {
		// an existing account: link it now
		link := &model.FederatedIdentity{UserID: fc.user.ID, RealmID: fc.realm.ID, IdentityProvider: idp.Alias,
			FederatedUserID: id.ID, FederatedUsername: id.BrokerUsername, Token: id.Token}
		err := h.Svc.Store.CreateFederatedIdentity(ctx, link)
		if errors.Is(err, store.ErrConflict) {
			h.errorPage(fc.w, fc.r, http.StatusConflict, "identityProviderAlreadyLinkedMessage", idp.Alias)
			return
		}
		if err != nil {
			h.serverErrorPage(fc.w, fc.r, err)
			return
		}
		mappers, err := h.Svc.Store.ListIdPMappers(ctx, fc.realm.ID, idp.Alias)
		if err != nil {
			h.serverErrorPage(fc.w, fc.r, err)
			return
		}
		mc := &mapperContext{ctx: ctx, st: h.Svc.Store, realm: fc.realm, idp: idp, id: id, user: fc.user, notes: notes}
		if err := runMappers(mc, mappers, false); err != nil {
			h.serverErrorPage(fc.w, fc.r, err)
			return
		}
		h.event(fc.r, fc.realm, "FEDERATED_IDENTITY_LINK", &eventInfo{client: fc.client, userID: fc.user.ID, details: map[string]string{
			"identity_provider": idp.Alias, "identity_provider_identity": id.BrokerUsername}})
	} else {
		for k := range fc.as.Params {
			if strings.HasPrefix(k, notePrefix) {
				notes[strings.TrimPrefix(k, notePrefix)] = fc.as.Params[k]
			}
		}
	}
	// a trusted provider verifies the email it returned
	if idp.TrustEmail && !fc.user.EmailVerified && id.Email != "" && strings.EqualFold(id.Email, fc.user.Email) && fc.as.Params[keyIdPReview] != "changed" {
		fc.user.EmailVerified = true
		if err := h.Svc.Store.UpdateUser(ctx, fc.user); err != nil {
			h.serverErrorPage(fc.w, fc.r, err)
			return
		}
	}
	h.event(fc.r, fc.realm, "IDENTITY_PROVIDER_FIRST_LOGIN", &eventInfo{client: fc.client, userID: fc.user.ID, details: map[string]string{
		"identity_provider": idp.Alias, "identity_provider_identity": id.BrokerUsername}})
	delete(fc.as.Params, keyIdPIdentity)
	h.brokerIdentified(fc, idp, id, notes)
}

// ---------------------------------------------------------------- account linking

// LinkHash is the hash a client sends to /broker/{alias}/link, binding the
// request to the user's session (Keycloak's client initiated account linking).
func LinkHash(nonce, sessionID, clientID, alias string) string {
	sum := sha256.Sum256([]byte(nonce + sessionID + clientID + alias))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// brokerLink handles /broker/{alias}/link: a logged in user links an
// identity provider account to theirs.
func (h *Handler) brokerLink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	realm, err := h.realm(r)
	if err != nil {
		h.errorPage(w, r, http.StatusNotFound, "realmNotFoundMessage")
		return
	}
	q := r.URL.Query()
	client, err := h.Svc.Store.GetClientByClientID(ctx, realm.ID, q.Get("client_id"))
	if err != nil || !client.Enabled {
		h.errorPage(w, r, http.StatusBadRequest, "clientNotFoundMessage")
		return
	}
	redirect := q.Get("redirect_uri")
	if redirect == "" || !matchRedirectURI(h.URLs.Base(r), client, redirect) {
		h.errorPage(w, r, http.StatusBadRequest, "invalidRedirectUriMessage")
		return
	}
	fail := func(code string) { h.redirectResult(w, r, redirect, "query", url.Values{"error": {code}}) }
	us, user := h.ssoSession(r, realm)
	if us == nil || !us.Clients[client.ID] {
		fail("not_logged_in")
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("hash")), []byte(LinkHash(q.Get("nonce"), us.ID, client.ClientID, r.PathValue("alias")))) != 1 {
		fail("invalid_hash")
		return
	}
	if ok, err := h.canManageLinks(r, realm, user); err != nil || !ok {
		fail("not_allowed")
		return
	}
	idp, err := h.enabledIdP(r, realm, r.PathValue("alias"))
	if err != nil {
		fail("unknown_provider")
		return
	}
	as, err := h.newAuthSession(w, r, realm, client, map[string]string{"client_id": client.ClientID, "redirect_uri": redirect,
		keyIdPLinkUser: user.ID, keyIdPLinkSession: us.ID})
	if err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	h.redirectToIdP(w, r, realm, as, idp)
}

// canManageLinks reports whether a user may link accounts: the account
// client's manage-account or manage-account-links role.
func (h *Handler) canManageLinks(r *http.Request, realm *model.Realm, user *model.User) (bool, error) {
	acc, err := h.Svc.Store.GetClientByClientID(r.Context(), realm.ID, service.AccountClient)
	if err != nil {
		return false, err
	}
	roles, err := h.Svc.EffectiveRoles(r.Context(), realm.ID, user.ID)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(roles, func(role *model.Role) bool {
		return role.ClientID == acc.ID && (role.Name == "manage-account" || role.Name == "manage-account-links")
	}), nil
}

// linkAccount completes client initiated account linking.
func (h *Handler) linkAccount(w http.ResponseWriter, r *http.Request, realm *model.Realm, client *model.Client, as *model.AuthSession,
	idp *model.IdentityProvider, id *brokeredIdentity) {
	ctx := r.Context()
	user, err := h.Svc.Store.GetUser(ctx, realm.ID, as.Params[keyIdPLinkUser])
	if err != nil || !user.Enabled {
		h.linkResult(w, r, realm, as, "not_logged_in")
		return
	}
	if us, _ := h.Svc.Store.GetUserSession(ctx, as.Params[keyIdPLinkSession]); us == nil || us.UserID != user.ID {
		h.linkResult(w, r, realm, as, "not_logged_in")
		return
	}
	existing, err := h.Svc.Store.FindFederatedIdentity(ctx, realm.ID, idp.Alias, id.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		h.serverErrorPage(w, r, err)
		return
	}
	if existing != nil && existing.UserID != user.ID {
		h.linkResult(w, r, realm, as, "identityProviderAlreadyLinkedMessage")
		return
	}
	link := &model.FederatedIdentity{UserID: user.ID, RealmID: realm.ID, IdentityProvider: idp.Alias,
		FederatedUserID: id.ID, FederatedUsername: id.BrokerUsername, Token: id.Token}
	current, err := h.Svc.Store.GetFederatedIdentity(ctx, user.ID, idp.Alias)
	switch {
	case err == nil && current.FederatedUserID != id.ID:
		h.linkResult(w, r, realm, as, "federatedIdentityAlreadyLinkedMessage")
		return
	case err == nil:
		err = h.Svc.Store.UpdateFederatedIdentity(ctx, link)
	case errors.Is(err, store.ErrNotFound):
		err = h.Svc.Store.CreateFederatedIdentity(ctx, link)
	}
	if err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	h.event(r, realm, "FEDERATED_IDENTITY_LINK", &eventInfo{client: client, userID: user.ID, details: map[string]string{
		"identity_provider": idp.Alias, "identity_provider_identity": id.BrokerUsername}})
	h.linkResult(w, r, realm, as, "")
}

// linkResult ends account linking by returning to the client.
func (h *Handler) linkResult(w http.ResponseWriter, r *http.Request, realm *model.Realm, as *model.AuthSession, errCode string) {
	h.Svc.Store.DeleteAuthSession(r.Context(), as.ID)
	h.clearCookie(w, r, realm, authSessionCookie)
	v := url.Values{}
	if errCode != "" {
		v.Set("error", errCode)
	}
	h.redirectResult(w, r, as.Params["redirect_uri"], "query", v)
}

// ---------------------------------------------------------------- stored tokens

// brokerToken handles /broker/{alias}/token: an application reads the
// provider token stored for its user (requires broker/read-token).
func (h *Handler) brokerToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	realm, err := h.realm(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	vt, err := h.Svc.VerifyToken(ctx, realm, bearerToken(r), h.URLs.Issuer(r, realm.Name), service.TokenBearer)
	if err != nil || vt.User == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": "Invalid token"})
		return
	}
	alias := r.PathValue("alias")
	idp, err := h.Svc.Store.GetIdentityProvider(ctx, realm.ID, alias)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"errorMessage": "Identity Provider [" + alias + "] not found."})
		return
	}
	broker, _ := vt.Claims["resource_access"].(map[string]any)
	roles, _ := broker[service.BrokerClient].(map[string]any)
	allowed := false
	for _, x := range toStrings(roles["roles"]) {
		allowed = allowed || x == service.ReadTokenRole
	}
	if !allowed {
		writeJSON(w, http.StatusForbidden, map[string]string{"errorMessage": "Client [" + vt.Claims.String("azp") +
			"] not authorized to retrieve tokens from identity provider [" + alias + "]."})
		return
	}
	if !idp.StoreToken {
		writeJSON(w, http.StatusBadRequest, map[string]string{"errorMessage": "Identity Provider [" + alias + "] does not support this operation."})
		return
	}
	link, err := h.Svc.Store.GetFederatedIdentity(ctx, vt.User.ID, alias)
	if err != nil || link.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"errorMessage": "User [" + vt.User.ID + "] is not associated with identity provider [" + alias + "]."})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(link.Token))
}

func toStrings(v any) []string {
	var out []string
	if list, ok := v.([]any); ok {
		for _, x := range list {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- login page

// providerLink is an identity provider button of the login page.
type providerLink struct {
	Alias, DisplayName, ProviderID, URL string
}

// loginProviders lists the providers shown on the login page.
func (h *Handler) loginProviders(r *http.Request, realm *model.Realm, as *model.AuthSession) []providerLink {
	idps, err := h.Svc.Store.ListIdentityProviders(r.Context(), realm.ID)
	if err != nil {
		return nil
	}
	var out []providerLink
	for _, idp := range idps {
		if !idp.Enabled || idp.LinkOnly || idp.HideOnLogin || IdPTypes[idp.ProviderID] == nil {
			continue
		}
		name := idp.DisplayName
		if name == "" {
			name = idp.Alias
			if t := IdPTypes[idp.ProviderID]; t.Social {
				name = t.Name
			}
		}
		out = append(out, providerLink{Alias: idp.Alias, DisplayName: name, ProviderID: idp.ProviderID,
			URL: h.brokerLoginURL(r, realm, idp.Alias, as.ID) + "&client_id=" + url.QueryEscape(as.Params["client_id"])})
	}
	return out
}

// ---------------------------------------------------------------- logout

// Session notes of a brokered login.
const (
	noteIdP          = "identity_provider"
	noteIdPIdentity  = "identity_provider_identity"
	noteFederatedIDT = "FEDERATED_ID_TOKEN"
	tokenLogoutState = "broker-logout"
)

// idpLogout ends the session at the identity provider the user logged in
// with, when the provider has a logout URL. A provider supporting
// back-channel logout is called directly. Otherwise, for a browser logout,
// the returned URL sends the browser to the provider, which returns to
// /broker/{alias}/endpoint/logout_response and then to redirect.
func (h *Handler) idpLogout(r *http.Request, realm *model.Realm, us *model.UserSession, browser bool, redirect, state string) string {
	alias, idToken := us.Notes[noteIdP], us.Notes[noteFederatedIDT]
	if alias == "" {
		return ""
	}
	idp, err := h.Svc.Store.GetIdentityProvider(r.Context(), realm.ID, alias)
	if err != nil || !idp.Enabled || idp.Config["logoutUrl"] == "" {
		return ""
	}
	logoutURL, err := url.Parse(idp.Config["logoutUrl"])
	if err != nil {
		return ""
	}
	q := logoutURL.Query()
	if idToken != "" {
		q.Set("id_token_hint", idToken)
	} else {
		q.Set("client_id", idp.Config["clientId"])
	}
	if idp.Config["backchannelSupported"] == "true" {
		q.Set("state", us.ID)
		logoutURL.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, logoutURL.String(), nil)
		if err == nil {
			var resp *http.Response
			if resp, err = brokerHTTP.Do(req); err == nil {
				resp.Body.Close()
			}
		}
		if err != nil {
			h.Log.Warn("identity provider back-channel logout", "alias", alias, "err", err)
		}
		return ""
	}
	if !browser {
		return ""
	}
	key, err := h.Svc.SigningKey(r.Context(), realm, "HS512")
	if err != nil {
		return ""
	}
	st, err := jwt.Sign(jwt.Claims{"typ": tokenLogoutState, "sid": us.ID, "reduri": redirect, "st": state,
		"exp": h.Svc.Now().Add(authSessionTTL).Unix()}, key)
	if err != nil {
		return ""
	}
	q.Set("state", st)
	q.Set("post_logout_redirect_uri", h.brokerEndpoint(r, realm, idp)+"/logout_response")
	logoutURL.RawQuery = q.Encode()
	return logoutURL.String()
}

// brokerLogoutResponse handles /broker/{alias}/endpoint/logout_response,
// where the provider returns the browser after a front-channel logout.
func (h *Handler) brokerLogoutResponse(w http.ResponseWriter, r *http.Request) {
	realm, err := h.realm(r)
	if err != nil {
		h.errorPage(w, r, http.StatusNotFound, "realmNotFoundMessage")
		return
	}
	claims, err := jwt.Verify(r.URL.Query().Get("state"), func(kid, alg string) *jwt.Key { return h.Svc.VerificationKey(r.Context(), realm.ID, kid, alg) })
	if err != nil || claims.String("typ") != tokenLogoutState || claims.Int("exp") < h.Svc.Now().Unix() {
		h.errorPage(w, r, http.StatusBadRequest, "identityProviderMissingStateMessage")
		return
	}
	if redirect := claims.String("reduri"); redirect != "" {
		h.redirectResult(w, r, redirect, "query", url.Values{"state": {claims.String("st")}})
		return
	}
	h.render(w, http.StatusOK, "info", pageData{realm: realm, r: r, Title: "loggedOut"})
}
