package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/etree"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/saml"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// This file implements Keycloak's SAML 2.0 identity provider: the
// /protocol/saml endpoint (AuthnRequest, LogoutRequest and LogoutResponse
// over the HTTP-Redirect and HTTP-POST bindings), IdP initiated login
// (/protocol/saml/clients/{name}) and the IdP metadata descriptor.

// Auth session parameters of a SAML login.
const (
	pSAMLRequestID = "saml_request_id"
	pSAMLBinding   = "saml_binding" // binding of the response: "post" or "redirect"
	pSAMLRelay     = "saml_relay_state"
	pSAMLNameID    = "saml_name_id_format" // NameID format asked by the request
)

const (
	bindingPost     = "post"
	bindingRedirect = "redirect"
)

// samlUserActionLifespan is Keycloak's default accessCodeLifespanUserAction,
// the validity of the subject confirmation.
const samlUserActionLifespan = 300 * time.Second

func (h *Handler) registerSAML(mux *http.ServeMux) {
	const p = "/realms/{realm}/protocol/saml"
	mux.HandleFunc("GET "+p, h.samlEndpoint)
	mux.HandleFunc("POST "+p, h.samlEndpoint)
	mux.HandleFunc("GET "+p+"/descriptor", h.samlDescriptor)
	mux.HandleFunc("GET "+p+"/clients/{client}", h.samlIdPInitiated)
	mux.HandleFunc("POST "+p+"/clients/{client}", h.samlIdPInitiated)
}

func (h *Handler) samlURL(r *http.Request, realm *model.Realm) string {
	return h.URLs.Issuer(r, realm.Name) + "/protocol/saml"
}

// samlNote is the user session note keeping per client SAML state.
func samlNote(clientID, key string) string { return "saml:" + clientID + ":" + key }

// ---------------------------------------------------------------- descriptor

// samlDescriptor serves the IdP metadata.
func (h *Handler) samlDescriptor(w http.ResponseWriter, r *http.Request) {
	realm, err := h.realm(r)
	if err != nil {
		h.errorPage(w, r, http.StatusNotFound, "realmNotFoundMessage")
		return
	}
	keys, err := h.Svc.RealmKeys(r.Context(), realm.ID)
	if err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	if _, err := h.Svc.SigningKey(r.Context(), realm, "RS256"); err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	var certs []saml.DescriptorKey
	for _, k := range keys {
		if k.Enabled && k.Alg == "RS256" && k.Certificate != nil {
			certs = append(certs, saml.DescriptorKey{Name: k.Kid, Cert: k.Certificate})
		}
	}
	w.Header().Set("Content-Type", "application/xml;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte(saml.IdPDescriptor(h.URLs.Issuer(r, realm.Name), h.samlURL(r, realm), certs)))
}

// ---------------------------------------------------------------- endpoint

// samlEndpoint handles the messages sent to /protocol/saml.
func (h *Handler) samlEndpoint(w http.ResponseWriter, r *http.Request) {
	realm, err := h.realm(r)
	if err != nil {
		h.errorPage(w, r, http.StatusNotFound, "realmNotFoundMessage")
		return
	}
	msg, err := saml.ReadMessage(r)
	if err != nil {
		h.errorPage(w, r, http.StatusBadRequest, "invalidRequestMessage")
		return
	}
	q, err := saml.Parse(msg.XML)
	if err != nil {
		h.errorPage(w, r, http.StatusBadRequest, "invalidRequestMessage")
		return
	}
	switch {
	case msg.Request && q.Name == "AuthnRequest":
		h.samlAuthnRequest(w, r, realm, msg, q)
	case msg.Request && q.Name == "LogoutRequest":
		h.samlLogoutRequest(w, r, realm, msg, q)
	case !msg.Request && q.Name == "LogoutResponse":
		h.samlLogoutResponse(w, r, realm, msg, q)
	default:
		h.errorPage(w, r, http.StatusBadRequest, "invalidRequestMessage")
	}
}

// samlRequester returns the enabled SAML client that sent a request, after
// checking its signature when the client must sign its requests.
func (h *Handler) samlRequester(w http.ResponseWriter, r *http.Request, realm *model.Realm, msg *saml.Message, q *saml.Request) (*model.Client, bool) {
	client, err := h.Svc.Store.GetClientByClientID(r.Context(), realm.ID, q.Issuer)
	if err != nil || client.Protocol != service.ProtocolSAML {
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			h.serverErrorPage(w, r, err)
			return nil, false
		}
		h.errorPage(w, r, http.StatusBadRequest, "invalidRequestMessage")
		return nil, false
	}
	if !client.Enabled {
		h.errorPage(w, r, http.StatusBadRequest, "loginRequesterNotEnabledMessage")
		return nil, false
	}
	if client.Attributes[service.SAMLClientSignature] == "true" {
		certs := service.ParseCertificates(client.Attributes[service.SAMLSigningCert])
		// the redirect binding signs the query string; some service
		// providers sign the message itself instead, which is accepted too
		if msg.Binding == saml.BindingRedirect && (msg.Signed() || !q.HasSignature) {
			err = msg.VerifyQuerySignature(certs)
		} else {
			err = q.VerifySignature(certs)
		}
		if err == nil && q.Issuer != client.ClientID {
			err = saml.ErrInvalid
		}
		if err != nil {
			h.Log.Debug("SAML request signature", "client", client.ClientID, "err", err)
			h.event(r, realm, "LOGIN_ERROR", &eventInfo{client: client, err: "invalid_signature"})
			h.errorPage(w, r, http.StatusBadRequest, "invalidRequesterMessage")
			return nil, false
		}
	}
	if q.Destination != "" && q.Destination != h.samlURL(r, realm) {
		h.errorPage(w, r, http.StatusBadRequest, "invalidRequestMessage")
		return nil, false
	}
	return client, true
}

// samlAssertionConsumer returns the configured assertion consumer URL of a
// client for a binding, falling back to the other binding and the admin URL.
func samlAssertionConsumer(base string, c *model.Client, binding string) (string, string) {
	post, redirect := c.Attributes[service.SAMLACSPost], c.Attributes[service.SAMLACSRedirect]
	switch {
	case binding == bindingPost && post != "":
		return post, bindingPost
	case binding == bindingRedirect && redirect != "":
		return redirect, bindingRedirect
	case post != "":
		return post, bindingPost
	case redirect != "":
		return redirect, bindingRedirect
	case c.AdminURL != "":
		return resolveURI(base, c, c.AdminURL), binding
	}
	return "", binding
}

// samlAuthnRequest starts a login for an AuthnRequest.
func (h *Handler) samlAuthnRequest(w http.ResponseWriter, r *http.Request, realm *model.Realm, msg *saml.Message, q *saml.Request) {
	client, ok := h.samlRequester(w, r, realm, msg, q)
	if !ok {
		return
	}
	base := h.URLs.Base(r)
	binding := bindingPost
	switch {
	case client.Attributes[service.SAMLForcePostBinding] == "true":
	case q.ProtocolBinding == saml.BindingRedirect:
		binding = bindingRedirect
	case q.ProtocolBinding == "" && msg.Binding == saml.BindingRedirect:
		binding = bindingRedirect
	}
	acs := q.ACSURL
	if acs != "" {
		if !matchRedirectURI(base, client, acs) {
			h.errorPage(w, r, http.StatusBadRequest, "invalidSamlRedirectUriMessage")
			return
		}
	} else {
		acs, binding = samlAssertionConsumer(base, client, binding)
		if acs == "" {
			h.errorPage(w, r, http.StatusBadRequest, "invalidSamlRedirectUriMessage")
			return
		}
	}
	params := map[string]string{
		"client_id": client.ClientID, "redirect_uri": acs,
		pSAMLRequestID: q.ID, pSAMLBinding: binding, pSAMLRelay: msg.RelayState, pSAMLNameID: q.NameIDPolicy,
	}
	if q.ForceAuthn {
		params["prompt"] = "login"
	}
	if q.IsPassive {
		us, user := h.ssoSession(r, realm)
		if us == nil || len(user.RequiredActions) > 0 {
			h.samlSendStatus(w, r, realm, client, params, saml.StatusResponder, saml.StatusNoPassive)
			return
		}
		h.finishLogin(w, r, realm, client, user, us, params)
		return
	}
	as, err := h.newAuthSession(w, r, realm, client, params)
	if err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	h.startFlow(w, r, realm, client, as, "browser")
}

// samlIdPInitiated starts an IdP initiated login for the client whose
// saml_idp_initiated_sso_url_name is the {client} path value.
func (h *Handler) samlIdPInitiated(w http.ResponseWriter, r *http.Request) {
	realm, err := h.realm(r)
	if err != nil {
		h.errorPage(w, r, http.StatusNotFound, "realmNotFoundMessage")
		return
	}
	name := r.PathValue("client")
	clients, err := h.Svc.Store.ListClients(r.Context(), realm.ID, "", 0, 0)
	if err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	var client *model.Client
	for _, c := range clients {
		if c.Protocol == service.ProtocolSAML && name != "" && c.Attributes[service.SAMLIdPInitiatedName] == name {
			client = c
			break
		}
	}
	if client == nil {
		h.errorPage(w, r, http.StatusBadRequest, "clientNotFoundMessage")
		return
	}
	if !client.Enabled {
		h.errorPage(w, r, http.StatusBadRequest, "loginRequesterNotEnabledMessage")
		return
	}
	acs, binding := samlAssertionConsumer(h.URLs.Base(r), client, bindingPost)
	if acs == "" {
		h.errorPage(w, r, http.StatusBadRequest, "invalidSamlRedirectUriMessage")
		return
	}
	relay := r.FormValue("RelayState")
	if relay == "" {
		relay = client.Attributes[service.SAMLIdPInitiatedRelay]
	}
	params := map[string]string{"client_id": client.ClientID, "redirect_uri": acs, pSAMLBinding: binding, pSAMLRelay: relay}
	as, err := h.newAuthSession(w, r, realm, client, params)
	if err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	h.startFlow(w, r, realm, client, as, "browser")
}

// ---------------------------------------------------------------- responses

// samlSigner returns the realm key signing SAML documents for a client.
func (h *Handler) samlSigner(ctx context.Context, realm *model.Realm, client *model.Client) (*saml.Signer, error) {
	k, err := h.Svc.SigningKey(ctx, realm, "RS256")
	if err != nil {
		return nil, err
	}
	priv, ok := k.Private.(*rsa.PrivateKey)
	if !ok || k.Certificate == nil {
		return nil, errors.New("the realm RS256 key has no certificate")
	}
	return &saml.Signer{Key: priv, Cert: k.Certificate, KeyName: k.Kid,
		Algorithm: saml.SignatureAlgorithm(client.Attributes[service.SAMLSignatureAlgorithm]),
		Canonical: client.Attributes[service.SAMLCanonicalization]}, nil
}

// samlSend delivers a message to a service provider: through the browser
// with the HTTP-POST (auto-submitted form) or HTTP-Redirect binding. The
// document (POST) or the query string (redirect) is signed when sign is set.
func (h *Handler) samlSend(w http.ResponseWriter, r *http.Request, signer *saml.Signer, sign bool, el *etree.Element, param, destination, binding, relayState string) {
	if !sign {
		signer = nil
	}
	if binding == bindingRedirect {
		xml, err := saml.Serialize(el)
		if err == nil {
			var u string
			if u, err = saml.RedirectURL(destination, param, xml, relayState, signer); err == nil {
				http.Redirect(w, r, u, http.StatusFound)
				return
			}
		}
		h.serverErrorPage(w, r, err)
		return
	}
	if signer != nil {
		if err := signer.Sign(el); err != nil {
			h.serverErrorPage(w, r, err)
			return
		}
	}
	xml, err := saml.Serialize(el)
	if err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	fields := url.Values{param: {base64.StdEncoding.EncodeToString(xml)}}
	if relayState != "" {
		fields.Set("RelayState", relayState)
	}
	w.Header().Set("Cache-Control", "no-store, must-revalidate, max-age=0")
	h.render(w, http.StatusOK, "form-post", pageData{Action: destination, Fields: fields, r: r})
}

// samlSendStatus answers a login request with an error status.
func (h *Handler) samlSendStatus(w http.ResponseWriter, r *http.Request, realm *model.Realm, client *model.Client, params map[string]string, status, sub string) {
	signer, err := h.samlSigner(r.Context(), realm, client)
	if err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	resp := &saml.Response{ID: saml.NewID(), InResponseTo: params[pSAMLRequestID], Destination: params["redirect_uri"],
		Issuer: h.URLs.Issuer(r, realm.Name), IssueInstant: h.Svc.Now(), Status: status, SubStatus: sub}
	h.samlSend(w, r, signer, client.Attributes[service.SAMLServerSignature] == "true", resp.Element(), "SAMLResponse",
		params["redirect_uri"], params[pSAMLBinding], params[pSAMLRelay])
}

// samlNameIDFormat returns the NameID format of a login: the requested one
// unless the client forces its own.
func samlNameIDFormat(c *model.Client, requested string) string {
	configured := map[string]string{"email": saml.NameIDEmail, "transient": saml.NameIDTransient,
		"persistent": saml.NameIDPersistent}[c.Attributes[service.SAMLNameIDFormat]]
	if configured == "" {
		configured = saml.NameIDUnspecified
	}
	if c.Attributes[service.SAMLForceNameIDFormat] != "true" && requested != "" && requested != saml.NameIDUnspecified {
		return requested
	}
	return configured
}

// samlNameID returns the NameID of the user for a format, as Keycloak
// computes it (a NameID mapper for the format takes precedence).
func samlNameID(tc *tokenContext, format string) string {
	u := tc.user
	for _, m := range tc.mappers {
		if m.Type == service.SAMLMapperNameID && m.Config["mapper.nameid.format"] == format {
			if v := u.Attributes[m.Config["user.attribute"]]; len(v) > 0 && v[0] != "" {
				return v[0]
			}
		}
	}
	switch format {
	case saml.NameIDEmail:
		if u.Email != "" {
			return u.Email
		}
	case saml.NameIDTransient:
		return "G-" + service.NewID()
	case saml.NameIDPersistent:
		// Keycloak reads the persistent id from a user attribute, and
		// otherwise generates one
		for _, k := range []string{"saml.persistent.name.id.for." + tc.client.ClientID, "saml.persistent.name.id.for.*"} {
			if v := u.Attributes[k]; len(v) > 0 && v[0] != "" {
				return v[0]
			}
		}
		return "G-" + service.NewID()
	}
	return u.Username
}

// samlLoginResponse finishes a SAML login: it issues the assertion and
// posts (or redirects) the response to the assertion consumer service.
func (h *Handler) samlLoginResponse(w http.ResponseWriter, r *http.Request, realm *model.Realm, client *model.Client, user *model.User, us *model.UserSession, params map[string]string) {
	ctx := r.Context()
	now := h.Svc.Now()
	tc, _, err := newTokenContext(ctx, h.Svc, h.URLs.Base(r), realm, client, user, us, "", false)
	if err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	format := samlNameIDFormat(client, params[pSAMLNameID])
	nameID := samlNameID(tc, format)
	if us.Notes == nil {
		us.Notes = map[string]string{}
	}
	csid := us.Notes[samlNote(client.ID, "csid")]
	if csid == "" {
		csid = service.NewID()
	}
	us.Notes[samlNote(client.ID, "csid")] = csid
	us.Notes[samlNote(client.ID, "nameid")] = nameID
	us.Notes[samlNote(client.ID, "nameid_format")] = format
	if err := h.Svc.Store.UpdateUserSession(ctx, us); err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	attrs, audiences, err := tc.samlAttributes(ctx)
	if err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	signer, err := h.samlSigner(ctx, realm, client)
	if err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	issuer := h.URLs.Issuer(r, realm.Name)
	acs := params["redirect_uri"]
	// Keycloak's validity window starts two seconds before the issue instant
	start := now.Add(-2 * time.Second)
	lifespan := time.Duration(realm.AccessCodeLifespan) * time.Second
	if n, err := strconv.Atoi(client.Attributes[service.SAMLAssertionLifespan]); err == nil && n > 0 {
		lifespan = time.Duration(n) * time.Second
	}
	a := &saml.Assertion{
		ID: saml.NewID(), Issuer: issuer, IssueInstant: now,
		NameID: nameID, NameIDFormat: format,
		InResponseTo: params[pSAMLRequestID], Recipient: acs, SubjectNotOnOrAfter: start.Add(samlUserActionLifespan),
		NotBefore: start, NotOnOrAfter: start.Add(lifespan), Audiences: append([]string{client.ClientID}, audiences...),
		AuthnStatement: client.Attributes[service.SAMLAuthnStatement] != "false", AuthnInstant: now,
		SessionIndex:        us.ID + "::" + csid,
		SessionNotOnOrAfter: now.Add(time.Duration(h.Svc.SessionMaxLifespan(realm, us)) * time.Second),
		Attributes:          attrs,
	}
	el := a.Element()
	if signer.Inclusive() {
		// the assertion is signed on its own but verified inside the
		// response, so it declares the namespaces it inherits there
		el.CreateAttr("xmlns:samlp", saml.NSProtocol)
	}
	if client.Attributes[service.SAMLAssertionSignature] == "true" {
		if err := signer.Sign(el); err != nil {
			h.serverErrorPage(w, r, err)
			return
		}
	}
	if client.Attributes[service.SAMLEncrypt] == "true" {
		certs := service.ParseCertificates(client.Attributes[service.SAMLEncryptionCert])
		if len(certs) == 0 {
			h.serverErrorPage(w, r, errors.New("SAML client "+client.ClientID+" has no encryption certificate"))
			return
		}
		if el, err = saml.EncryptAssertion(el, certs[0], saml.EncryptionOptions{
			Algorithm: client.Attributes[service.SAMLEncryptionAlgorithm], KeyAlgorithm: client.Attributes[service.SAMLEncryptionKeyAlg],
			Digest: client.Attributes[service.SAMLEncryptionDigest], MGF: client.Attributes[service.SAMLEncryptionMGF],
		}); err != nil {
			h.serverErrorPage(w, r, err)
			return
		}
	}
	resp := &saml.Response{ID: saml.NewID(), InResponseTo: params[pSAMLRequestID], Destination: acs, Issuer: issuer,
		IssueInstant: now, Assertion: el}
	h.event(r, realm, "LOGIN", &eventInfo{client: client, userID: user.ID, sessionID: us.ID, details: map[string]string{
		"auth_method": "saml", "redirect_uri": acs, "consent": "no_consent_required", "code_id": us.ID, "username": user.Username}})
	h.samlSend(w, r, signer, client.Attributes[service.SAMLServerSignature] == "true", resp.Element(), "SAMLResponse",
		acs, params[pSAMLBinding], params[pSAMLRelay])
}

// ---------------------------------------------------------------- logout

// samlLogoutTarget is a SAML client of a session to notify at logout.
type samlLogoutTarget struct {
	client       *model.Client
	nameID       string
	format       string
	sessionIndex string
}

// samlLogoutTargets returns the SAML clients of a session with a logout
// service, except the one initiating the logout.
func (h *Handler) samlLogoutTargets(ctx context.Context, realm *model.Realm, us *model.UserSession, except string) ([]samlLogoutTarget, error) {
	var out []samlLogoutTarget
	ids := make([]string, 0, len(us.Clients))
	for id := range us.Clients {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		if id == except || us.Notes[samlNote(id, "nameid")] == "" {
			continue
		}
		c, err := h.Svc.Store.GetClient(ctx, realm.ID, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if c.Protocol != service.ProtocolSAML || !c.Enabled {
			continue
		}
		out = append(out, samlLogoutTarget{client: c, nameID: us.Notes[samlNote(id, "nameid")],
			format: us.Notes[samlNote(id, "nameid_format")], sessionIndex: us.ID + "::" + us.Notes[samlNote(id, "csid")]})
	}
	return out, nil
}

// samlLogoutURL returns where a client receives logout messages through the
// browser, and the binding.
func samlLogoutURL(c *model.Client) (string, string) {
	post, redirect := c.Attributes[service.SAMLSLOPost], c.Attributes[service.SAMLSLORedirect]
	switch {
	case post != "" && (redirect == "" || c.Attributes[service.SAMLForcePostBinding] == "true"):
		return post, bindingPost
	case redirect != "":
		return redirect, bindingRedirect
	}
	return "", ""
}

func (h *Handler) samlLogoutRequestElement(r *http.Request, realm *model.Realm, t samlLogoutTarget, destination string) *etree.Element {
	return (&saml.LogoutRequest{ID: saml.NewID(), Destination: destination, Issuer: h.URLs.Issuer(r, realm.Name),
		IssueInstant: h.Svc.Now(), NameID: t.nameID, NameIDFormat: t.format, SessionIndex: t.sessionIndex}).Element()
}

// Logout state kept in an auth session while the browser visits the
// front-channel logout services of the session's SAML clients.
const (
	pLogoutChain     = "_saml_logout"      // client ids still to visit
	pLogoutTargets   = "_saml_targets"     // client id -> "nameid\x00format\x00sessionIndex"
	pLogoutInitiator = "_saml_initiator"   // SAML client that sent the LogoutRequest
	pLogoutRequestID = "_saml_request_id"  // its request id
	pLogoutRelay     = "_saml_relay_state" // its relay state
	pLogoutRedirect  = "_logout_redirect"  // OIDC post logout redirect (with state)
)

// samlLogoutRequest handles a LogoutRequest from a service provider.
func (h *Handler) samlLogoutRequest(w http.ResponseWriter, r *http.Request, realm *model.Realm, msg *saml.Message, q *saml.Request) {
	ctx := r.Context()
	client, ok := h.samlRequester(w, r, realm, msg, q)
	if !ok {
		return
	}
	// the session of the browser, or the one named by the session index
	us, _ := h.ssoSession(r, realm)
	if us == nil {
		for _, si := range q.SessionIndexes {
			sid, _, _ := strings.Cut(si, "::")
			s, err := h.Svc.Store.GetUserSession(ctx, sid)
			if err != nil || s.RealmID != realm.ID {
				continue
			}
			// the session must include the client, with the same NameID
			if nameID := s.Notes[samlNote(client.ID, "nameid")]; nameID != "" && nameID == q.NameID {
				us = s
				break
			}
		}
	}
	state := &model.AuthSession{ID: service.RandomToken(24), RealmID: realm.ID, ClientID: client.ID,
		ExpiresAt: h.Svc.Now().Add(authSessionTTL),
		Params:    map[string]string{pLogoutInitiator: client.ID, pLogoutRequestID: q.ID, pLogoutRelay: msg.RelayState}}
	if us != nil {
		if err := h.samlEndSession(w, r, realm, us, client.ID, state); err != nil {
			h.serverErrorPage(w, r, err)
			return
		}
		h.event(r, realm, "LOGOUT", &eventInfo{client: client, userID: us.UserID, sessionID: us.ID})
	}
	h.samlContinueLogout(w, r, realm, state)
}

// samlEndSession ends a user session at logout: the back-channel clients are
// notified now, the front-channel ones are queued in state, and the session
// and the SSO cookies are removed.
func (h *Handler) samlEndSession(w http.ResponseWriter, r *http.Request, realm *model.Realm, us *model.UserSession, initiator string, state *model.AuthSession) error {
	ctx := r.Context()
	if _, err := h.queueSAMLLogouts(r, realm, us, initiator, state); err != nil {
		return err
	}
	h.idpLogout(r, realm, us, false, "", "")
	if err := h.Svc.Store.DeleteUserSession(ctx, us.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	h.clearCookie(w, r, realm, identityCookie)
	h.clearCookie(w, r, realm, sessionCookie)
	return nil
}

// samlContinueLogout sends the browser to the next front-channel logout
// service, or finishes the logout.
func (h *Handler) samlContinueLogout(w http.ResponseWriter, r *http.Request, realm *model.Realm, state *model.AuthSession) {
	ctx := r.Context()
	chain := strings.Fields(state.Params[pLogoutChain])
	for len(chain) > 0 {
		id := chain[0]
		chain = chain[1:]
		c, err := h.Svc.Store.GetClient(ctx, realm.ID, id)
		if err != nil {
			continue
		}
		dest, binding := samlLogoutURL(c)
		parts := strings.SplitN(state.Params[pLogoutTargets+"."+id], "\x00", 3)
		if dest == "" || len(parts) != 3 {
			continue
		}
		state.Params[pLogoutChain] = strings.Join(chain, " ")
		if err := h.saveLogoutState(ctx, state); err != nil {
			h.serverErrorPage(w, r, err)
			return
		}
		signer, err := h.samlSigner(ctx, realm, c)
		if err != nil {
			h.serverErrorPage(w, r, err)
			return
		}
		el := h.samlLogoutRequestElement(r, realm, samlLogoutTarget{nameID: parts[0], format: parts[1], sessionIndex: parts[2]}, dest)
		h.samlSend(w, r, signer, c.Attributes[service.SAMLServerSignature] == "true", el, "SAMLRequest", dest, binding, state.ID)
		return
	}
	_ = h.Svc.Store.DeleteAuthSession(ctx, state.ID)

	if redirect, ok := state.Params[pLogoutRedirect]; ok {
		if redirect != "" {
			http.Redirect(w, r, redirect, http.StatusFound)
			return
		}
		h.render(w, http.StatusOK, "info", pageData{realm: realm, r: r, Title: "loggedOut"})
		return
	}
	// answer the service provider that initiated the logout
	initiator, err := h.Svc.Store.GetClient(ctx, realm.ID, state.Params[pLogoutInitiator])
	dest, binding := "", ""
	if err == nil {
		dest, binding = samlLogoutURL(initiator)
	}
	if dest == "" {
		h.render(w, http.StatusOK, "info", pageData{realm: realm, r: r, Title: "loggedOut"})
		return
	}
	signer, err := h.samlSigner(ctx, realm, initiator)
	if err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	resp := &saml.LogoutResponse{ID: saml.NewID(), InResponseTo: state.Params[pLogoutRequestID], Destination: dest,
		Issuer: h.URLs.Issuer(r, realm.Name), IssueInstant: h.Svc.Now()}
	h.samlSend(w, r, signer, initiator.Attributes[service.SAMLServerSignature] == "true", resp.Element(), "SAMLResponse",
		dest, binding, state.Params[pLogoutRelay])
}

func (h *Handler) saveLogoutState(ctx context.Context, state *model.AuthSession) error {
	if _, err := h.Svc.Store.GetAuthSession(ctx, state.ID); errors.Is(err, store.ErrNotFound) {
		return h.Svc.Store.CreateAuthSession(ctx, state)
	} else if err != nil {
		return err
	}
	return h.Svc.Store.UpdateAuthSession(ctx, state)
}

// samlLogoutResponse continues a front-channel logout when a service
// provider answers our LogoutRequest; the relay state names the logout.
func (h *Handler) samlLogoutResponse(w http.ResponseWriter, r *http.Request, realm *model.Realm, msg *saml.Message, q *saml.Request) {
	state, err := h.Svc.Store.GetAuthSession(r.Context(), msg.RelayState)
	if err != nil || state.RealmID != realm.ID || h.Svc.Now().After(state.ExpiresAt) || state.Params[pLogoutInitiator] == "" && state.Params[pLogoutRedirect] == "" && state.Params[pLogoutChain] == "" {
		// a logout we do not know (or that already finished)
		h.render(w, http.StatusOK, "info", pageData{realm: realm, r: r, Title: "loggedOut"})
		return
	}
	if q.Status != saml.StatusSuccess {
		h.Log.Info("SAML logout response", "issuer", q.Issuer, "status", q.Status)
	}
	h.samlContinueLogout(w, r, realm, state)
}

// samlBrowserLogout runs the front-channel SAML logouts of a session ended
// by the OIDC logout endpoint; redirect is where the browser goes after
// ("" shows the logged out page). It reports false when there is nothing to
// do through the browser.
func (h *Handler) samlBrowserLogout(w http.ResponseWriter, r *http.Request, realm *model.Realm, us *model.UserSession, redirect string) (bool, error) {
	state := &model.AuthSession{ID: service.RandomToken(24), RealmID: realm.ID, ExpiresAt: h.Svc.Now().Add(authSessionTTL),
		Params: map[string]string{pLogoutRedirect: redirect}}
	n, err := h.queueSAMLLogouts(r, realm, us, "", state)
	if err != nil || n == 0 {
		return false, err
	}
	h.samlContinueLogout(w, r, realm, state)
	return true, nil
}

// queueSAMLLogouts notifies the back-channel SAML clients of a session and
// queues the front-channel ones in the logout state; it returns how many
// were queued.
func (h *Handler) queueSAMLLogouts(r *http.Request, realm *model.Realm, us *model.UserSession, initiator string, state *model.AuthSession) (int, error) {
	targets, err := h.samlLogoutTargets(r.Context(), realm, us, initiator)
	if err != nil {
		return 0, err
	}
	var chain []string
	for _, t := range targets {
		if !t.client.FrontchannelLogout {
			h.samlBackchannel(r.Context(), h.URLs.Issuer(r, realm.Name), realm, t)
			continue
		}
		if u, _ := samlLogoutURL(t.client); u == "" {
			continue
		}
		chain = append(chain, t.client.ID)
		state.Params[pLogoutTargets+"."+t.client.ID] = t.nameID + "\x00" + t.format + "\x00" + t.sessionIndex
	}
	state.Params[pLogoutChain] = strings.Join(chain, " ")
	if len(chain) > 0 && state.ClientID == "" {
		state.ClientID = chain[0]
	}
	return len(chain), nil
}

// samlBackchannel posts a LogoutRequest to a client from the server: with
// the SOAP binding when the client has a SOAP logout URL, otherwise as a
// form to its POST logout URL (or admin URL).
func (h *Handler) samlBackchannel(ctx context.Context, issuer string, realm *model.Realm, t samlLogoutTarget) {
	c := t.client
	soap := c.Attributes[service.SAMLSLOSOAP]
	dest := soap
	if dest == "" {
		if dest = c.Attributes[service.SAMLSLOPost]; dest == "" {
			dest = c.AdminURL
		}
	}
	if dest == "" {
		return
	}
	el := (&saml.LogoutRequest{ID: saml.NewID(), Destination: dest, Issuer: issuer, IssueInstant: h.Svc.Now(),
		NameID: t.nameID, NameIDFormat: t.format, SessionIndex: t.sessionIndex}).Element()
	if c.Attributes[service.SAMLServerSignature] == "true" {
		signer, err := h.samlSigner(ctx, realm, c)
		if err != nil {
			h.Log.Warn("SAML back-channel logout", "client", c.ClientID, "err", err)
			return
		}
		if err := signer.Sign(el); err != nil {
			h.Log.Warn("SAML back-channel logout", "client", c.ClientID, "err", err)
			return
		}
	}
	var req *http.Request
	var err error
	if soap != "" {
		var body []byte
		if body, err = saml.Serialize(saml.SOAPEnvelope(el)); err == nil {
			req, err = http.NewRequestWithContext(ctx, http.MethodPost, dest, strings.NewReader(string(body)))
			if err == nil {
				req.Header.Set("Content-Type", "text/xml; charset=utf-8")
				req.Header.Set("SOAPAction", "http://www.oasis-open.org/committees/security")
			}
		}
	} else {
		var body []byte
		if body, err = saml.Serialize(el); err == nil {
			form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(body)}}
			req, err = http.NewRequestWithContext(ctx, http.MethodPost, dest, strings.NewReader(form.Encode()))
			if err == nil {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
		}
	}
	if err == nil {
		var resp *http.Response
		if resp, err = brokerHTTP.Do(req); err == nil {
			resp.Body.Close()
			if resp.StatusCode >= 300 {
				h.Log.Warn("SAML back-channel logout", "client", c.ClientID, "status", resp.StatusCode)
			}
		}
	}
	if err != nil {
		h.Log.Warn("SAML back-channel logout", "client", c.ClientID, "err", err)
	}
}

// BackchannelLogout notifies the SAML clients of sessions ended outside of
// a browser logout (registered as the service's LogoutHandler).
func (h *Handler) BackchannelLogout(ctx context.Context, base string, realm *model.Realm, sessions []*model.UserSession) {
	issuer := base + "/realms/" + url.PathEscape(realm.Name)
	for _, us := range sessions {
		targets, err := h.samlLogoutTargets(ctx, realm, us, "")
		if err != nil {
			h.Log.Warn("SAML back-channel logout", "err", err)
			continue
		}
		for _, t := range targets {
			// front-channel clients can only be reached through the browser
			if !t.client.FrontchannelLogout || t.client.Attributes[service.SAMLSLOSOAP] != "" {
				h.samlBackchannel(ctx, issuer, realm, t)
			}
		}
	}
}
