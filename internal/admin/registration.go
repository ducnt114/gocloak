package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// Dynamic client registration (OpenID Connect Dynamic Client Registration,
// RFC 7591 / 7592) at /realms/{realm}/clients-registrations/openid-connect,
// and a variant taking client representations at .../default.
// Clients register anonymously, with an initial access token or with a
// user's access token, under the realm's client registration policies; each
// registered client gets a registration access token to manage itself.

const (
	tokenTypeIAT = "InitialAccessToken"
	tokenTypeRAT = "RegistrationAccessToken"
)

func regError(status int, code, desc string) error {
	return &httpError{status: status, key: code, msg: desc}
}

// regAuth is how a registration request authenticated.
type regAuth struct {
	kind string // anonymous or authenticated: the policies that apply
	iat  *model.InitialAccessToken
	user bool // a user's access token
}

func (h *Handler) registerClientRegistration(mux *http.ServeMux, add func(string, handlerFunc)) {
	const D = "/realms/{realm}/clients-registrations"
	plain := func(fn func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if err := fn(w, r); err != nil {
				h.writeError(w, r, err)
			}
		}
	}
	for _, kind := range []string{"openid-connect", "default"} {
		kind := kind
		mux.HandleFunc("POST "+D+"/"+kind, plain(func(w http.ResponseWriter, r *http.Request) error { return h.registerClient(w, r, kind) }))
		mux.HandleFunc("GET "+D+"/"+kind+"/{client}", plain(func(w http.ResponseWriter, r *http.Request) error { return h.getRegisteredClient(w, r, kind) }))
		mux.HandleFunc("PUT "+D+"/"+kind+"/{client}", plain(func(w http.ResponseWriter, r *http.Request) error { return h.updateRegisteredClient(w, r, kind) }))
		mux.HandleFunc("DELETE "+D+"/"+kind+"/{client}", plain(h.deleteRegisteredClient))
	}
	const R = "/admin/realms/{realm}"
	add("POST "+R+"/clients-initial-access", h.createInitialAccess)
	add("GET "+R+"/clients-initial-access", h.listInitialAccess)
	add("DELETE "+R+"/clients-initial-access/{id}", h.deleteInitialAccess)
	add("POST "+R+"/clients/{id}/registration-access-token", h.regenerateRegistrationToken)
	add("GET "+R+"/client-registration-policy/providers", h.registrationPolicyProviders)
}

// ---------------------------------------------------------------- tokens

func (h *Handler) signRegistrationToken(ctx context.Context, r *http.Request, realm *model.Realm, claims jwt.Claims) (string, error) {
	key, err := h.Svc.SigningKey(ctx, realm, "HS512")
	if err != nil {
		return "", err
	}
	iss := h.URLs.Issuer(r, realm.Name)
	claims["iss"], claims["aud"] = iss, iss
	return jwt.Sign(claims, key)
}

// registrationToken issues the registration access token of a client; with
// rotate a new token replaces the previous ones, otherwise the current one
// is signed again.
func (h *Handler) registrationToken(ctx context.Context, r *http.Request, realm *model.Realm, c *model.Client, kind string, rotate bool) (string, error) {
	id, err := h.Svc.Store.RegistrationTokenID(ctx, c.ID)
	if err != nil {
		return "", err
	}
	if id == "" || rotate {
		id = service.NewID()
		if err := h.Svc.Store.SetRegistrationTokenID(ctx, c.ID, id); err != nil {
			return "", err
		}
	}
	if kind == "" {
		kind = "authenticated"
	}
	return h.signRegistrationToken(ctx, r, realm, jwt.Claims{"jti": id, "typ": tokenTypeRAT, "registration_auth": kind,
		"iat": h.Svc.Now().Unix(), "exp": 0})
}

// verifyRegistrationToken checks an initial or registration access token.
func (h *Handler) verifyRegistrationToken(r *http.Request, realm *model.Realm, tok string) (jwt.Claims, error) {
	claims, err := jwt.Verify(tok, func(kid, alg string) *jwt.Key { return h.Svc.VerificationKey(r.Context(), realm.ID, kid, alg) })
	if err != nil || claims.String("iss") != h.URLs.Issuer(r, realm.Name) {
		return nil, regError(http.StatusUnauthorized, "invalid_token", "Failed decode token")
	}
	return claims, nil
}

// registrationAuth authenticates a request creating a client.
func (h *Handler) registrationAuth(r *http.Request, realm *model.Realm) (*regAuth, error) {
	tok, _ := service.AccessToken(r)
	if tok == "" {
		return &regAuth{kind: "anonymous"}, nil
	}
	_, claims, err := jwt.Parse(tok)
	if err != nil {
		return nil, regError(http.StatusUnauthorized, "invalid_token", "Failed decode token")
	}
	if claims.String("typ") == tokenTypeIAT {
		if claims, err = h.verifyRegistrationToken(r, realm, tok); err != nil {
			return nil, err
		}
		iat, err := h.Svc.Store.GetInitialAccessToken(r.Context(), realm.ID, claims.String("jti"))
		if errors.Is(err, store.ErrNotFound) {
			return nil, regError(http.StatusUnauthorized, "invalid_token", "Initial Access Token not found")
		}
		if err != nil {
			return nil, err
		}
		if iat.Expiration > 0 && h.Svc.Now().Unix() > iat.Created+int64(iat.Expiration) {
			return nil, regError(http.StatusUnauthorized, "invalid_token", "Expired initial access token")
		}
		if iat.Remaining <= 0 {
			return nil, regError(http.StatusUnauthorized, "invalid_token", "No remaining count on initial access token")
		}
		return &regAuth{kind: "authenticated", iat: iat}, nil
	}
	p, err := h.authenticate(r)
	if err != nil || !p.can(realm, permCreateClient) {
		return nil, regError(http.StatusUnauthorized, "invalid_token", "Failed decode token")
	}
	return &regAuth{kind: "authenticated", user: true}, nil
}

// registeredClient loads the client of a registration management request
// and checks its registration access token (or a user's token allowed to
// manage clients).
func (h *Handler) registeredClient(r *http.Request, write bool) (*model.Realm, *model.Client, string, error) {
	ctx := r.Context()
	realm, err := h.Svc.Store.GetRealmByName(ctx, r.PathValue("realm"))
	if err != nil {
		return nil, nil, "", regError(http.StatusNotFound, "not_found", "Realm not found")
	}
	denied := regError(http.StatusUnauthorized, "invalid_token", "Not authorized to view client. Not valid token or client credentials provided.")
	if write {
		denied = regError(http.StatusUnauthorized, "invalid_token", "Not authorized to update client. Maybe missing token or bad token type.")
	}
	tok, _ := service.AccessToken(r)
	if tok == "" {
		return nil, nil, "", denied
	}
	c, err := h.Svc.Store.GetClientByClientID(ctx, realm.ID, r.PathValue("client"))
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, "", denied
	}
	if err != nil {
		return nil, nil, "", err
	}
	_, claims, err := jwt.Parse(tok)
	if err != nil {
		return nil, nil, "", denied
	}
	if claims.String("typ") == tokenTypeRAT {
		if claims, err = h.verifyRegistrationToken(r, realm, tok); err != nil {
			return nil, nil, "", denied
		}
		id, err := h.Svc.Store.RegistrationTokenID(ctx, c.ID)
		if err != nil {
			return nil, nil, "", err
		}
		if id == "" || id != claims.String("jti") {
			return nil, nil, "", denied
		}
		return realm, c, claims.String("registration_auth"), nil
	}
	p, err := h.authenticate(r)
	if err != nil || !p.can(realm, permManageClients) && (write || !p.can(realm, permViewClients)) {
		return nil, nil, "", denied
	}
	return realm, c, "authenticated", nil
}

// ---------------------------------------------------------------- policies

type policyInput struct {
	client   *model.Client
	scopes   []string // client scope names the client asks for
	mappers  []string // protocol mapper types of the client
	update   bool
	previous *model.Client
}

// checkPolicies applies the client registration policies of a kind
// (anonymous or authenticated), adjusting or rejecting the client.
func (h *Handler) checkPolicies(r *http.Request, realm *model.Realm, kind string, in *policyInput) error {
	ctx := r.Context()
	policies, err := h.Svc.Store.ListComponents(ctx, realm.ID, service.RegistrationPolicyType)
	if err != nil {
		return err
	}
	for _, p := range policies {
		if p.SubType != kind {
			continue
		}
		reject := func(detail string) error {
			return regError(http.StatusForbidden, "insufficient_scope",
				"Policy '"+p.Name+"' rejected request to client-registration service. Details: "+detail)
		}
		switch p.ProviderID {
		case "trusted-hosts":
			trusted := p.Config["trusted-hosts"]
			if p.Get("host-sending-registration-request-must-match") != "false" && !hostTrusted(remoteIP(r), trusted) {
				return reject("Host not trusted.")
			}
			if p.Get("client-uris-must-match") != "false" {
				uris := append([]string{in.client.RootURL, in.client.BaseURL, in.client.AdminURL}, in.client.RedirectURIs...)
				for _, u := range uris {
					if u == "" {
						continue
					}
					parsed, err := url.Parse(strings.TrimSuffix(u, "*"))
					if err != nil || !nameTrusted(parsed.Hostname(), trusted) {
						return reject("URL doesn't match any trusted host or trusted domain")
					}
				}
			}
		case "consent-required":
			if !in.update {
				in.client.ConsentRequired = true
			} else if !in.client.ConsentRequired && in.previous != nil && in.previous.ConsentRequired {
				return reject("Not permitted to update consentRequired to false")
			}
		case "scope":
			if !in.update {
				in.client.FullScopeAllowed = false
			} else if in.client.FullScopeAllowed && in.previous != nil && !in.previous.FullScopeAllowed {
				return reject("Not permitted to enable fullScopeAllowed")
			}
		case "max-clients":
			if in.update {
				continue
			}
			clients, err := h.Svc.Store.ListClients(ctx, realm.ID, "", 0, 0)
			if err != nil {
				return err
			}
			if max := atoiDefault(p.Get("max-clients"), 200); len(clients) >= max {
				return reject("It's allowed to have max " + p.Get("max-clients") + " clients per realm")
			}
		case "allowed-protocol-mappers":
			allowed := p.Config["allowed-protocol-mapper-types"]
			for _, m := range in.mappers {
				if !slices.Contains(allowed, m) {
					return reject("ProtocolMapper type not allowed")
				}
			}
		case "allowed-client-templates":
			allowed := slices.Clone(p.Config["allowed-client-scopes"])
			if p.Get("allow-default-scopes") != "false" {
				links, err := h.Svc.Store.ListRealmDefaultScopes(ctx, realm.ID)
				if err != nil {
					return err
				}
				for _, l := range links {
					if cs, err := h.Svc.Store.GetClientScope(ctx, realm.ID, l.ScopeID); err == nil {
						allowed = append(allowed, cs.Name)
					}
				}
			}
			for _, s := range in.scopes {
				if !slices.Contains(allowed, s) {
					return reject("Not permitted to use specified clientScope")
				}
			}
		}
	}
	return nil
}

func atoiDefault(s string, def int) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	if s == "" {
		return def
	}
	return n
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// hostTrusted checks the address sending a registration against trusted
// hosts (names, addresses or *.domain wildcards).
func hostTrusted(ip string, trusted []string) bool {
	for _, t := range trusted {
		t = strings.TrimSpace(t)
		if t == ip {
			return true
		}
		if strings.HasPrefix(t, "*.") {
			names, _ := net.LookupAddr(ip)
			for _, n := range names {
				if strings.HasSuffix(strings.TrimSuffix(n, "."), t[1:]) {
					return true
				}
			}
			continue
		}
		addrs, _ := net.LookupHost(t)
		if slices.Contains(addrs, ip) {
			return true
		}
	}
	return false
}

func nameTrusted(host string, trusted []string) bool {
	for _, t := range trusted {
		t = strings.TrimSpace(t)
		if strings.EqualFold(t, host) || strings.HasPrefix(t, "*.") && strings.HasSuffix(strings.ToLower(host), strings.ToLower(t[1:])) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- OIDC metadata

// clientMetadata is the OAuth 2.0 / OpenID Connect client metadata.
type clientMetadata struct {
	ClientID                    string          `json:"client_id,omitempty"`
	ClientSecret                string          `json:"client_secret,omitempty"`
	ClientIDIssuedAt            int64           `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt       *int64          `json:"client_secret_expires_at,omitempty"`
	RedirectURIs                listMap1        `json:"redirect_uris"`
	TokenEndpointAuthMethod     string          `json:"token_endpoint_auth_method,omitempty"`
	TokenEndpointAuthSigningAlg string          `json:"token_endpoint_auth_signing_alg,omitempty"`
	GrantTypes                  listMap1        `json:"grant_types"`
	ResponseTypes               listMap1        `json:"response_types"`
	ClientName                  string          `json:"client_name,omitempty"`
	ClientURI                   string          `json:"client_uri,omitempty"`
	LogoURI                     string          `json:"logo_uri,omitempty"`
	PolicyURI                   string          `json:"policy_uri,omitempty"`
	TOSURI                      string          `json:"tos_uri,omitempty"`
	Scope                       string          `json:"scope,omitempty"`
	Contacts                    listMap1        `json:"contacts,omitempty"`
	JWKSURI                     string          `json:"jwks_uri,omitempty"`
	JWKS                        json.RawMessage `json:"jwks,omitempty"`
	SubjectType                 string          `json:"subject_type,omitempty"`
	IDTokenSignedResponseAlg    string          `json:"id_token_signed_response_alg,omitempty"`
	UserinfoSignedResponseAlg   string          `json:"userinfo_signed_response_alg,omitempty"`
	RequestObjectSigningAlg     string          `json:"request_object_signing_alg,omitempty"`
	RequestURIs                 listMap1        `json:"request_uris"`
	PostLogoutRedirectURIs      listMap1        `json:"post_logout_redirect_uris"`
	FrontchannelLogoutURI       string          `json:"frontchannel_logout_uri,omitempty"`
	FrontchannelLogoutSession   *bool           `json:"frontchannel_logout_session_required,omitempty"`
	BackchannelLogoutURI        string          `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSession    *bool           `json:"backchannel_logout_session_required,omitempty"`
	BackchannelLogoutRevoke     *bool           `json:"backchannel_logout_revoke_offline_tokens,omitempty"`
	RequirePAR                  *bool           `json:"require_pushed_authorization_requests,omitempty"`
	DPoPBound                   *bool           `json:"dpop_bound_access_tokens,omitempty"`
	TLSBound                    *bool           `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	RegistrationClientURI       string          `json:"registration_client_uri,omitempty"`
	RegistrationAccessToken     string          `json:"registration_access_token,omitempty"`
}

// listMap1 accepts a single string for a list.
type listMap1 []string

func (l *listMap1) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*l = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*l = many
	return nil
}

var authMethods = map[string]string{
	"client_secret_basic": "client-secret", "client_secret_post": "client-secret", "client_secret_jwt": "client-secret-jwt",
	"private_key_jwt": "client-jwt",
}

func setAttr(c *model.Client, k, v string) {
	if v == "" {
		delete(c.Attributes, k)
	} else {
		c.Attributes[k] = v
	}
}

func boolAttr(c *model.Client, k string, v *bool) {
	if v != nil {
		c.Attributes[k] = boolString(*v)
	}
}

// applyMetadata turns client metadata into the client.
func applyMetadata(c *model.Client, md *clientMetadata) error {
	for _, u := range md.RedirectURIs {
		p, err := url.Parse(u)
		if err != nil || !p.IsAbs() {
			return regError(http.StatusBadRequest, "invalid_redirect_uri", "A redirect URI is not a valid URI")
		}
	}
	if c.Attributes == nil {
		c.Attributes = map[string]string{}
	}
	c.Name = md.ClientName
	c.RedirectURIs = append([]string{}, md.RedirectURIs...)
	c.BaseURL = md.ClientURI
	switch m := md.TokenEndpointAuthMethod; {
	case m == "none":
		c.PublicClient, c.ClientAuthenticatorType = true, "none"
	case m == "":
		c.PublicClient, c.ClientAuthenticatorType = false, "client-secret"
	case authMethods[m] != "":
		c.PublicClient, c.ClientAuthenticatorType = false, authMethods[m]
	default:
		return regError(http.StatusBadRequest, "invalid_client_metadata", "Invalid client metadata: token_endpoint_auth_method")
	}
	grants := md.GrantTypes
	c.StandardFlowEnabled = true
	c.DirectAccessGrantsEnabled = grants == nil || slices.Contains(grants, "password")
	c.ServiceAccountsEnabled = slices.Contains(grants, "client_credentials")
	setAttr(c, "use.refresh.tokens", map[bool]string{true: "", false: "false"}[grants == nil || slices.Contains(grants, "refresh_token")])
	setAttr(c, "oauth2.device.authorization.grant.enabled", map[bool]string{true: "true"}[slices.Contains(grants, "urn:ietf:params:oauth:grant-type:device_code")])
	setAttr(c, "logoUri", md.LogoURI)
	setAttr(c, "policyUri", md.PolicyURI)
	setAttr(c, "tosUri", md.TOSURI)
	setAttr(c, "contacts", strings.Join(md.Contacts, "##"))
	setAttr(c, "token.endpoint.auth.signing.alg", md.TokenEndpointAuthSigningAlg)
	setAttr(c, "id.token.signed.response.alg", md.IDTokenSignedResponseAlg)
	setAttr(c, "user.info.response.signature.alg", md.UserinfoSignedResponseAlg)
	setAttr(c, "request.object.signature.alg", md.RequestObjectSigningAlg)
	setAttr(c, "request.uris", strings.Join(md.RequestURIs, "##"))
	setAttr(c, "post.logout.redirect.uris", strings.Join(md.PostLogoutRedirectURIs, "##"))
	setAttr(c, "backchannel.logout.url", md.BackchannelLogoutURI)
	setAttr(c, "frontchannel.logout.url", md.FrontchannelLogoutURI)
	c.FrontchannelLogout = md.FrontchannelLogoutURI != ""
	boolAttr(c, "frontchannel.logout.session.required", md.FrontchannelLogoutSession)
	if md.BackchannelLogoutSession == nil {
		md.BackchannelLogoutSession = ptr(true)
	}
	boolAttr(c, "backchannel.logout.session.required", md.BackchannelLogoutSession)
	boolAttr(c, "backchannel.logout.revoke.offline.tokens", md.BackchannelLogoutRevoke)
	boolAttr(c, "require.pushed.authorization.requests", md.RequirePAR)
	boolAttr(c, "dpop.bound.access.tokens", md.DPoPBound)
	delete(c.Attributes, "use.jwks.url")
	delete(c.Attributes, "use.jwks.string")
	switch {
	case md.JWKSURI != "":
		c.Attributes["use.jwks.url"], c.Attributes["jwks.url"] = "true", md.JWKSURI
	case len(md.JWKS) > 0:
		c.Attributes["use.jwks.string"], c.Attributes["jwks.string"] = "true", string(md.JWKS)
	}
	return nil
}

func splitAttr(c *model.Client, k string) []string {
	out := []string{}
	for _, v := range strings.Split(c.Attributes[k], "##") {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// clientToMetadata describes a client as OIDC client metadata.
func (h *Handler) clientToMetadata(ctx context.Context, c *model.Client) (*clientMetadata, error) {
	md := &clientMetadata{ClientID: c.ClientID, ClientName: c.Name, ClientURI: c.BaseURL, RedirectURIs: append(listMap1{}, c.RedirectURIs...),
		SubjectType: "public", ResponseTypes: listMap1{"code", "none"}, RequestURIs: splitAttr(c, "request.uris"),
		JWKSURI: c.Attributes["jwks.url"], IDTokenSignedResponseAlg: c.Attributes["id.token.signed.response.alg"],
		UserinfoSignedResponseAlg: c.Attributes["user.info.response.signature.alg"], RequestObjectSigningAlg: c.Attributes["request.object.signature.alg"],
		TokenEndpointAuthSigningAlg: c.Attributes["token.endpoint.auth.signing.alg"],
		BackchannelLogoutURI:        c.Attributes["backchannel.logout.url"], FrontchannelLogoutURI: c.Attributes["frontchannel.logout.url"],
		BackchannelLogoutSession:  ptr(c.Attributes["backchannel.logout.session.required"] == "true"),
		FrontchannelLogoutSession: ptr(c.Attributes["frontchannel.logout.session.required"] == "true"),
		RequirePAR:                ptr(c.Attributes["require.pushed.authorization.requests"] == "true"),
		DPoPBound:                 ptr(c.Attributes["dpop.bound.access.tokens"] == "true"), TLSBound: ptr(false)}
	if c.Attributes["use.jwks.url"] != "true" {
		md.JWKSURI = ""
	}
	if c.Attributes["use.jwks.string"] == "true" {
		md.JWKS = json.RawMessage(c.Attributes["jwks.string"])
	}
	md.PostLogoutRedirectURIs = splitAttr(c, "post.logout.redirect.uris")
	if v := c.Attributes["post.logout.redirect.uris"]; v == "" || v == "+" {
		md.PostLogoutRedirectURIs = append(listMap1{}, c.RedirectURIs...)
	}
	switch {
	case c.PublicClient:
		md.TokenEndpointAuthMethod = "none"
	case c.ClientAuthenticatorType == "client-jwt":
		md.TokenEndpointAuthMethod = "private_key_jwt"
	case c.ClientAuthenticatorType == "client-secret-jwt":
		md.TokenEndpointAuthMethod = "client_secret_jwt"
	default:
		md.TokenEndpointAuthMethod = "client_secret_basic"
	}
	if !c.PublicClient {
		md.ClientSecret, md.ClientSecretExpiresAt = c.Secret, ptr(int64(0))
	}
	md.GrantTypes = listMap1{}
	if c.StandardFlowEnabled {
		md.GrantTypes = append(md.GrantTypes, "authorization_code")
	}
	if c.ServiceAccountsEnabled {
		md.GrantTypes = append(md.GrantTypes, "client_credentials")
	}
	if c.Attributes["use.refresh.tokens"] != "false" && c.StandardFlowEnabled {
		md.GrantTypes = append(md.GrantTypes, "refresh_token")
	}
	if c.Attributes["oauth2.device.authorization.grant.enabled"] == "true" {
		md.GrantTypes = append(md.GrantTypes, "urn:ietf:params:oauth:grant-type:device_code")
	}
	links, err := h.Svc.Store.ListClientScopeLinks(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	var optional []string
	for _, l := range links {
		if !l.Default {
			if cs, err := h.Svc.Store.GetClientScope(ctx, c.RealmID, l.ScopeID); err == nil {
				optional = append(optional, cs.Name)
			}
		}
	}
	md.Scope = strings.Join(optional, " ")
	return md, nil
}

// ---------------------------------------------------------------- handlers

func readJSON(r *http.Request, v any) error {
	b, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 1<<20))
	if err != nil || json.Unmarshal(b, v) != nil {
		return regError(http.StatusBadRequest, "invalid_client_metadata", "Invalid client metadata")
	}
	return nil
}

// registerClient creates a client (POST .../openid-connect or .../default).
func (h *Handler) registerClient(w http.ResponseWriter, r *http.Request, kind string) error {
	ctx := r.Context()
	realm, err := h.Svc.Store.GetRealmByName(ctx, r.PathValue("realm"))
	if err != nil {
		return regError(http.StatusNotFound, "not_found", "Realm not found")
	}
	auth, err := h.registrationAuth(r, realm)
	if err != nil {
		return err
	}
	var c *model.Client
	var rep ClientRep
	in := &policyInput{}
	if kind == "openid-connect" {
		var md clientMetadata
		if err := readJSON(r, &md); err != nil {
			return err
		}
		c = newClient(realm.ID)
		c.ClientID = service.NewID()
		if err := applyMetadata(c, &md); err != nil {
			return err
		}
		if md.Scope != "" {
			in.scopes = strings.Fields(md.Scope)
			rep.OptionalClientScopes = in.scopes
		}
	} else {
		if err := readJSON(r, &rep); err != nil {
			return err
		}
		if rep.ClientID == nil || *rep.ClientID == "" {
			rep.ClientID = ptr(service.NewID())
		}
		rep.ID = nil
		c = newClientFromRep(realm.ID, &rep)
		in.scopes = append(append([]string{}, rep.DefaultClientScopes...), rep.OptionalClientScopes...)
		for _, m := range rep.ProtocolMappers {
			in.mappers = append(in.mappers, m.ProtocolMapper)
		}
	}
	in.client = c
	if err := h.checkPolicies(r, realm, auth.kind, in); err != nil {
		return err
	}
	var rat string
	err = h.withTx(ctx, func(tx *store.Store) error {
		if err := h.Svc.CreateClient(ctx, tx, c); err != nil {
			return err
		}
		if err := applyClientScopes(ctx, tx, c, &rep, kind == "default"); err != nil {
			return err
		}
		if auth.iat != nil {
			if err := tx.UseInitialAccessToken(ctx, realm.ID, auth.iat.ID); errors.Is(err, store.ErrNotFound) {
				return regError(http.StatusUnauthorized, "invalid_token", "No remaining count on initial access token")
			} else if err != nil {
				return err
			}
		}
		return nil
	})
	if errors.Is(err, store.ErrConflict) {
		return regError(http.StatusBadRequest, "invalid_client_metadata", "Client Identifier in use")
	}
	if err != nil {
		return err
	}
	if rat, err = h.registrationToken(ctx, r, realm, c, auth.kind, true); err != nil {
		return err
	}
	return h.writeRegistered(w, r, realm, c, kind, rat, http.StatusCreated)
}

func (h *Handler) writeRegistered(w http.ResponseWriter, r *http.Request, realm *model.Realm, c *model.Client, kind, rat string, status int) error {
	ctx := r.Context()
	if kind == "openid-connect" {
		md, err := h.clientToMetadata(ctx, c)
		if err != nil {
			return err
		}
		if status == http.StatusCreated {
			md.ClientIDIssuedAt = h.Svc.Now().Unix()
		}
		md.RegistrationAccessToken = rat
		md.RegistrationClientURI = h.URLs.Issuer(r, realm.Name) + "/clients-registrations/openid-connect/" + url.PathEscape(c.ClientID)
		writeJSON(w, status, md)
		return nil
	}
	rep, err := clientRepWithScopes(ctx, h.Svc.Store, c)
	if err != nil {
		return err
	}
	if !c.PublicClient && !c.BearerOnly {
		rep.Secret = ptr(c.Secret)
	}
	rep.RegistrationAccessToken = rat
	writeJSON(w, status, rep)
	return nil
}

func (h *Handler) getRegisteredClient(w http.ResponseWriter, r *http.Request, kind string) error {
	realm, c, auth, err := h.registeredClient(r, false)
	if err != nil {
		return err
	}
	rat, err := h.registrationToken(r.Context(), r, realm, c, auth, false)
	if err != nil {
		return err
	}
	return h.writeRegistered(w, r, realm, c, kind, rat, http.StatusOK)
}

func (h *Handler) updateRegisteredClient(w http.ResponseWriter, r *http.Request, kind string) error {
	ctx := r.Context()
	realm, c, auth, err := h.registeredClient(r, true)
	if err != nil {
		return err
	}
	previous := *c
	previous.Attributes = map[string]string{}
	for k, v := range c.Attributes {
		previous.Attributes[k] = v
	}
	in := &policyInput{client: c, update: true, previous: &previous}
	var rep ClientRep
	if kind == "openid-connect" {
		var md clientMetadata
		if err := readJSON(r, &md); err != nil {
			return err
		}
		if md.ClientID != "" && md.ClientID != c.ClientID {
			return regError(http.StatusBadRequest, "invalid_client_metadata", "Client Identifier modified")
		}
		if err := applyMetadata(c, &md); err != nil {
			return err
		}
		if md.ClientSecret != "" && md.ClientSecret != c.Secret && !c.PublicClient {
			return regError(http.StatusBadRequest, "invalid_client_metadata", "Client secret modified")
		}
		if md.Scope != "" {
			in.scopes = strings.Fields(md.Scope)
			rep.OptionalClientScopes = in.scopes
		}
	} else {
		if err := readJSON(r, &rep); err != nil {
			return err
		}
		if rep.ClientID != nil && *rep.ClientID != c.ClientID {
			return regError(http.StatusBadRequest, "invalid_client_metadata", "Client Identifier modified")
		}
		applyClientRep(c, &rep)
		in.scopes = append(append([]string{}, rep.DefaultClientScopes...), rep.OptionalClientScopes...)
		for _, m := range rep.ProtocolMappers {
			in.mappers = append(in.mappers, m.ProtocolMapper)
		}
	}
	if auth == "" {
		auth = "authenticated"
	}
	if err := h.checkPolicies(r, realm, auth, in); err != nil {
		return err
	}
	err = h.withTx(ctx, func(tx *store.Store) error {
		if err := tx.UpdateClient(ctx, c); err != nil {
			return err
		}
		return applyClientScopes(ctx, tx, c, &rep, kind == "default")
	})
	if err != nil {
		return err
	}
	rat, err := h.registrationToken(ctx, r, realm, c, auth, true)
	if err != nil {
		return err
	}
	return h.writeRegistered(w, r, realm, c, kind, rat, http.StatusOK)
}

func (h *Handler) deleteRegisteredClient(w http.ResponseWriter, r *http.Request) error {
	_, c, _, err := h.registeredClient(r, true)
	if err != nil {
		return err
	}
	if err := h.Svc.Store.DeleteClient(r.Context(), c.ID); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---------------------------------------------------------------- admin

type initialAccessRep struct {
	ID             string `json:"id"`
	Token          string `json:"token,omitempty"`
	Timestamp      int64  `json:"timestamp"`
	Expiration     int    `json:"expiration"`
	Count          int    `json:"count"`
	RemainingCount int    `json:"remainingCount"`
}

func (h *Handler) createInitialAccess(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageClients)
	if err != nil {
		return err
	}
	var in struct {
		Expiration int `json:"expiration"`
		Count      int `json:"count"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	if in.Expiration < 0 || in.Count < 0 {
		return badRequest("Invalid value for expiration or count")
	}
	if in.Count == 0 {
		in.Count = 1
	}
	t := &model.InitialAccessToken{ID: service.NewID(), RealmID: realm.ID, Created: h.Svc.Now().Unix(), Expiration: in.Expiration,
		Count: in.Count, Remaining: in.Count}
	if err := h.Svc.Store.CreateInitialAccessToken(r.Context(), t); err != nil {
		return err
	}
	claims := jwt.Claims{"jti": t.ID, "typ": tokenTypeIAT, "iat": t.Created}
	if t.Expiration > 0 {
		claims["exp"] = t.Created + int64(t.Expiration)
	}
	tok, err := h.signRegistrationToken(r.Context(), r, realm, claims)
	if err != nil {
		return err
	}
	return ok(w, initialAccessRep{ID: t.ID, Token: tok, Timestamp: t.Created, Expiration: t.Expiration, Count: t.Count, RemainingCount: t.Remaining})
}

func (h *Handler) listInitialAccess(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewClients)
	if err != nil {
		return err
	}
	list, err := h.Svc.Store.ListInitialAccessTokens(r.Context(), realm.ID)
	if err != nil {
		return err
	}
	out := []initialAccessRep{}
	now := h.Svc.Now().Unix()
	for _, t := range list {
		if t.Expiration > 0 && now > t.Created+int64(t.Expiration) {
			continue
		}
		out = append(out, initialAccessRep{ID: t.ID, Timestamp: t.Created, Expiration: t.Expiration, Count: t.Count, RemainingCount: t.Remaining})
	}
	return ok(w, out)
}

func (h *Handler) deleteInitialAccess(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageClients)
	if err != nil {
		return err
	}
	if err := h.Svc.Store.DeleteInitialAccessToken(r.Context(), realm.ID, r.PathValue("id")); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return noContent(w)
}

// regenerateRegistrationToken issues a new registration access token.
func (h *Handler) regenerateRegistrationToken(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageClients)
	if err != nil {
		return err
	}
	c, err := h.loadClient(r, realm)
	if err != nil {
		return err
	}
	rat, err := h.registrationToken(r.Context(), r, realm, c, "authenticated", true)
	if err != nil {
		return err
	}
	rep, err := h.clientRep(r.Context(), p, realm, c)
	if err != nil {
		return err
	}
	rep.RegistrationAccessToken = rat
	return ok(w, rep)
}

// registrationPolicyProviders lists the policy providers (from serverinfo).
func (h *Handler) registrationPolicyProviders(w http.ResponseWriter, r *http.Request, p *principal) error {
	if _, err := h.realmFor(r, p, permViewRealm); err != nil {
		return err
	}
	var info struct {
		ComponentTypes map[string][]map[string]any `json:"componentTypes"`
	}
	if err := json.Unmarshal(serverInfoCatalog, &info); err != nil {
		return err
	}
	out := info.ComponentTypes[service.RegistrationPolicyType]
	if out == nil {
		out = []map[string]any{}
	}
	return ok(w, out)
}
