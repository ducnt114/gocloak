// Package oidc implements the OpenID Connect / OAuth 2.0 endpoints of a
// realm under /realms/{realm}/..., following Keycloak's URL layout.
package oidc

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
	"github.com/ducnt114/gocloak/internal/theme"
)

// URLs builds absolute URLs for a request. It is shared with the admin API.
type URLs struct {
	// Hostname is the fixed public base URL (e.g. https://sso.example.com).
	// When empty it is derived from the request.
	Hostname string
	// ProxyHeaders trusts X-Forwarded-Proto / X-Forwarded-Host.
	ProxyHeaders bool
}

// Base returns the public base URL without trailing slash.
func (u URLs) Base(r *http.Request) string {
	if u.Hostname != "" {
		h := strings.TrimSuffix(u.Hostname, "/")
		if !strings.Contains(h, "://") {
			h = "https://" + h
		}
		return h
	}
	scheme, host := "http", r.Host
	if r.TLS != nil {
		scheme = "https"
	}
	if u.ProxyHeaders {
		if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
			scheme = strings.TrimSpace(strings.Split(p, ",")[0])
		}
		if h := r.Header.Get("X-Forwarded-Host"); h != "" {
			host = strings.TrimSpace(strings.Split(h, ",")[0])
		}
	}
	return scheme + "://" + host
}

// Issuer returns the issuer URL of a realm.
func (u URLs) Issuer(r *http.Request, realm string) string {
	return u.Base(r) + "/realms/" + url.PathEscape(realm)
}

// Handler serves the protocol endpoints.
type Handler struct {
	Svc    *service.Service
	URLs   URLs
	Log    *slog.Logger
	Themes *theme.Manager

	jwks jwksCache
}

// Register adds the OIDC routes to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	const p = "/realms/{realm}/protocol/openid-connect"
	mux.HandleFunc("GET /realms/{realm}", h.realmInfo)
	mux.HandleFunc("GET /realms/{realm}/.well-known/openid-configuration", h.discovery)
	mux.HandleFunc("GET "+p+"/certs", h.certs)
	mux.HandleFunc("GET "+p+"/auth", h.authorize)
	mux.HandleFunc("POST "+p+"/auth", h.authorize)
	mux.HandleFunc("POST "+p+"/token", h.cors(h.token))
	mux.HandleFunc("POST "+p+"/ext/par/request", h.cors(h.par))
	mux.HandleFunc("POST "+p+"/auth/device", h.cors(h.deviceAuthorization))
	mux.HandleFunc("POST "+p+"/ext/ciba/auth", h.cibaAuth)
	mux.HandleFunc("POST "+p+"/ext/ciba/auth/callback", h.cibaCallback)
	mux.HandleFunc("GET /realms/{realm}/device", h.deviceVerification)
	mux.HandleFunc("POST /realms/{realm}/device", h.deviceVerification)
	mux.HandleFunc("GET "+p+"/userinfo", h.cors(h.userinfo))
	mux.HandleFunc("POST "+p+"/userinfo", h.cors(h.userinfo))
	mux.HandleFunc("POST "+p+"/token/introspect", h.cors(h.introspect))
	mux.HandleFunc("POST "+p+"/revoke", h.cors(h.revoke))
	mux.HandleFunc("GET "+p+"/logout", h.logout)
	mux.HandleFunc("POST "+p+"/logout", h.cors(h.logout))
	mux.HandleFunc("OPTIONS "+p+"/{endpoint...}", h.preflight)
	mux.HandleFunc("GET "+p+"/registrations", h.registrations)
	mux.HandleFunc("GET /realms/{realm}/login-actions/authenticate", h.authenticateEndpoint)
	mux.HandleFunc("POST /realms/{realm}/login-actions/authenticate", h.authenticateEndpoint)
	mux.HandleFunc("GET /realms/{realm}/login-actions/required-action", h.requiredActionEndpoint)
	mux.HandleFunc("POST /realms/{realm}/login-actions/consent", h.consentEndpoint)
	mux.HandleFunc("POST /realms/{realm}/login-actions/required-action", h.requiredActionEndpoint)
	mux.HandleFunc("GET /realms/{realm}/login-actions/registration", h.registrationEndpoint)
	mux.HandleFunc("GET /realms/{realm}/login-actions/reset-credentials", h.resetCredentialsEndpoint)
	mux.HandleFunc("GET /realms/{realm}/login-actions/restart", h.restartEndpoint)
	mux.HandleFunc("GET /realms/{realm}/login-actions/action-token", h.actionToken)
	mux.HandleFunc("GET /resources/{theme}/{type}/{path...}", h.resources)
	h.registerBroker(mux)
	h.registerIframes(mux)
	h.registerUMA(mux)
	h.registerSAML(mux)
}

// ---------------------------------------------------------------- helpers

// oauthError is an RFC 6749 error response.
type oauthError struct {
	Status      int    `json:"-"`
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func (e *oauthError) Error() string { return e.Code + ": " + e.Description }

func errInvalidRequest(d string) *oauthError {
	return &oauthError{http.StatusBadRequest, "invalid_request", d}
}
func errInvalidGrant(d string) *oauthError {
	return &oauthError{http.StatusBadRequest, "invalid_grant", d}
}
func errInvalidClient(d string) *oauthError {
	return &oauthError{http.StatusUnauthorized, "invalid_client", d}
}
func errInvalidClient400(d string) *oauthError {
	return &oauthError{http.StatusBadRequest, "invalid_client", d}
}
func errUnauthorizedClient(d string) *oauthError {
	return &oauthError{http.StatusBadRequest, "unauthorized_client", d}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (h *Handler) writeError(w http.ResponseWriter, err error) {
	var oe *oauthError
	if errors.As(err, &oe) {
		if oe.Status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Basic realm="gocloak"`)
		}
		writeJSON(w, oe.Status, oe)
		return
	}
	h.Log.Error("internal error", "err", err)
	writeJSON(w, http.StatusInternalServerError, &oauthError{Code: "server_error", Description: "internal server error"})
}

// realm loads the enabled realm named in the path.
func (h *Handler) realm(r *http.Request) (*model.Realm, error) {
	realm, err := h.Svc.Store.GetRealmByName(r.Context(), r.PathValue("realm"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, &oauthError{http.StatusNotFound, "not_found", "Realm does not exist"}
		}
		return nil, err
	}
	if !realm.Enabled {
		return nil, &oauthError{http.StatusNotFound, "not_found", "Realm not enabled"}
	}
	return realm, nil
}

// bearerToken returns the access token of a request (Bearer or DPoP scheme).
func bearerToken(r *http.Request) string {
	tok, _ := service.AccessToken(r)
	return tok
}

// ---------------------------------------------------------------- CORS

// cors wraps an endpoint so that browser clients listed in the client's
// web origins can call it.
func (h *Handler) cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && h.originAllowed(r, origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Add("Vary", "Origin")
		}
		next(w, r)
	}
}

func (h *Handler) originAllowed(r *http.Request, origin string) bool {
	realm, err := h.realm(r)
	if err != nil {
		return false
	}
	clientID := r.FormValue("client_id")
	if id, _, ok := r.BasicAuth(); ok {
		clientID, _ = url.QueryUnescape(id)
	}
	if clientID == "" {
		// userinfo: use the azp of the bearer token, unverified; the endpoint
		// itself verifies the token.
		if tok := bearerToken(r); tok != "" {
			if c, err := h.Svc.VerifyToken(r.Context(), realm, tok, h.URLs.Issuer(r, realm.Name), ""); err == nil {
				clientID = c.Claims.String("azp")
			}
		}
	}
	if clientID == "" {
		return false
	}
	c, err := h.Svc.Store.GetClientByClientID(r.Context(), realm.ID, clientID)
	if err != nil {
		return false
	}
	return webOriginAllowed(h.URLs.Base(r), c, origin)
}

func webOriginAllowed(base string, c *model.Client, origin string) bool {
	for _, o := range c.WebOrigins {
		switch o {
		case "*":
			return true
		case "+":
			for _, ru := range c.RedirectURIs {
				if originOf(resolveURI(base, c, ru)) == origin {
					return true
				}
			}
		default:
			if strings.TrimSuffix(o, "/") == origin {
				return true
			}
		}
	}
	return false
}

func originOf(raw string) string {
	u, err := url.Parse(strings.TrimSuffix(raw, "*"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func (h *Handler) preflight(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Accept, X-Requested-With, Content-Type, Authorization, DPoP")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.Header().Add("Vary", "Origin")
	}
	w.WriteHeader(http.StatusOK)
}

// ---------------------------------------------------------------- redirect URIs

// resolveURI makes a relative redirect URI absolute using the client's root
// URL, or the server's base URL when the client has none. "${authBaseUrl}"
// in the root URL stands for the server's base URL, as in Keycloak.
func resolveURI(base string, c *model.Client, u string) string {
	if !strings.HasPrefix(u, "/") {
		return u
	}
	root := strings.ReplaceAll(strings.ReplaceAll(c.RootURL, "${authBaseUrl}", base), "${authAdminUrl}", base)
	if root == "" {
		root = base
	}
	return strings.TrimSuffix(root, "/") + u
}

// matchRedirectURI reports whether uri is allowed for client. Patterns may
// end with '*' for a prefix match, like in Keycloak.
func matchRedirectURI(base string, c *model.Client, uri string) bool {
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme == "" || parsed.Fragment != "" {
		return false
	}
	for _, p := range c.RedirectURIs {
		p = resolveURI(base, c, p)
		switch {
		case p == "*":
			return true
		case strings.HasSuffix(p, "*"):
			if strings.HasPrefix(uri, strings.TrimSuffix(p, "*")) {
				return true
			}
		case p == uri:
			return true
		}
	}
	return false
}

// postLogoutRedirectAllowed checks the client's post.logout.redirect.uris
// attribute ("+" means "same as the redirect URIs", the default).
func postLogoutRedirectAllowed(base string, c *model.Client, uri string) bool {
	attr, ok := c.Attributes["post.logout.redirect.uris"]
	if !ok {
		attr = "+"
	}
	pc := *c
	pc.RedirectURIs = nil
	for _, p := range strings.Split(attr, "##") {
		if p == "+" {
			pc.RedirectURIs = append(pc.RedirectURIs, c.RedirectURIs...)
		} else if p != "" {
			pc.RedirectURIs = append(pc.RedirectURIs, p)
		}
	}
	return matchRedirectURI(base, &pc, uri)
}

// RedirectAllowed reports whether uri is a valid redirect URI of client.
func RedirectAllowed(base string, c *model.Client, uri string) bool {
	return matchRedirectURI(base, c, uri)
}
