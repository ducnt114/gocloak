package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
)

// Pushed Authorization Requests (RFC 9126) and request objects (OIDC Core
// 6, RFC 9101): "request" and "request_uri" authorization parameters.

const (
	parURNPrefix = "urn:ietf:params:oauth:request_uri:"
	keyPAR       = "_par" // marks auth sessions holding pushed requests

	attrRequirePAR       = "require.pushed.authorization.requests"
	attrRequestObjectAlg = "request.object.signature.alg"
	attrRequestObjectReq = "request.object.required"
	attrRequestURIs      = "request.uris"
)

// errInvalidRequestObject is any unusable request object or request URI;
// Keycloak answers them with its "Invalid Request" error page.
var errInvalidRequestObject = errors.New("invalid request object")

// parLifespan is the realm's parRequestUriLifespan (seconds).
func parLifespan(realm *model.Realm) int {
	if n, err := strconv.Atoi(realm.Attributes["parRequestUriLifespan"]); err == nil && n > 0 {
		return n
	}
	return 60
}

// pushedRequest consumes the parameters pushed with a PAR request URI.
func (h *Handler) pushedRequest(ctx context.Context, realm *model.Realm, client *model.Client, requestURI string) (url.Values, error) {
	id := strings.TrimPrefix(requestURI, parURNPrefix)
	as, err := h.Svc.Store.GetAuthSession(ctx, id)
	if err != nil || as.Params[keyPAR] == "" || as.RealmID != realm.ID || as.ClientID != client.ID || h.Svc.Now().After(as.ExpiresAt) {
		return nil, errInvalidRequestObject
	}
	// a request URI is used once
	if err := h.Svc.Store.DeleteAuthSession(ctx, id); err != nil {
		return nil, err
	}
	v := url.Values{}
	for k, val := range as.Params {
		if k != keyPAR {
			v.Set(k, val)
		}
	}
	return v, nil
}

// applyRequestObject merges the request object of the parameters (given
// inline or by reference) into them, after checking it was sent by client.
func (h *Handler) applyRequestObject(ctx context.Context, realm *model.Realm, client *model.Client, params url.Values) error {
	raw := params.Get("request")
	if u := params.Get("request_uri"); raw == "" && u != "" {
		var err error
		if raw, err = h.fetchRequestObject(ctx, client, u); err != nil {
			return err
		}
	}
	if raw == "" {
		return nil
	}
	claims, err := h.verifyRequestObject(ctx, client, raw)
	if err != nil {
		return err
	}
	if id, ok := claims["client_id"]; ok && fmt.Sprint(id) != client.ClientID {
		return errInvalidRequestObject
	}
	for k, v := range claims {
		switch k {
		case "iss", "aud", "exp", "iat", "nbf", "jti", "request", "request_uri":
			continue
		}
		switch x := v.(type) {
		case string:
			params.Set(k, x)
		case float64:
			params.Set(k, strconv.FormatFloat(x, 'f', -1, 64))
		case bool:
			params.Set(k, strconv.FormatBool(x))
		default:
			b, _ := json.Marshal(x)
			params.Set(k, string(b))
		}
	}
	params.Del("request")
	params.Del("request_uri")
	return nil
}

// verifyRequestObject checks the signature of a request object: unsigned
// ("none"), HMAC with the client secret, or the client's keys, restricted to
// the client's request.object.signature.alg when set.
func (h *Handler) verifyRequestObject(ctx context.Context, client *model.Client, raw string) (jwt.Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errInvalidRequestObject
	}
	var header jwt.Header
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &header) != nil {
		return nil, errInvalidRequestObject
	}
	if want := client.Attributes[attrRequestObjectAlg]; want != "" && want != "any" && want != header.Alg {
		return nil, errInvalidRequestObject
	}
	if header.Alg == "none" {
		if parts[2] != "" {
			return nil, errInvalidRequestObject
		}
		pb, err := base64.RawURLEncoding.DecodeString(parts[1])
		var claims jwt.Claims
		if err != nil || json.Unmarshal(pb, &claims) != nil {
			return nil, errInvalidRequestObject
		}
		return claims, nil
	}
	var key *jwt.Key
	switch jwt.Family(header.Alg) {
	case "OCT":
		if client.Secret == "" || client.PublicClient {
			return nil, errInvalidRequestObject
		}
		key = &jwt.Key{Alg: header.Alg, Secret: []byte(client.Secret)}
	case "":
		return nil, errInvalidRequestObject
	default:
		if key, err = h.clientKey(ctx, client, header); err != nil {
			return nil, errInvalidRequestObject
		}
	}
	claims, err := jwt.Verify(raw, func(string, string) *jwt.Key { return key })
	if err != nil {
		return nil, errInvalidRequestObject
	}
	return claims, nil
}

// fetchRequestObject downloads a request object from a request URI the
// client registered (request.uris, "##" separated, '*' wildcards).
func (h *Handler) fetchRequestObject(ctx context.Context, client *model.Client, u string) (string, error) {
	allowed := false
	for _, p := range strings.Split(client.Attributes[attrRequestURIs], "##") {
		p = strings.TrimSpace(p)
		if p != "" && (p == u || strings.HasSuffix(p, "*") && strings.HasPrefix(u, strings.TrimSuffix(p, "*"))) {
			allowed = true
		}
	}
	if !allowed || !(strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://")) {
		return "", errInvalidRequestObject
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", errInvalidRequestObject
	}
	resp, err := brokerHTTP.Do(req)
	if err != nil {
		return "", errInvalidRequestObject
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errInvalidRequestObject
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", errInvalidRequestObject
	}
	return strings.TrimSpace(string(b)), nil
}

// par serves the pushed authorization request endpoint.
func (h *Handler) par(w http.ResponseWriter, r *http.Request) {
	realm, err := h.realm(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	ctx := r.Context()
	client, err := h.authenticateClient(r, realm)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, &oauthError{Code: "invalid_request", Description: "Authentication failed."})
		return
	}
	bad := func(status int, code, desc string) {
		writeJSON(w, status, &oauthError{Code: code, Description: desc})
	}
	params := url.Values{}
	for k, v := range r.PostForm {
		switch k {
		case "client_secret", "client_assertion", "client_assertion_type":
			continue
		}
		params[k] = v
	}
	if params.Get("request_uri") != "" {
		bad(http.StatusBadRequest, "invalid_request", "It is not allowed to include request_uri to PAR.")
		return
	}
	if err := h.applyRequestObject(ctx, realm, client, params); err != nil {
		bad(http.StatusBadRequest, "invalid_request_object", "Invalid Request Object")
		return
	}
	params.Set("client_id", client.ClientID)
	redirectURI := params.Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = soleRedirectURI(h.URLs.Base(r), client)
	}
	if redirectURI == "" || !matchRedirectURI(h.URLs.Base(r), client, redirectURI) {
		bad(http.StatusBadRequest, "invalid_request", "Invalid parameter: redirect_uri")
		return
	}
	if rt := params.Get("response_type"); rt != "code" {
		bad(http.StatusUnauthorized, "unauthorized_client", "Client is not allowed to initiate browser login with given response_type. "+
			"Only the authorization code flow is supported.")
		return
	}
	if _, _, invalid, err := resolveScopes(ctx, h.Svc.Store, realm, client, params.Get("scope")); err != nil {
		h.writeError(w, err)
		return
	} else if len(invalid) > 0 {
		bad(http.StatusBadRequest, "invalid_request", "Invalid scopes: "+params.Get("scope"))
		return
	}
	stored := map[string]string{keyPAR: "1"}
	for k := range params {
		stored[k] = params.Get(k)
	}
	lifespan := parLifespan(realm)
	as := &model.AuthSession{ID: service.NewID(), RealmID: realm.ID, ClientID: client.ID, Params: stored,
		ExpiresAt: h.Svc.Now().Add(time.Duration(lifespan) * time.Second)}
	if err := h.Svc.Store.CreateAuthSession(ctx, as); err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"request_uri": parURNPrefix + as.ID, "expires_in": lifespan})
}
