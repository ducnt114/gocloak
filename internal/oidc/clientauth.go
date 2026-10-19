package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/store"
)

// Client authenticator types, as in Keycloak.
const (
	AuthClientSecret    = "client-secret"
	AuthClientSecretJWT = "client-secret-jwt"
	AuthClientJWT       = "client-jwt"
	jwtBearerAssertion  = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	assertionClockSkew  = 10 * time.Second
)

// authenticateClient authenticates the calling client with
// client_secret_basic, client_secret_post, client_secret_jwt or
// private_key_jwt, depending on the client's authenticator type. Public
// clients only identify themselves.
func (h *Handler) authenticateClient(r *http.Request, realm *model.Realm) (*model.Client, error) {
	if r.PostFormValue("client_assertion_type") != "" || r.PostFormValue("client_assertion") != "" {
		return h.authenticateAssertion(r, realm)
	}
	id, secret, hasBasic := r.BasicAuth()
	if hasBasic {
		var err error
		if id, err = url.QueryUnescape(id); err != nil {
			return nil, errInvalidClient("Invalid client credentials")
		}
		if secret, err = url.QueryUnescape(secret); err != nil {
			return nil, errInvalidClient("Invalid client credentials")
		}
	} else {
		id, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	}
	c, err := h.lookupClient(r.Context(), realm, id)
	if err != nil {
		return nil, err
	}
	if c.PublicClient {
		return c, nil
	}
	if c.ClientAuthenticatorType != "" && c.ClientAuthenticatorType != AuthClientSecret {
		return nil, errInvalidClient("Invalid client or Invalid client credentials")
	}
	if secret == "" || subtle.ConstantTimeCompare([]byte(secret), []byte(c.Secret)) != 1 {
		return nil, errInvalidClient("Invalid client or Invalid client credentials")
	}
	return c, nil
}

func (h *Handler) lookupClient(ctx context.Context, realm *model.Realm, id string) (*model.Client, error) {
	if id == "" {
		return nil, errInvalidClient("Missing client_id parameter")
	}
	c, err := h.Svc.Store.GetClientByClientID(ctx, realm.ID, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errInvalidClient("Invalid client or Invalid client credentials")
		}
		return nil, err
	}
	if !c.Enabled {
		return nil, errInvalidClient("Invalid client or Invalid client credentials")
	}
	if c.BearerOnly {
		return nil, errUnauthorizedClient("Bearer-only not allowed")
	}
	return c, nil
}

// authenticateAssertion verifies a client_secret_jwt / private_key_jwt
// assertion (RFC 7523).
func (h *Handler) authenticateAssertion(r *http.Request, realm *model.Realm) (*model.Client, error) {
	ctx := r.Context()
	bad := func(msg string) error { return errInvalidClient(msg) }
	if r.PostFormValue("client_assertion_type") != jwtBearerAssertion {
		return nil, bad("Parameter client_assertion_type is missing or has wrong value")
	}
	assertion := r.PostFormValue("client_assertion")
	header, claims, err := jwt.Parse(assertion)
	if err != nil {
		return nil, bad("Client authentication with signed JWT failed: Invalid token")
	}
	clientID := claims.String("sub")
	if clientID == "" || claims.String("iss") != clientID {
		return nil, bad("Client authentication with signed JWT failed: Token issuer and subject must be the client id")
	}
	if p := r.PostFormValue("client_id"); p != "" && p != clientID {
		return nil, bad("client_id parameter does not match the assertion")
	}
	c, err := h.lookupClient(ctx, realm, clientID)
	if err != nil {
		return nil, err
	}
	if want := c.Attributes["token.endpoint.auth.signing.alg"]; want != "" && want != header.Alg {
		return nil, bad("Client authentication with signed JWT failed: invalid signature algorithm")
	}
	var key *jwt.Key
	switch c.ClientAuthenticatorType {
	case AuthClientSecretJWT:
		if jwt.Family(header.Alg) != "OCT" || c.Secret == "" {
			return nil, bad("Client authentication with signed JWT failed: invalid signature algorithm")
		}
		key = &jwt.Key{Alg: header.Alg, Secret: []byte(c.Secret), Kid: header.Kid}
	case AuthClientJWT:
		if jwt.Family(header.Alg) == "OCT" || jwt.Family(header.Alg) == "" {
			return nil, bad("Client authentication with signed JWT failed: invalid signature algorithm")
		}
		if key, err = h.clientKey(ctx, c, header); err != nil {
			return nil, bad("Client authentication with signed JWT failed: " + err.Error())
		}
	default:
		return nil, bad("Invalid client or Invalid client credentials")
	}
	if _, err := jwt.Verify(assertion, func(string, string) *jwt.Key { return key }); err != nil {
		return nil, bad("Client authentication with signed JWT failed: Signature on JWT token by client: " + clientID + " failed validation")
	}
	now := h.Svc.Now()
	exp := claims.Int("exp")
	if exp == 0 || time.Unix(exp, 0).Add(assertionClockSkew).Before(now) {
		return nil, bad("Client authentication with signed JWT failed: Token is not active")
	}
	if nbf := claims.Int("nbf"); nbf > 0 && time.Unix(nbf, 0).After(now.Add(assertionClockSkew)) {
		return nil, bad("Client authentication with signed JWT failed: Token is not active")
	}
	iss := h.URLs.Issuer(r, realm.Name)
	allowed := map[string]bool{iss: true}
	for _, ep := range []string{"/token", "/token/introspect", "/revoke", "/logout"} {
		allowed[iss+"/protocol/openid-connect"+ep] = true
	}
	audOK := false
	for _, a := range claims.Audience() {
		audOK = audOK || allowed[a]
	}
	if !audOK {
		return nil, bad("Client authentication with signed JWT failed: Token audience doesn't match domain name")
	}
	jti := claims.String("jti")
	if jti == "" {
		return nil, bad("Client authentication with signed JWT failed: Missing ID on the token")
	}
	replayKey := "client-assertion:" + c.ID + ":" + jti
	if used, err := h.Svc.Store.IsTokenRevoked(ctx, replayKey); err != nil {
		return nil, err
	} else if used {
		return nil, bad("Client authentication with signed JWT failed: Token reuse detected")
	}
	if err := h.Svc.Store.RevokeToken(ctx, replayKey, time.Unix(exp, 0).Add(assertionClockSkew)); err != nil {
		return nil, err
	}
	return c, nil
}

// clientKey finds the public key that verifies a client's assertion: from
// its JWKS URL, inline JWKS, or uploaded certificate (Keycloak attributes).
func (h *Handler) clientKey(ctx context.Context, c *model.Client, header jwt.Header) (*jwt.Key, error) {
	attrs := c.Attributes
	pick := func(keys []jwt.JWK) (*jwt.Key, error) {
		for _, j := range keys {
			if (header.Kid == "" || j.Kid == header.Kid) && (j.Use == "" || j.Use == "sig") {
				return jwt.KeyFromJWK(j, header.Alg)
			}
		}
		return nil, errors.New("no key in the client's JWKS matches the token")
	}
	switch {
	case attrs["use.jwks.url"] == "true":
		u := attrs["jwks.url"]
		if u == "" {
			return nil, errors.New("client has no JWKS URL")
		}
		keys, err := h.jwks.get(ctx, u, header.Kid)
		if err != nil {
			return nil, err
		}
		k, err := pick(keys)
		if k != nil {
			k.Alg = header.Alg
		}
		return k, err
	case attrs["use.jwks.string"] == "true":
		var set struct{ Keys []jwt.JWK }
		if err := json.Unmarshal([]byte(attrs["jwks.string"]), &set); err != nil {
			return nil, errors.New("invalid JWKS of the client")
		}
		k, err := pick(set.Keys)
		if k != nil {
			k.Alg = header.Alg
		}
		return k, err
	case attrs["jwt.credential.certificate"] != "":
		cert, err := jwt.ParseCertificate(attrs["jwt.credential.certificate"])
		if err != nil {
			return nil, errors.New("invalid certificate of the client")
		}
		return &jwt.Key{Alg: header.Alg, Public: cert.PublicKey, Certificate: cert}, nil
	}
	return nil, errors.New("client has no key configured")
}

// jwksCache fetches and caches client JWKS documents.
type jwksCache struct {
	mu      sync.Mutex
	entries map[string]jwksEntry
	client  *http.Client
}

type jwksEntry struct {
	keys    []jwt.JWK
	fetched time.Time
}

const (
	jwksTTL        = 10 * time.Minute
	jwksMinRefresh = 10 * time.Second
)

// get returns the keys at u, refetching when kid is unknown (key rotation)
// but at most every jwksMinRefresh.
func (c *jwksCache) get(ctx context.Context, u, kid string) ([]jwt.JWK, error) {
	c.mu.Lock()
	if c.entries == nil {
		c.entries = map[string]jwksEntry{}
	}
	e, ok := c.entries[u]
	c.mu.Unlock()
	known := false
	for _, k := range e.keys {
		known = known || k.Kid == kid
	}
	if ok && time.Since(e.fetched) < jwksTTL && (known || kid == "" || time.Since(e.fetched) < jwksMinRefresh) {
		return e.keys, nil
	}
	hc := c.client
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch JWKS: HTTP %d", resp.StatusCode)
	}
	var set struct{ Keys []jwt.JWK }
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, errors.New("invalid JWKS document")
	}
	c.mu.Lock()
	c.entries[u] = jwksEntry{keys: set.Keys, fetched: time.Now()}
	c.mu.Unlock()
	return set.Keys, nil
}
