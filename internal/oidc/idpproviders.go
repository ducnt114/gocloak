package oidc

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
)

// This file holds the identity provider types: generic OpenID Connect and
// OAuth 2.0 providers, and the social login presets.

// IdPType describes an identity provider type.
type IdPType struct {
	ID     string
	Name   string
	Social bool
	// OIDC providers return an ID token; the others are plain OAuth 2.0
	// with a profile endpoint.
	OIDC bool

	// Default endpoints of presets; the provider's config overrides them.
	authURL, tokenURL, userInfoURL, issuer, jwksURL, scope string

	// profile builds the brokered identity from the token response.
	profile func(ctx context.Context, b *brokerCall) (*brokeredIdentity, error)
}

// IdPTypes are the supported provider types, by provider id.
var IdPTypes = map[string]*IdPType{
	"oidc":          {ID: "oidc", Name: "OpenID Connect v1.0", OIDC: true, scope: "openid", profile: oidcProfile},
	"keycloak-oidc": {ID: "keycloak-oidc", Name: "Keycloak OpenID Connect", OIDC: true, scope: "openid", profile: oidcProfile},
	"oauth2":        {ID: "oauth2", Name: "OAuth v2", profile: oauth2Profile},
	"google": {ID: "google", Name: "Google", Social: true, OIDC: true,
		authURL: "https://accounts.google.com/o/oauth2/v2/auth", tokenURL: "https://oauth2.googleapis.com/token",
		userInfoURL: "https://openidconnect.googleapis.com/v1/userinfo", issuer: "https://accounts.google.com",
		jwksURL: "https://www.googleapis.com/oauth2/v3/certs", scope: "openid profile email", profile: oidcProfile},
	"microsoft": {ID: "microsoft", Name: "Microsoft", Social: true,
		authURL:     "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
		tokenURL:    "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
		userInfoURL: "https://graph.microsoft.com/v1.0/me/", scope: "User.read", profile: microsoftProfile},
	"github": {ID: "github", Name: "GitHub", Social: true,
		authURL: "https://github.com/login/oauth/authorize", tokenURL: "https://github.com/login/oauth/access_token",
		userInfoURL: "https://api.github.com/user", scope: "user:email", profile: githubProfile},
	"gitlab": {ID: "gitlab", Name: "GitLab", Social: true, OIDC: true,
		authURL: "https://gitlab.com/oauth/authorize", tokenURL: "https://gitlab.com/oauth/token",
		userInfoURL: "https://gitlab.com/oauth/userinfo", issuer: "https://gitlab.com", jwksURL: "https://gitlab.com/oauth/discovery/keys",
		scope: "openid read_user", profile: oidcProfile},
	"facebook": {ID: "facebook", Name: "Facebook", Social: true,
		authURL: "https://graph.facebook.com/oauth/authorize", tokenURL: "https://graph.facebook.com/oauth/access_token",
		userInfoURL: "https://graph.facebook.com/me?fields=id,name,email,first_name,last_name", scope: "email", profile: facebookProfile},
	"apple": {ID: "apple", Name: "Apple", Social: true, OIDC: true,
		authURL: "https://appleid.apple.com/auth/authorize", tokenURL: "https://appleid.apple.com/auth/token",
		issuer: "https://appleid.apple.com", jwksURL: "https://appleid.apple.com/auth/keys", scope: "openid name email",
		profile: appleProfile},
}

// brokeredIdentity is the user as the identity provider describes it.
type brokeredIdentity struct {
	ID        string         `json:"id"`
	Username  string         `json:"username"`
	Email     string         `json:"email,omitempty"`
	FirstName string         `json:"firstName,omitempty"`
	LastName  string         `json:"lastName,omitempty"`
	Claims    map[string]any `json:"claims,omitempty"`
	// BrokerUsername is the username stored on the link.
	BrokerUsername string `json:"brokerUsername,omitempty"`
	// Attributes collected by the review profile form or mappers before the
	// user exists.
	Attributes map[string][]string `json:"attributes,omitempty"`
	Token      string              `json:"token,omitempty"`   // token response JSON
	IDToken    string              `json:"idToken,omitempty"` // for logout
}

// endpoint returns a configured endpoint, or the preset's default.
func (t *IdPType) endpoint(idp *model.IdentityProvider, key, def string) string {
	if v := idp.Config[key]; v != "" {
		return v
	}
	tenant := idp.Config["tenantId"]
	if tenant == "" {
		tenant = "common"
	}
	def = strings.ReplaceAll(def, "{tenant}", url.PathEscape(tenant))
	if idp.ProviderID == "github" {
		// GitHub Enterprise: baseUrl and apiUrl replace github.com.
		if b := strings.TrimSuffix(idp.Config["baseUrl"], "/"); b != "" {
			def = strings.Replace(def, "https://github.com", b, 1)
		}
		if a := strings.TrimSuffix(idp.Config["apiUrl"], "/"); a != "" {
			def = strings.Replace(def, "https://api.github.com", a, 1)
		}
	}
	return def
}

func (t *IdPType) defaultScope(idp *model.IdentityProvider) string {
	if s := strings.TrimSpace(idp.Config["defaultScope"]); s != "" {
		if t.OIDC && !t.Social && !strings.Contains(" "+s+" ", " openid ") {
			s = "openid " + s
		}
		return s
	}
	return t.scope
}

// brokerHTTP is the client used to call identity providers.
var brokerHTTP = &http.Client{Timeout: 10 * time.Second}

// brokerCall is one exchange with an identity provider.
type brokerCall struct {
	h     *Handler
	r     *http.Request
	realm *model.Realm
	idp   *model.IdentityProvider
	typ   *IdPType
	nonce string

	tokenJSON   []byte
	accessToken string
	idToken     string
}

// authorizationURL builds the request that sends the browser to the provider.
func (h *Handler) authorizationURL(r *http.Request, realm *model.Realm, idp *model.IdentityProvider, as *model.AuthSession, state, nonce, verifier string) (string, error) {
	t := IdPTypes[idp.ProviderID]
	authURL := t.endpoint(idp, "authorizationUrl", t.authURL)
	if authURL == "" {
		return "", errors.New("identity provider has no authorization URL")
	}
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {idp.Config["clientId"]},
		"redirect_uri":  {h.brokerEndpoint(r, realm, idp)},
		"state":         {state},
	}
	if scope := t.defaultScope(idp); scope != "" {
		q.Set("scope", scope)
	}
	if t.OIDC && idp.Config["disableNonce"] != "true" {
		q.Set("nonce", nonce)
	}
	if idp.Config["pkceEnabled"] == "true" {
		method := idp.Config["pkceMethod"]
		if method == "" {
			method = "S256"
		}
		challenge := verifier
		if method == "S256" {
			sum := sha256.Sum256([]byte(verifier))
			challenge = base64.RawURLEncoding.EncodeToString(sum[:])
		}
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", method)
	}
	if p := idp.Config["prompt"]; p != "" {
		q.Set("prompt", p)
	}
	if as != nil {
		if strings.Contains(as.Params["prompt"], "none") && idp.Config["acceptsPromptNoneForwardFromClient"] == "true" {
			q.Set("prompt", "none")
		}
		if idp.Config["loginHint"] == "true" && as.Params["login_hint"] != "" {
			q.Set("login_hint", as.Params["login_hint"])
		}
		if idp.Config["passMaxAge"] == "true" && as.Params["max_age"] != "" {
			q.Set("max_age", as.Params["max_age"])
		}
		for _, p := range strings.Split(idp.Config["forwardParameters"], ",") {
			if p = strings.TrimSpace(p); p != "" && as.Params["fwd."+p] != "" {
				q.Set(p, as.Params["fwd."+p])
			}
		}
	}
	if idp.Config["uiLocales"] == "true" {
		q.Set("ui_locales", h.Locale(nil, r, realm, nil))
	}
	switch idp.ProviderID {
	case "google":
		if hd := idp.Config["hostedDomain"]; hd != "" {
			q.Set("hd", hd)
		}
		if idp.Config["offlineAccess"] == "true" {
			q.Set("access_type", "offline")
		}
	case "apple":
		// Apple posts the result when name or email are requested.
		q.Set("response_mode", "form_post")
	}
	sep := "?"
	if strings.Contains(authURL, "?") {
		sep = "&"
	}
	return authURL + sep + q.Encode(), nil
}

func (h *Handler) brokerEndpoint(r *http.Request, realm *model.Realm, idp *model.IdentityProvider) string {
	return h.URLs.Issuer(r, realm.Name) + "/broker/" + url.PathEscape(idp.Alias) + "/endpoint"
}

// exchangeCode redeems the authorization code at the token endpoint.
func (b *brokerCall) exchangeCode(code, verifier string) error {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {b.h.brokerEndpoint(b.r, b.realm, b.idp)}}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	tokenURL := b.typ.endpoint(b.idp, "tokenUrl", b.typ.tokenURL)
	req, err := b.clientAuthRequest(tokenURL, form)
	if err != nil {
		return err
	}
	resp, err := brokerHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token request: HTTP %d: %s", resp.StatusCode, body)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		// GitHub and Facebook may answer form encoded
		v, perr := url.ParseQuery(string(body))
		if perr != nil {
			return errors.New("invalid token response")
		}
		tr.AccessToken, tr.IDToken = v.Get("access_token"), v.Get("id_token")
		m := map[string]string{}
		for k := range v {
			m[k] = v.Get(k)
		}
		body, _ = json.Marshal(m)
	}
	if tr.AccessToken == "" {
		return errors.New("no access token in the token response")
	}
	b.tokenJSON, b.accessToken, b.idToken = body, tr.AccessToken, tr.IDToken
	return nil
}

// clientAuthRequest builds a token endpoint request authenticated with the
// provider's clientAuthMethod.
func (b *brokerCall) clientAuthRequest(tokenURL string, form url.Values) (*http.Request, error) {
	cfg := b.idp.Config
	clientID, secret := cfg["clientId"], cfg["clientSecret"]
	if b.idp.ProviderID == "apple" {
		var err error
		if secret, err = appleClientSecret(b.h.Svc.Now(), cfg); err != nil {
			return nil, err
		}
	}
	method := cfg["clientAuthMethod"]
	if method == "" {
		method = "client_secret_post"
	}
	assertion := func(key *jwt.Key) (string, error) {
		now := b.h.Svc.Now()
		aud := cfg["clientAssertionAudience"]
		if aud == "" {
			aud = tokenURL
		}
		return jwt.Sign(jwt.Claims{"iss": clientID, "sub": clientID, "aud": aud, "jti": service.NewID(),
			"iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}, key)
	}
	var basic bool
	switch method {
	case "client_secret_basic":
		basic = true
	case "client_secret_jwt":
		alg := cfg["clientAssertionSigningAlg"]
		if alg == "" {
			alg = "HS256"
		}
		tok, err := assertion(&jwt.Key{Alg: alg, Secret: []byte(secret)})
		if err != nil {
			return nil, err
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", tok)
		form.Set("client_id", clientID)
	case "private_key_jwt":
		alg := cfg["clientAssertionSigningAlg"]
		if alg == "" {
			alg = "RS256"
		}
		key, err := b.h.Svc.SigningKey(b.r.Context(), b.realm, alg)
		if err != nil {
			return nil, err
		}
		tok, err := assertion(key)
		if err != nil {
			return nil, err
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", tok)
		form.Set("client_id", clientID)
	default: // client_secret_post
		form.Set("client_id", clientID)
		if secret != "" {
			form.Set("client_secret", secret)
		}
	}
	req, err := http.NewRequestWithContext(b.r.Context(), http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basic {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	}
	return req, nil
}

// getJSON calls a profile endpoint with the access token.
func (b *brokerCall) getJSON(u string, v any) error {
	req, err := http.NewRequestWithContext(b.r.Context(), http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+b.accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := brokerHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("profile request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("profile request %s: HTTP %d", u, resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/jwt") {
		// a signed userinfo response
		_, c, err := jwt.Parse(strings.TrimSpace(string(body)))
		if err != nil {
			return err
		}
		body, _ = json.Marshal(c)
	}
	return json.Unmarshal(body, v)
}

// verifyIDToken checks the ID token of the token response.
func (b *brokerCall) verifyIDToken() (jwt.Claims, error) {
	cfg := b.idp.Config
	var claims jwt.Claims
	var err error
	validate := cfg["validateSignature"] == "true" || (b.typ.Social && b.typ.jwksURL != "")
	if validate {
		claims, err = jwt.Verify(b.idToken, func(kid, alg string) *jwt.Key {
			k, err := b.providerKey(kid, alg)
			if err != nil {
				b.h.Log.Warn("identity provider key", "alias", b.idp.Alias, "err", err)
				return nil
			}
			return k
		})
	} else {
		_, claims, err = jwt.Parse(b.idToken)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid ID token: %w", err)
	}
	skew := int64(0)
	if s := cfg["allowedClockSkew"]; s != "" {
		fmt.Sscan(s, &skew)
	}
	now := b.h.Svc.Now().Unix()
	iss := b.typ.endpoint(b.idp, "issuer", b.typ.issuer)
	switch {
	case claims.Int("exp") != 0 && claims.Int("exp")+skew < now:
		return nil, errors.New("ID token expired")
	case iss != "" && !strings.Contains(" "+iss+" ", " "+claims.String("iss")+" ") && !strings.Contains(","+iss+",", ","+claims.String("iss")+","):
		return nil, fmt.Errorf("wrong ID token issuer %q", claims.String("iss"))
	case !contains(claims.Audience(), cfg["clientId"]):
		return nil, errors.New("wrong ID token audience")
	case cfg["disableNonce"] != "true" && claims.String("nonce") != b.nonce && (b.idp.ProviderID != "apple" || claims.String("nonce") != ""):
		return nil, errors.New("wrong ID token nonce")
	}
	return claims, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// providerKey finds the provider's key that verifies a token.
func (b *brokerCall) providerKey(kid, alg string) (*jwt.Key, error) {
	cfg := b.idp.Config
	if strings.HasPrefix(alg, "HS") {
		return &jwt.Key{Alg: alg, Secret: []byte(cfg["clientSecret"])}, nil
	}
	pick := func(keys []jwt.JWK) (*jwt.Key, error) {
		for _, j := range keys {
			if (kid == "" || j.Kid == kid) && (j.Use == "" || j.Use == "sig") {
				k, err := jwt.KeyFromJWK(j, alg)
				if err == nil {
					k.Alg = alg
				}
				return k, err
			}
		}
		return nil, fmt.Errorf("no key %q in the provider's JWKS", kid)
	}
	jwksURL := b.typ.endpoint(b.idp, "jwksUrl", b.typ.jwksURL)
	if cfg["useJwksUrl"] == "true" || (cfg["useJwksUrl"] == "" && jwksURL != "") {
		keys, err := b.h.jwks.get(b.r.Context(), jwksURL, kid)
		if err != nil {
			return nil, err
		}
		return pick(keys)
	}
	pub := strings.TrimSpace(cfg["publicKeySignatureVerifier"])
	if pub == "" {
		return nil, errors.New("no key configured to validate signatures")
	}
	if strings.HasPrefix(pub, "{") {
		var j jwt.JWK
		if err := json.Unmarshal([]byte(pub), &j); err != nil {
			return nil, err
		}
		return pick([]jwt.JWK{j})
	}
	if want := cfg["publicKeySignatureVerifierKeyId"]; want != "" && kid != "" && want != kid {
		return nil, fmt.Errorf("unknown key id %q", kid)
	}
	if cert, err := jwt.ParseCertificate(pub); err == nil {
		return &jwt.Key{Alg: alg, Public: cert.PublicKey}, nil
	}
	key, err := parsePublicKey(pub)
	if err != nil {
		return nil, err
	}
	return &jwt.Key{Alg: alg, Public: key}, nil
}

// ---------------------------------------------------------------- profiles

func str(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%.0f", v)
	case json.Number:
		return v.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

// splitName splits a full name into first and last name.
func splitName(name string) (string, string) {
	name = strings.TrimSpace(name)
	if i := strings.LastIndex(name, " "); i > 0 {
		return name[:i], name[i+1:]
	}
	return name, ""
}

func oidcProfile(ctx context.Context, b *brokerCall) (*brokeredIdentity, error) {
	claims := map[string]any{}
	if b.idToken != "" {
		c, err := b.verifyIDToken()
		if err != nil {
			return nil, err
		}
		for k, v := range c {
			claims[k] = v
		}
	} else if b.typ.OIDC && b.idp.ProviderID != "gitlab" {
		return nil, errors.New("no ID token in the token response")
	}
	if u := b.typ.endpoint(b.idp, "userInfoUrl", b.typ.userInfoURL); u != "" && b.idp.Config["disableUserInfo"] != "true" {
		var info map[string]any
		if err := b.getJSON(u, &info); err != nil {
			if b.idToken == "" {
				return nil, err
			}
			b.h.Log.Warn("identity provider userinfo", "alias", b.idp.Alias, "err", err)
		} else {
			if sub, ok := claims["sub"]; ok && str(info, "sub") != "" && str(info, "sub") != fmt.Sprint(sub) {
				return nil, errors.New("userinfo subject does not match the ID token")
			}
			for k, v := range info {
				claims[k] = v
			}
		}
	}
	id := &brokeredIdentity{ID: str(claims, "sub"), Claims: claims, Email: str(claims, "email"),
		FirstName: str(claims, "given_name"), LastName: str(claims, "family_name")}
	if id.FirstName == "" && id.LastName == "" && str(claims, "name") != "" {
		id.FirstName, id.LastName = splitName(str(claims, "name"))
	}
	id.Username = str(claims, "preferred_username")
	if id.Username == "" {
		id.Username = id.Email
	}
	if id.Username == "" {
		id.Username = id.ID
	}
	return id, nil
}

// oauth2Profile reads the profile of a generic OAuth 2.0 provider, with
// configurable claim names.
func oauth2Profile(ctx context.Context, b *brokerCall) (*brokeredIdentity, error) {
	cfg := b.idp.Config
	var info map[string]any
	if err := b.getJSON(cfg["userInfoUrl"], &info); err != nil {
		return nil, err
	}
	claim := func(key, def string) string {
		name := cfg[key]
		if name == "" {
			name = def
		}
		return str(info, name)
	}
	id := &brokeredIdentity{Claims: info, ID: claim("userIDClaim", "sub"), Username: claim("userNameClaim", "preferred_username"),
		Email: claim("emailClaim", "email"), FirstName: claim("givenNameClaim", "given_name"), LastName: claim("familyNameClaim", "family_name")}
	if full := claim("fullNameClaim", "name"); id.FirstName == "" && id.LastName == "" && full != "" {
		id.FirstName, id.LastName = splitName(full)
	}
	if id.Username == "" {
		id.Username = id.Email
	}
	if id.Username == "" {
		id.Username = id.ID
	}
	return id, nil
}

func githubProfile(ctx context.Context, b *brokerCall) (*brokeredIdentity, error) {
	var info map[string]any
	profileURL := b.typ.endpoint(b.idp, "userInfoUrl", b.typ.userInfoURL)
	if err := b.getJSON(profileURL, &info); err != nil {
		return nil, err
	}
	id := &brokeredIdentity{ID: str(info, "id"), Username: str(info, "login"), Email: str(info, "email"), Claims: info}
	id.FirstName, id.LastName = splitName(str(info, "name"))
	if id.Email == "" {
		// the primary verified address, from the emails API
		var emails []map[string]any
		if err := b.getJSON(strings.TrimSuffix(profileURL, "/")+"/emails", &emails); err == nil {
			for _, e := range emails {
				if e["primary"] == true && e["verified"] == true {
					id.Email = str(e, "email")
				}
			}
		}
	}
	return id, nil
}

func microsoftProfile(ctx context.Context, b *brokerCall) (*brokeredIdentity, error) {
	var info map[string]any
	if err := b.getJSON(b.typ.endpoint(b.idp, "userInfoUrl", b.typ.userInfoURL), &info); err != nil {
		return nil, err
	}
	id := &brokeredIdentity{ID: str(info, "id"), Username: str(info, "userPrincipalName"), Email: str(info, "mail"),
		FirstName: str(info, "givenName"), LastName: str(info, "surname"), Claims: info}
	if id.Email == "" {
		id.Email = id.Username
	}
	return id, nil
}

func facebookProfile(ctx context.Context, b *brokerCall) (*brokeredIdentity, error) {
	var info map[string]any
	u := b.typ.endpoint(b.idp, "userInfoUrl", b.typ.userInfoURL)
	if extra := b.idp.Config["fetchedFields"]; extra != "" {
		u += "," + extra
	}
	if err := b.getJSON(u, &info); err != nil {
		return nil, err
	}
	id := &brokeredIdentity{ID: str(info, "id"), Email: str(info, "email"), FirstName: str(info, "first_name"),
		LastName: str(info, "last_name"), Claims: info}
	id.Username = id.Email
	if id.Username == "" {
		id.Username = "facebook." + id.ID
	}
	return id, nil
}

func appleProfile(ctx context.Context, b *brokerCall) (*brokeredIdentity, error) {
	id, err := oidcProfile(ctx, b)
	if err != nil {
		return nil, err
	}
	// The name is only sent on the first authorization, as a form field.
	var user struct {
		Name struct {
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
		} `json:"name"`
	}
	if json.Unmarshal([]byte(b.r.PostFormValue("user")), &user) == nil {
		id.FirstName, id.LastName = user.Name.FirstName, user.Name.LastName
	}
	if id.Username == id.ID && id.Email != "" {
		id.Username = id.Email
	}
	return id, nil
}

// appleClientSecret is the ES256 JWT Apple expects as client secret, signed
// with the key of the Apple developer account (config p8Key, keyId, teamId).
func appleClientSecret(now time.Time, cfg map[string]string) (string, error) {
	if cfg["p8Key"] == "" {
		return cfg["clientSecret"], nil
	}
	priv, err := jwt.ParsePrivateKey(cfg["p8Key"])
	if err != nil {
		return "", fmt.Errorf("apple p8 key: %w", err)
	}
	return jwt.Sign(jwt.Claims{"iss": cfg["teamId"], "sub": cfg["clientId"], "aud": "https://appleid.apple.com",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}, &jwt.Key{Kid: cfg["keyId"], Alg: "ES256", Private: priv})
}

// parsePublicKey reads a PEM or base64 DER (PKIX) public key.
func parsePublicKey(s string) (crypto.PublicKey, error) {
	der := []byte(nil)
	if blk, _ := pem.Decode([]byte(s)); blk != nil {
		der = blk.Bytes
	} else {
		b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
		if err != nil {
			return nil, errors.New("invalid public key")
		}
		der = b
	}
	return x509.ParsePKIXPublicKey(der)
}
