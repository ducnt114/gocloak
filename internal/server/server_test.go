package server

import (
	"bytes"
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ducnt114/gocloak/internal/jwt"
)

type env struct {
	t   *testing.T
	srv *httptest.Server
	app *Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	app, err := New(context.Background(), Config{
		DB: testDB(t), AdminUser: "admin", AdminPassword: "admin",
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(func() { srv.Close(); app.Close() })
	return &env{t: t, srv: srv, app: app}
}

type response struct {
	status int
	header http.Header
	body   []byte
}

func (r *response) json(v any) {
	if err := json.Unmarshal(r.body, v); err != nil {
		panic(fmt.Sprintf("decode %s: %v", r.body, err))
	}
}

func (e *env) do(client *http.Client, method, path, token string, body any, form url.Values) *response {
	e.t.Helper()
	var rd io.Reader
	ct := ""
	switch {
	case form != nil:
		rd, ct = strings.NewReader(form.Encode()), "application/x-www-form-urlencoded"
	case body != nil:
		b, _ := json.Marshal(body)
		rd, ct = bytes.NewReader(b), "application/json"
	}
	u := path
	if strings.HasPrefix(path, "/") {
		u = e.srv.URL + path
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return &response{status: resp.StatusCode, header: resp.Header, body: b}
}

func (e *env) expect(r *response, status int) *response {
	e.t.Helper()
	if r.status != status {
		e.t.Fatalf("expected status %d, got %d: %s", status, r.status, r.body)
	}
	return r
}

type tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
	SessionState string `json:"session_state"`
	ExpiresIn    int    `json:"expires_in"`
}

func (e *env) passwordGrant(realm, clientID, secret, user, pass string) (*tokens, *response) {
	f := url.Values{"grant_type": {"password"}, "client_id": {clientID}, "username": {user}, "password": {pass}, "scope": {"openid"}}
	if secret != "" {
		f.Set("client_secret", secret)
	}
	r := e.do(nil, "POST", "/realms/"+realm+"/protocol/openid-connect/token", "", nil, f)
	var t tokens
	if r.status == 200 {
		r.json(&t)
	}
	return &t, r
}

func (e *env) adminToken() string {
	t, r := e.passwordGrant("master", "admin-cli", "", "admin", "admin")
	e.expect(r, 200)
	return t.AccessToken
}

func claims(t *testing.T, tok string) jwt.Claims {
	t.Helper()
	_, c, err := jwt.Parse(tok)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func strs(v any) []string {
	var out []string
	if a, ok := v.([]any); ok {
		for _, x := range a {
			out = append(out, fmt.Sprint(x))
		}
	}
	return out
}

func realmRoles(c jwt.Claims) []string {
	ra, _ := c["realm_access"].(map[string]any)
	return strs(ra["roles"])
}

func clientRoles(c jwt.Claims, client string) []string {
	ra, _ := c["resource_access"].(map[string]any)
	cr, _ := ra[client].(map[string]any)
	return strs(cr["roles"])
}

func idFromLocation(t *testing.T, r *response) string {
	t.Helper()
	loc := r.header.Get("Location")
	if loc == "" {
		t.Fatalf("missing Location header")
	}
	return loc[strings.LastIndex(loc, "/")+1:]
}

// setupDemo creates realm "demo" with a confidential client "web", a
// service account client "svc", a group "staff" carrying realm role
// "editor", and user alice (member of staff).
func (e *env) setupDemo() (adminTok, aliceID string) {
	adminTok = e.adminToken()
	e.expect(e.do(nil, "POST", "/admin/realms", adminTok, map[string]any{"realm": "demo", "enabled": true}, nil), 201)
	e.expect(e.do(nil, "POST", "/admin/realms/demo/clients", adminTok, map[string]any{
		"clientId": "web", "secret": "web-secret", "redirectUris": []string{"http://app.test/cb*"},
		"webOrigins": []string{"+"}, "directAccessGrantsEnabled": true,
	}, nil), 201)
	e.expect(e.do(nil, "POST", "/admin/realms/demo/clients", adminTok, map[string]any{
		"clientId": "svc", "secret": "svc-secret", "serviceAccountsEnabled": true, "standardFlowEnabled": false,
	}, nil), 201)
	e.expect(e.do(nil, "POST", "/admin/realms/demo/roles", adminTok, map[string]any{"name": "editor"}, nil), 201)
	groupID := idFromLocation(e.t, e.expect(e.do(nil, "POST", "/admin/realms/demo/groups", adminTok, map[string]any{"name": "staff"}, nil), 201))
	editor := map[string]any{}
	e.expect(e.do(nil, "GET", "/admin/realms/demo/roles/editor", adminTok, nil, nil), 200).json(&editor)
	e.expect(e.do(nil, "POST", "/admin/realms/demo/groups/"+groupID+"/role-mappings/realm", adminTok, []any{editor}, nil), 204)

	r := e.expect(e.do(nil, "POST", "/admin/realms/demo/users", adminTok, map[string]any{
		"username": "Alice", "email": "alice@example.com", "firstName": "Alice", "lastName": "Liddell", "enabled": true,
		"credentials": []map[string]any{{"type": "password", "value": "wonderland", "temporary": false}},
	}, nil), 201)
	aliceID = idFromLocation(e.t, r)
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+aliceID+"/groups/"+groupID, adminTok, nil, nil), 204)
	return adminTok, aliceID
}

func TestDiscoveryAndCerts(t *testing.T) {
	e := newEnv(t)
	var d map[string]any
	e.expect(e.do(nil, "GET", "/realms/master/.well-known/openid-configuration", "", nil, nil), 200).json(&d)
	if d["issuer"] != e.srv.URL+"/realms/master" {
		t.Fatalf("issuer = %v", d["issuer"])
	}
	if d["token_endpoint"] != e.srv.URL+"/realms/master/protocol/openid-connect/token" {
		t.Fatalf("token_endpoint = %v", d["token_endpoint"])
	}
	var jwks struct{ Keys []jwt.JWK }
	e.expect(e.do(nil, "GET", "/realms/master/protocol/openid-connect/certs", "", nil, nil), 200).json(&jwks)
	if len(jwks.Keys) != 1 || jwks.Keys[0].Kty != "RSA" {
		t.Fatalf("unexpected jwks %+v", jwks)
	}
	e.expect(e.do(nil, "GET", "/realms/nope/.well-known/openid-configuration", "", nil, nil), 404)
	e.expect(e.do(nil, "GET", "/health/ready", "", nil, nil), 200)
}

func TestPasswordGrantAndRoles(t *testing.T) {
	e := newEnv(t)
	e.setupDemo()

	tok, r := e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	e.expect(r, 200)
	c := claims(t, tok.AccessToken)
	if c.String("preferred_username") != "alice" || c.String("email") != "alice@example.com" || c.String("name") != "Alice Liddell" {
		t.Fatalf("unexpected profile claims %v", c)
	}
	if c.String("iss") != e.srv.URL+"/realms/demo" || c.String("typ") != "Bearer" || c.String("azp") != "web" {
		t.Fatalf("unexpected claims %v", c)
	}
	for _, want := range []string{"editor", "offline_access", "uma_authorization", "default-roles-demo"} {
		if !slices.Contains(realmRoles(c), want) {
			t.Errorf("realm role %s missing from %v", want, realmRoles(c))
		}
	}
	if acc := clientRoles(c, "account"); !slices.Contains(acc, "manage-account") || !slices.Contains(acc, "manage-account-links") {
		t.Errorf("account roles = %v", acc)
	}
	if c.String("aud") != "account" {
		t.Errorf("aud = %v", c["aud"])
	}
	if tok.Scope != "openid email profile" || tok.IDToken == "" {
		t.Errorf("scope=%q id_token=%q", tok.Scope, tok.IDToken)
	}
	idc := claims(t, tok.IDToken)
	if idc.String("aud") != "web" || idc.String("typ") != "ID" || idc.String("sid") != tok.SessionState {
		t.Errorf("unexpected id token %v", idc)
	}

	// Login with email works too; wrong password and wrong secret fail.
	_, r = e.passwordGrant("demo", "web", "web-secret", "alice@example.com", "wonderland")
	e.expect(r, 200)
	_, r = e.passwordGrant("demo", "web", "web-secret", "alice", "nope")
	e.expect(r, 401) // invalid_grant, as in Keycloak
	_, r = e.passwordGrant("demo", "web", "bad", "alice", "wonderland")
	e.expect(r, 401)

	// userinfo
	var ui map[string]any
	e.expect(e.do(nil, "GET", "/realms/demo/protocol/openid-connect/userinfo", tok.AccessToken, nil, nil), 200).json(&ui)
	if ui["preferred_username"] != "alice" || ui["sub"] != c.String("sub") {
		t.Fatalf("userinfo = %v", ui)
	}
	// a master token is not valid for demo
	e.expect(e.do(nil, "GET", "/realms/demo/protocol/openid-connect/userinfo", e.adminToken(), nil, nil), 401)
}

func TestAuthorizationCodeFlowWithPKCE(t *testing.T) {
	e := newEnv(t)
	e.setupDemo()

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	verifier := strings.Repeat("v", 50)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authURL := "/realms/demo/protocol/openid-connect/auth?" + url.Values{
		"client_id": {"web"}, "redirect_uri": {"http://app.test/cb"}, "response_type": {"code"},
		"scope": {"openid email"}, "state": {"xyz"}, "nonce": {"n-1"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode()

	// Invalid redirect URIs are never redirected to.
	bad := e.do(browser, "GET", strings.Replace(authURL, "app.test", "evil.test", 1), "", nil, nil)
	e.expect(bad, 400)

	page := e.expect(e.do(browser, "GET", authURL, "", nil, nil), 200)
	m := regexp.MustCompile(`action="([^"]+)"`).FindSubmatch(page.body)
	if m == nil {
		t.Fatalf("no login form in %s", page.body)
	}
	action := strings.ReplaceAll(string(m[1]), "&amp;", "&")

	// wrong password re-renders the form
	r := e.do(browser, "POST", action, "", nil, url.Values{"username": {"alice"}, "password": {"x"}})
	if r.status != 401 || !bytes.Contains(r.body, []byte("Invalid username or password.")) {
		t.Fatalf("expected login error, got %d %s", r.status, r.body)
	}
	r = e.expect(e.do(browser, "POST", action, "", nil, url.Values{"username": {"alice"}, "password": {"wonderland"}}), 302)
	loc, _ := url.Parse(r.header.Get("Location"))
	if loc.Host != "app.test" || loc.Query().Get("state") != "xyz" || loc.Query().Get("iss") != e.srv.URL+"/realms/demo" {
		t.Fatalf("unexpected redirect %s", loc)
	}
	code := loc.Query().Get("code")

	exchange := func(code, verifier string) *response {
		return e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://app.test/cb"},
			"client_id": {"web"}, "client_secret": {"web-secret"}, "code_verifier": {verifier},
		})
	}
	e.expect(exchange(code, strings.Repeat("w", 50)), 400) // wrong verifier consumes the code
	e.expect(exchange(code, verifier), 400)                // codes are single use

	// Second login: the SSO cookie skips the login form.
	r = e.expect(e.do(browser, "GET", authURL, "", nil, nil), 302)
	loc, _ = url.Parse(r.header.Get("Location"))
	var tok tokens
	e.expect(exchange(loc.Query().Get("code"), verifier), 200).json(&tok)
	idc := claims(t, tok.IDToken)
	if idc.String("nonce") != "n-1" || idc.String("at_hash") == "" {
		t.Fatalf("id token = %v", idc)
	}

	// refresh
	refresh := func(rt string) *response {
		return e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {"web"}, "client_secret": {"web-secret"},
		})
	}
	var tok2 tokens
	e.expect(refresh(tok.RefreshToken), 200).json(&tok2)
	if tok2.AccessToken == "" || claims(t, tok2.AccessToken).String("sid") != tok.SessionState {
		t.Fatalf("refresh returned %+v", tok2)
	}

	// prompt=none works while logged in
	e.expect(e.do(browser, "GET", authURL+"&prompt=none", "", nil, nil), 302)

	// RP-initiated logout with id_token_hint ends the session
	r = e.expect(e.do(browser, "GET", "/realms/demo/protocol/openid-connect/logout?"+url.Values{
		"id_token_hint": {tok.IDToken}, "post_logout_redirect_uri": {"http://app.test/cb/bye"}, "state": {"s1"},
	}.Encode(), "", nil, nil), 302)
	if r.header.Get("Location") != "http://app.test/cb/bye?state=s1" {
		t.Fatalf("logout redirect = %s", r.header.Get("Location"))
	}
	e.expect(refresh(tok.RefreshToken), 400)
	e.expect(e.do(nil, "GET", "/realms/demo/protocol/openid-connect/userinfo", tok2.AccessToken, nil, nil), 401)

	// prompt=none now reports login_required
	r = e.expect(e.do(browser, "GET", authURL+"&prompt=none", "", nil, nil), 302)
	loc, _ = url.Parse(r.header.Get("Location"))
	if loc.Query().Get("error") != "login_required" {
		t.Fatalf("expected login_required, got %s", loc)
	}
}

func TestClientCredentialsIntrospectRevoke(t *testing.T) {
	e := newEnv(t)
	e.setupDemo()

	var tok tokens
	e.expect(e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {"svc-secret"},
	}), 200).json(&tok)
	c := claims(t, tok.AccessToken)
	if c.String("preferred_username") != "service-account-svc" || c.String("client_id") != "svc" || tok.RefreshToken != "" {
		t.Fatalf("unexpected client credentials token %v", c)
	}
	// public clients may not use it, nor clients without service accounts
	e.expect(e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"web"}, "client_secret": {"web-secret"},
	}), 400)

	introspect := func(token string) map[string]any {
		var out map[string]any
		e.expect(e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token/introspect", "", nil, url.Values{
			"token": {token}, "client_id": {"web"}, "client_secret": {"web-secret"},
		}), 200).json(&out)
		return out
	}
	if in := introspect(tok.AccessToken); in["active"] != true || in["username"] != "service-account-svc" {
		t.Fatalf("introspect = %v", in)
	}
	if in := introspect("garbage"); in["active"] != false {
		t.Fatalf("introspect garbage = %v", in)
	}
	e.expect(e.do(nil, "POST", "/realms/demo/protocol/openid-connect/revoke", "", nil, url.Values{
		"token": {tok.AccessToken}, "client_id": {"svc"}, "client_secret": {"svc-secret"},
	}), 200)
	if in := introspect(tok.AccessToken); in["active"] != false {
		t.Fatalf("revoked token still active: %v", in)
	}

	// service account roles show up in the token
	admin := e.adminToken()
	var clients []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/clients?clientId=svc", admin, nil, nil), 200).json(&clients)
	var sa map[string]any
	e.expect(e.do(nil, "GET", fmt.Sprintf("/admin/realms/demo/clients/%s/service-account-user", clients[0]["id"]), admin, nil, nil), 200).json(&sa)
	e.expect(e.do(nil, "POST", fmt.Sprintf("/admin/realms/demo/users/%s/role-mappings/realm", sa["id"]), admin, []any{map[string]any{"name": "editor"}}, nil), 204)
	e.expect(e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {"svc-secret"},
	}), 200).json(&tok)
	if !slices.Contains(realmRoles(claims(t, tok.AccessToken)), "editor") {
		t.Fatalf("editor missing: %v", claims(t, tok.AccessToken))
	}
}

func TestTemporaryPasswordRequiresUpdate(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+aliceID+"/reset-password", admin,
		map[string]any{"type": "password", "value": "temp", "temporary": true}, nil), 204)

	_, r := e.passwordGrant("demo", "web", "web-secret", "alice", "temp")
	if r.status != 400 || !bytes.Contains(r.body, []byte("not fully set up")) {
		t.Fatalf("expected not fully set up, got %d %s", r.status, r.body)
	}

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	page := e.expect(e.do(browser, "GET", "/realms/demo/protocol/openid-connect/auth?client_id=web&response_type=code&redirect_uri=http%3A%2F%2Fapp.test%2Fcb", "", nil, nil), 200)
	action := strings.ReplaceAll(string(regexp.MustCompile(`action="([^"]+)"`).FindSubmatch(page.body)[1]), "&amp;", "&")
	page = e.expect(e.do(browser, "POST", action, "", nil, url.Values{"username": {"alice"}, "password": {"temp"}}), 200)
	if !bytes.Contains(page.body, []byte("password-new")) {
		t.Fatalf("expected update password form, got %s", page.body)
	}
	action = strings.ReplaceAll(string(regexp.MustCompile(`action="([^"]+)"`).FindSubmatch(page.body)[1]), "&amp;", "&")
	e.expect(e.do(browser, "POST", action, "", nil, url.Values{"password-new": {"a"}, "password-confirm": {"b"}}), 400)
	r = e.expect(e.do(browser, "POST", action, "", nil, url.Values{"password-new": {"newpass"}, "password-confirm": {"newpass"}}), 302)
	if !strings.Contains(r.header.Get("Location"), "code=") {
		t.Fatalf("expected code redirect, got %s", r.header.Get("Location"))
	}
	_, r = e.passwordGrant("demo", "web", "web-secret", "alice", "newpass")
	e.expect(r, 200)
}

func TestAdminAPI(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()

	// unauthenticated and bad tokens
	e.expect(e.do(nil, "GET", "/admin/realms", "", nil, nil), 401)
	e.expect(e.do(nil, "GET", "/admin/realms", "garbage", nil, nil), 401)

	var realms []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms", admin, nil, nil), 200).json(&realms)
	if len(realms) != 2 {
		t.Fatalf("realms = %v", realms)
	}
	e.expect(e.do(nil, "POST", "/admin/realms", admin, map[string]any{"realm": "demo"}, nil), 409)

	// users: duplicates, search, count, update
	e.expect(e.do(nil, "POST", "/admin/realms/demo/users", admin, map[string]any{"username": "alice"}, nil), 409)
	e.expect(e.do(nil, "POST", "/admin/realms/demo/users", admin, map[string]any{"username": "other", "email": "ALICE@example.com"}, nil), 409)
	e.expect(e.do(nil, "POST", "/admin/realms/demo/users", admin, map[string]any{"username": "bob", "enabled": true}, nil), 201)
	var users []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users?search=ali", admin, nil, nil), 200).json(&users)
	if len(users) != 1 || users[0]["username"] != "alice" {
		t.Fatalf("search = %v", users)
	}
	var n int
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/count", admin, nil, nil), 200).json(&n)
	if n != 2 { // service account users are not listed
		t.Fatalf("count = %d", n)
	}
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+aliceID, admin, map[string]any{"firstName": "Al"}, nil), 204)
	var alice map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/"+aliceID, admin, nil, nil), 200).json(&alice)
	if alice["firstName"] != "Al" || alice["lastName"] != "Liddell" || alice["enabled"] != true {
		t.Fatalf("partial update failed: %v", alice)
	}
	var groups []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/"+aliceID+"/groups", admin, nil, nil), 200).json(&groups)
	if len(groups) != 1 || groups[0]["path"] != "/staff" {
		t.Fatalf("groups = %v", groups)
	}
	var composite []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/"+aliceID+"/role-mappings/realm/composite", admin, nil, nil), 200).json(&composite)
	names := []string{}
	for _, r := range composite {
		names = append(names, r["name"].(string))
	}
	if !slices.Contains(names, "editor") {
		t.Fatalf("effective roles = %v", names)
	}

	// A realm admin of demo: grant view-users only.
	e.expect(e.do(nil, "POST", "/admin/realms/demo/users", admin, map[string]any{
		"username": "helpdesk", "enabled": true, "credentials": []any{map[string]any{"value": "pw", "temporary": false}},
		"clientRoles": map[string][]string{"realm-management": {"view-users"}},
	}, nil), 201)
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/clients/"+clientUUID(e, admin, "admin-cli"), admin, map[string]any{"directAccessGrantsEnabled": true}, nil), 204)
	hd, r := e.passwordGrant("demo", "admin-cli", "", "helpdesk", "pw")
	e.expect(r, 200)
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users", hd.AccessToken, nil, nil), 200)
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/"+aliceID, hd.AccessToken, nil, nil), 200)
	e.expect(e.do(nil, "POST", "/admin/realms/demo/users", hd.AccessToken, map[string]any{"username": "x"}, nil), 403)
	e.expect(e.do(nil, "GET", "/admin/realms/demo/clients", hd.AccessToken, nil, nil), 403)
	e.expect(e.do(nil, "GET", "/admin/realms/master/users", hd.AccessToken, nil, nil), 403)
	e.expect(e.do(nil, "POST", "/admin/realms", hd.AccessToken, map[string]any{"realm": "x"}, nil), 403)

	// A user manager may map ordinary roles but not admin roles it lacks.
	mgrID := idFromLocation(t, e.expect(e.do(nil, "POST", "/admin/realms/demo/users", admin, map[string]any{
		"username": "usermgr", "enabled": true, "credentials": []any{map[string]any{"value": "pw", "temporary": false}},
		"clientRoles": map[string][]string{"realm-management": {"manage-users"}},
	}, nil), 201))
	mgr, r := e.passwordGrant("demo", "admin-cli", "", "usermgr", "pw")
	e.expect(r, 200)
	mgmtID := clientUUID(e, admin, "realm-management")
	var realmAdmin map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/clients/"+mgmtID+"/roles/realm-admin", admin, nil, nil), 200).json(&realmAdmin)
	e.expect(e.do(nil, "POST", "/admin/realms/demo/users/"+mgrID+"/role-mappings/clients/"+mgmtID, mgr.AccessToken, []any{realmAdmin}, nil), 403)
	e.expect(e.do(nil, "POST", "/admin/realms/demo/users", mgr.AccessToken, map[string]any{
		"username": "sneaky", "clientRoles": map[string][]string{"realm-management": {"realm-admin"}},
	}, nil), 403)
	e.expect(e.do(nil, "POST", "/admin/realms/demo/users/"+aliceID+"/role-mappings/realm", mgr.AccessToken, []any{map[string]any{"name": "editor"}}, nil), 204)

	// disabling a user ends their sessions
	alTok, r := e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	e.expect(r, 200)
	var sessions []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/"+aliceID+"/sessions", admin, nil, nil), 200).json(&sessions)
	if len(sessions) != 1 || sessions[0]["clients"].(map[string]any)[clientUUID(e, admin, "web")] != "web" {
		t.Fatalf("sessions = %v", sessions)
	}
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+aliceID, admin, map[string]any{"enabled": false}, nil), 204)
	e.expect(e.do(nil, "GET", "/realms/demo/protocol/openid-connect/userinfo", alTok.AccessToken, nil, nil), 401)

	// client secret rotation
	webID := clientUUID(e, admin, "web")
	var secret map[string]string
	e.expect(e.do(nil, "POST", "/admin/realms/demo/clients/"+webID+"/client-secret", admin, nil, nil), 200).json(&secret)
	if secret["value"] == "" || secret["value"] == "web-secret" {
		t.Fatalf("secret = %v", secret)
	}

	// client roles & composites
	e.expect(e.do(nil, "POST", "/admin/realms/demo/clients/"+webID+"/roles", admin, map[string]any{"name": "viewer"}, nil), 201)
	e.expect(e.do(nil, "POST", "/admin/realms/demo/roles/editor/composites", admin, []any{map[string]any{"name": "viewer", "clientRole": true, "containerId": webID}}, nil), 204)
	var editor map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/roles/editor", admin, nil, nil), 200).json(&editor)
	if editor["composite"] != true {
		t.Fatalf("editor = %v", editor)
	}

	// deleting the realm
	e.expect(e.do(nil, "DELETE", "/admin/realms/demo", admin, nil, nil), 204)
	e.expect(e.do(nil, "GET", "/admin/realms/demo", admin, nil, nil), 404)
	e.expect(e.do(nil, "DELETE", "/admin/realms/master", admin, nil, nil), 400)
}

func clientUUID(e *env, admin, clientID string) string {
	var clients []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/clients?clientId="+clientID, admin, nil, nil), 200).json(&clients)
	if len(clients) != 1 {
		e.t.Fatalf("client %s not found", clientID)
	}
	return clients[0]["id"].(string)
}

func TestRealmImport(t *testing.T) {
	e := newEnv(t)
	admin := e.adminToken()
	// pbkdf2-sha256 hash of "secret" with salt "salt0123456789ab", 1000 iterations, 32 bytes.
	export := `{
	  "realm": "imported", "enabled": true, "displayName": "Imported",
	  "roles": {
	    "realm": [{"name": "manager", "composite": true, "composites": {"realm": ["staff"]}}, {"name": "staff"}],
	    "client": {"shop": [{"name": "buyer"}]}
	  },
	  "clients": [{"clientId": "shop", "publicClient": true, "directAccessGrantsEnabled": true, "redirectUris": ["/*"], "rootUrl": "http://shop.test"}],
	  "groups": [{"name": "eu", "subGroups": [{"name": "fr", "realmRoles": ["manager"]}]}],
	  "users": [
	    {"id": "11111111-2222-3333-4444-555555555555", "username": "carol", "enabled": true, "groups": ["/eu/fr"],
	     "clientRoles": {"shop": ["buyer"]},
	     "credentials": [{"type": "password",
	        "secretData": "{\"value\":\"` + pbkdf2Hash("secret") + `\",\"salt\":\"c2FsdDAxMjM0NTY3ODlhYg==\",\"additionalParameters\":{}}",
	        "credentialData": "{\"hashIterations\":1000,\"algorithm\":\"pbkdf2-sha256\",\"additionalParameters\":{}}"}]}
	  ]
	}`
	var rep map[string]any
	if err := json.Unmarshal([]byte(export), &rep); err != nil {
		t.Fatal(err)
	}
	e.expect(e.do(nil, "POST", "/admin/realms", admin, rep, nil), 201)

	tok, r := e.passwordGrant("imported", "shop", "", "carol", "secret")
	e.expect(r, 200)
	c := claims(t, tok.AccessToken)
	if c.String("sub") != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("sub = %s", c.String("sub"))
	}
	if rr := realmRoles(c); !slices.Contains(rr, "manager") || !slices.Contains(rr, "staff") {
		t.Fatalf("realm roles = %v", rr)
	}
	if cr := clientRoles(c, "shop"); !slices.Contains(cr, "buyer") {
		t.Fatalf("shop roles = %v", cr)
	}

	var g map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/imported/group-by-path/eu/fr", admin, nil, nil), 200).json(&g)
	if g["path"] != "/eu/fr" {
		t.Fatalf("group = %v", g)
	}
	// relative redirect URIs resolve against rootUrl
	e.expect(e.do(&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		"GET", "/realms/imported/protocol/openid-connect/auth?client_id=shop&response_type=code&redirect_uri=http%3A%2F%2Fshop.test%2Fcb", "", nil, nil), 200)
}

func pbkdf2Hash(pw string) string {
	sum, err := pbkdf2.Key(sha256.New, pw, []byte("salt0123456789ab"), 1000, 32)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(sum)
}

func cookiejarNew() (http.CookieJar, error) { return cookiejar.New(nil) }

var formActionRe = regexp.MustCompile(`action="([^"]+)"`)

func formAction(t *testing.T, body []byte) string {
	t.Helper()
	m := formActionRe.FindSubmatch(body)
	if m == nil {
		t.Fatalf("no form in %s", body)
	}
	return strings.ReplaceAll(string(m[1]), "&amp;", "&")
}
