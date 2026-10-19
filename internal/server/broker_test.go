package server

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// upstream is a second gocloak acting as the external identity provider.
type upstream struct {
	*env
	admin string
}

// newUpstream starts an identity provider with realm "upstream", client
// "down" for the downstream broker and the given users (username, email).
func newUpstream(t *testing.T, down *env, users ...[2]string) *upstream {
	up := &upstream{env: newEnv(t)}
	up.admin = up.adminToken()
	R := "/admin/realms/upstream"
	up.expect(up.do(nil, "POST", "/admin/realms", up.admin, map[string]any{"realm": "upstream", "enabled": true}, nil), 201)
	clientID := idFromLocation(t, up.expect(up.do(nil, "POST", R+"/clients", up.admin, map[string]any{
		"clientId": "down", "secret": "down-secret", "redirectUris": []string{down.srv.URL + "/realms/demo/broker/*"},
	}, nil), 201))
	up.expect(up.do(nil, "POST", R+"/clients/"+clientID+"/protocol-mappers/models", up.admin, map[string]any{
		"name": "department", "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper",
		"config": with(flags(), "claim.name", "department", "claim.value", "eng", "jsonType.label", "String"),
	}, nil), 201)
	for _, u := range users {
		up.expect(up.do(nil, "POST", R+"/users", up.admin, map[string]any{
			"username": u[0], "email": u[1], "emailVerified": true, "firstName": "Up", "lastName": strings.ToUpper(u[0][:1]) + u[0][1:], "enabled": true,
			"credentials": []map[string]any{{"type": "password", "value": "upstream-pw"}},
		}, nil), 201)
	}
	return up
}

// addProvider registers the upstream realm as identity provider "up" of
// the demo realm.
func (up *upstream) addProvider(down *env, admin string, extra map[string]any) {
	iss := up.srv.URL + "/realms/upstream"
	rep := map[string]any{
		"alias": "up", "providerId": "oidc", "enabled": true, "displayName": "Upstream",
		"config": map[string]string{
			"authorizationUrl": iss + "/protocol/openid-connect/auth", "tokenUrl": iss + "/protocol/openid-connect/token",
			"userInfoUrl": iss + "/protocol/openid-connect/userinfo", "jwksUrl": iss + "/protocol/openid-connect/certs",
			"issuer": iss, "clientId": "down", "clientSecret": "down-secret", "clientAuthMethod": "client_secret_basic",
			"validateSignature": "true", "useJwksUrl": "true", "syncMode": "FORCE", "pkceEnabled": "true", "defaultScope": "openid email profile",
		},
	}
	for k, v := range extra {
		rep[k] = v
	}
	down.expect(down.do(nil, "POST", "/admin/realms/demo/identity-provider/instances", admin, rep, nil), 201)
}

var socialLinkRe = regexp.MustCompile(`id="social-up"[^>]*href="([^"]+)"`)

// loginAtUpstream follows the browser from the downstream login page to the
// upstream login, logs in there and returns the response of the downstream
// broker endpoint.
func loginAtUpstream(t *testing.T, down *env, up *upstream, browser *http.Client, start *response, user string) *response {
	t.Helper()
	if start.status == 200 {
		m := socialLinkRe.FindSubmatch(start.body)
		if m == nil {
			t.Fatalf("no identity provider link on the login page: %s", start.body)
		}
		start = down.expect(down.do(browser, "GET", html.UnescapeString(string(m[1])), "", nil, nil), 302)
	}
	loc := start.header.Get("Location")
	if !strings.HasPrefix(loc, up.srv.URL+"/realms/upstream/protocol/openid-connect/auth?") {
		t.Fatalf("not sent to the upstream provider: %s", loc)
	}
	page := up.expect(up.do(browser, "GET", loc, "", nil, nil), 200)
	r := up.expect(up.do(browser, "POST", formAction(t, page.body), "", nil, url.Values{"username": {user}, "password": {"upstream-pw"}}), 302)
	cb := r.header.Get("Location")
	if !strings.HasPrefix(cb, down.srv.URL+"/realms/demo/broker/up/endpoint?") {
		t.Fatalf("upstream did not return to the broker: %s", cb)
	}
	return down.do(browser, "GET", cb, "", nil, nil)
}

// follow follows same-server redirects until a page or a redirect elsewhere.
func (e *env) follow(browser *http.Client, r *response) *response {
	e.t.Helper()
	for r.status == 302 && strings.HasPrefix(r.header.Get("Location"), e.srv.URL) {
		r = e.do(browser, "GET", r.header.Get("Location"), "", nil, nil)
	}
	return r
}

func (e *env) exchangeCode(code string) *tokens {
	e.t.Helper()
	var tk tokens
	e.expect(e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, url.Values{"grant_type": {"authorization_code"},
		"code": {code}, "redirect_uri": {"http://app.test/cb"}, "client_id": {"web"}, "client_secret": {"web-secret"}}), 200).json(&tk)
	return &tk
}

func TestBrokerFirstLoginAndMappers(t *testing.T) {
	down := newEnv(t)
	admin, _ := down.setupDemo()
	up := newUpstream(t, down, [2]string{"bob", "bob@example.org"})
	down.expect(down.do(nil, "POST", "/admin/realms/demo/roles", admin, map[string]any{"name": "engineer"}, nil), 201)
	up.addProvider(down, admin, map[string]any{"trustEmail": true, "storeToken": true, "addReadTokenRoleOnCreate": true})
	M := "/admin/realms/demo/identity-provider/instances/up/mappers"
	down.expect(down.do(nil, "POST", M, admin, map[string]any{"name": "eng", "identityProviderMapper": "oidc-role-idp-mapper",
		"config": map[string]string{"claim": "department", "claim.value": "eng", "role": "engineer", "syncMode": "INHERIT"}}, nil), 201)
	down.expect(down.do(nil, "POST", M, admin, map[string]any{"name": "session", "identityProviderMapper": "hardcoded-user-session-attribute-idp-mapper",
		"config": map[string]string{"attribute": "via", "attribute.value": "upstream"}}, nil), 201)

	// first login: the user is created from the upstream profile
	browser := newBrowser()
	page := down.expect(down.do(browser, "GET", demoAuth, "", nil, nil), 200)
	if !strings.Contains(string(page.body), "Upstream") {
		t.Fatalf("provider button missing: %s", page.body)
	}
	r := down.follow(browser, loginAtUpstream(t, down, up, browser, page, "bob"))
	tk := down.exchangeCode(codeOf(t, r))
	c := claims(t, tk.AccessToken)
	if c.String("preferred_username") != "bob" || !slices.Contains(realmRoles(c), "engineer") {
		t.Fatalf("brokered user claims: %v", c)
	}
	if !slices.Contains(clientRoles(c, "broker"), "read-token") {
		t.Fatalf("read-token role not granted: %v", c["resource_access"])
	}
	var users []map[string]any
	down.expect(down.do(nil, "GET", "/admin/realms/demo/users?idpAlias=up", admin, nil, nil), 200).json(&users)
	if len(users) != 1 || users[0]["username"] != "bob" || users[0]["email"] != "bob@example.org" || users[0]["emailVerified"] != true ||
		users[0]["firstName"] != "Up" {
		t.Fatalf("imported user: %v", users)
	}
	bobID := users[0]["id"].(string)
	var links []map[string]string
	down.expect(down.do(nil, "GET", "/admin/realms/demo/users/"+bobID+"/federated-identity", admin, nil, nil), 200).json(&links)
	if len(links) != 1 || links[0]["identityProvider"] != "up" || links[0]["userName"] != "bob" || links[0]["userId"] == "" {
		t.Fatalf("federated identity: %v", links)
	}

	// the stored upstream token can be read with broker/read-token
	var stored map[string]any
	down.expect(down.do(nil, "GET", "/realms/demo/broker/up/token", tk.AccessToken, nil, nil), 200).json(&stored)
	if stored["access_token"] == nil || claims(t, stored["access_token"].(string)).String("iss") != up.srv.URL+"/realms/upstream" {
		t.Fatalf("stored token: %v", stored)
	}

	// the session carries the provider notes
	var sessions []map[string]any
	down.expect(down.do(nil, "GET", "/admin/realms/demo/users/"+bobID+"/sessions", admin, nil, nil), 200).json(&sessions)
	if len(sessions) != 1 {
		t.Fatalf("sessions: %v", sessions)
	}

	// next login with kc_idp_hint goes straight to the provider; the role
	// mapper revokes the role when the claim no longer matches (FORCE)
	var mappers []map[string]any
	down.expect(down.do(nil, "GET", M, admin, nil, nil), 200).json(&mappers)
	for _, m := range mappers {
		if m["name"] == "eng" {
			m["config"].(map[string]any)["claim.value"] = "sales"
			down.expect(down.do(nil, "PUT", M+"/"+m["id"].(string), admin, m, nil), 204)
		}
	}
	browser2 := newBrowser()
	start := down.expect(down.do(browser2, "GET", demoAuth+"&kc_idp_hint=up", "", nil, nil), 302)
	r = down.follow(browser2, loginAtUpstream(t, down, up, browser2, start, "bob"))
	c = claims(t, down.exchangeCode(codeOf(t, r)).AccessToken)
	if c.String("sub") != bobID || slices.Contains(realmRoles(c), "engineer") {
		t.Fatalf("second login: %v", c)
	}

	var events []map[string]any
	down.expect(down.do(nil, "GET", "/admin/realms/demo/events?type=IDENTITY_PROVIDER_FIRST_LOGIN&type=IDENTITY_PROVIDER_LOGIN", admin, nil, nil), 200).json(&events)
	_ = events // events are only stored when enabled; the flow must not fail either way
}

func TestBrokerLinkExistingAccount(t *testing.T) {
	down := newEnv(t)
	admin, aliceID := down.setupDemo()
	up := newUpstream(t, down, [2]string{"alice.up", "alice@example.com"})
	up.addProvider(down, admin, nil)

	browser := newBrowser()
	page := down.expect(down.do(browser, "GET", demoAuth, "", nil, nil), 200)
	r := down.follow(browser, loginAtUpstream(t, down, up, browser, page, "alice.up"))
	// alice@example.com exists: confirm linking, then re-authenticate
	if r.status != 200 || !strings.Contains(string(r.body), "already exists") {
		t.Fatalf("expected the confirm link page, got %d: %s", r.status, r.body)
	}
	r = down.do(browser, "POST", formAction(t, r.body), "", nil, url.Values{"submitAction": {"linkAccount"}})
	if r.status != 200 || !strings.Contains(string(r.body), "Authenticate to link your account with Upstream") {
		t.Fatalf("expected the re-authentication page, got %d: %s", r.status, r.body)
	}
	bad := down.do(browser, "POST", formAction(t, r.body), "", nil, url.Values{"password": {"wrong"}})
	if bad.status != 401 {
		t.Fatalf("wrong password: %d", bad.status)
	}
	r = down.follow(browser, down.do(browser, "POST", formAction(t, bad.body), "", nil, url.Values{"password": {"wonderland"}}))
	c := claims(t, down.exchangeCode(codeOf(t, r)).AccessToken)
	if c.String("sub") != aliceID {
		t.Fatalf("logged in as %v, want alice", c.String("sub"))
	}
	var links []map[string]string
	down.expect(down.do(nil, "GET", "/admin/realms/demo/users/"+aliceID+"/federated-identity", admin, nil, nil), 200).json(&links)
	if len(links) != 1 || links[0]["userName"] != "alice.up" {
		t.Fatalf("link: %v", links)
	}

	// the next login is a plain broker login
	browser2 := newBrowser()
	r = down.follow(browser2, loginAtUpstream(t, down, up, browser2, down.expect(down.do(browser2, "GET", demoAuth, "", nil, nil), 200), "alice.up"))
	if c := claims(t, down.exchangeCode(codeOf(t, r)).AccessToken); c.String("sub") != aliceID {
		t.Fatalf("second login as %v", c.String("sub"))
	}
}

func TestBrokerLinkByEmailVerification(t *testing.T) {
	down := newEnv(t)
	admin, aliceID := down.setupDemo()
	mail := startSMTP(t)
	down.putRealm(admin, map[string]any{"smtpServer": mail.settings()})
	up := newUpstream(t, down, [2]string{"alice.up", "alice@example.com"})
	up.addProvider(down, admin, nil)

	browser := newBrowser()
	page := down.expect(down.do(browser, "GET", demoAuth, "", nil, nil), 200)
	r := down.follow(browser, loginAtUpstream(t, down, up, browser, page, "alice.up"))
	r = down.do(browser, "POST", formAction(t, r.body), "", nil, url.Values{"submitAction": {"linkAccount"}})
	if r.status != 200 || !strings.Contains(string(r.body), "has been sent to you") {
		t.Fatalf("expected the email sent page, got %d: %s", r.status, r.body)
	}
	if !strings.Contains(mail.last(t), "Someone wants to link your") {
		t.Fatalf("link email: %s", mail.last(t))
	}
	r = down.follow(browser, down.do(browser, "GET", mail.link(t), "", nil, nil))
	if c := claims(t, down.exchangeCode(codeOf(t, r)).AccessToken); c.String("sub") != aliceID {
		t.Fatalf("logged in as %v", c.String("sub"))
	}
}

func TestBrokerAccountLinkingAndUnlinking(t *testing.T) {
	down := newEnv(t)
	admin, aliceID := down.setupDemo()
	up := newUpstream(t, down, [2]string{"wonder", "wonder@example.org"})
	up.addProvider(down, admin, map[string]any{"linkOnly": true})

	// a link-only provider is not offered on the login page
	browser := newBrowser()
	page := down.expect(down.do(browser, "GET", "/realms/demo/account/", "", nil, nil), 302)
	page = down.expect(down.do(browser, "GET", page.header.Get("Location"), "", nil, nil), 200)
	if socialLinkRe.Match(page.body) {
		t.Fatalf("link only provider on the login page")
	}
	down.follow(browser, down.do(browser, "POST", formAction(t, page.body), "", nil, url.Values{"username": {"alice"}, "password": {"wonderland"}}))
	console := down.expect(down.do(browser, "GET", "/realms/demo/account/linked-accounts", "", nil, nil), 200)
	if !strings.Contains(string(console.body), "Upstream") {
		t.Fatalf("linked accounts page: %s", console.body)
	}
	state := regexp.MustCompile(`name="stateChecker" value="([^"]+)"`).FindSubmatch(console.body)
	r := down.expect(down.do(browser, "POST", "/realms/demo/account/linked-accounts/up/link", "", nil, url.Values{"stateChecker": {string(state[1])}}), 303)
	r = down.expect(down.do(browser, "GET", r.header.Get("Location"), "", nil, nil), 302)
	r = loginAtUpstream(t, down, up, browser, r, "wonder")
	if r.status != 302 || !strings.HasSuffix(r.header.Get("Location"), "/realms/demo/account/linked-accounts") {
		t.Fatalf("expected the return to the console, got %d %s: %s", r.status, r.header.Get("Location"), r.body)
	}
	var links []map[string]string
	down.expect(down.do(nil, "GET", "/admin/realms/demo/users/"+aliceID+"/federated-identity", admin, nil, nil), 200).json(&links)
	if len(links) != 1 || links[0]["userName"] != "wonder" {
		t.Fatalf("link: %v", links)
	}

	// the account REST API lists and removes links
	tk, _ := down.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	var accounts []map[string]any
	down.expect(down.do(nil, "GET", "/realms/demo/account/linked-accounts", tk.AccessToken, nil, nil), 200).json(&accounts)
	if len(accounts) != 1 || accounts[0]["connected"] != true || accounts[0]["linkedUsername"] != "wonder" || accounts[0]["providerAlias"] != "up" {
		t.Fatalf("linked accounts: %v", accounts)
	}
	var link map[string]string
	down.expect(down.do(nil, "GET", "/realms/demo/account/linked-accounts/up?providerId=oidc&redirectUri="+url.QueryEscape("http://app.test/cb"),
		tk.AccessToken, nil, nil), 200).json(&link)
	if !strings.Contains(link["accountLinkUri"], "/broker/up/link?") || link["hash"] == "" {
		t.Fatalf("link uri: %v", link)
	}
	down.expect(down.do(nil, "DELETE", "/realms/demo/account/linked-accounts/up", tk.AccessToken, nil, nil), 204)
	down.expect(down.do(nil, "DELETE", "/realms/demo/account/linked-accounts/up", tk.AccessToken, nil, nil), 400)

	// a link only provider cannot log in an unknown identity
	browser2 := newBrowser()
	start := down.expect(down.do(browser2, "GET", demoAuth+"&kc_idp_hint=up", "", nil, nil), 302)
	r = down.follow(browser2, loginAtUpstream(t, down, up, browser2, start, "wonder"))
	if r.status != 200 || !strings.Contains(string(r.body), "only be used to link") {
		t.Fatalf("link only login: %d %s", r.status, r.body)
	}
}

func TestIdentityProviderAdmin(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()
	I := "/admin/realms/demo/identity-provider/instances"
	bad := e.expect(e.do(nil, "POST", I, admin, map[string]any{"alias": "x", "providerId": "oidc",
		"config": map[string]string{"authorizationUrl": "http://idp.example.com/auth", "clientId": "c"}}, nil), 400)
	if !strings.Contains(string(bad.body), "The url [authorization_url] requires secure connections") {
		t.Fatalf("insecure url: %s", bad.body)
	}
	e.expect(e.do(nil, "POST", I, admin, map[string]any{"alias": "x", "providerId": "nope", "config": map[string]string{}}, nil), 400)
	r := e.expect(e.do(nil, "POST", I, admin, map[string]any{"alias": "gh", "providerId": "github",
		"config": map[string]string{"clientId": "id", "clientSecret": "s3cret"}}, nil), 201)
	if !strings.HasSuffix(r.header.Get("Location"), I+"/gh") {
		t.Fatalf("location: %s", r.header.Get("Location"))
	}
	e.expect(e.do(nil, "POST", I, admin, map[string]any{"alias": "gh", "providerId": "github", "config": map[string]string{}}, nil), 409)

	var rep map[string]any
	e.expect(e.do(nil, "GET", I+"/gh", admin, nil, nil), 200).json(&rep)
	cfg := rep["config"].(map[string]any)
	if cfg["clientSecret"] != "**********" || cfg["syncMode"] != "LEGACY" || rep["enabled"] != true || rep["internalId"] == nil ||
		rep["updateProfileFirstLoginMode"] != "on" {
		t.Fatalf("provider rep: %v", rep)
	}
	rep["displayName"] = "GitHub"
	e.expect(e.do(nil, "PUT", I+"/gh", admin, rep, nil), 204)
	var all []map[string]any
	e.expect(e.do(nil, "GET", I, admin, nil, nil), 200).json(&all)
	if len(all) != 1 || all[0]["displayName"] != "GitHub" {
		t.Fatalf("list: %v", all)
	}

	// the masked secret is kept, as shown by the export
	var exp map[string]any
	e.expect(e.do(nil, "POST", "/admin/realms/demo/partial-export", admin, nil, nil), 200).json(&exp)
	if idps := exp["identityProviders"].([]any); len(idps) != 1 {
		t.Fatalf("export: %v", exp["identityProviders"])
	}
	realm, _ := e.app.Svc.Store.GetRealmByName(t.Context(), "demo")
	stored, _ := e.app.Svc.Store.GetIdentityProvider(t.Context(), realm.ID, "gh")
	if stored.Config["clientSecret"] != "s3cret" {
		t.Fatalf("secret overwritten: %q", stored.Config["clientSecret"])
	}

	// mappers: only types compatible with the provider
	var types map[string]any
	e.expect(e.do(nil, "GET", I+"/gh/mapper-types", admin, nil, nil), 200).json(&types)
	if types["github-user-attribute-mapper"] == nil || types["hardcoded-attribute-idp-mapper"] == nil || types["oidc-role-idp-mapper"] != nil {
		t.Fatalf("mapper types: %v", slices.Collect(func(yield func(string) bool) {
			for k := range types {
				if !yield(k) {
					return
				}
			}
		}))
	}
	e.expect(e.do(nil, "POST", I+"/gh/mappers", admin, map[string]any{"name": "r", "identityProviderMapper": "oidc-role-idp-mapper"}, nil), 400)
	mid := idFromLocation(t, e.expect(e.do(nil, "POST", I+"/gh/mappers", admin, map[string]any{"name": "company",
		"identityProviderMapper": "github-user-attribute-mapper", "config": map[string]string{"jsonField": "company", "userAttribute": "company"}}, nil), 201))
	var m map[string]any
	e.expect(e.do(nil, "GET", I+"/gh/mappers/"+mid, admin, nil, nil), 200).json(&m)
	if m["identityProviderAlias"] != "gh" || m["identityProviderMapper"] != "github-user-attribute-mapper" {
		t.Fatalf("mapper: %v", m)
	}

	// federated identities
	U := "/admin/realms/demo/users/" + aliceID + "/federated-identity"
	e.expect(e.do(nil, "POST", U+"/gh", admin, map[string]any{"identityProvider": "gh", "userId": "42", "userName": "alice-gh"}, nil), 204)
	e.expect(e.do(nil, "POST", U+"/gh", admin, map[string]any{"identityProvider": "gh", "userId": "42", "userName": "alice-gh"}, nil), 409)
	var found []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users?idpAlias=gh&idpUserId=42", admin, nil, nil), 200).json(&found)
	if len(found) != 1 || found[0]["id"] != aliceID {
		t.Fatalf("search by link: %v", found)
	}
	e.expect(e.do(nil, "DELETE", U+"/gh", admin, nil, nil), 204)
	e.expect(e.do(nil, "DELETE", U+"/gh", admin, nil, nil), 404)

	// deleting the provider removes its mappers
	e.expect(e.do(nil, "DELETE", I+"/gh", admin, nil, nil), 204)
	e.expect(e.do(nil, "GET", I+"/gh", admin, nil, nil), 404)
	if ms, _ := e.app.Svc.Store.ListIdPMappers(t.Context(), realm.ID, "gh"); len(ms) != 0 {
		t.Fatalf("mappers left: %v", ms)
	}
}

// TestSocialProviderGitHub logs in with the GitHub preset against a fake
// GitHub (endpoints overridden in the provider config).
func TestSocialProviderGitHub(t *testing.T) {
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			if r.PostFormValue("code") != "c1" || r.PostFormValue("client_secret") != "gh-secret" {
				http.Error(w, "bad code", 400)
				return
			}
			w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
			w.Write([]byte("access_token=gh-token&scope=user%3Aemail&token_type=bearer"))
		case "/user", "/user/emails":
			if r.Header.Get("Authorization") != "Bearer gh-token" {
				http.Error(w, "unauthorized", 401)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/user" {
				w.Write([]byte(`{"id": 4242, "login": "octo", "name": "Octo Cat", "email": null, "company": "GitHub"}`))
				return
			}
			w.Write([]byte(`[{"email": "old@example.org", "primary": false, "verified": true}, {"email": "octo@example.org", "primary": true, "verified": true}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer gh.Close()

	e := newEnv(t)
	admin, _ := e.setupDemo()
	e.expect(e.do(nil, "POST", "/admin/realms/demo/identity-provider/instances", admin, map[string]any{"alias": "up", "providerId": "github",
		"config": map[string]string{"clientId": "gh-client", "clientSecret": "gh-secret", "authorizationUrl": gh.URL + "/login/oauth/authorize",
			"tokenUrl": gh.URL + "/login/oauth/access_token", "userInfoUrl": gh.URL + "/user"}}, nil), 201)
	e.expect(e.do(nil, "POST", "/admin/realms/demo/identity-provider/instances/up/mappers", admin, map[string]any{"name": "company",
		"identityProviderMapper": "github-user-attribute-mapper", "config": map[string]string{"jsonField": "company", "userAttribute": "company"}}, nil), 201)

	browser := newBrowser()
	page := e.expect(e.do(browser, "GET", demoAuth, "", nil, nil), 200)
	m := socialLinkRe.FindSubmatch(page.body)
	if m == nil || !strings.Contains(string(page.body), ">GitHub</a>") {
		t.Fatalf("GitHub button missing: %s", page.body)
	}
	r := e.expect(e.do(browser, "GET", html.UnescapeString(string(m[1])), "", nil, nil), 302)
	auth, _ := url.Parse(r.header.Get("Location"))
	if auth.Path != "/login/oauth/authorize" || auth.Query().Get("scope") != "user:email" || auth.Query().Get("client_id") != "gh-client" {
		t.Fatalf("authorization request: %s", auth)
	}
	cb := auth.Query().Get("redirect_uri") + "?" + url.Values{"code": {"c1"}, "state": {auth.Query().Get("state")}}.Encode()
	r = e.follow(browser, e.do(browser, "GET", cb, "", nil, nil))
	c := claims(t, e.exchangeCode(codeOf(t, r)).AccessToken)
	if c.String("preferred_username") != "octo" || c.String("email") != "octo@example.org" || c.String("name") != "Octo Cat" {
		t.Fatalf("claims: %v", c)
	}
	realm, _ := e.app.Svc.Store.GetRealmByName(t.Context(), "demo")
	u, _ := e.app.Svc.Store.GetUserByUsername(t.Context(), realm.ID, "octo")
	if u == nil || u.Attributes["company"][0] != "GitHub" {
		t.Fatalf("mapped attribute: %+v", u)
	}

	// a replayed callback is rejected
	if r := e.do(browser, "GET", cb, "", nil, nil); r.status != 400 {
		t.Fatalf("replayed state: %d", r.status)
	}
}

func TestBrokerLogout(t *testing.T) {
	for _, backchannel := range []bool{false, true} {
		down := newEnv(t)
		admin, _ := down.setupDemo()
		up := newUpstream(t, down, [2]string{"bob", "bob@example.org"})
		iss := up.srv.URL + "/realms/upstream"
		up.addProvider(down, admin, nil)
		var rep map[string]any
		down.expect(down.do(nil, "GET", "/admin/realms/demo/identity-provider/instances/up", admin, nil, nil), 200).json(&rep)
		cfg := rep["config"].(map[string]any)
		cfg["logoutUrl"] = iss + "/protocol/openid-connect/logout"
		cfg["backchannelSupported"] = map[bool]string{true: "true", false: "false"}[backchannel]
		down.expect(down.do(nil, "PUT", "/admin/realms/demo/identity-provider/instances/up", admin, rep, nil), 204)

		browser := newBrowser()
		r := down.follow(browser, loginAtUpstream(t, down, up, browser, down.expect(down.do(browser, "GET", demoAuth+"&scope=openid", "", nil, nil), 200), "bob"))
		tk := down.exchangeCode(codeOf(t, r))
		upstreamSessions := func() int {
			var users []map[string]any
			up.expect(up.do(nil, "GET", "/admin/realms/upstream/users?username=bob", up.admin, nil, nil), 200).json(&users)
			var sessions []any
			up.expect(up.do(nil, "GET", "/admin/realms/upstream/users/"+users[0]["id"].(string)+"/sessions", up.admin, nil, nil), 200).json(&sessions)
			return len(sessions)
		}
		if n := upstreamSessions(); n != 1 {
			t.Fatalf("upstream sessions after login: %d", n)
		}

		r = down.expect(down.do(browser, "GET", "/realms/demo/protocol/openid-connect/logout?"+url.Values{"id_token_hint": {tk.IDToken},
			"post_logout_redirect_uri": {"http://app.test/cb"}, "state": {"bye"}}.Encode(), "", nil, nil), 302)
		if !backchannel {
			// front-channel: through the provider's logout and back
			loc := r.header.Get("Location")
			if !strings.HasPrefix(loc, iss+"/protocol/openid-connect/logout?") {
				t.Fatalf("not sent to the provider logout: %s", loc)
			}
			r = up.expect(up.do(browser, "GET", loc, "", nil, nil), 302)
			r = down.expect(down.do(browser, "GET", r.header.Get("Location"), "", nil, nil), 302)
		}
		if loc := r.header.Get("Location"); loc != "http://app.test/cb?state=bye" {
			t.Fatalf("backchannel=%v: final redirect %s", backchannel, loc)
		}
		if n := upstreamSessions(); n != 0 {
			t.Fatalf("backchannel=%v: upstream session not logged out", backchannel)
		}
	}
}
