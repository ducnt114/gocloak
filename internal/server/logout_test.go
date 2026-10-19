package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/ducnt114/gocloak/internal/jwt"
)

func TestLightweightAccessTokens(t *testing.T) {
	e := newEnv(t)
	admin := e.adminToken()
	c := claims(t, admin)
	if _, ok := c["sub"]; ok || c.String("sid") == "" || c["realm_access"] != nil || c.String("azp") != "admin-cli" {
		t.Fatalf("admin-cli access token is not lightweight: %v", c)
	}
	// the admin API finds the user through the session
	e.expect(e.do(nil, "GET", "/admin/realms", admin, nil, nil), 200)
	adm, _ := e.setupDemo()
	_ = adm
	// introspection returns the claims left out of the token
	var out map[string]any
	e.expect(e.do(nil, "POST", "/realms/master/protocol/openid-connect/token/introspect", "", nil, url.Values{
		"token": {admin}, "client_id": {"admin-cli"}}), 403)
	e.expect(e.do(nil, "POST", "/admin/realms/master/clients", admin, map[string]any{"clientId": "rs", "secret": "rs-secret"}, nil), 201)
	e.expect(e.do(nil, "POST", "/realms/master/protocol/openid-connect/token/introspect", "", nil, url.Values{
		"token": {admin}, "client_id": {"rs"}, "client_secret": {"rs-secret"}}), 200).json(&out)
	if out["active"] != true || out["sub"] == nil || out["preferred_username"] != "admin" || out["realm_access"] == nil {
		t.Fatalf("introspection: %v", out)
	}

	// any client can use them; userinfo works from the session
	var rep map[string]any
	id := clientUUID(e, adm, "web")
	e.expect(e.do(nil, "GET", "/admin/realms/demo/clients/"+id, adm, nil, nil), 200).json(&rep)
	rep["attributes"] = map[string]string{"client.use.lightweight.access.token.enabled": "true"}
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/clients/"+id, adm, rep, nil), 204)
	tk, r := e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	e.expect(r, 200)
	if c := claims(t, tk.AccessToken); c["sub"] != nil || c["email"] != nil {
		t.Fatalf("lightweight token: %v", c)
	}
	var info map[string]any
	e.expect(e.do(nil, "GET", "/realms/demo/protocol/openid-connect/userinfo", tk.AccessToken, nil, nil), 200).json(&info)
	if info["email"] != "alice@example.com" || info["sub"] == nil {
		t.Fatalf("userinfo: %v", info)
	}
}

func TestOIDCClientLogout(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()
	var mu sync.Mutex
	var logoutTokens []string
	rp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		v, _ := url.ParseQuery(string(b))
		mu.Lock()
		logoutTokens = append(logoutTokens, v.Get("logout_token"))
		mu.Unlock()
	}))
	defer rp.Close()
	e.expect(e.do(nil, "POST", "/admin/realms/demo/clients", admin, map[string]any{"clientId": "bc", "secret": "s",
		"redirectUris": []string{"http://app.test/*"}, "attributes": map[string]string{"backchannel.logout.url": rp.URL + "/bc",
			"backchannel.logout.revoke.offline.tokens": "true"}}, nil), 201)
	e.expect(e.do(nil, "POST", "/admin/realms/demo/clients", admin, map[string]any{"clientId": "fc", "secret": "s", "name": "Front app",
		"redirectUris": []string{"http://app.test/*"}, "frontchannelLogout": true,
		"attributes": map[string]string{"frontchannel.logout.url": "https://fc.test/logout"}}, nil), 201)

	login := func(browser *http.Client, client string) string {
		u := "/realms/demo/protocol/openid-connect/auth?" + url.Values{"client_id": {client}, "response_type": {"code"},
			"scope": {"openid"}, "redirect_uri": {"http://app.test/cb"}}.Encode()
		r := e.do(browser, "GET", u, "", nil, nil)
		if r.status == 200 {
			r = e.do(browser, "POST", formAction(t, r.body), "", nil, url.Values{"username": {"alice"}, "password": {"wonderland"}})
		}
		var tk tokens
		e.expect(e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, url.Values{"grant_type": {"authorization_code"},
			"code": {codeOf(t, r)}, "redirect_uri": {"http://app.test/cb"}, "client_id": {client}, "client_secret": {"s"}}), 200).json(&tk)
		return tk.IDToken
	}
	browser := newBrowser()
	idToken := login(browser, "bc")
	login(browser, "fc")
	r := e.expect(e.do(browser, "GET", "/realms/demo/protocol/openid-connect/logout?"+url.Values{"id_token_hint": {idToken},
		"post_logout_redirect_uri": {"http://app.test/after"}, "state": {"x"}}.Encode(), "", nil, nil), 200)
	body := string(r.body)
	if !strings.Contains(body, `<iframe src="https://fc.test/logout?iss=`) || !strings.Contains(body, "Front app") ||
		!strings.Contains(body, `href="http://app.test/after?state=x"`) {
		t.Fatalf("front-channel logout page: %s", body)
	}
	if csp := r.header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-src 'self' fc.test;") {
		t.Fatalf("CSP: %s", csp)
	}
	mu.Lock()
	if len(logoutTokens) != 1 {
		t.Fatalf("logout tokens: %d", len(logoutTokens))
	}
	tok := logoutTokens[0]
	logoutTokens = nil
	mu.Unlock()
	h, lc, err := jwt.Parse(tok)
	if err != nil || h.Typ != "logout+jwt" {
		t.Fatalf("logout token header: %+v %v", h, err)
	}
	ev, _ := lc["events"].(map[string]any)
	if lc.String("aud") != "bc" || lc.String("sub") != aliceID || lc.String("typ") != "Logout" || lc.String("sid") == "" ||
		ev["http://schemas.openid.net/event/backchannel-logout"] == nil || lc["revoke_offline_access"] != true || lc["nonce"] != nil {
		t.Fatalf("logout token claims: %v", lc)
	}

	// an administrator logout notifies the client too
	login(newBrowser(), "bc")
	e.expect(e.do(nil, "POST", "/admin/realms/demo/users/"+aliceID+"/logout", admin, nil, nil), 204)
	mu.Lock()
	defer mu.Unlock()
	if len(logoutTokens) != 1 {
		t.Fatalf("logout tokens after admin logout: %d", len(logoutTokens))
	}
}
