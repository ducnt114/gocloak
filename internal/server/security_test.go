package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ducnt114/gocloak/internal/jwt"
)

func (e *env) putRealm(admin string, settings map[string]any) {
	e.t.Helper()
	e.expect(e.do(nil, "PUT", "/admin/realms/demo", admin, settings, nil), 204)
}

func TestBruteForceDetection(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()
	e.putRealm(admin, map[string]any{"bruteForceProtected": true, "failureFactor": 2, "waitIncrementSeconds": 60, "quickLoginCheckMilliSeconds": 0})

	for i := 0; i < 2; i++ {
		_, r := e.passwordGrant("demo", "web", "web-secret", "alice", "wrong")
		e.expect(r, 401)
	}
	// locked: even the right password is refused, with the same error
	_, r := e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	if r.status != 401 || !strings.Contains(string(r.body), "Invalid user credentials") {
		t.Fatalf("expected lockout, got %d %s", r.status, r.body)
	}
	var st map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/attack-detection/brute-force/users/"+aliceID, admin, nil, nil), 200).json(&st)
	if st["disabled"] != true || st["numFailures"] != float64(2) || st["numTemporaryLockouts"] != float64(1) {
		t.Fatalf("brute force status = %v", st)
	}
	var u map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/"+aliceID, admin, nil, nil), 200).json(&u)
	if u["enabled"] != false {
		t.Fatalf("locked user reported enabled: %v", u)
	}
	// the login form is locked too
	browser := newBrowser()
	page := e.expect(e.do(browser, "GET", "/realms/demo/protocol/openid-connect/auth?client_id=web&response_type=code&redirect_uri=http%3A%2F%2Fapp.test%2Fcb", "", nil, nil), 200)
	e.expect(e.do(browser, "POST", formAction(t, page.body), "", nil, url.Values{"username": {"alice"}, "password": {"wonderland"}}), 401)

	e.expect(e.do(nil, "DELETE", "/admin/realms/demo/attack-detection/brute-force/users/"+aliceID, admin, nil, nil), 204)
	_, r = e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	e.expect(r, 200)

	// permanent lockout disables the user
	e.putRealm(admin, map[string]any{"permanentLockout": true, "eventsEnabled": true})
	for i := 0; i < 2; i++ {
		e.passwordGrant("demo", "web", "web-secret", "alice", "wrong")
	}
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/"+aliceID, admin, nil, nil), 200).json(&u)
	if u["enabled"] != false {
		t.Fatalf("user not disabled by permanent lockout: %v", u)
	}
	var events []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/events?type=USER_DISABLED_BY_PERMANENT_LOCKOUT", admin, nil, nil), 200).json(&events)
	if len(events) != 1 {
		t.Fatalf("lockout events = %v", events)
	}
}

func TestPasswordPolicy(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()
	e.expect(e.do(nil, "PUT", "/admin/realms/demo", admin, map[string]any{"passwordPolicy": "length(8) and nope(1)"}, nil), 400)
	e.putRealm(admin, map[string]any{"passwordPolicy": "length(8) and digits(1) and passwordHistory(2) and hashAlgorithm(pbkdf2-sha256) and hashIterations(1000)"})

	reset := func(pw string) *response {
		return e.do(nil, "PUT", "/admin/realms/demo/users/"+aliceID+"/reset-password", admin, map[string]any{"type": "password", "value": pw, "temporary": false}, nil)
	}
	var body map[string]string
	e.expect(reset("short"), 400).json(&body)
	if body["error"] != "invalidPasswordMinLengthMessage" || body["error_description"] != "Invalid password: minimum length 8." {
		t.Fatalf("policy error = %v", body)
	}
	e.expect(reset("abcdefgh"), 400).json(&body)
	if body["error"] != "invalidPasswordMinDigitsMessage" {
		t.Fatalf("policy error = %v", body)
	}
	e.expect(reset("abcdefg1"), 204)
	e.expect(reset("abcdefg1"), 400).json(&body)
	if body["error"] != "invalidPasswordHistoryMessage" {
		t.Fatalf("history error = %v", body)
	}
	e.expect(reset("abcdefg2"), 204)
	e.expect(reset("abcdefg1"), 400) // still within the last 2 passwords
	var creds []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/"+aliceID+"/credentials", admin, nil, nil), 200).json(&creds)
	types := []string{}
	for _, c := range creds {
		types = append(types, c["type"].(string))
	}
	if !slices.Contains(types, "password") || !slices.Contains(types, "password-history") {
		t.Fatalf("credential types = %v", types)
	}
	if !strings.Contains(fmt.Sprint(creds), "pbkdf2-sha256") {
		t.Fatalf("password not hashed per policy: %v", creds)
	}
	e.expect(e.do(nil, "POST", "/admin/realms/demo/users", admin, map[string]any{"username": "weak", "enabled": true,
		"credentials": []any{map[string]any{"type": "password", "value": "x"}}}, nil), 400)

	// the update password page reports policy violations
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+aliceID+"/reset-password", admin, map[string]any{"value": "temp1234", "temporary": true}, nil), 204)
	browser := newBrowser()
	page := e.expect(e.do(browser, "GET", "/realms/demo/protocol/openid-connect/auth?client_id=web&response_type=code&redirect_uri=http%3A%2F%2Fapp.test%2Fcb", "", nil, nil), 200)
	page = e.expect(e.do(browser, "POST", formAction(t, page.body), "", nil, url.Values{"username": {"alice"}, "password": {"temp1234"}}), 200)
	page = e.expect(e.do(browser, "POST", formAction(t, page.body), "", nil, url.Values{"password-new": {"short"}, "password-confirm": {"short"}}), 400)
	if !strings.Contains(string(page.body), "Invalid password: minimum length 8.") {
		t.Fatalf("policy message missing: %s", page.body)
	}
}

func TestEvents(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()
	e.putRealm(admin, map[string]any{"eventsEnabled": true, "adminEventsEnabled": true, "adminEventsDetailsEnabled": true})

	e.passwordGrant("demo", "web", "web-secret", "alice", "wrong")
	tok, r := e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	e.expect(r, 200)
	e.expect(e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {"web"}, "client_secret": {"web-secret"}}), 200)

	var events []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/events", admin, nil, nil), 200).json(&events)
	byType := map[string]map[string]any{}
	for _, ev := range events {
		byType[ev["type"].(string)] = ev
	}
	login, failed := byType["LOGIN"], byType["LOGIN_ERROR"]
	if login == nil || failed == nil {
		t.Fatalf("events = %v", events)
	}
	if byType["REFRESH_TOKEN"] != nil {
		t.Fatal("REFRESH_TOKEN is not stored by default")
	}
	d := login["details"].(map[string]any)
	if login["userId"] != aliceID || login["clientId"] != "web" || d["grant_type"] != "password" || d["token_id"] == nil || d["refresh_token_type"] != "Refresh" {
		t.Fatalf("LOGIN event = %v", login)
	}
	if failed["error"] != "invalid_user_credentials" {
		t.Fatalf("LOGIN_ERROR event = %v", failed)
	}
	e.expect(e.do(nil, "GET", "/admin/realms/demo/events?type=LOGIN_ERROR&user="+aliceID, admin, nil, nil), 200).json(&events)
	if len(events) != 1 {
		t.Fatalf("filtered events = %v", events)
	}

	// admin events, with secrets removed from representations
	e.expect(e.do(nil, "POST", "/admin/realms/demo/users", admin, map[string]any{"username": "carol", "enabled": true,
		"credentials": []any{map[string]any{"type": "password", "value": "topsecret1"}}}, nil), 201)
	var aev []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/admin-events?operationTypes=CREATE&resourceTypes=USER", admin, nil, nil), 200).json(&aev)
	if len(aev) != 1 || !strings.HasPrefix(aev[0]["resourcePath"].(string), "users/") {
		t.Fatalf("admin events = %v", aev)
	}
	if rep := aev[0]["representation"].(string); !strings.Contains(rep, "carol") || strings.Contains(rep, "topsecret1") {
		t.Fatalf("representation = %s", rep)
	}

	var cfg map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/events/config", admin, nil, nil), 200).json(&cfg)
	if cfg["eventsEnabled"] != true || len(cfg["enabledEventTypes"].([]any)) < 50 {
		t.Fatalf("events config = %v", cfg)
	}
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/events/config", admin, map[string]any{"eventsListeners": []string{"nope"}}, nil), 400)
	e.expect(e.do(nil, "DELETE", "/admin/realms/demo/events", admin, nil, nil), 204)
	e.expect(e.do(nil, "GET", "/admin/realms/demo/events", admin, nil, nil), 200).json(&events)
	if len(events) != 0 {
		t.Fatalf("events not deleted: %v", events)
	}
}

func refreshGrant(e *env, client, secret, token string) *response {
	return e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {token}, "client_id": {client}, "client_secret": {secret}})
}

func TestOfflineTokens(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()
	f := url.Values{"grant_type": {"password"}, "client_id": {"web"}, "client_secret": {"web-secret"},
		"username": {"alice"}, "password": {"wonderland"}, "scope": {"openid offline_access"}}
	var body map[string]any
	e.expect(e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, f), 200).json(&body)
	off := body["refresh_token"].(string)
	c := claims(t, off)
	if c.String("typ") != "Offline" || c["exp"] != nil || body["refresh_expires_in"] != float64(0) {
		t.Fatalf("offline token claims = %v, response %v", c, body)
	}
	if !strings.Contains(body["scope"].(string), "offline_access") {
		t.Fatalf("scope = %v", body["scope"])
	}
	// logging the user out ends SSO sessions, not offline sessions
	e.expect(e.do(nil, "POST", "/admin/realms/demo/users/"+aliceID+"/logout", admin, nil, nil), 204)
	var refreshed map[string]any
	e.expect(refreshGrant(e, "web", "web-secret", off), 200).json(&refreshed)
	if claims(t, refreshed["refresh_token"].(string)).String("typ") != "Offline" {
		t.Fatal("refreshing an offline token must return an offline token")
	}
	var sessions []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/"+aliceID+"/offline-sessions/"+clientUUID(e, admin, "web"), admin, nil, nil), 200).json(&sessions)
	if len(sessions) != 1 {
		t.Fatalf("offline sessions = %v", sessions)
	}
	var consents []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/"+aliceID+"/consents", admin, nil, nil), 200).json(&consents)
	if len(consents) != 1 || consents[0]["clientId"] != "web" {
		t.Fatalf("consents = %v", consents)
	}
	e.expect(e.do(nil, "DELETE", "/admin/realms/demo/users/"+aliceID+"/consents/web", admin, nil, nil), 204)
	e.expect(refreshGrant(e, "web", "web-secret", off), 400)

	// users without the offline_access role cannot get offline tokens
	var defaults map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/roles/default-roles-demo", admin, nil, nil), 200).json(&defaults)
	var offlineRole map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/roles/offline_access", admin, nil, nil), 200).json(&offlineRole)
	e.expect(e.do(nil, "DELETE", "/admin/realms/demo/roles/default-roles-demo/composites", admin, []any{offlineRole}, nil), 204)
	r := e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, f)
	if r.status != 400 || !strings.Contains(string(r.body), "not_allowed") {
		t.Fatalf("expected not_allowed, got %d %s", r.status, r.body)
	}
}

func TestRefreshTokenRotation(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	e.putRealm(admin, map[string]any{"revokeRefreshToken": true, "refreshTokenMaxReuse": 1})
	tok, r := e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	e.expect(r, 200)
	var r2 map[string]any
	e.expect(refreshGrant(e, "web", "web-secret", tok.RefreshToken), 200).json(&r2)
	e.expect(refreshGrant(e, "web", "web-secret", tok.RefreshToken), 200) // one reuse allowed
	r = refreshGrant(e, "web", "web-secret", tok.RefreshToken)
	if r.status != 400 || !strings.Contains(string(r.body), "Maximum allowed refresh token reuse exceeded") {
		t.Fatalf("expected reuse error, got %d %s", r.status, r.body)
	}
	// exceeding the limit detaches the client: newer tokens die too
	r = refreshGrant(e, "web", "web-secret", r2["refresh_token"].(string))
	if r.status != 400 || !strings.Contains(string(r.body), "Session doesn't have required client") {
		t.Fatalf("expected detached client, got %d %s", r.status, r.body)
	}
}

func TestNotBeforePolicy(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	tok, r := e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	e.expect(r, 200)
	e.expect(e.do(nil, "GET", "/realms/demo/protocol/openid-connect/userinfo", tok.AccessToken, nil, nil), 200)
	e.putRealm(admin, map[string]any{"notBefore": time.Now().Unix() + 1})
	e.expect(e.do(nil, "GET", "/realms/demo/protocol/openid-connect/userinfo", tok.AccessToken, nil, nil), 401)
	e.expect(refreshGrant(e, "web", "web-secret", tok.RefreshToken), 400)
	var res map[string]any
	e.expect(e.do(nil, "POST", "/admin/realms/demo/push-revocation", admin, nil, nil), 200).json(&res)
	if _, ok := res["successRequests"]; !ok {
		t.Fatalf("push-revocation = %v", res)
	}
}

func TestKeyProviders(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	const R = "/admin/realms/demo"
	var keys map[string]any
	e.expect(e.do(nil, "GET", R+"/keys", admin, nil, nil), 200).json(&keys)
	active := keys["active"].(map[string]any)
	if active["RS256"] == nil || active["HS512"] == nil {
		t.Fatalf("active keys = %v", active)
	}
	tok, _ := e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	hdr, _, _ := jwt.Parse(tok.AccessToken)
	if hdr.Alg != "RS256" || hdr.Kid != active["RS256"] {
		t.Fatalf("access token header = %+v", hdr)
	}
	if h, _, _ := jwt.Parse(tok.RefreshToken); h.Alg != "HS512" {
		t.Fatalf("refresh token alg = %s", h.Alg)
	}
	var comps []map[string]any
	e.expect(e.do(nil, "GET", R+"/components?type=org.gocloak.keys.KeyProvider", admin, nil, nil), 200).json(&comps)
	for _, c := range comps {
		cfg := c["config"].(map[string]any)
		if cfg["privateKey"] != nil || cfg["secret"] != nil {
			t.Fatalf("component exposes secrets: %v", c)
		}
	}

	// An ES256 key and a client asking for ES256 access tokens.
	e.expect(e.do(nil, "POST", R+"/components", admin, map[string]any{"name": "ec", "providerId": "ecdsa-generated",
		"providerType": "org.gocloak.keys.KeyProvider", "config": map[string][]string{"priority": {"100"}, "ecdsaEllipticCurveKey": {"P-256"}}}, nil), 201)
	web := clientUUID(e, admin, "web")
	e.expect(e.do(nil, "PUT", R+"/clients/"+web, admin, map[string]any{"attributes": map[string]string{"access.token.signed.response.alg": "ES256"}}, nil), 204)
	tok2, _ := e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	hdr, _, _ = jwt.Parse(tok2.AccessToken)
	if hdr.Alg != "ES256" {
		t.Fatalf("expected ES256 access token, got %s", hdr.Alg)
	}
	var jwks struct{ Keys []jwt.JWK }
	e.expect(e.do(nil, "GET", "/realms/demo/protocol/openid-connect/certs", "", nil, nil), 200).json(&jwks)
	verify := func(token string) error {
		_, err := jwt.Verify(token, func(kid, alg string) *jwt.Key {
			for _, j := range jwks.Keys {
				if j.Kid == kid {
					k, _ := jwt.KeyFromJWK(j, alg)
					return k
				}
			}
			return nil
		})
		return err
	}
	if err := verify(tok2.AccessToken); err != nil {
		t.Fatalf("ES256 token does not verify against the JWKS: %v", err)
	}
	for _, j := range jwks.Keys {
		if j.Kty == "RSA" && len(j.X5c) == 0 {
			t.Fatalf("RSA JWK without certificate: %+v", j)
		}
	}

	// Rotation: a higher priority RSA key takes over, the old one still verifies.
	e.expect(e.do(nil, "PUT", R+"/clients/"+web, admin, map[string]any{"attributes": map[string]string{"access.token.signed.response.alg": ""}}, nil), 204)
	e.expect(e.do(nil, "POST", R+"/components", admin, map[string]any{"name": "rsa-new", "providerId": "rsa-generated",
		"providerType": "org.gocloak.keys.KeyProvider", "config": map[string][]string{"priority": {"200"}}}, nil), 201)
	tok3, _ := e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	if h, _, _ := jwt.Parse(tok3.AccessToken); h.Kid == active["RS256"] {
		t.Fatal("rotation did not change the signing key")
	}
	e.expect(e.do(nil, "GET", "/realms/demo/protocol/openid-connect/userinfo", tok.AccessToken, nil, nil), 200)

	// Disabling the old key removes it from verification and the JWKS.
	for _, c := range comps {
		if c["name"] == "rsa-generated" {
			e.expect(e.do(nil, "PUT", R+"/components/"+c["id"].(string), admin, map[string]any{"config": map[string][]string{"enabled": {"false"}}}, nil), 204)
		}
	}
	e.expect(e.do(nil, "GET", "/realms/demo/protocol/openid-connect/userinfo", tok.AccessToken, nil, nil), 401)
	e.expect(e.do(nil, "GET", "/realms/demo/protocol/openid-connect/userinfo", tok3.AccessToken, nil, nil), 200)

	// A default algorithm without a key gets a fallback provider.
	e.putRealm(admin, map[string]any{"defaultSignatureAlgorithm": "PS256"})
	tok4, _ := e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	if h, _, _ := jwt.Parse(tok4.AccessToken); h.Alg != "PS256" {
		t.Fatalf("expected PS256, got %s", h.Alg)
	}
	e.expect(e.do(nil, "GET", R+"/components?name=fallback-PS256", admin, nil, nil), 200).json(&comps)
	if len(comps) != 1 {
		t.Fatalf("fallback component = %v", comps)
	}
}

func TestJWTClientAuthentication(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	const R = "/admin/realms/demo"
	tokenURL := e.srv.URL + "/realms/demo/protocol/openid-connect/token"
	assertion := func(clientID string, k *jwt.Key, aud string) string {
		tok, err := jwt.Sign(jwt.Claims{"iss": clientID, "sub": clientID, "aud": aud, "jti": fmt.Sprint(time.Now().UnixNano()),
			"exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix()}, k)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	grant := func(clientID, a string) *response {
		return e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, url.Values{
			"grant_type": {"client_credentials"}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion": {a}})
	}

	// client_secret_jwt
	e.expect(e.do(nil, "POST", R+"/clients", admin, map[string]any{"clientId": "hs", "secret": "a-long-shared-secret-for-hmac-signing",
		"clientAuthenticatorType": "client-secret-jwt", "serviceAccountsEnabled": true}, nil), 201)
	hk := &jwt.Key{Alg: "HS256", Secret: []byte("a-long-shared-secret-for-hmac-signing")}
	a := assertion("hs", hk, tokenURL)
	e.expect(grant("hs", a), 200)
	if r := grant("hs", a); r.status != 401 || !strings.Contains(string(r.body), "reuse") {
		t.Fatalf("replayed assertion: %d %s", r.status, r.body)
	}
	e.expect(grant("hs", assertion("hs", hk, "https://elsewhere")), 401)
	e.expect(grant("hs", assertion("hs", &jwt.Key{Alg: "HS256", Secret: []byte("wrong")}, tokenURL)), 401)
	e.expect(e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"hs"}, "client_secret": {"a-long-shared-secret-for-hmac-signing"}}), 401)

	// private_key_jwt with an inline JWKS
	rk, _ := jwt.GenerateRSA(2048, "RS256", "client")
	pub, _ := rk.JWK()
	set, _ := json.Marshal(map[string]any{"keys": []jwt.JWK{pub}})
	e.expect(e.do(nil, "POST", R+"/clients", admin, map[string]any{"clientId": "pk", "clientAuthenticatorType": "client-jwt",
		"serviceAccountsEnabled": true, "attributes": map[string]string{"use.jwks.string": "true", "jwks.string": string(set)}}, nil), 201)
	e.expect(grant("pk", assertion("pk", rk, e.srv.URL+"/realms/demo")), 200)
	other, _ := jwt.GenerateRSA(2048, "RS256", "other")
	other.Kid = rk.Kid
	e.expect(grant("pk", assertion("pk", other, tokenURL)), 401)

	// private_key_jwt with a JWKS URL (ES256)
	ek, _ := jwt.GenerateEC("ES256", "client")
	epub, _ := ek.JWK()
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []jwt.JWK{epub}})
	}))
	defer jwksSrv.Close()
	e.expect(e.do(nil, "POST", R+"/clients", admin, map[string]any{"clientId": "ec", "clientAuthenticatorType": "client-jwt",
		"serviceAccountsEnabled": true, "attributes": map[string]string{"use.jwks.url": "true", "jwks.url": jwksSrv.URL}}, nil), 201)
	e.expect(grant("ec", assertion("ec", ek, tokenURL)), 200)
}

func TestRateLimit(t *testing.T) {
	app, err := New(t.Context(), Config{DB: testDB(t), AdminUser: "admin", AdminPassword: "admin", RateLimit: 1, RateBurst: 3,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()
	codes := []int{}
	for i := 0; i < 5; i++ {
		resp, err := http.Get(srv.URL + "/realms/master/.well-known/openid-configuration")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		codes = append(codes, resp.StatusCode)
	}
	if codes[0] != 200 || codes[4] != 429 {
		t.Fatalf("status codes = %v", codes)
	}
	// health checks are not limited
	resp, _ := http.Get(srv.URL + "/health")
	if resp.StatusCode != 200 {
		t.Fatalf("health = %d", resp.StatusCode)
	}
}
