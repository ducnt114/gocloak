package server

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDeviceAuthorizationGrant(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()
	e.expect(e.do(nil, "POST", "/admin/realms/demo/clients", admin, map[string]any{"clientId": "tv", "publicClient": true,
		"attributes": map[string]string{"oauth2.device.authorization.grant.enabled": "true", "oauth2.device.polling.interval": "1"}}, nil), 201)
	const P = "/realms/demo/protocol/openid-connect"

	// clients need the grant enabled
	r := e.expect(e.do(nil, "POST", P+"/auth/device", "", nil, url.Values{"client_id": {"web"}, "client_secret": {"web-secret"}}), 400)
	if !strings.Contains(string(r.body), "unauthorized_client") {
		t.Fatalf("device grant of web: %s", r.body)
	}
	var d struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	e.expect(e.do(nil, "POST", P+"/auth/device", "", nil, url.Values{"client_id": {"tv"}, "scope": {"openid"}}), 200).json(&d)
	if len(d.UserCode) != 9 || d.UserCode[4] != '-' || d.VerificationURI != e.srv.URL+"/realms/demo/device" || d.ExpiresIn != 600 || d.Interval != 1 {
		t.Fatalf("device authorization: %+v", d)
	}
	poll := func() *response {
		return e.do(nil, "POST", P+"/token", "", nil, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"},
			"client_id": {"tv"}, "device_code": {d.DeviceCode}})
	}
	expectErr := func(r *response, code string) {
		t.Helper()
		if r.status != 400 || !strings.Contains(string(r.body), `"error":"`+code+`"`) {
			t.Fatalf("expected %s, got %d %s", code, r.status, r.body)
		}
	}
	expectErr(poll(), "authorization_pending")
	expectErr(poll(), "slow_down")

	// the user enters the code (in lower case, without the dash) and logs in
	browser := newBrowser()
	r = e.expect(e.do(browser, "GET", "/realms/demo/device", "", nil, nil), 200)
	if !strings.Contains(string(r.body), `name="device_user_code"`) {
		t.Fatalf("device page: %s", r.body)
	}
	bad := e.expect(e.do(browser, "POST", "/realms/demo/device", "", nil, url.Values{"device_user_code": {"BBBB-BBBB"}}), 400)
	if !strings.Contains(string(bad.body), "Invalid code") {
		t.Fatalf("bad code: %s", bad.body)
	}
	code := strings.ToLower(strings.ReplaceAll(d.UserCode, "-", ""))
	r = e.expect(e.do(browser, "POST", "/realms/demo/device", "", nil, url.Values{"device_user_code": {code}}), 200)
	r = e.expect(e.do(browser, "POST", formAction(t, r.body), "", nil, url.Values{"username": {"alice"}, "password": {"wonderland"}}), 200)
	if !strings.Contains(string(r.body), "Grant Access to tv") {
		t.Fatalf("consent page: %s", r.body)
	}
	r = e.expect(e.do(browser, "POST", formAction(t, r.body), "", nil, url.Values{"accept": {"Yes"}}), 200)
	if !strings.Contains(string(r.body), "Device Login Successful") {
		t.Fatalf("approval page: %s", r.body)
	}
	time.Sleep(1100 * time.Millisecond)
	var tk tokens
	e.expect(poll(), 200).json(&tk)
	if c := claims(t, tk.AccessToken); c.String("sub") != aliceID || c.String("azp") != "tv" || tk.IDToken == "" || tk.RefreshToken == "" {
		t.Fatalf("device tokens: %v", c)
	}
	expectErr(poll(), "invalid_grant")

	// a denied device gets access_denied
	e.expect(e.do(nil, "POST", P+"/auth/device", "", nil, url.Values{"client_id": {"tv"}}), 200).json(&d)
	r = e.expect(e.do(browser, "GET", d.VerificationURIComplete, "", nil, nil), 200)
	r = e.expect(e.do(browser, "POST", formAction(t, r.body), "", nil, url.Values{"cancel": {"No"}}), 200)
	if !strings.Contains(string(r.body), "Device Login Failed") {
		t.Fatalf("denial page: %s", r.body)
	}
	expectErr(poll(), "access_denied")
	expectErr(poll(), "invalid_grant")
}
