package server

import (
	"strings"
	"testing"
)

func TestDynamicClientRegistration(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	const D = "/realms/demo/clients-registrations"

	// anonymous registrations are refused by the default Trusted Hosts policy
	r := e.do(nil, "POST", D+"/openid-connect", "", map[string]any{"redirect_uris": []string{"https://app.example/cb"}}, nil)
	if r.status != 403 || !strings.Contains(string(r.body), "Policy 'Trusted Hosts' rejected request") {
		t.Fatalf("anonymous: %d %s", r.status, r.body)
	}
	var iat struct {
		Token          string `json:"token"`
		RemainingCount int    `json:"remainingCount"`
	}
	e.expect(e.do(nil, "POST", "/admin/realms/demo/clients-initial-access", admin, map[string]any{"expiration": 600, "count": 1}, nil), 200).json(&iat)
	if iat.Token == "" || iat.RemainingCount != 1 {
		t.Fatalf("initial access token: %+v", iat)
	}
	var reg map[string]any
	e.expect(e.do(nil, "POST", D+"/openid-connect", iat.Token, map[string]any{"redirect_uris": []string{"https://app.example/cb"},
		"client_name": "My App", "grant_types": []string{"authorization_code", "client_credentials"}, "scope": "phone",
		"backchannel_logout_uri": "https://app.example/bc"}, nil), 201).json(&reg)
	clientID, _ := reg["client_id"].(string)
	rat, _ := reg["registration_access_token"].(string)
	if clientID == "" || rat == "" || reg["client_secret"] == "" || reg["registration_client_uri"] != e.srv.URL+D+"/openid-connect/"+clientID ||
		reg["scope"] != "phone" || !slicesEqualAny(reg["grant_types"], "authorization_code", "client_credentials") {
		t.Fatalf("registration: %v", reg)
	}
	// the initial access token was single use
	r = e.do(nil, "POST", D+"/openid-connect", iat.Token, map[string]any{"redirect_uris": []string{"https://x.example/cb"}}, nil)
	if r.status != 401 || !strings.Contains(string(r.body), "No remaining count") {
		t.Fatalf("reused initial access token: %d %s", r.status, r.body)
	}
	// the registered client works
	tk := e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, map[string][]string{"grant_type": {"client_credentials"},
		"client_id": {clientID}, "client_secret": {reg["client_secret"].(string)}})
	e.expect(tk, 200)

	// managed with its registration access token, which rotates on update
	e.expect(e.do(nil, "GET", D+"/openid-connect/"+clientID, rat, nil, nil), 200)
	e.expect(e.do(nil, "GET", D+"/openid-connect/"+clientID, "", nil, nil), 401)
	reg["client_name"] = "Renamed"
	var upd map[string]any
	e.expect(e.do(nil, "PUT", D+"/openid-connect/"+clientID, rat, reg, nil), 200).json(&upd)
	if upd["client_name"] != "Renamed" || upd["registration_access_token"] == rat {
		t.Fatalf("update: %v", upd)
	}
	e.expect(e.do(nil, "GET", D+"/openid-connect/"+clientID, rat, nil, nil), 401)
	newRAT := upd["registration_access_token"].(string)
	reg["client_id"] = "other"
	if r := e.do(nil, "PUT", D+"/openid-connect/"+clientID, newRAT, reg, nil); r.status != 400 {
		t.Fatalf("client id change: %d", r.status)
	}

	// the default provider takes a client representation, with a user allowed
	// to create clients
	var kc map[string]any
	e.expect(e.do(nil, "POST", D+"/default", e.adminToken(), map[string]any{"clientId": "kc-app", "redirectUris": []string{"https://kc.example/*"}}, nil), 201).json(&kc)
	if kc["clientId"] != "kc-app" || kc["registrationAccessToken"] == nil {
		t.Fatalf("default registration: %v", kc)
	}
	e.expect(e.do(nil, "GET", D+"/default/kc-app", kc["registrationAccessToken"].(string), nil, nil), 200)
	if r := e.do(nil, "POST", D+"/default", e.adminToken(), map[string]any{"clientId": "kc-app"}, nil); r.status != 400 {
		t.Fatalf("duplicate client id: %d %s", r.status, r.body)
	}

	// anonymous registration once the host is trusted, with the anonymous policies applied
	var comps []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/components?type=org.gocloak.services.clientregistration.policy.ClientRegistrationPolicy", admin, nil, nil), 200).json(&comps)
	for _, c := range comps {
		if c["providerId"] == "trusted-hosts" {
			c["config"] = map[string][]string{"trusted-hosts": {"127.0.0.1", "*.example"}, "host-sending-registration-request-must-match": {"true"},
				"client-uris-must-match": {"true"}}
			e.expect(e.do(nil, "PUT", "/admin/realms/demo/components/"+c["id"].(string), admin, c, nil), 204)
		}
	}
	e.expect(e.do(nil, "POST", D+"/openid-connect", "", map[string]any{"redirect_uris": []string{"https://app.example/cb"}}, nil), 201).json(&reg)
	var rep map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/clients/"+clientUUID(e, admin, reg["client_id"].(string)), admin, nil, nil), 200).json(&rep)
	if rep["consentRequired"] != true || rep["fullScopeAllowed"] != false {
		t.Fatalf("anonymous policies not applied: %v", rep)
	}
	if r := e.do(nil, "POST", D+"/openid-connect", "", map[string]any{"redirect_uris": []string{"https://evil.test/cb"}}, nil); r.status != 403 {
		t.Fatalf("untrusted redirect: %d", r.status)
	}

	// deletion
	e.expect(e.do(nil, "DELETE", D+"/openid-connect/"+clientID, newRAT, nil, nil), 204)
	if r := e.do(nil, "GET", "/admin/realms/demo/clients?clientId="+clientID, admin, nil, nil); !strings.Contains(string(r.body), "[]") {
		t.Fatalf("client not deleted: %s", r.body)
	}
}

func slicesEqualAny(v any, want ...string) bool {
	got := strs(v)
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
