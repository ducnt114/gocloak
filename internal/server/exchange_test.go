package server

import (
	"net/url"
	"strings"
	"testing"
)

func TestTokenExchange(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()
	webID := clientUUID(e, admin, "web")
	e.expect(e.do(nil, "POST", "/admin/realms/demo/clients/"+webID+"/protocol-mappers/models", admin, map[string]any{
		"name": "backend audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
		"config": map[string]string{"included.client.audience": "backend", "access.token.claim": "true"}}, nil), 201)
	for _, c := range []map[string]any{
		{"clientId": "backend", "secret": "b-secret", "attributes": map[string]string{"standard.token.exchange.enabled": "true"}},
		{"clientId": "refresher", "secret": "r-secret", "attributes": map[string]string{"standard.token.exchange.enabled": "true",
			"standard.token.exchange.enableRefreshRequestedTokenType": "SAME_SESSION"}},
		{"clientId": "plain", "secret": "p-secret"},
	} {
		e.expect(e.do(nil, "POST", "/admin/realms/demo/clients", admin, c, nil), 201)
	}
	// let "refresher" receive the token too
	e.expect(e.do(nil, "POST", "/admin/realms/demo/clients/"+webID+"/protocol-mappers/models", admin, map[string]any{
		"name": "refresher audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
		"config": map[string]string{"included.client.audience": "refresher", "access.token.claim": "true"}}, nil), 201)
	tk, r := e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	e.expect(r, 200)

	exchange := func(client, secret string, extra url.Values) *response {
		f := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "client_id": {client}, "client_secret": {secret},
			"subject_token": {tk.AccessToken}, "subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}}
		for k, v := range extra {
			f[k] = v
		}
		return e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, f)
	}
	var out map[string]any
	e.expect(exchange("backend", "b-secret", nil), 200).json(&out)
	c := claims(t, out["access_token"].(string))
	if c.String("azp") != "backend" || c.String("sub") != aliceID || out["issued_token_type"] != "urn:ietf:params:oauth:token-type:access_token" ||
		out["refresh_token"] != nil {
		t.Fatalf("exchanged token: %v %v", out, c)
	}
	// narrowed to an audience the token may have
	e.expect(exchange("backend", "b-secret", url.Values{"audience": {"account"}}), 200).json(&out)
	if a := claims(t, out["access_token"].(string)).Audience(); len(a) != 1 || a[0] != "account" {
		t.Fatalf("audience: %v", a)
	}
	for name, tc := range map[string]struct {
		r      *response
		status int
		want   string
	}{
		"unavailable audience": {exchange("backend", "b-secret", url.Values{"audience": {"svc"}}), 400, "Requested audience not available: svc"},
		"not in the audience":  {exchange("plain", "p-secret", nil), 400, "Standard token exchange is not enabled"},
		"refresh not enabled":  {exchange("backend", "b-secret", url.Values{"requested_token_type": {"urn:ietf:params:oauth:token-type:refresh_token"}}), 400, "requested_token_type unsupported"},
		"bad subject":          {exchange("backend", "b-secret", url.Values{"subject_token": {"x.y.z"}}), 400, "invalid_token"},
		"bad scope":            {exchange("backend", "b-secret", url.Values{"scope": {"nope"}}), 400, "invalid_scope"},
	} {
		if tc.r.status != tc.status || !strings.Contains(string(tc.r.body), tc.want) {
			t.Errorf("%s: %d %s", name, tc.r.status, tc.r.body)
		}
	}
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/clients/"+clientUUID(e, admin, "plain"), admin, map[string]any{
		"attributes": map[string]string{"standard.token.exchange.enabled": "true"}}, nil), 204)
	if r := exchange("plain", "p-secret", nil); r.status != 403 || !strings.Contains(string(r.body), "Client is not within the token audience") {
		t.Fatalf("audience check: %d %s", r.status, r.body)
	}
	// a refresh token for the same session
	e.expect(exchange("refresher", "r-secret", url.Values{"requested_token_type": {"urn:ietf:params:oauth:token-type:refresh_token"}}), 200).json(&out)
	rt, _ := out["refresh_token"].(string)
	if rt == "" || out["issued_token_type"] != "urn:ietf:params:oauth:token-type:refresh_token" {
		t.Fatalf("refresh exchange: %v", out)
	}
	e.expect(e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, url.Values{"grant_type": {"refresh_token"},
		"refresh_token": {rt}, "client_id": {"refresher"}, "client_secret": {"r-secret"}}), 200)
}
