package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCIBA(t *testing.T) {
	var mu sync.Mutex
	var channel []map[string]any
	var bearers, pings []string
	dev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		b, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/ping" {
			pings = append(pings, r.Header.Get("Authorization")+" "+string(b))
			return
		}
		var m map[string]any
		json.Unmarshal(b, &m)
		channel = append(channel, m)
		bearers = append(bearers, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		w.WriteHeader(http.StatusCreated)
	}))
	defer dev.Close()
	e := newEnvWith(t, func(c *Config) { c.CIBAChannelURI = dev.URL + "/channel" })
	admin, aliceID := e.setupDemo()
	e.expect(e.do(nil, "POST", "/admin/realms/demo/clients", admin, map[string]any{"clientId": "bank", "secret": "s",
		"attributes": map[string]string{"oidc.ciba.grant.enabled": "true"}}, nil), 201)
	e.expect(e.do(nil, "POST", "/admin/realms/demo/clients", admin, map[string]any{"clientId": "pinger", "secret": "s",
		"attributes": map[string]string{"oidc.ciba.grant.enabled": "true", "ciba.backchannel.token.delivery.mode": "ping",
			"ciba.backchannel.client.notification.endpoint": dev.URL + "/ping"}}, nil), 201)
	const P = "/realms/demo/protocol/openid-connect"
	auth := func(client string, extra url.Values) *response {
		f := url.Values{"client_id": {client}, "client_secret": {"s"}, "scope": {"openid"}, "login_hint": {"alice"}, "binding_message": {"B1"}}
		for k, v := range extra {
			f[k] = v
		}
		return e.do(nil, "POST", P+"/ext/ciba/auth", "", nil, f)
	}
	if r := auth("web", url.Values{"client_secret": {"web-secret"}}); r.status != 401 {
		t.Fatalf("client without CIBA: %d %s", r.status, r.body)
	}
	if r := auth("bank", url.Values{"login_hint": {"nobody"}}); r.status != 400 || !strings.Contains(string(r.body), "invalid user") {
		t.Fatalf("unknown user: %d %s", r.status, r.body)
	}
	var a struct {
		AuthReqID string `json:"auth_req_id"`
		ExpiresIn int    `json:"expires_in"`
		Interval  int    `json:"interval"`
	}
	e.expect(auth("bank", nil), 200).json(&a)
	if a.AuthReqID == "" || a.ExpiresIn != 120 || a.Interval != 5 {
		t.Fatalf("auth response: %+v", a)
	}
	mu.Lock()
	if len(channel) != 1 || channel[0]["login_hint"] != "alice" || channel[0]["binding_message"] != "B1" {
		t.Fatalf("channel request: %v", channel)
	}
	bearer := bearers[0]
	mu.Unlock()
	if c := claims(t, bearer); c.String("sub") != aliceID || c.String("azp") != "bank" {
		t.Fatalf("channel token: %v", c)
	}
	poll := func(client, id string) *response {
		return e.do(nil, "POST", P+"/token", "", nil, url.Values{"grant_type": {"urn:openid:params:grant-type:ciba"},
			"client_id": {client}, "client_secret": {"s"}, "auth_req_id": {id}})
	}
	if r := poll("bank", a.AuthReqID); r.status != 400 || !strings.Contains(string(r.body), "authorization_pending") {
		t.Fatalf("pending: %d %s", r.status, r.body)
	}
	if r := poll("bank", a.AuthReqID); !strings.Contains(string(r.body), "slow_down") {
		t.Fatalf("slow down: %s", r.body)
	}
	callback := func(tok, status string) int {
		return e.do(nil, "POST", P+"/ext/ciba/auth/callback", tok, map[string]string{"status": status}, nil).status
	}
	if st := callback("", "SUCCEED"); st != 401 {
		t.Fatalf("callback without token: %d", st)
	}
	if st := callback(bearer, "SUCCEED"); st != 200 {
		t.Fatalf("callback: %d", st)
	}
	if st := callback(bearer, "SUCCEED"); st != 403 {
		t.Fatalf("second callback: %d", st)
	}
	time.Sleep(5100 * time.Millisecond)
	var tk tokens
	e.expect(poll("bank", a.AuthReqID), 200).json(&tk)
	if c := claims(t, tk.IDToken); c.String("sub") != aliceID || c.String("azp") != "bank" {
		t.Fatalf("CIBA tokens: %v", c)
	}
	if r := poll("bank", a.AuthReqID); r.status != 400 {
		t.Fatalf("reused auth_req_id: %d", r.status)
	}

	// ping mode: the client is notified, a denial gives access_denied
	e.expect(auth("pinger", url.Values{"client_notification_token": {"nt-123"}}), 200).json(&a)
	mu.Lock()
	bearer = bearers[len(bearers)-1]
	mu.Unlock()
	if st := callback(bearer, "CANCELLED"); st != 200 {
		t.Fatalf("cancel: %d", st)
	}
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	if len(pings) != 1 || !strings.HasPrefix(pings[0], "Bearer nt-123 ") || !strings.Contains(pings[0], a.AuthReqID) {
		t.Fatalf("ping: %v", pings)
	}
	mu.Unlock()
	if r := poll("pinger", a.AuthReqID); !strings.Contains(string(r.body), "access_denied") {
		t.Fatalf("denied: %s", r.body)
	}
}
