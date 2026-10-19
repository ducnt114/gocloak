package server

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManagementInterface(t *testing.T) {
	e := newEnvWith(t, func(c *Config) { c.MetricsEnabled = true })
	e.setupDemo()
	e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	e.passwordGrant("demo", "web", "web-secret", "alice", "wrong")
	mgmt := httptest.NewServer(e.app.ManagementHandler())
	defer mgmt.Close()
	for _, p := range []string{"/health", "/health/live", "/health/ready", "/health/started"} {
		r := e.expect(e.do(nil, "GET", mgmt.URL+p, "", nil, nil), 200)
		if !strings.Contains(string(r.body), `"status":"UP"`) {
			t.Fatalf("%s: %s", p, r.body)
		}
	}
	resp, err := mgmt.Client().Get(mgmt.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	out := string(b)
	for _, want := range []string{
		`http_server_requests_seconds_count{method="POST",outcome="SUCCESS",status="200",uri="/realms/{realm}/protocol/openid-connect/token"} `,
		`keycloak_user_events_total{client_id="web",error="",event="login",idp="",realm="demo"} 1`,
		`keycloak_user_events_total{client_id="web",error="invalid_user_credentials",event="login_error",idp="",realm="demo"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s", want)
		}
	}
	// without metrics, the management interface only has the health checks
	plain := httptest.NewServer(newEnv(t).app.ManagementHandler())
	defer plain.Close()
	if r := e.do(nil, "GET", plain.URL+"/metrics", "", nil, nil); r.status != 404 {
		t.Fatalf("metrics without --metrics-enabled: %d", r.status)
	}
}
