package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetrics(t *testing.T) {
	r := New(true)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /realms/{realm}/token", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) })
	h := r.Middleware(mux)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/realms/a/token", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/nowhere", nil))
	r.ObserveEvent("demo", "LOGIN_ERROR", "web", "", "invalid_user_credentials")
	var b strings.Builder
	r.Write(&b)
	out := b.String()
	for _, want := range []string{
		`http_server_requests_seconds_count{method="POST",outcome="CLIENT_ERROR",status="401",uri="/realms/{realm}/token"} 1`,
		`http_server_requests_seconds_bucket{method="POST",outcome="CLIENT_ERROR",status="401",uri="/realms/{realm}/token",le="+Inf"} 1`,
		`uri="NOT_FOUND"`,
		`gocloak_user_events_total{client_id="web",error="invalid_user_credentials",event="login_error",idp="",realm="demo"} 1`,
		"# TYPE http_server_requests_seconds histogram",
		"go_goroutines ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in\n%s", want, out)
		}
	}
}
