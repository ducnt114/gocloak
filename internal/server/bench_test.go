package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Benchmarks of the main request paths, over HTTP on a test server:
//
//	go test -run XXX -bench . -benchtime 5s ./internal/server

func BenchmarkClientCredentials(b *testing.B) {
	e := newBenchEnv(b)
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {"svc-secret"}}.Encode()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !benchPost(b, e.srv.URL+"/realms/demo/protocol/openid-connect/token", form) {
				return
			}
		}
	})
}

func BenchmarkRefreshToken(b *testing.B) {
	e := newBenchEnv(b)
	tk, _ := e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"web"}, "client_secret": {"web-secret"},
		"refresh_token": {tk.RefreshToken}}.Encode()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !benchPost(b, e.srv.URL+"/realms/demo/protocol/openid-connect/token", form) {
				return
			}
		}
	})
}

func BenchmarkUserinfo(b *testing.B) {
	e := newBenchEnv(b)
	tk, _ := e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, _ := http.NewRequest("GET", e.srv.URL+"/realms/demo/protocol/openid-connect/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+tk.AccessToken)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				b.Error(err)
				return
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				b.Errorf("userinfo: %s", resp.Status)
				return
			}
		}
	})
}

// BenchmarkBrowserLogin is a whole authorization code flow: login page,
// password check (argon2), code exchange.
func BenchmarkBrowserLogin(b *testing.B) {
	e := newBenchEnv(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		code := e.browserLogin(newBrowser(), "openid", "alice", "wonderland")
		e.exchangeCode(code)
	}
}

func newBenchEnv(b *testing.B) *env {
	e := newEnvWith(b, func(c *Config) { c.RateLimit = 0 })
	e.setupDemo()
	return e
}

// benchPost posts a form from a RunParallel goroutine (which must not call
// b.Fatal) and tells whether it succeeded.
func benchPost(b *testing.B, u, form string) bool {
	resp, err := http.Post(u, "application/x-www-form-urlencoded", strings.NewReader(form))
	if err != nil {
		b.Error(err)
		return false
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		b.Errorf("post %s: %s", u, resp.Status)
		return false
	}
	return true
}
