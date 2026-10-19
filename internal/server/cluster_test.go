package server

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ducnt114/gocloak/internal/jwt"
)

// TestCluster runs three nodes on one PostgreSQL database behind a round
// robin load balancer without sticky sessions.
func TestCluster(t *testing.T) {
	if os.Getenv("GOCLOAK_TEST_POSTGRES_URL") == "" {
		t.Skip("needs GOCLOAK_TEST_POSTGRES_URL")
	}
	db := testDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var backends []*url.URL
	var nodes []*Server
	for i := 0; i < 3; i++ {
		app, err := New(ctx, Config{DB: db, AdminUser: "admin", AdminPassword: "admin", Log: slog.New(slog.NewTextHandler(testLogOut(), nil))})
		if err != nil {
			t.Fatal(err)
		}
		go app.Svc.RunInvalidation(ctx)
		srv := httptest.NewServer(app.Handler())
		t.Cleanup(func() { srv.Close(); app.Close() })
		u, _ := url.Parse(srv.URL)
		backends = append(backends, u)
		nodes = append(nodes, app)
	}
	var next atomic.Int64
	var hits [3]atomic.Int64
	lb := httptest.NewUnstartedServer(nil)
	lb.Config.Handler = &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		i := int(next.Add(1) % 3)
		hits[i].Add(1)
		pr.SetURL(backends[i])
		pr.Out.Host = pr.In.Host // the public host, as behind a real load balancer
	}}
	lb.Start()
	defer lb.Close()
	e := &env{t: t, srv: lb, app: nodes[0]}
	admin, aliceID := e.setupDemo()

	// a browser login and refreshes, each request on another node
	browser := newBrowser()
	code := e.browserLogin(browser, "openid", "alice", "wonderland")
	tk := e.exchangeCode(code)
	for i := 0; i < 6; i++ {
		var next tokens
		e.expect(e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, url.Values{"grant_type": {"refresh_token"},
			"refresh_token": {tk.RefreshToken}, "client_id": {"web"}, "client_secret": {"web-secret"}}), 200).json(&next)
		tk = &next
		e.expect(e.do(nil, "GET", "/realms/demo/protocol/openid-connect/userinfo", tk.AccessToken, nil, nil), 200)
	}
	if claims(t, tk.AccessToken).String("sub") != aliceID {
		t.Fatal("wrong subject")
	}
	for i := range hits {
		if hits[i].Load() == 0 {
			t.Fatalf("node %d got no request", i)
		}
	}

	// a key added on one node is used by all of them at once
	var keys struct {
		Active map[string]string `json:"active"`
	}
	e.expect(e.do(nil, "GET", "/admin/realms/demo/keys", admin, nil, nil), 200).json(&keys)
	oldKid := keys.Active["RS256"]
	e.expect(e.do(nil, "POST", "/admin/realms/demo/components", admin, map[string]any{"name": "rotated", "providerId": "rsa-generated",
		"providerType": "org.keycloak.keys.KeyProvider", "config": map[string][]string{"priority": {"500"}}}, nil), 201)
	deadline := time.Now().Add(5 * time.Second)
	for i := 0; ; i++ {
		fresh := map[string]bool{}
		for n := 0; n < 3; n++ {
			got, r := e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
			e.expect(r, 200)
			h, _, _ := jwt.Parse(got.AccessToken)
			fresh[h.Kid] = true
		}
		if len(fresh) == 1 && !fresh[oldKid] {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("nodes still sign with the old key: %v", fresh)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// jobs run on one node at a time
	unlock, ok, err := nodes[0].Svc.Store.TryLock(ctx, "test-job")
	if err != nil || !ok {
		t.Fatalf("lock: %v %v", ok, err)
	}
	if _, ok, _ := nodes[1].Svc.Store.TryLock(ctx, "test-job"); ok {
		t.Fatal("two nodes hold the lock")
	}
	unlock()
	if u2, ok, _ := nodes[2].Svc.Store.TryLock(ctx, "test-job"); !ok {
		t.Fatal("lock not released")
	} else {
		u2()
	}
}
