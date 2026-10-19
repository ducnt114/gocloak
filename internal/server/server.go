// Package server wires storage, services and HTTP handlers together.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/admin"
	"github.com/ducnt114/gocloak/internal/oidc"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// Config configures a Server.
type Config struct {
	DBPath        string
	Hostname      string
	ProxyHeaders  bool
	AdminUser     string
	AdminPassword string
	ImportDir     string
	Log           *slog.Logger
}

// Server is a running gocloak instance.
type Server struct {
	Svc     *service.Service
	Log     *slog.Logger
	handler http.Handler
}

// New opens the database, bootstraps the master realm and imports realms.
func New(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if dir := filepath.Dir(cfg.DBPath); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	svc := service.New(st)
	s := &Server{Svc: svc, Log: cfg.Log}

	createdMaster, err := svc.Bootstrap(ctx, cfg.AdminUser, cfg.AdminPassword)
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	if createdMaster {
		if cfg.AdminUser != "" {
			cfg.Log.Info("created master realm and temporary admin user", "username", cfg.AdminUser)
		} else {
			cfg.Log.Warn("created master realm without an admin user; run 'gocloak bootstrap-admin' or set KC_BOOTSTRAP_ADMIN_USERNAME/KC_BOOTSTRAP_ADMIN_PASSWORD")
		}
	}
	if cfg.ImportDir != "" {
		if err := s.ImportDir(ctx, cfg.ImportDir); err != nil {
			st.Close()
			return nil, err
		}
	}

	urls := oidc.URLs{Hostname: cfg.Hostname, ProxyHeaders: cfg.ProxyHeaders}
	mux := http.NewServeMux()
	(&oidc.Handler{Svc: svc, URLs: urls, Log: cfg.Log}).Register(mux)
	(&admin.Handler{Svc: svc, URLs: urls, Log: cfg.Log}).Register(mux)
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /health/live", s.health)
	mux.HandleFunc("GET /health/ready", s.health)
	mux.HandleFunc("GET /{$}", s.welcome)
	s.handler = s.logRequests(mux)
	return s, nil
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler { return s.handler }

// Close releases the database.
func (s *Server) Close() error { return s.Svc.Store.Close() }

// ImportFile imports one realm export. Existing realms are skipped.
func (s *Server) ImportFile(ctx context.Context, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// A file may hold a single realm or a list of realms.
	var reps []admin.RealmRep
	if trimmed := strings.TrimSpace(string(b)); strings.HasPrefix(trimmed, "[") {
		err = json.Unmarshal(b, &reps)
	} else {
		var rep admin.RealmRep
		err = json.Unmarshal(b, &rep)
		reps = []admin.RealmRep{rep}
	}
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	for i := range reps {
		rep := &reps[i]
		if rep.Realm == nil {
			return fmt.Errorf("%s: missing realm name", path)
		}
		if _, err := s.Svc.Store.GetRealmByName(ctx, *rep.Realm); err == nil {
			s.Log.Info("realm already exists, skipping import", "realm", *rep.Realm, "file", path)
			continue
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if _, err := admin.Import(ctx, s.Svc, rep); err != nil {
			return fmt.Errorf("import %s from %s: %w", *rep.Realm, path, err)
		}
		s.Log.Info("realm imported", "realm", *rep.Realm, "file", path)
	}
	return nil
}

// ImportDir imports every *.json file of dir, in name order.
func (s *Server) ImportDir(ctx context.Context, dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, f := range files {
		if err := s.ImportFile(ctx, f); err != nil {
			return err
		}
	}
	return nil
}

// BootstrapAdmin creates (or resets) an admin user in the master realm.
func (s *Server) BootstrapAdmin(ctx context.Context, username, password string) error {
	return s.Svc.EnsureAdmin(ctx, username, password)
}

// RunJanitor periodically removes expired sessions, codes and revocations.
func (s *Server) RunJanitor(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Svc.Store.PurgeExpired(ctx, s.Svc.Now()); err != nil && ctx.Err() == nil {
				s.Log.Error("purge expired", "err", err)
			}
		}
	}
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := s.Svc.Store.Ping(r.Context()); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `{"status":"DOWN","checks":[{"name":"database","status":"DOWN"}]}`)
		return
	}
	fmt.Fprint(w, `{"status":"UP","checks":[{"name":"database","status":"UP"}]}`)
}

func (s *Server) welcome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>gocloak</title>
<style>body{font:15px/1.6 system-ui,sans-serif;max-width:640px;margin:48px auto;padding:0 16px;color:#151515;background:#fff}code{background:#f0f0f0;padding:1px 4px;border-radius:3px}@media (prefers-color-scheme:dark){body{color:#e0e0e0;background:#1b1d21}code{background:#2c2f33}}</style></head>
<body><h1>gocloak</h1><p>Identity and access management server, compatible with Keycloak's OpenID Connect and admin REST APIs.</p>
<ul><li>Discovery: <code>/realms/{realm}/.well-known/openid-configuration</code></li><li>Admin API: <code>/admin/realms</code></li><li>Health: <code>/health</code></li></ul></body></html>`)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.Log.Debug("http", "method", r.Method, "path", r.URL.Path, "status", rec.status, "duration", time.Since(start))
	})
}
