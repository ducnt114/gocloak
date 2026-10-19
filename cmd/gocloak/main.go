// Command gocloak runs the gocloak identity server.
//
//	gocloak start-dev                       development mode (HTTP, hostname from request)
//	gocloak start --hostname https://sso.example.com
//	gocloak import --file realm-export.json
//	gocloak export --realm demo --file demo-realm.json
//	gocloak bootstrap-admin --username admin --password secret
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ducnt114/gocloak/internal/adminconsole"
	"github.com/ducnt114/gocloak/internal/server"
	"github.com/ducnt114/gocloak/internal/store"
)

var version = "dev"

func env(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

func envDefault(def string, names ...string) string {
	if v := env(names...); v != "" {
		return v
	}
	return def
}

func usage() {
	fmt.Fprint(os.Stderr, `gocloak - Keycloak compatible identity server written in Go

Usage:
  gocloak start-dev [flags]        start in development mode
  gocloak start [flags]            start in production mode (requires --hostname)
  gocloak import --file <path>     import realm export(s) and exit
  gocloak export --realm <name> --file <path>
                                   export a realm (or --dir for all realms) and exit
  gocloak bootstrap-admin          create or reset a master realm admin and exit
  gocloak download-admin-console --dir <dir>
                                   download Keycloak's admin console (from Maven Central)
  gocloak version

Run 'gocloak <command> -h' for the flags of a command.
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "start", "start-dev":
		err = start(args, cmd == "start-dev")
	case "import":
		err = importCmd(args)
	case "bootstrap-admin":
		err = bootstrapAdmin(args)
	case "export":
		err = exportCmd(args)
	case "download-admin-console":
		err = downloadConsole(args)
	case "version", "--version", "-v":
		fmt.Println("gocloak", version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type commonFlags struct {
	db, dbURL, dbUser, dbPassword *string
	logLevel                      *string
}

func addCommon(fs *flag.FlagSet, dev bool) commonFlags {
	level := "info"
	if dev {
		level = "debug"
	}
	return commonFlags{
		db:         fs.String("db", envDefault(store.SQLite, "KC_DB"), "database vendor: sqlite or postgres (env KC_DB)"),
		dbURL:      fs.String("db-url", env("KC_DB_URL"), "SQLite file path (default data/gocloak.db), or PostgreSQL URL: postgres://host/db or jdbc:postgresql://host/db (env KC_DB_URL)"),
		dbUser:     fs.String("db-username", env("KC_DB_USERNAME"), "PostgreSQL user (env KC_DB_USERNAME)"),
		dbPassword: fs.String("db-password", env("KC_DB_PASSWORD"), "PostgreSQL password (env KC_DB_PASSWORD)"),
		logLevel:   fs.String("log-level", envDefault(level, "KC_LOG_LEVEL"), "log level: debug, info, warn, error (env KC_LOG_LEVEL)"),
	}
}

// dbConfig builds the store configuration, accepting Keycloak's JDBC URLs.
func (c commonFlags) dbConfig() (store.Config, error) {
	switch *c.db {
	case store.SQLite, "":
		u := *c.dbURL
		if u == "" {
			u = envDefault("data/gocloak.db", "GOCLOAK_DB")
		}
		return store.Config{Driver: store.SQLite, URL: u}, nil
	case store.Postgres:
		raw := *c.dbURL
		if raw == "" {
			raw = "postgres://localhost:5432/keycloak"
		}
		raw = strings.TrimPrefix(raw, "jdbc:")
		if strings.HasPrefix(raw, "postgresql://") {
			raw = "postgres://" + strings.TrimPrefix(raw, "postgresql://")
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "postgres" {
			return store.Config{}, fmt.Errorf("invalid --db-url %q", *c.dbURL)
		}
		if *c.dbUser != "" {
			if *c.dbPassword != "" {
				u.User = url.UserPassword(*c.dbUser, *c.dbPassword)
			} else {
				u.User = url.User(*c.dbUser)
			}
		}
		return store.Config{Driver: store.Postgres, URL: u.String()}, nil
	}
	return store.Config{}, fmt.Errorf("unsupported --db %q (use sqlite or postgres)", *c.db)
}

func (c commonFlags) logger() *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*c.logLevel)); err != nil {
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

func start(args []string, dev bool) error {
	name := "start"
	if dev {
		name = "start-dev"
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	common := addCommon(fs, dev)
	host := fs.String("http-host", envDefault("0.0.0.0", "KC_HTTP_HOST"), "HTTP listen address (env KC_HTTP_HOST)")
	port := fs.Int("http-port", atoi(envDefault("8080", "KC_HTTP_PORT")), "HTTP port (env KC_HTTP_PORT)")
	httpsPort := fs.Int("https-port", atoi(envDefault("8443", "KC_HTTPS_PORT")), "HTTPS port (env KC_HTTPS_PORT)")
	certFile := fs.String("https-certificate-file", env("KC_HTTPS_CERTIFICATE_FILE"), "TLS certificate (PEM); enables HTTPS (env KC_HTTPS_CERTIFICATE_FILE)")
	keyFile := fs.String("https-certificate-key-file", env("KC_HTTPS_CERTIFICATE_KEY_FILE"), "TLS private key (PEM) (env KC_HTTPS_CERTIFICATE_KEY_FILE)")
	hostname := fs.String("hostname", env("KC_HOSTNAME"), "public base URL, e.g. https://sso.example.com (env KC_HOSTNAME)")
	strict := fs.Bool("hostname-strict", envDefault(strconv.FormatBool(!dev), "KC_HOSTNAME_STRICT") == "true", "require --hostname (env KC_HOSTNAME_STRICT)")
	proxy := fs.String("proxy-headers", env("KC_PROXY_HEADERS"), "trust X-Forwarded-* headers when set to 'xforwarded' (env KC_PROXY_HEADERS)")
	importDir := fs.String("import-dir", env("GOCLOAK_IMPORT_DIR"), "import realm exports (*.json) from this directory at startup (env GOCLOAK_IMPORT_DIR)")
	themesDir := fs.String("themes-dir", envDefault("", "GOCLOAK_THEMES_DIR"), "directory of custom themes (env GOCLOAK_THEMES_DIR)")
	consoleDir := fs.String("admin-console-dir", env("GOCLOAK_ADMIN_CONSOLE_DIR"), "directory of the admin console jars, see 'gocloak download-admin-console' (env GOCLOAK_ADMIN_CONSOLE_DIR)")
	themeCache := fs.Bool("theme-cache", !dev, "cache themes (disable while developing a theme)")
	rateLimit := fs.Float64("rate-limit", atof(envDefault("100", "GOCLOAK_RATE_LIMIT")), "requests per second allowed per client IP on /realms and /admin, 0 to disable (env GOCLOAK_RATE_LIMIT)")
	cibaURI := fs.String("ciba-auth-channel-uri", envDefault(env("KC_SPI_CIBA_AUTH_CHANNEL_CIBA_HTTP_AUTH_CHANNEL_HTTP_AUTHENTICATION_CHANNEL_URI"), "GOCLOAK_CIBA_AUTH_CHANNEL_URI"),
		"URL the CIBA authentication requests are posted to (env GOCLOAK_CIBA_AUTH_CHANNEL_URI or Keycloak's KC_SPI_CIBA_AUTH_CHANNEL_CIBA_HTTP_AUTH_CHANNEL_HTTP_AUTHENTICATION_CHANNEL_URI)")
	rateBurst := fs.Int("rate-burst", atoi(envDefault("200", "GOCLOAK_RATE_BURST")), "burst size of the per IP rate limit (env GOCLOAK_RATE_BURST)")
	fs.Parse(args)

	log := common.logger()
	if *hostname == "" && *strict {
		return errors.New("--hostname is required in production mode (or pass --hostname-strict=false)")
	}
	if *proxy != "" && *proxy != "xforwarded" && *proxy != "forwarded" {
		return fmt.Errorf("unsupported --proxy-headers value %q", *proxy)
	}

	dbCfg, err := common.dbConfig()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv, err := server.New(ctx, server.Config{
		DB: dbCfg, Hostname: *hostname, ProxyHeaders: *proxy != "", ImportDir: *importDir, Log: log, CIBAChannelURI: *cibaURI,
		RateLimit: *rateLimit, RateBurst: *rateBurst, ThemesDir: *themesDir, NoThemeCache: !*themeCache,
		AdminConsoleDir: *consoleDir, Version: version,
		AdminUser:     env("KC_BOOTSTRAP_ADMIN_USERNAME", "KEYCLOAK_ADMIN"),
		AdminPassword: env("KC_BOOTSTRAP_ADMIN_PASSWORD", "KEYCLOAK_ADMIN_PASSWORD"),
	})
	if err != nil {
		return err
	}
	defer srv.Close()
	go srv.RunJanitor(ctx, time.Minute)
	go srv.RunFederationSync(ctx)
	go srv.Svc.RunInvalidation(ctx)

	tls := *certFile != "" && *keyFile != ""
	p := *port
	if tls {
		p = *httpsPort
	}
	hs := &http.Server{
		Addr:              net.JoinHostPort(*host, strconv.Itoa(p)),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("gocloak started", "version", version, "addr", hs.Addr, "tls", tls, "dev", dev, "db", dbCfg.Driver)
		if tls {
			errc <- hs.ListenAndServeTLS(*certFile, *keyFile)
		} else {
			errc <- hs.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return hs.Shutdown(shutdownCtx)
}

func importCmd(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	common := addCommon(fs, false)
	file := fs.String("file", "", "realm export `file` (JSON)")
	dir := fs.String("dir", "", "directory of realm exports (*.json)")
	fs.Parse(args)
	if *file == "" && *dir == "" {
		return errors.New("--file or --dir is required")
	}
	dbCfg, err := common.dbConfig()
	if err != nil {
		return err
	}
	ctx := context.Background()
	srv, err := server.New(ctx, server.Config{DB: dbCfg, Log: common.logger(),
		AdminUser: env("KC_BOOTSTRAP_ADMIN_USERNAME", "KEYCLOAK_ADMIN"), AdminPassword: env("KC_BOOTSTRAP_ADMIN_PASSWORD", "KEYCLOAK_ADMIN_PASSWORD")})
	if err != nil {
		return err
	}
	defer srv.Close()
	if *file != "" {
		return srv.ImportFile(ctx, *file)
	}
	return srv.ImportDir(ctx, *dir)
}

func bootstrapAdmin(args []string) error {
	fs := flag.NewFlagSet("bootstrap-admin", flag.ExitOnError)
	common := addCommon(fs, false)
	username := fs.String("username", envDefault("admin", "KC_BOOTSTRAP_ADMIN_USERNAME"), "admin username")
	password := fs.String("password", env("KC_BOOTSTRAP_ADMIN_PASSWORD"), "admin password (env KC_BOOTSTRAP_ADMIN_PASSWORD)")
	fs.Parse(args)
	if *password == "" {
		return errors.New("--password (or KC_BOOTSTRAP_ADMIN_PASSWORD) is required")
	}
	dbCfg, err := common.dbConfig()
	if err != nil {
		return err
	}
	ctx := context.Background()
	srv, err := server.New(ctx, server.Config{DB: dbCfg, Log: common.logger()})
	if err != nil {
		return err
	}
	defer srv.Close()
	if err := srv.BootstrapAdmin(ctx, *username, *password); err != nil {
		return err
	}
	fmt.Printf("admin user %q is ready in the master realm\n", *username)
	return nil
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

func exportCmd(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	common := addCommon(fs, false)
	realm := fs.String("realm", "", "realm to export (all realms when empty, requires --dir)")
	file := fs.String("file", "", "output `file` for a single realm")
	dir := fs.String("dir", "", "output directory: one <realm>-realm.json per realm")
	users := fs.String("users", "realm_file", "realm_file to include users, skip to leave them out")
	fs.Parse(args)
	if (*file == "") == (*dir == "") {
		return errors.New("exactly one of --file or --dir is required")
	}
	if *file != "" && *realm == "" {
		return errors.New("--file requires --realm")
	}
	if *users != "realm_file" && *users != "skip" {
		return fmt.Errorf("unsupported --users %q (use realm_file or skip)", *users)
	}
	dbCfg, err := common.dbConfig()
	if err != nil {
		return err
	}
	ctx := context.Background()
	srv, err := server.New(ctx, server.Config{DB: dbCfg, Log: common.logger()})
	if err != nil {
		return err
	}
	defer srv.Close()
	names := []string{*realm}
	if *realm == "" {
		if names, err = srv.RealmNames(ctx); err != nil {
			return err
		}
	}
	for _, name := range names {
		rep, err := srv.ExportRealm(ctx, name)
		if err != nil {
			return err
		}
		if *users == "skip" {
			rep.Users = nil
		}
		b, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return err
		}
		out := *file
		if out == "" {
			if err := os.MkdirAll(*dir, 0o700); err != nil {
				return err
			}
			out = filepath.Join(*dir, name+"-realm.json")
		}
		if err := os.WriteFile(out, append(b, '\n'), 0o600); err != nil {
			return err
		}
		fmt.Printf("exported realm %q to %s\n", name, out)
	}
	return nil
}

func atof(s string) float64 {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return f
}

func downloadConsole(args []string) error {
	fs := flag.NewFlagSet("download-admin-console", flag.ExitOnError)
	dir := fs.String("dir", envDefault("admin-console", "GOCLOAK_ADMIN_CONSOLE_DIR"), "directory to download the jars to")
	ver := fs.String("version", adminconsole.Version, "Keycloak version of the admin console")
	fs.Parse(args)
	err := adminconsole.Download(context.Background(), *dir, *ver, func(f string, a ...any) { fmt.Printf(f+"\n", a...) })
	if err == nil {
		fmt.Printf("done: start gocloak with --admin-console-dir %s\n", *dir)
	}
	return err
}
