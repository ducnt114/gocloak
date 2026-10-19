// Command gocloak runs the gocloak identity server.
//
//	gocloak start-dev                       development mode (HTTP, hostname from request)
//	gocloak start --hostname https://sso.example.com
//	gocloak import --file realm-export.json
//	gocloak bootstrap-admin --username admin --password secret
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/ducnt114/gocloak/internal/server"
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
  gocloak bootstrap-admin          create or reset a master realm admin and exit
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
	db       *string
	logLevel *string
}

func addCommon(fs *flag.FlagSet, dev bool) commonFlags {
	level := "info"
	if dev {
		level = "debug"
	}
	return commonFlags{
		db:       fs.String("db", envDefault("data/gocloak.db", "GOCLOAK_DB"), "path of the SQLite database `file` (env GOCLOAK_DB)"),
		logLevel: fs.String("log-level", envDefault(level, "KC_LOG_LEVEL"), "log level: debug, info, warn, error (env KC_LOG_LEVEL)"),
	}
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
	fs.Parse(args)

	log := common.logger()
	if *hostname == "" && *strict {
		return errors.New("--hostname is required in production mode (or pass --hostname-strict=false)")
	}
	if *proxy != "" && *proxy != "xforwarded" && *proxy != "forwarded" {
		return fmt.Errorf("unsupported --proxy-headers value %q", *proxy)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv, err := server.New(ctx, server.Config{
		DBPath: *common.db, Hostname: *hostname, ProxyHeaders: *proxy != "", ImportDir: *importDir, Log: log,
		AdminUser:     env("KC_BOOTSTRAP_ADMIN_USERNAME", "KEYCLOAK_ADMIN"),
		AdminPassword: env("KC_BOOTSTRAP_ADMIN_PASSWORD", "KEYCLOAK_ADMIN_PASSWORD"),
	})
	if err != nil {
		return err
	}
	defer srv.Close()
	go srv.RunJanitor(ctx, time.Minute)

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
		log.Info("gocloak started", "version", version, "addr", hs.Addr, "tls", tls, "dev", dev, "db", *common.db)
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
	ctx := context.Background()
	srv, err := server.New(ctx, server.Config{DBPath: *common.db, Log: common.logger(),
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
	ctx := context.Background()
	srv, err := server.New(ctx, server.Config{DBPath: *common.db, Log: common.logger()})
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
