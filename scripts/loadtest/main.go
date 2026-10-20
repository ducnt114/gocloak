// loadtest drives load against gocloak (or the upstream server) and reports
// the latency of each request kind, or runs a round-robin load balancer in
// front of several nodes.
//
//	go run ./scripts/loadtest -url http://localhost:8080 -setup -scenarios token,refresh,login -c 16 -d 60s
//	go run ./scripts/loadtest -lb :8080 -backends http://localhost:8081,http://localhost:8082
//
// -setup creates realm "load" with a confidential client "load" and users
// load-0..load-N (password "load-password") through the admin API. The
// scenarios:
//
//	token    client credentials grants
//	refresh  refresh token grants, each worker refreshing its own session
//	login    browser logins: the login page, the form post and the code
//	         exchange, each with a fresh cookie jar
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	baseURL     = flag.String("url", "http://localhost:8080", "base URL of the server (or of the load balancer)")
	realm       = flag.String("realm", "load", "realm under test")
	setup       = flag.Bool("setup", false, "create the realm, client and users first")
	adminUser   = flag.String("admin-user", "admin", "master realm admin, for -setup")
	adminPass   = flag.String("admin-password", "admin", "password of -admin-user")
	users       = flag.Int("users", 50, "number of users (load-0..) to create and log in as")
	scenarios   = flag.String("scenarios", "token,refresh,login", "comma separated scenarios to run in turn")
	concurrency = flag.Int("c", 16, "concurrent workers")
	duration    = flag.Duration("d", 30*time.Second, "duration of each scenario")
	warmup      = flag.Duration("warmup", 5*time.Second, "unmeasured run before each scenario")
	lbAddr      = flag.String("lb", "", "run a round-robin load balancer on this address instead")
	backends    = flag.String("backends", "", "comma separated backend URLs of the load balancer")
)

const (
	clientID     = "load"
	clientSecret = "load-secret"
	userPassword = "load-password"
	redirectURI  = "http://localhost/cb"
)

func main() {
	flag.Parse()
	if *lbAddr != "" {
		runLB()
		return
	}
	if *setup {
		if err := createRealm(); err != nil {
			log.Fatal("setup: ", err)
		}
	}
	fmt.Printf("%d workers, %s per scenario, against %s\n\n", *concurrency, *duration, *baseURL)
	fmt.Println("| request | count | errors | req/s | p50 | p90 | p99 | max |")
	fmt.Println("|---|---:|---:|---:|---:|---:|---:|---:|")
	for _, sc := range strings.Split(*scenarios, ",") {
		fn, ok := map[string]func(*worker) error{"token": (*worker).token, "refresh": (*worker).refresh, "login": (*worker).login}[sc]
		if !ok {
			log.Fatalf("unknown scenario %q", sc)
		}
		run(fn, *warmup, false)
		for _, s := range run(fn, *duration, true) {
			s.print(*duration)
		}
	}
}

// ---------------------------------------------------------------- load balancer

func runLB() {
	var targets []*url.URL
	for _, b := range strings.Split(*backends, ",") {
		u, err := url.Parse(strings.TrimSpace(b))
		if err != nil || u.Host == "" {
			log.Fatalf("bad backend %q", b)
		}
		targets = append(targets, u)
	}
	if len(targets) == 0 {
		log.Fatal("-lb needs -backends")
	}
	var next atomic.Uint64
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(targets[next.Add(1)%uint64(len(targets))])
			pr.SetXForwarded()
			pr.Out.Host = pr.In.Host
		},
		Transport: &http.Transport{MaxIdleConnsPerHost: 256, IdleConnTimeout: 90 * time.Second},
	}
	log.Printf("round robin on %s over %d backends", *lbAddr, len(targets))
	log.Fatal(http.ListenAndServe(*lbAddr, proxy))
}

// ---------------------------------------------------------------- setup

func createRealm() error {
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	r, err := post(http.DefaultClient, *baseURL+"/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {*adminUser}, "password": {*adminPass}})
	if err != nil {
		return err
	}
	if err := r.json(&tok); err != nil {
		return err
	}
	admin := func(path string, body any) error {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", *baseURL+"/admin/realms"+path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
			msg, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("POST %s: %s %s", path, resp.Status, msg)
		}
		return nil
	}
	if err := admin("", map[string]any{"realm": *realm, "enabled": true}); err != nil {
		return err
	}
	if err := admin("/"+*realm+"/clients", map[string]any{"clientId": clientID, "secret": clientSecret,
		"redirectUris": []string{redirectURI}, "directAccessGrantsEnabled": true, "serviceAccountsEnabled": true}); err != nil {
		return err
	}
	for i := 0; i < *users; i++ {
		name := fmt.Sprintf("load-%d", i)
		if err := admin("/"+*realm+"/users", map[string]any{"username": name, "enabled": true,
			"email": name + "@example.com", "firstName": "Load", "lastName": fmt.Sprint(i),
			"credentials": []map[string]any{{"type": "password", "value": userPassword, "temporary": false}}}); err != nil {
			return err
		}
	}
	log.Printf("realm %q ready with %d users", *realm, *users)
	return nil
}

// ---------------------------------------------------------------- workers

type worker struct {
	id      int
	client  *http.Client
	session string // refresh token of the worker's session (refresh scenario)
	timings map[string][]time.Duration
	errors  map[string]int
	lastErr map[string]error
	measure bool
}

func (w *worker) user() string { return fmt.Sprintf("load-%d", rand.IntN(*users)) }

func (w *worker) tokenURL() string {
	return *baseURL + "/realms/" + *realm + "/protocol/openid-connect/token"
}

// timed runs one request and records its latency under name.
func (w *worker) timed(name string, fn func() error) error {
	start := time.Now()
	err := fn()
	if !w.measure {
		return err
	}
	if err != nil {
		w.errors[name]++
		w.lastErr[name] = err
		return err
	}
	w.timings[name] = append(w.timings[name], time.Since(start))
	return nil
}

func (w *worker) token() error {
	return w.timed("token (client_credentials)", func() error {
		_, err := post(w.client, w.tokenURL(), url.Values{"grant_type": {"client_credentials"},
			"client_id": {clientID}, "client_secret": {clientSecret}})
		return err
	})
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (w *worker) refresh() error {
	if w.session == "" {
		r, err := post(w.client, w.tokenURL(), url.Values{"grant_type": {"password"}, "client_id": {clientID},
			"client_secret": {clientSecret}, "username": {w.user()}, "password": {userPassword}, "scope": {"openid"}})
		if err != nil {
			return err
		}
		var t tokenResponse
		if err := r.json(&t); err != nil {
			return err
		}
		w.session = t.RefreshToken
	}
	return w.timed("token (refresh_token)", func() error {
		r, err := post(w.client, w.tokenURL(), url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID},
			"client_secret": {clientSecret}, "refresh_token": {w.session}})
		if err != nil {
			w.session = "" // start a new session
			return err
		}
		var t tokenResponse
		if err := r.json(&t); err != nil {
			return err
		}
		w.session = t.RefreshToken
		return nil
	})
}

var formActionRe = regexp.MustCompile(`<form[^>]*action="([^"]+)"`)

func (w *worker) login() error {
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, Transport: w.client.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var action string
	err := w.timed("login page", func() error {
		r, err := get(browser, *baseURL+"/realms/"+*realm+"/protocol/openid-connect/auth?"+url.Values{
			"client_id": {clientID}, "response_type": {"code"}, "scope": {"openid"}, "redirect_uri": {redirectURI},
			"state": {"s"}}.Encode())
		if err != nil {
			return err
		}
		m := formActionRe.FindSubmatch(r.body)
		if m == nil {
			return errors.New("no login form")
		}
		action = strings.ReplaceAll(string(m[1]), "&amp;", "&")
		return nil
	})
	if err != nil {
		return err
	}
	var code string
	err = w.timed("login form post", func() error {
		r, err := send(browser, "POST", action, url.Values{"username": {w.user()}, "password": {userPassword}}, http.StatusFound)
		if err != nil {
			return err
		}
		loc, err := url.Parse(r.header.Get("Location"))
		if err != nil {
			return err
		}
		if code = loc.Query().Get("code"); code == "" {
			return fmt.Errorf("no code in %s", loc)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return w.timed("token (authorization_code)", func() error {
		_, err := post(w.client, w.tokenURL(), url.Values{"grant_type": {"authorization_code"}, "code": {code},
			"client_id": {clientID}, "client_secret": {clientSecret}, "redirect_uri": {redirectURI}})
		return err
	})
}

// run runs fn in a loop on every worker for d.
func run(fn func(*worker) error, d time.Duration, measure bool) []*stats {
	if d <= 0 {
		return nil
	}
	transport := &http.Transport{MaxIdleConnsPerHost: *concurrency * 2}
	workers := make([]*worker, *concurrency)
	var wg sync.WaitGroup
	deadline := time.Now().Add(d)
	for i := range workers {
		w := &worker{id: i, client: &http.Client{Transport: transport, Timeout: 30 * time.Second}, measure: measure,
			timings: map[string][]time.Duration{}, errors: map[string]int{}, lastErr: map[string]error{}}
		workers[i] = w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				if err := fn(w); err != nil {
					time.Sleep(10 * time.Millisecond)
				}
			}
		}()
	}
	wg.Wait()
	byName := map[string]*stats{}
	var names []string
	for _, w := range workers {
		for name, ts := range w.timings {
			s := byName[name]
			if s == nil {
				s = &stats{name: name}
				byName[name] = s
				names = append(names, name)
			}
			s.timings = append(s.timings, ts...)
		}
		for name, n := range w.errors {
			s := byName[name]
			if s == nil {
				s = &stats{name: name}
				byName[name] = s
				names = append(names, name)
			}
			s.errors += n
			s.lastErr = w.lastErr[name]
		}
	}
	slices.Sort(names)
	var out []*stats
	for _, n := range names {
		out = append(out, byName[n])
	}
	return out
}

type stats struct {
	name    string
	timings []time.Duration
	errors  int
	lastErr error
}

func (s *stats) print(d time.Duration) {
	slices.Sort(s.timings)
	pct := func(p float64) string {
		if len(s.timings) == 0 {
			return "-"
		}
		i := int(float64(len(s.timings))*p+0.5) - 1
		return ms(s.timings[max(0, min(i, len(s.timings)-1))])
	}
	maxT := "-"
	if len(s.timings) > 0 {
		maxT = ms(s.timings[len(s.timings)-1])
	}
	fmt.Printf("| %s | %d | %d | %.0f | %s | %s | %s | %s |\n", s.name, len(s.timings), s.errors,
		float64(len(s.timings))/d.Seconds(), pct(0.50), pct(0.90), pct(0.99), maxT)
	if s.lastErr != nil {
		fmt.Fprintf(os.Stderr, "%s: last error: %v\n", s.name, s.lastErr)
	}
}

func ms(d time.Duration) string { return fmt.Sprintf("%.1f ms", float64(d.Microseconds())/1000) }

// ---------------------------------------------------------------- http

type response struct {
	header http.Header
	body   []byte
}

func (r *response) json(v any) error { return json.Unmarshal(r.body, v) }

func post(c *http.Client, u string, form url.Values) (*response, error) {
	return send(c, "POST", u, form, http.StatusOK)
}

func get(c *http.Client, u string) (*response, error) { return send(c, "GET", u, nil, http.StatusOK) }

func send(c *http.Client, method, u string, form url.Values, want int) (*response, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return nil, err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != want {
		if len(b) > 200 {
			b = b[:200]
		}
		return nil, fmt.Errorf("%s %s: %s %s", method, u, resp.Status, b)
	}
	return &response{header: resp.Header, body: b}, nil
}
