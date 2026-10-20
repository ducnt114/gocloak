// Package metrics exposes gocloak's metrics in the Prometheus text format,
// with Keycloak's metric names where Keycloak has them:
// http_server_requests_seconds (count, sum and max per method, outcome,
// status and route) and keycloak_user_events_total, plus Go runtime and
// process metrics.
package metrics

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Registry collects the metrics of a gocloak process.
type Registry struct {
	mu       sync.Mutex
	requests map[requestKey]*summary
	events   map[eventKey]float64
	buckets  []float64 // optional histogram buckets of request durations
	started  time.Time
}

type requestKey struct{ method, outcome, status, uri string }

type eventKey struct{ realm, event, client, idp, err string }

type summary struct {
	count   float64
	sum     float64
	max     float64
	buckets []float64 // cumulative counts per Registry.buckets
}

// New returns an empty registry; with histograms, request durations are
// also counted in buckets (Keycloak's --http-metrics-histograms-enabled).
func New(histograms bool) *Registry {
	r := &Registry{requests: map[requestKey]*summary{}, events: map[eventKey]float64{}, started: time.Now()}
	if histograms {
		r.buckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	}
	return r
}

func outcome(status int) string {
	switch {
	case status < 200:
		return "INFORMATIONAL"
	case status < 300:
		return "SUCCESS"
	case status < 400:
		return "REDIRECTION"
	case status < 500:
		return "CLIENT_ERROR"
	}
	return "SERVER_ERROR"
}

// ObserveRequest records an HTTP request; route is the matched pattern.
func (r *Registry) ObserveRequest(method, route string, status int, d time.Duration) {
	if route == "" {
		route = "NOT_FOUND"
		if status < 400 {
			route = "UNKNOWN"
		}
	}
	k := requestKey{method, outcome(status), strconv.Itoa(status), route}
	secs := d.Seconds()
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.requests[k]
	if s == nil {
		s = &summary{buckets: make([]float64, len(r.buckets))}
		r.requests[k] = s
	}
	s.count++
	s.sum += secs
	s.max = math.Max(s.max, secs)
	for i, b := range r.buckets {
		if secs <= b {
			s.buckets[i]++
		}
	}
}

// ObserveEvent counts a user event (error is "" for successes).
func (r *Registry) ObserveEvent(realm, event, client, idp, errCode string) {
	r.mu.Lock()
	r.events[eventKey{realm, strings.ToLower(event), client, idp, errCode}]++
	r.mu.Unlock()
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Middleware records the requests served by next (a ServeMux, whose
// matched pattern labels the request).
func (r *Registry) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, req)
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		route := req.Pattern
		if i := strings.IndexByte(route, ' '); i >= 0 {
			route = route[i+1:]
		}
		r.ObserveRequest(req.Method, route, sw.status, time.Since(start))
	})
}

func labels(kv ...string) string {
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i+1 < len(kv); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		v := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(kv[i+1])
		fmt.Fprintf(&b, `%s="%s"`, kv[i], v)
	}
	b.WriteByte('}')
	return b.String()
}

func num(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

// Write renders the metrics in the Prometheus text exposition format.
func (r *Registry) Write(w io.Writer) {
	r.mu.Lock()
	reqKeys := make([]requestKey, 0, len(r.requests))
	for k := range r.requests {
		reqKeys = append(reqKeys, k)
	}
	sort.Slice(reqKeys, func(i, j int) bool { return fmt.Sprint(reqKeys[i]) < fmt.Sprint(reqKeys[j]) })
	evKeys := make([]eventKey, 0, len(r.events))
	for k := range r.events {
		evKeys = append(evKeys, k)
	}
	sort.Slice(evKeys, func(i, j int) bool { return fmt.Sprint(evKeys[i]) < fmt.Sprint(evKeys[j]) })

	typ := "summary"
	if len(r.buckets) > 0 {
		typ = "histogram"
	}
	fmt.Fprintf(w, "# HELP http_server_requests_seconds HTTP server requests\n# TYPE http_server_requests_seconds %s\n", typ)
	for _, k := range reqKeys {
		s := r.requests[k]
		l := []string{"method", k.method, "outcome", k.outcome, "status", k.status, "uri", k.uri}
		for i, b := range r.buckets {
			fmt.Fprintf(w, "http_server_requests_seconds_bucket%s %s\n", labels(append(l, "le", num(b))...), num(s.buckets[i]))
		}
		if len(r.buckets) > 0 {
			fmt.Fprintf(w, "http_server_requests_seconds_bucket%s %s\n", labels(append(l, "le", "+Inf")...), num(s.count))
		}
		fmt.Fprintf(w, "http_server_requests_seconds_count%s %s\n", labels(l...), num(s.count))
		fmt.Fprintf(w, "http_server_requests_seconds_sum%s %s\n", labels(l...), num(s.sum))
	}
	fmt.Fprint(w, "# HELP http_server_requests_seconds_max HTTP server requests\n# TYPE http_server_requests_seconds_max gauge\n")
	for _, k := range reqKeys {
		fmt.Fprintf(w, "http_server_requests_seconds_max%s %s\n",
			labels("method", k.method, "outcome", k.outcome, "status", k.status, "uri", k.uri), num(r.requests[k].max))
	}
	fmt.Fprint(w, "# HELP gocloak_user_events_total gocloak user events\n# TYPE gocloak_user_events_total counter\n")
	for _, k := range evKeys {
		fmt.Fprintf(w, "gocloak_user_events_total%s %s\n",
			labels("client_id", k.client, "error", k.err, "event", k.event, "idp", k.idp, "realm", k.realm), num(r.events[k]))
	}
	r.mu.Unlock()

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	gauge := func(name, help string, v float64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %s\n", name, help, name, name, num(v))
	}
	gauge("go_goroutines", "Number of goroutines that currently exist.", float64(runtime.NumGoroutine()))
	gauge("go_memstats_alloc_bytes", "Number of bytes allocated and still in use.", float64(ms.Alloc))
	gauge("go_memstats_heap_inuse_bytes", "Number of heap bytes that are in use.", float64(ms.HeapInuse))
	gauge("go_memstats_sys_bytes", "Number of bytes obtained from system.", float64(ms.Sys))
	fmt.Fprintf(w, "# HELP go_gc_cycles_total Number of completed GC cycles.\n# TYPE go_gc_cycles_total counter\ngo_gc_cycles_total %d\n", ms.NumGC)
	gauge("process_start_time_seconds", "Start time of the process since unix epoch in seconds.", float64(r.started.Unix()))
	gauge("process_uptime_seconds", "The uptime of the process.", time.Since(r.started).Seconds())
}

// Handler serves the metrics.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		r.Write(w)
	})
}
