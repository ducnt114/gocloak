// Package tracing records a span for every HTTP request and exports them
// to an OpenTelemetry collector with OTLP over HTTP (protobuf), following
// the W3C traceparent of incoming requests. It implements the small part of
// the OTLP wire format it needs, without the OpenTelemetry SDK.
package tracing

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"time"
)

// Config of the exporter (Keycloak's --tracing-* options).
type Config struct {
	Endpoint    string  // OTLP/HTTP endpoint, e.g. http://localhost:4318 (/v1/traces is added)
	ServiceName string  // service.name resource attribute
	Ratio       float64 // sampled fraction of new traces (0..1)
	Attributes  map[string]string
	Log         *slog.Logger
}

// Span is a finished server span.
type Span struct {
	TraceID    [16]byte
	SpanID     [8]byte
	Parent     [8]byte
	Name       string
	Start, End time.Time
	Attrs      []Attr
	Error      bool
}

// Attr is a span attribute (string or int).
type Attr struct {
	Key   string
	Str   string
	Int   int64
	IsInt bool
}

// Tracer collects and exports spans.
type Tracer struct {
	cfg   Config
	queue chan *Span
	done  chan struct{}
}

// New starts a tracer exporting in the background until ctx ends.
func New(ctx context.Context, cfg Config) *Tracer {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "gocloak"
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	cfg.Endpoint = strings.TrimSuffix(cfg.Endpoint, "/")
	if !strings.HasSuffix(cfg.Endpoint, "/v1/traces") {
		cfg.Endpoint += "/v1/traces"
	}
	t := &Tracer{cfg: cfg, queue: make(chan *Span, 4096), done: make(chan struct{})}
	go t.run(ctx)
	return t
}

func (t *Tracer) run(ctx context.Context) {
	defer close(t.done)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	var batch []*Span
	flush := func() {
		if len(batch) > 0 {
			t.export(batch)
			batch = nil
		}
	}
	for {
		select {
		case s := <-t.queue:
			batch = append(batch, s)
			if len(batch) >= 512 {
				flush()
			}
		case <-tick.C:
			flush()
		case <-ctx.Done():
			for {
				select {
				case s := <-t.queue:
					batch = append(batch, s)
				default:
					flush()
					return
				}
			}
		}
	}
}

// Wait blocks until the exporter stopped (after its context ended).
func (t *Tracer) Wait() { <-t.done }

func (t *Tracer) export(spans []*Span) {
	body := encodeRequest(t.cfg, spans)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.cfg.Log.Warn("exporting traces", "err", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		t.cfg.Log.Warn("exporting traces", "status", resp.StatusCode)
	}
}

// parseTraceparent reads a W3C traceparent header.
func parseTraceparent(h string) (trace [16]byte, parent [8]byte, sampled, ok bool) {
	parts := strings.Split(h, "-")
	if len(parts) != 4 || parts[0] != "00" || len(parts[1]) != 32 || len(parts[2]) != 16 || len(parts[3]) != 2 {
		return
	}
	if _, err := hex.Decode(trace[:], []byte(parts[1])); err != nil {
		return
	}
	if _, err := hex.Decode(parent[:], []byte(parts[2])); err != nil {
		return
	}
	flags, err := hex.DecodeString(parts[3])
	if err != nil || trace == [16]byte{} || parent == [8]byte{} {
		return
	}
	return trace, parent, flags[0]&1 == 1, true
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

type traceKey struct{}

// TraceID returns the trace id of a request being traced ("" if none).
func TraceID(ctx context.Context) string {
	if s, ok := ctx.Value(traceKey{}).(*Span); ok {
		return hex.EncodeToString(s.TraceID[:])
	}
	return ""
}

// Middleware traces the requests served by next (a ServeMux: its matched
// pattern names the span).
func (t *Tracer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trace, parent, sampled, ok := parseTraceparent(r.Header.Get("traceparent"))
		if !ok {
			_, _ = rand.Read(trace[:])
			sampled = t.cfg.Ratio >= 1 || binary.BigEndian.Uint64(trace[8:])>>1 < uint64(t.cfg.Ratio*math.MaxInt64)
		}
		if !sampled {
			next.ServeHTTP(w, r)
			return
		}
		s := &Span{TraceID: trace, Parent: parent, Start: time.Now()}
		_, _ = rand.Read(s.SpanID[:])
		sw := &statusWriter{ResponseWriter: w}
		r = r.WithContext(context.WithValue(r.Context(), traceKey{}, s))
		next.ServeHTTP(sw, r)
		s.End = time.Now()
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		route := r.Pattern
		if i := strings.IndexByte(route, ' '); i >= 0 {
			route = route[i+1:]
		}
		s.Name = r.Method
		if route != "" {
			s.Name += " " + route
		}
		s.Error = sw.status >= 500
		s.Attrs = []Attr{{Key: "http.request.method", Str: r.Method}, {Key: "url.path", Str: r.URL.Path},
			{Key: "http.response.status_code", Int: int64(sw.status), IsInt: true}, {Key: "server.address", Str: r.Host},
			{Key: "user_agent.original", Str: r.UserAgent()}}
		if route != "" {
			s.Attrs = append(s.Attrs, Attr{Key: "http.route", Str: route})
		}
		select {
		case t.queue <- s:
		default: // drop spans rather than slow requests down
		}
	})
}

// ---------------------------------------------------------------- OTLP protobuf

type pb struct{ bytes.Buffer }

func (b *pb) varint(v uint64) {
	var buf [binary.MaxVarintLen64]byte
	b.Write(buf[:binary.PutUvarint(buf[:], v)])
}

func (b *pb) tag(field, wire int) { b.varint(uint64(field<<3 | wire)) }

func (b *pb) bytesField(field int, v []byte) {
	b.tag(field, 2)
	b.varint(uint64(len(v)))
	b.Write(v)
}

func (b *pb) str(field int, v string) {
	if v != "" {
		b.bytesField(field, []byte(v))
	}
}

func (b *pb) msg(field int, m *pb) { b.bytesField(field, m.Bytes()) }

func (b *pb) fixed64(field int, v uint64) {
	b.tag(field, 1)
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	b.Write(buf[:])
}

func keyValue(a Attr) *pb {
	kv, val := &pb{}, &pb{}
	kv.str(1, a.Key)
	if a.IsInt {
		val.tag(3, 0)
		val.varint(uint64(a.Int))
	} else {
		val.bytesField(1, []byte(a.Str))
	}
	kv.msg(2, val)
	return kv
}

// encodeRequest builds an OTLP ExportTraceServiceRequest.
func encodeRequest(cfg Config, spans []*Span) []byte {
	resource := &pb{}
	attrs := []Attr{{Key: "service.name", Str: cfg.ServiceName}}
	for k, v := range cfg.Attributes {
		attrs = append(attrs, Attr{Key: k, Str: v})
	}
	for _, a := range attrs {
		resource.msg(1, keyValue(a))
	}
	scope := &pb{}
	scope.str(1, "gocloak")
	scopeSpans := &pb{}
	scopeSpans.msg(1, scope)
	for _, s := range spans {
		sp := &pb{}
		sp.bytesField(1, s.TraceID[:])
		sp.bytesField(2, s.SpanID[:])
		if s.Parent != [8]byte{} {
			sp.bytesField(4, s.Parent[:])
		}
		sp.str(5, s.Name)
		sp.tag(6, 0)
		sp.varint(2) // SPAN_KIND_SERVER
		sp.fixed64(7, uint64(s.Start.UnixNano()))
		sp.fixed64(8, uint64(s.End.UnixNano()))
		for _, a := range s.Attrs {
			sp.msg(9, keyValue(a))
		}
		if s.Error {
			st := &pb{}
			st.tag(3, 0)
			st.varint(2) // STATUS_CODE_ERROR
			sp.msg(15, st)
		}
		scopeSpans.msg(2, sp)
	}
	rs := &pb{}
	rs.msg(1, resource)
	rs.msg(2, scopeSpans)
	req := &pb{}
	req.msg(1, rs)
	return req.Bytes()
}
