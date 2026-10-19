package tracing

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fields decodes one level of a protobuf message: field number -> values
// (raw bytes for length-delimited fields, the number otherwise).
func fields(b []byte) map[int][][]byte {
	out := map[int][][]byte{}
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		b = b[n:]
		field, wire := int(key>>3), key&7
		switch wire {
		case 0:
			v, n := binary.Uvarint(b)
			out[field] = append(out[field], binary.AppendUvarint(nil, v))
			b = b[n:]
		case 1:
			out[field] = append(out[field], b[:8])
			b = b[8:]
		case 2:
			l, n := binary.Uvarint(b)
			b = b[n:]
			out[field] = append(out[field], b[:l])
			b = b[l:]
		default:
			panic("unexpected wire type")
		}
	}
	return out
}

func TestExportSpans(t *testing.T) {
	var mu sync.Mutex
	var bodies [][]byte
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/v1/traces" || r.Header.Get("Content-Type") != "application/x-protobuf" {
			t.Errorf("bad export request %s %s", r.URL.Path, r.Header.Get("Content-Type"))
		}
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
	}))
	defer collector.Close()
	ctx, cancel := context.WithCancel(context.Background())
	tr := New(ctx, Config{Endpoint: collector.URL, ServiceName: "test-svc", Ratio: 1})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /realms/{realm}/thing", func(w http.ResponseWriter, r *http.Request) {
		if TraceID(r.Context()) != "0af7651916cd43dd8448eb211c80319c" {
			t.Errorf("trace id in context: %s", TraceID(r.Context()))
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(tr.Middleware(mux))
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/realms/demo/thing", nil)
	req.Header.Set("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	time.Sleep(50 * time.Millisecond)
	cancel()
	tr.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("exports: %d", len(bodies))
	}
	rs := fields(fields(bodies[0])[1][0])
	res := fields(rs[1][0])
	kv := fields(res[1][0])
	if string(kv[1][0]) != "service.name" || string(fields(kv[2][0])[1][0]) != "test-svc" {
		t.Fatalf("resource: %v", kv)
	}
	span := fields(fields(rs[2][0])[2][0])
	if hex.EncodeToString(span[1][0]) != "0af7651916cd43dd8448eb211c80319c" || hex.EncodeToString(span[4][0]) != "b7ad6b7169203331" {
		t.Fatalf("trace and parent ids: %x %x", span[1][0], span[4][0])
	}
	if string(span[5][0]) != "GET /realms/{realm}/thing" {
		t.Fatalf("span name %q", span[5][0])
	}
	status := fields(span[15][0])
	if v, _ := binary.Uvarint(status[3][0]); v != 2 {
		t.Fatalf("status %v", status)
	}
	if len(span[9]) < 5 {
		t.Fatalf("attributes: %d", len(span[9]))
	}
}

func TestSampling(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tr := New(ctx, Config{Endpoint: "http://127.0.0.1:1", Ratio: 0})
	h := tr.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if TraceID(r.Context()) != "" {
			t.Error("unsampled request traced")
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	if len(tr.queue) != 0 {
		t.Fatal("span queued")
	}
	if _, _, _, ok := parseTraceparent("00-00000000000000000000000000000000-b7ad6b7169203331-01"); ok {
		t.Fatal("zero trace id accepted")
	}
}
