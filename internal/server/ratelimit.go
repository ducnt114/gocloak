package server

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// rateLimiter is a per client IP token bucket for the unauthenticated
// protocol endpoints and the admin API. It bounds the state anonymous
// callers can create (auth sessions, failed login records) and slows down
// password guessing on top of brute force detection.
type rateLimiter struct {
	rate         float64
	burst        float64
	proxyHeaders bool

	mu      sync.Mutex
	buckets map[string]*bucket
	lastGC  time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rate float64, burst int, proxyHeaders bool) *rateLimiter {
	if burst <= 0 {
		burst = int(rate * 2)
	}
	return &rateLimiter{rate: rate, burst: float64(burst), proxyHeaders: proxyHeaders, buckets: map[string]*bucket{}}
}

func (l *rateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastGC) > time.Minute {
		for k, b := range l.buckets {
			if now.Sub(b.last) > time.Minute {
				delete(l.buckets, k)
			}
		}
		l.lastGC = now
	}
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *rateLimiter) clientKey(r *http.Request) string {
	if l.proxyHeaders {
		if f := r.Header.Get("X-Forwarded-For"); f != "" {
			return strings.TrimSpace(strings.Split(f, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (l *rateLimiter) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limited := strings.HasPrefix(r.URL.Path, "/realms/") || strings.HasPrefix(r.URL.Path, "/admin/")
		if limited && !l.allow(l.clientKey(r), time.Now()) {
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"too_many_requests","error_description":"Too many requests"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}
