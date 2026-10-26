package main

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// rateLimiter is a per-IP token bucket applied to unauthenticated API traffic.
//
// config.yaml advertised orchestrator.rate_limit.* long before anything read
// it. This is the implementation those keys were written for: it protects the
// login form and the ingest endpoints from floods and password guessing, while
// authenticated dashboard sessions are exempt so polling and SSE streaming are
// never throttled.
type rateLimiter struct {
	enabled  bool
	ratePerS float64 // tokens added per second
	capacity float64 // bucket size

	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

func newRateLimiter(enabled bool, requestsPerMinute, burst int) *rateLimiter {
	if requestsPerMinute <= 0 {
		requestsPerMinute = 120
	}
	if burst <= 0 {
		burst = 20
	}
	return &rateLimiter{
		enabled:  enabled,
		ratePerS: float64(requestsPerMinute) / 60.0,
		capacity: math.Max(float64(burst), 1),
		buckets:  make(map[string]*bucket),
		lastSweep: time.Now(),
	}
}

// Allow consumes one token for key, refilling first.
func (rl *rateLimiter) Allow(key string) bool {
	if !rl.enabled {
		return true
	}
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.sweepLocked(now)

	b, ok := rl.buckets[key]
	if !ok {
		b = &bucket{tokens: rl.capacity, lastSeen: now}
		rl.buckets[key] = b
	} else {
		elapsed := now.Sub(b.lastSeen).Seconds()
		b.tokens = math.Min(rl.capacity, b.tokens+elapsed*rl.ratePerS)
		b.lastSeen = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweepLocked drops buckets that refilled completely and went idle, so a scan
// across many source addresses cannot grow the map without bound.
func (rl *rateLimiter) sweepLocked(now time.Time) {
	if now.Sub(rl.lastSweep) < 5*time.Minute {
		return
	}
	rl.lastSweep = now
	idleAfter := time.Duration(float64(time.Second) * (rl.capacity/rl.ratePerS)) + time.Minute
	for key, b := range rl.buckets {
		if now.Sub(b.lastSeen) > idleAfter {
			delete(rl.buckets, key)
		}
	}
}

// Wrap applies the limiter to API traffic that has not been authenticated yet.
func (rl *rateLimiter) Wrap(next http.Handler) http.Handler {
	if !rl.enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.shouldLimit(r) {
			next.ServeHTTP(w, r)
			return
		}
		if !rl.Allow(clientKey(r)) {
			retry := 1
			if rl.ratePerS > 0 {
				retry = int(math.Ceil(1 / rl.ratePerS))
			}
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			respondJSON(w, http.StatusTooManyRequests, map[string]string{
				"error": "rate_limited",
				"hint":  "too many unauthenticated requests; retry later or authenticate",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (rl *rateLimiter) shouldLimit(r *http.Request) bool {
	if r.URL.Path == "/health" {
		return false
	}
	if !isAPIPath(r.URL.Path) {
		return false
	}
	// Authenticated callers are trusted: the dashboard polls several endpoints
	// and holds an SSE stream open.
	if hasValidSession(r) || hasValidAPIKey(r) {
		return false
	}
	return true
}

func isAPIPath(path string) bool {
	return len(path) >= 5 && path[:5] == "/api/"
}

func clientKey(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}
