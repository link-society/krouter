package ratelimiting

import (
	"math"

	"strings"

	"sync"

	"net/http"

	"time"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// sweepEvery bounds how often idle buckets are reclaimed, so memory
// never grows unboundedly with the number of distinct client keys
// (docs/spec/extensions.md Rate limiting).
const sweepEvery = 256

// Limiter enforces one rule's merged rate limiting configuration with a
// token bucket per client key (docs/spec/extensions.md Rate limiting).
// State is local to the routing table holding it: buckets reset on table
// swap, like round-robin counters.
type Limiter struct {
	requests float64
	window   time.Duration
	burst    float64
	key      string
	status   int32

	now func() time.Time

	mu      sync.Mutex
	ops     int
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func NewLimiter(config *compiled.RateLimit) *Limiter {
	return &Limiter{
		requests: float64(config.Requests),
		window:   time.Duration(config.WindowMillis) * time.Millisecond,
		burst:    float64(config.Burst),
		key:      config.Key,
		status:   config.Status,
		now:      time.Now,
		buckets:  map[string]*bucket{},
	}
}

// Status is the rejection status code (default 429).
func (l *Limiter) Status() int32 { return l.status }

// KeyFor extracts the bucket key for one request
// (docs/spec/extensions.md Rate limiting): the resolved client IP
// (docs/spec/traffic.md Forwarding headers), or the first value of the
// configured header. Requests without the header share one anonymous
// bucket ("").
func (l *Limiter) KeyFor(r *http.Request, clientIP string) string {
	if name, ok := strings.CutPrefix(l.key, "header:"); ok {
		return r.Header.Get(name)
	}

	return clientIP
}

// Allow consumes one token from the key's bucket. When the bucket is
// empty it reports the wait until the next token, for Retry-After.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.ops++
	if l.ops%sweepEvery == 0 {
		l.sweep(now)
	}

	entry, ok := l.buckets[key]
	if !ok {
		entry = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = entry
	}

	rate := l.requests / float64(l.window) // tokens per nanosecond

	elapsed := now.Sub(entry.last)
	if elapsed > 0 {
		entry.tokens = math.Min(l.burst, entry.tokens+float64(elapsed)*rate)
	}
	entry.last = now

	if entry.tokens >= 1 {
		entry.tokens--
		return true, 0
	}

	wait := time.Duration((1 - entry.tokens) / rate)

	return false, wait
}

// sweep drops buckets idle long enough to be full again: reclaiming them
// cannot grant any extra capacity.
func (l *Limiter) sweep(now time.Time) {
	horizon := now.Add(-2 * l.window)

	for key, entry := range l.buckets {
		if entry.last.Before(horizon) {
			delete(l.buckets, key)
		}
	}
}
