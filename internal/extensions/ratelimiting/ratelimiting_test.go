package ratelimiting

import (
	"testing"

	"net/http"
	"net/http/httptest"

	"time"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

func int64Ptr(v int64) *int64 { return &v }

// ------------------------------------------------------------- parsing --

func TestParseFullDocument(t *testing.T) {
	doc, err := Parse(`
version = 1

rate_limit {
  requests = 100
  window   = "1m"
  burst    = 20
  key      = "header:X-Api-Key"
  status   = 418
}
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if *doc.Requests != 100 || *doc.Window != time.Minute ||
		*doc.Burst != 20 || *doc.Key != "header:X-Api-Key" || *doc.Status != 418 {
		t.Errorf("unexpected document: %+v", doc)
	}
}

func TestParsePartialDocument(t *testing.T) {
	// Every attribute is optional per document (docs/spec/extensions.md):
	// completeness is only checked on the merged result.
	doc, err := Parse("version = 1\n\nrate_limit {\n  status = 503\n}\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if doc.Requests != nil || doc.Window != nil || *doc.Status != 503 {
		t.Errorf("unexpected document: %+v", doc)
	}
}

func TestParseRejectsInvalidDocuments(t *testing.T) {
	cases := map[string]string{
		"unsupported version": "version = 2\n\nrate_limit {}\n",
		"missing block":       "version = 1\n",
		"unknown field":       "version = 1\n\nrate_limit {\n  bogus = 1\n}\n",
		"zero requests":       "version = 1\n\nrate_limit {\n  requests = 0\n}\n",
		"bad window":          "version = 1\n\nrate_limit {\n  window = \"soon\"\n}\n",
		"negative window":     "version = 1\n\nrate_limit {\n  window = \"-1s\"\n}\n",
		"zero burst":          "version = 1\n\nrate_limit {\n  burst = 0\n}\n",
		"bad key":             "version = 1\n\nrate_limit {\n  key = \"cookie\"\n}\n",
		"empty header key":    "version = 1\n\nrate_limit {\n  key = \"header:\"\n}\n",
		"low status":          "version = 1\n\nrate_limit {\n  status = 302\n}\n",
	}

	for name, src := range cases {
		if _, err := Parse(src); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// ------------------------------------------------------------- merging --

func TestMergeOverridesInOrder(t *testing.T) {
	window := time.Hour
	status := int32(418)

	merged, err := Merge([]*Document{
		{Requests: int64Ptr(5), Window: &window},
		{Status: &status, Requests: int64Ptr(3)},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if merged.Requests != 3 || merged.WindowMillis != time.Hour.Milliseconds() {
		t.Errorf("unexpected limits: %+v", merged)
	}

	if merged.Status != 418 {
		t.Errorf("later status must win, got %d", merged.Status)
	}

	// Defaults fill the unset attributes (docs/spec/extensions.md).
	if merged.Burst != 3 || merged.Key != "client_ip" {
		t.Errorf("unexpected defaults: %+v", merged)
	}
}

func TestMergeRequiresCompleteness(t *testing.T) {
	if _, err := Merge([]*Document{{Burst: int64Ptr(5)}}); err == nil {
		t.Error("merged configuration without requests and window must fail")
	}
}

// ------------------------------------------------------------- limiter --

func testLimiter(requests, burst int64, window time.Duration) (*Limiter, *time.Time) {
	limiter := NewLimiter(&compiled.RateLimit{
		Requests:     requests,
		WindowMillis: window.Milliseconds(),
		Burst:        burst,
		Key:          "client_ip",
		Status:       429,
	})

	now := time.Unix(1000, 0)
	limiter.now = func() time.Time { return now }

	return limiter, &now
}

func TestLimiterExhaustsAndRefills(t *testing.T) {
	limiter, now := testLimiter(2, 2, time.Minute)

	for i := range 2 {
		if ok, _ := limiter.Allow("k"); !ok {
			t.Fatalf("request %d must pass", i)
		}
	}

	ok, wait := limiter.Allow("k")
	if ok {
		t.Fatal("exhausted bucket must reject")
	}

	if wait <= 0 || wait > 30*time.Second {
		t.Errorf("expected a wait up to half the window, got %v", wait)
	}

	// One token refills after half the window (2 per minute).
	*now = now.Add(31 * time.Second)

	if ok, _ := limiter.Allow("k"); !ok {
		t.Error("refilled bucket must pass")
	}
}

func TestLimiterIsolatesKeys(t *testing.T) {
	limiter, _ := testLimiter(1, 1, time.Hour)

	if ok, _ := limiter.Allow("alice"); !ok {
		t.Fatal("first key must pass")
	}

	if ok, _ := limiter.Allow("alice"); ok {
		t.Fatal("exhausted key must reject")
	}

	if ok, _ := limiter.Allow("bob"); !ok {
		t.Error("a fresh key holds a fresh bucket")
	}
}

func TestLimiterSweepsIdleBuckets(t *testing.T) {
	limiter, now := testLimiter(1, 1, time.Second)

	limiter.Allow("idle")
	*now = now.Add(time.Minute)

	// Force sweeps past the idle horizon.
	for range 2 * sweepEvery {
		limiter.Allow("active")
	}

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	if _, ok := limiter.buckets["idle"]; ok {
		t.Error("idle bucket must be reclaimed")
	}
}

func TestKeyFor(t *testing.T) {
	byIP := NewLimiter(&compiled.RateLimit{Key: "client_ip"})
	byHeader := NewLimiter(&compiled.RateLimit{Key: "header:X-Api-Key"})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.7:4242"
	r.Header.Set("X-Api-Key", "alice")

	// The client key is the resolved client IP, which the request path
	// computes from the connection and the gateway's trusted proxies
	// (docs/spec/traffic.md Forwarding headers).
	if key := byIP.KeyFor(r, "203.0.113.7"); key != "203.0.113.7" {
		t.Errorf("client_ip key: got %q", key)
	}

	if key := byHeader.KeyFor(r, "203.0.113.7"); key != "alice" {
		t.Errorf("header key: got %q", key)
	}

	r.Header.Del("X-Api-Key")
	if key := byHeader.KeyFor(r, "203.0.113.7"); key != "" {
		t.Errorf("missing header must share the anonymous bucket, got %q", key)
	}
}
