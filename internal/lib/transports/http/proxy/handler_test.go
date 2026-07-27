package proxy

import (
	"testing"

	"bufio"
	"bytes"

	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
)

// fakeHijacker records the controller calls that must reach the wrapped
// writer for streaming responses and upgrades to keep working.
type fakeHijacker struct {
	*httptest.ResponseRecorder
	flushed  bool
	hijacked bool
}

func (f *fakeHijacker) Flush() { f.flushed = true }

func (f *fakeHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	f.hijacked = true

	server, client := net.Pipe()
	client.Close()

	return server, bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server)), nil
}

// TestCountingWriterPreservesController proves the byte-counting wrapper
// stays transparent to http.ResponseController, which is how the reverse
// proxy flushes streaming responses and hijacks upgrade connections.
func TestCountingWriterPreservesController(t *testing.T) {
	inner := &fakeHijacker{ResponseRecorder: httptest.NewRecorder()}
	w := &countingWriter{ResponseWriter: inner}

	rc := http.NewResponseController(w)

	if err := rc.Flush(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !inner.flushed {
		t.Error("Flush must reach the wrapped writer")
	}

	conn, _, err := rc.Hijack()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	conn.Close()

	if !inner.hijacked {
		t.Error("Hijack must reach the wrapped writer")
	}

	if _, err := w.Write([]byte("payload")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := inner.Body.String(); got != "payload" {
		t.Errorf("writes must pass through unchanged, got %q", got)
	}
}

// TestCountingBodyReadsThrough proves the request-body counter is a
// transparent reader.
func TestCountingBodyReadsThrough(t *testing.T) {
	body := countingBody{ReadCloser: http.NoBody}

	if n, _ := body.Read(make([]byte, 8)); n != 0 {
		t.Errorf("empty body must stay empty, got %d bytes", n)
	}

	payload := bytes.NewBufferString("hello")
	wrapped := countingBody{ReadCloser: readCloser{Reader: payload, Closer: http.NoBody}}

	buf := make([]byte, 8)
	if n, _ := wrapped.Read(buf); string(buf[:n]) != "hello" {
		t.Errorf("reads must pass through unchanged, got %q", buf[:n])
	}
}

// proxyRequest models what ReverseProxy hands to Rewrite: Out is a clone
// of the inbound request whose forwarding headers have already been
// stripped, so Rewrite alone decides what the backend sees.
func proxyRequest(in *http.Request) *httputil.ProxyRequest {
	out := in.Clone(in.Context())
	for _, name := range []string{
		"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
	} {
		out.Header.Del(name)
	}

	return &httputil.ProxyRequest{In: in, Out: out}
}

func TestForwardingHeadersFromUntrustedPeer(t *testing.T) {
	// docs/spec/traffic.md: values from an untrusted peer are replaced by
	// the connection krouter actually terminated.
	in := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	in.RemoteAddr = "10.0.0.9:5555"
	in.Header.Set("X-Forwarded-For", "203.0.113.7")
	in.Header.Set("X-Forwarded-Host", "spoofed.example.com")
	in.Header.Set("X-Forwarded-Proto", "https")
	in.Header.Set("Forwarded", "for=203.0.113.7;host=spoofed.example.com;proto=https")

	pr := proxyRequest(in)
	rewriteForwardingHeaders(pr, false, false)

	if got := pr.Out.Header.Get("X-Forwarded-For"); got != "10.0.0.9" {
		t.Errorf("spoofed chain must be replaced by the peer, got %q", got)
	}

	if got := pr.Out.Header.Get("X-Forwarded-Host"); got != "app.example.com" {
		t.Errorf("spoofed host must be replaced, got %q", got)
	}

	if got := pr.Out.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Errorf("proto must describe the listener, got %q", got)
	}

	want := "for=10.0.0.9;host=app.example.com;proto=http"
	if got := pr.Out.Header.Get("Forwarded"); got != want {
		t.Errorf("Forwarded must be regenerated, got %q", got)
	}
}

func TestForwardingHeadersFromTrustedPeer(t *testing.T) {
	// docs/spec/traffic.md: a trusted peer described a client leg krouter
	// never saw, so its values reach the backend with the peer appended.
	in := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	in.RemoteAddr = "10.0.0.9:5555"
	in.Header.Set("X-Forwarded-For", "203.0.113.7")
	in.Header.Set("X-Forwarded-Host", "front.example.com")
	in.Header.Set("X-Forwarded-Proto", "https")

	pr := proxyRequest(in)
	rewriteForwardingHeaders(pr, false, true)

	if got := pr.Out.Header.Get("X-Forwarded-For"); got != "203.0.113.7, 10.0.0.9" {
		t.Errorf("the peer must be appended to the chain, got %q", got)
	}

	if got := pr.Out.Header.Get("X-Forwarded-Host"); got != "front.example.com" {
		t.Errorf("trusted host must pass through, got %q", got)
	}

	if got := pr.Out.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Errorf("trusted proto must pass through, got %q", got)
	}

	// The peer sent no Forwarded, so one describing the hop krouter saw is
	// generated for it.
	want := "for=10.0.0.9;host=app.example.com;proto=http"
	if got := pr.Out.Header.Get("Forwarded"); got != want {
		t.Errorf("missing Forwarded must be generated, got %q", got)
	}
}

func TestForwardingHeadersFromTrustedPeerWithoutChain(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	in.RemoteAddr = "10.0.0.9:5555"

	pr := proxyRequest(in)
	rewriteForwardingHeaders(pr, true, true)

	if got := pr.Out.Header.Get("X-Forwarded-For"); got != "10.0.0.9" {
		t.Errorf("the peer starts the chain, got %q", got)
	}

	if got := pr.Out.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Errorf("proto must describe the listener, got %q", got)
	}
}
