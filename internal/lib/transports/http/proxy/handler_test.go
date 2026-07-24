package proxy

import (
	"testing"

	"bufio"
	"bytes"

	"net"
	"net/http"
	"net/http/httptest"
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
