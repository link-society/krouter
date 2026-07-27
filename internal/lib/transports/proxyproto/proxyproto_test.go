package proxyproto

import (
	"strings"

	"bufio"
	"bytes"
	"io"

	"net"
	"net/netip"

	"testing"
	"time"
)

// v1 renders a version 1 preamble.
func v1(rest string) []byte { return []byte("PROXY " + rest + "\r\n") }

// v2 renders a version 2 preamble: signature, version/command byte,
// family/protocol byte, then the declared address block.
func v2(command, family byte, body []byte) []byte {
	out := bytes.NewBuffer(signature)
	out.WriteByte(command)
	out.WriteByte(family)
	out.WriteByte(byte(len(body) >> 8))
	out.WriteByte(byte(len(body)))
	out.Write(body)

	return out.Bytes()
}

// v2TCP4 renders the address block of an IPv4 TCP connection.
func v2TCP4(src, dst [4]byte, sport, dport uint16) []byte {
	body := bytes.NewBuffer(nil)
	body.Write(src[:])
	body.Write(dst[:])
	body.WriteByte(byte(sport >> 8))
	body.WriteByte(byte(sport))
	body.WriteByte(byte(dport >> 8))
	body.WriteByte(byte(dport))

	return body.Bytes()
}

func read(t *testing.T, preamble []byte) (netip.AddrPort, error) {
	t.Helper()

	return Read(bufio.NewReader(bytes.NewReader(preamble)))
}

// ---------------------------------------------------------------- parsing --

func TestReadVersion1(t *testing.T) {
	cases := map[string]struct {
		line string
		want string
	}{
		"TCP4": {"TCP4 203.0.113.7 10.0.0.1 56324 443", "203.0.113.7:56324"},
		"TCP6": {"TCP6 2001:db8::7 2001:db8::1 56324 443", "[2001:db8::7]:56324"},
	}

	for name, tc := range cases {
		source, err := read(t, v1(tc.line))
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}

		if source.String() != tc.want {
			t.Errorf("%s: got %q, want %q", name, source, tc.want)
		}
	}
}

func TestReadVersion1Unknown(t *testing.T) {
	// docs/spec/traffic.md: UNKNOWN carries no client address, the caller
	// keeps the peer.
	source, err := read(t, v1("UNKNOWN"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if source.IsValid() {
		t.Errorf("expected no address, got %q", source)
	}
}

func TestReadVersion2(t *testing.T) {
	preamble := v2(cmdProxy, famTCP4,
		v2TCP4([4]byte{203, 0, 113, 7}, [4]byte{10, 0, 0, 1}, 56324, 443))

	source, err := read(t, preamble)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if source.String() != "203.0.113.7:56324" {
		t.Errorf("got %q", source)
	}
}

func TestReadVersion2SkipsTypeLengthValues(t *testing.T) {
	// Trailing TLV blocks are declared in the length and MUST be skipped
	// without being interpreted (docs/spec/traffic.md).
	body := append(
		v2TCP4([4]byte{203, 0, 113, 7}, [4]byte{10, 0, 0, 1}, 56324, 443),
		0x03, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef, // CRC32C TLV
	)

	source, err := read(t, v2(cmdProxy, famTCP4, body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if source.String() != "203.0.113.7:56324" {
		t.Errorf("got %q", source)
	}
}

func TestReadVersion2Local(t *testing.T) {
	// LOCAL is what load balancer health checks send: no client address,
	// the connection proceeds with the peer (docs/spec/traffic.md).
	source, err := read(t, v2(cmdLocal, famUnspec, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if source.IsValid() {
		t.Errorf("expected no address, got %q", source)
	}
}

func TestReadStopsAtTheEndOfThePreamble(t *testing.T) {
	// The bytes after the preamble belong to the client and must stay
	// readable.
	reader := bufio.NewReader(bytes.NewReader(
		append(v1("TCP4 203.0.113.7 10.0.0.1 56324 443"), []byte("GET / HTTP/1.1\r\n")...)))

	if _, err := Read(reader); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(rest) != "GET / HTTP/1.1\r\n" {
		t.Errorf("payload must survive the preamble, got %q", rest)
	}
}

func TestReadRejectsInvalidPreambles(t *testing.T) {
	cases := map[string][]byte{
		"no preamble":        []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		"truncated v1":       []byte("PROXY TCP4 203.0.113.7 10.0.0.1"),
		"oversized v1":       []byte("PROXY TCP4 " + strings.Repeat("9", MaxLineLength) + "\r\n"),
		"unknown v1 family":  v1("TCP5 203.0.113.7 10.0.0.1 56324 443"),
		"bad v1 address":     v1("TCP4 not-an-ip 10.0.0.1 56324 443"),
		"bad v1 port":        v1("TCP4 203.0.113.7 10.0.0.1 no 443"),
		"v1 family mismatch": v1("TCP4 2001:db8::7 2001:db8::1 56324 443"),
		"bad v2 version":     v2(0x30, famTCP4, v2TCP4([4]byte{1, 1, 1, 1}, [4]byte{2, 2, 2, 2}, 1, 2)),
		"v2 udp":             v2(cmdProxy, 0x12, v2TCP4([4]byte{1, 1, 1, 1}, [4]byte{2, 2, 2, 2}, 1, 2)),
		"v2 unix":            v2(cmdProxy, 0x31, make([]byte, 216)),
		"truncated v2":       v2(cmdProxy, famTCP4, []byte{1, 2, 3}),
	}

	for name, preamble := range cases {
		if _, err := read(t, preamble); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// -------------------------------------------------------------- listener --

// dial starts a wrapped listener, writes payload to it, and returns the
// accepted connection.
func dial(t *testing.T, trusted TrustFunc, payload []byte) (net.Conn, error) {
	t.Helper()

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ln := Wrap(raw, trusted)
	t.Cleanup(func() { ln.Close() })

	client, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	if _, err := client.Write(payload); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// The preamble is consumed on first use, so force it before returning.
	buf := make([]byte, 4)
	_, readErr := conn.Read(buf)

	return conn, readErr
}

func trustAll(netip.Addr) bool  { return true }
func trustNone(netip.Addr) bool { return false }

func TestConnReportsThePreambleAddress(t *testing.T) {
	payload := append(v1("TCP4 203.0.113.7 10.0.0.1 56324 443"), []byte("ping")...)

	conn, err := dial(t, trustAll, payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if host != "203.0.113.7" {
		t.Errorf("expected the preamble address, got %q", conn.RemoteAddr())
	}
}

func TestConnKeepsThePeerForLocalPreambles(t *testing.T) {
	conn, err := dial(t, trustAll, append(v2(cmdLocal, famUnspec, nil), []byte("ping")...))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if host != "127.0.0.1" {
		t.Errorf("expected the peer address, got %q", conn.RemoteAddr())
	}
}

func TestConnRejectsAnUntrustedPeer(t *testing.T) {
	// docs/spec/security.md: a preamble from a peer outside the trust list
	// is an attempt to choose a client address.
	payload := append(v1("TCP4 203.0.113.7 10.0.0.1 56324 443"), []byte("ping")...)

	if _, err := dial(t, trustNone, payload); err == nil {
		t.Fatal("expected the connection to fail")
	}
}

func TestConnRejectsAMissingPreamble(t *testing.T) {
	if _, err := dial(t, trustAll, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err == nil {
		t.Fatal("expected the connection to fail")
	}
}

func TestConnKeepsCloseWrite(t *testing.T) {
	// The TCP forwarder half-closes connections (docs/spec/traffic.md), so
	// the wrapper must not hide CloseWrite.
	payload := append(v1("TCP4 203.0.113.7 10.0.0.1 56324 443"), []byte("ping")...)

	conn, err := dial(t, trustAll, payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := conn.(interface{ CloseWrite() error }); !ok {
		t.Error("wrapped connection must still expose CloseWrite")
	}
}
