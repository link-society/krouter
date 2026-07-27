// Package proxyproto reads the PROXY protocol preamble that a load
// balancer sends before anything else on a connection, and wraps a
// net.Listener so the accepted connections report the client it names
// (docs/spec/traffic.md Proxy protocol).
//
// Parsing is deliberate about what it refuses: the preamble is the first
// thing an untrusted network can send, and the address it carries decides
// who a request is attributed to.
package proxyproto

import (
	"errors"
	"fmt"
	"log/slog"

	"strconv"
	"strings"

	"bufio"
	"io"

	"net"
	"net/netip"

	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// connectionsRejected counts connections closed before any request
// (docs/spec/observability.md). The peer stays out of the labels: client
// addresses are unbounded.
var connectionsRejected = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "krouter_dataplane_connections_rejected_total",
		Help: "Connections closed before any request, by cause (docs/spec/traffic.md Proxy protocol).",
	},
	[]string{"cause"}, // no_preamble | untrusted_peer | malformed
)

// MaxLineLength bounds a version 1 preamble, per the protocol
// (docs/spec/traffic.md Proxy protocol).
const MaxLineLength = 107

// readTimeout bounds how long a connection may take to deliver its
// preamble. It only covers the preamble: the connection keeps its own
// deadlines afterwards.
const readTimeout = 10 * time.Second

// signature opens a version 2 preamble.
var signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// Version 2 command and family bytes.
const (
	cmdLocal = 0x20 // version 2, LOCAL: the proxy speaks for itself
	cmdProxy = 0x21 // version 2, PROXY: the proxy speaks for a client

	famUnspec = 0x00
	famTCP4   = 0x11
	famTCP6   = 0x21
)

var (
	// ErrNoPreamble reports a connection that did not begin with one.
	ErrNoPreamble = errors.New("no proxy protocol preamble")
	// ErrUntrusted reports a preamble from a peer outside the trust list.
	ErrUntrusted = errors.New("proxy protocol preamble from an untrusted peer")
)

// TrustFunc reports whether a peer may speak for a client
// (docs/spec/security.md Client IP trust).
type TrustFunc func(netip.Addr) bool

// Read consumes the preamble and returns the client address it carries.
// A LOCAL or UNKNOWN preamble returns an invalid address: it names no
// client, and the caller keeps the peer.
func Read(r *bufio.Reader) (netip.AddrPort, error) {
	prefix, err := r.Peek(len(signature))
	if err != nil {
		return netip.AddrPort{}, ErrNoPreamble
	}

	if string(prefix) == string(signature) {
		return readV2(r)
	}

	if string(prefix[:6]) != "PROXY " {
		return netip.AddrPort{}, ErrNoPreamble
	}

	return readV1(r)
}

// readV1 parses the text form: PROXY <family> <src> <dst> <sport> <dport>.
func readV1(r *bufio.Reader) (netip.AddrPort, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("truncated preamble: %w", err)
	}

	if len(line) > MaxLineLength {
		return netip.AddrPort{}, fmt.Errorf("preamble longer than %d bytes", MaxLineLength)
	}

	fields := strings.Fields(strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"))

	// UNKNOWN carries nothing usable, whatever follows it.
	if len(fields) >= 2 && fields[1] == "UNKNOWN" {
		return netip.AddrPort{}, nil
	}

	if len(fields) != 6 {
		return netip.AddrPort{}, fmt.Errorf("malformed preamble %q", line)
	}

	source, err := netip.ParseAddr(fields[2])
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid source address %q", fields[2])
	}

	switch fields[1] {
	case "TCP4":
		if !source.Is4() {
			return netip.AddrPort{}, fmt.Errorf("address %q is not IPv4", fields[2])
		}

	case "TCP6":
		if !source.Is6() || source.Is4In6() {
			return netip.AddrPort{}, fmt.Errorf("address %q is not IPv6", fields[2])
		}

	default:
		return netip.AddrPort{}, fmt.Errorf("unsupported transport %q", fields[1])
	}

	port, err := strconv.ParseUint(fields[4], 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid source port %q", fields[4])
	}

	return netip.AddrPortFrom(source, uint16(port)), nil
}

// readV2 parses the binary form: signature, version/command, family, and a
// declared address block whose trailing type-length-value entries are
// skipped without being interpreted.
func readV2(r *bufio.Reader) (netip.AddrPort, error) {
	header := make([]byte, len(signature)+4)
	if _, err := io.ReadFull(r, header); err != nil {
		return netip.AddrPort{}, fmt.Errorf("truncated preamble: %w", err)
	}

	command := header[len(signature)]
	family := header[len(signature)+1]
	length := int(header[len(signature)+2])<<8 | int(header[len(signature)+3])

	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return netip.AddrPort{}, fmt.Errorf("truncated address block: %w", err)
	}

	switch command {
	case cmdLocal:
		// The proxy speaks for itself: health checks, keepalives.
		return netip.AddrPort{}, nil

	case cmdProxy:

	default:
		return netip.AddrPort{}, fmt.Errorf("unsupported version or command %#02x", command)
	}

	var size int
	switch family {
	case famTCP4:
		size = 4

	case famTCP6:
		size = 16

	case famUnspec:
		return netip.AddrPort{}, nil

	default:
		return netip.AddrPort{}, fmt.Errorf("unsupported address family %#02x", family)
	}

	// Source address, destination address, then both ports.
	if length < size*2+4 {
		return netip.AddrPort{}, fmt.Errorf("address block shorter than family %#02x", family)
	}

	source, ok := netip.AddrFromSlice(body[:size])
	if !ok {
		return netip.AddrPort{}, errors.New("invalid source address")
	}

	port := int(body[size*2])<<8 | int(body[size*2+1])

	return netip.AddrPortFrom(source, uint16(port)), nil
}

// Wrap returns a listener whose connections require a preamble from a
// trusted peer (docs/spec/traffic.md Proxy protocol). The preamble is read
// on first use of the connection, not during Accept, so a slow or hostile
// client delays only itself.
func Wrap(ln net.Listener, trusted TrustFunc) net.Listener {
	return &listener{Listener: ln, trusted: trusted}
}

type listener struct {
	net.Listener
	trusted TrustFunc
}

var _ net.Listener = (*listener)(nil)

func (l *listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &Conn{Conn: conn, reader: bufio.NewReader(conn), trusted: l.trusted}, nil
}

// Conn is an accepted connection whose peer address is the one its
// preamble names.
type Conn struct {
	net.Conn

	reader  *bufio.Reader
	trusted TrustFunc

	once   sync.Once
	source netip.AddrPort
	err    error
}

var _ net.Conn = (*Conn)(nil)

// preamble reads the preamble exactly once, whichever call needs it first.
// The read has its own deadline: the connection's own deadlines apply to
// the traffic that follows.
func (c *Conn) preamble() error {
	c.once.Do(func() {
		peer, err := peerAddr(c.Conn.RemoteAddr())
		if err != nil {
			c.reject("malformed", err)
			return
		}

		if c.trusted == nil || !c.trusted(peer) {
			c.reject("untrusted_peer", ErrUntrusted)
			return
		}

		c.Conn.SetReadDeadline(time.Now().Add(readTimeout))
		defer c.Conn.SetReadDeadline(time.Time{})

		source, err := Read(c.reader)
		if err != nil {
			cause := "malformed"
			if errors.Is(err, ErrNoPreamble) {
				cause = "no_preamble"
			}

			c.reject(cause, err)
			return
		}

		c.source = source
	})

	return c.err
}

// reject records the refusal and closes the connection: no request was
// read, so there is no response to give (docs/spec/traffic.md Proxy
// protocol, docs/spec/observability.md).
func (c *Conn) reject(cause string, err error) {
	c.err = err

	connectionsRejected.WithLabelValues(cause).Inc()
	slog.Warn("connection rejected",
		"peer", c.Conn.RemoteAddr().String(),
		"cause", cause,
		"error", err,
	)

	c.Conn.Close()
}

func (c *Conn) Read(b []byte) (int, error) {
	if err := c.preamble(); err != nil {
		return 0, err
	}

	return c.reader.Read(b)
}

func (c *Conn) Write(b []byte) (int, error) {
	if err := c.preamble(); err != nil {
		return 0, err
	}

	return c.Conn.Write(b)
}

// RemoteAddr reports the client the preamble names, or the peer when it
// named none. Servers read it before the first byte of the request, so it
// waits for the preamble like Read does.
func (c *Conn) RemoteAddr() net.Addr {
	if err := c.preamble(); err == nil && c.source.IsValid() {
		return net.TCPAddrFromAddrPort(c.source)
	}

	return c.Conn.RemoteAddr()
}

// CloseWrite half-closes the connection, which the raw stream forwarder
// relies on (docs/spec/traffic.md TCP forwarding).
func (c *Conn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}

	return nil
}

func peerAddr(addr net.Addr) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return netip.Addr{}, fmt.Errorf("unusable peer address %q", addr)
	}

	peer, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("unusable peer address %q", addr)
	}

	return peer.Unmap().WithZone(""), nil
}
