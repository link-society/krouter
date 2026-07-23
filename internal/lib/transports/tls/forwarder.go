// Package tls is the data-plane TLS routing path: it reads the SNI value
// from the ClientHello, selects a backend endpoint per connection, and
// either forwards the still-encrypted stream (Passthrough listeners) or
// terminates the session with the listener certificate and forwards the
// decrypted stream (Terminate listeners) — docs/spec/traffic.md TLS
// passthrough and termination. It is deliberately not an actor — it is
// the engine the tlsserver actors drive.
package tls

import (
	"log/slog"

	"bytes"
	"io"

	stdtls "crypto/tls"
	"net"

	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/link-society/krouter/internal/lib/transports/tcp"
)

var connectionsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "krouter_dataplane_tls_connections_total",
		Help: "TLS passthrough connections handled by the data plane, by result.",
	},
	[]string{"result"}, // forwarded | refused | error
)

var activeConnections = promauto.NewGauge(
	prometheus.GaugeOpts{
		Name: "krouter_dataplane_tls_active_connections",
		Help: "TLS passthrough connections currently forwarded by the data plane.",
	},
)

// Selection identifies the backend endpoint chosen for one downstream
// connection, with the identities required by the access log
// (docs/spec/observability.md).
type Selection struct {
	Endpoint string // host:port
	Gateway  string // namespace/name
	Route    string // namespace/name
	Backend  string // namespace/name:port

	// Terminate marks a Terminate-mode listener: the session ends at the
	// gateway with Certificate, and the decrypted stream is forwarded
	// (docs/spec/traffic.md TLS passthrough and termination).
	Terminate   bool
	Certificate *stdtls.Certificate
}

// Picker selects a backend endpoint for one new downstream connection on
// an internal TLS passthrough listener port, matching the SNI value
// against listener and TLSRoute hostnames (docs/spec/traffic.md).
type Picker interface {
	PickTLS(port int32, sni string) (Selection, bool)
}

// Forwarder is the passthrough engine shared by every tlsserver actor.
type Forwarder struct {
	picker       Picker
	helloTimeout time.Duration
	dialTimeout  time.Duration
}

func NewForwarder(picker Picker) *Forwarder {
	return &Forwarder{
		picker:       picker,
		helloTimeout: 10 * time.Second,
		dialTimeout:  10 * time.Second,
	}
}

// Serve forwards one accepted downstream connection. Connections whose SNI
// matches no route are refused without completing a handshake
// (docs/spec/traffic.md, docs/spec/failure-modes.md).
func (f *Forwarder) Serve(downstream net.Conn, port int32) {
	defer downstream.Close()

	start := time.Now()

	downstream.SetReadDeadline(time.Now().Add(f.helloTimeout))

	sni, recorded, err := peekClientHello(downstream)
	if err != nil {
		connectionsTotal.WithLabelValues("refused").Inc()
		slog.Warn("tls connection rejected: unreadable ClientHello",
			"port", port,
			"client", downstream.RemoteAddr().String(),
			"error", err,
		)

		return
	}

	downstream.SetReadDeadline(time.Time{})

	selection, ok := f.picker.PickTLS(port, sni)
	if !ok {
		connectionsTotal.WithLabelValues("refused").Inc()
		slog.Warn("tls connection refused",
			"port", port,
			"sni", sni,
			"client", downstream.RemoteAddr().String(),
		)

		return
	}

	if selection.Terminate {
		f.serveTerminated(downstream, recorded, selection, port, sni, start)
		return
	}

	// Replay the recorded ClientHello: the backend performs the handshake
	// with the original client bytes (docs/spec/traffic.md).
	f.forward(downstream, selection, port, sni, "", recorded, start)
}

// forward dials the backend, optionally replays prefix bytes into it,
// splices the stream with the backend, and emits the metrics and access
// log shared by the passthrough and terminate paths
// (docs/spec/observability.md).
func (f *Forwarder) forward(
	stream net.Conn,
	selection Selection,
	port int32,
	sni, mode string,
	prefix []byte,
	start time.Time,
) {
	backend, err := net.DialTimeout("tcp", selection.Endpoint, f.dialTimeout)
	if err != nil {
		connectionsTotal.WithLabelValues("error").Inc()
		slog.Error("tls backend dial failed",
			"port", port,
			"sni", sni,
			"endpoint", selection.Endpoint,
			"error", err,
		)

		return
	}
	defer backend.Close()

	if len(prefix) > 0 {
		if _, err := backend.Write(prefix); err != nil {
			connectionsTotal.WithLabelValues("error").Inc()

			return
		}
	}

	activeConnections.Inc()
	defer activeConnections.Dec()

	received, sent := tcp.Splice(stream, backend)

	connectionsTotal.WithLabelValues("forwarded").Inc()

	// One access-log event per closed connection (docs/spec/observability.md).
	attrs := []any{
		"gateway", selection.Gateway,
		"route", selection.Route,
		"backend", selection.Backend,
		"endpoint", selection.Endpoint,
		"client", stream.RemoteAddr().String(),
		"protocol", "TLS",
	}

	if mode != "" {
		attrs = append(attrs, "mode", mode)
	}

	attrs = append(attrs,
		"sni", sni,
		"duration", time.Since(start).String(),
		"bytes_received", received+int64(len(prefix)),
		"bytes_sent", sent,
	)

	slog.Info("tls connection closed", attrs...)
}

// serveTerminated handles a Terminate-mode listener
// (docs/spec/traffic.md TLS passthrough and termination): the recorded
// ClientHello is replayed into a local handshake using the listener
// certificate, then the decrypted stream is forwarded to the backend with
// raw TCP semantics.
func (f *Forwarder) serveTerminated(
	downstream net.Conn,
	recorded []byte,
	selection Selection,
	port int32,
	sni string,
	start time.Time,
) {
	if selection.Certificate == nil {
		connectionsTotal.WithLabelValues("refused").Inc()
		return
	}

	tlsConn := stdtls.Server(
		&replayConn{
			Conn:   downstream,
			reader: io.MultiReader(bytes.NewReader(recorded), downstream),
		},
		&stdtls.Config{Certificates: []stdtls.Certificate{*selection.Certificate}},
	)

	downstream.SetReadDeadline(time.Now().Add(f.helloTimeout))

	if err := tlsConn.Handshake(); err != nil {
		connectionsTotal.WithLabelValues("refused").Inc()
		slog.Warn("tls handshake failed",
			"port", port,
			"sni", sni,
			"client", downstream.RemoteAddr().String(),
			"error", err,
		)

		return
	}

	downstream.SetReadDeadline(time.Time{})

	f.forward(tlsConn, selection, port, sni, "terminate", nil, start)
}

// replayConn prepends the recorded ClientHello bytes to the connection's
// read stream, so the local handshake sees the exact original bytes.
type replayConn struct {
	net.Conn
	reader io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
