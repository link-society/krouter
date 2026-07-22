// Package tls is the data-plane TLS passthrough path: it reads the SNI
// value from the ClientHello without terminating the session, selects a
// backend endpoint per connection, and forwards the still-encrypted stream
// (docs/spec/traffic.md). The backend owns TLS end to end
// (docs/spec/security.md). It is deliberately not an actor — it is the
// engine the tlsserver actors drive.
package tls

import (
	"log/slog"

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

	// Replay the recorded ClientHello: the backend performs the handshake
	// with the original client bytes (docs/spec/traffic.md).
	if _, err := backend.Write(recorded); err != nil {
		connectionsTotal.WithLabelValues("error").Inc()

		return
	}

	activeConnections.Inc()
	defer activeConnections.Dec()

	received, sent := tcp.Splice(downstream, backend)

	connectionsTotal.WithLabelValues("forwarded").Inc()

	// One access-log event per closed connection (docs/spec/observability.md).
	slog.Info("tls connection closed",
		"gateway", selection.Gateway,
		"route", selection.Route,
		"backend", selection.Backend,
		"endpoint", selection.Endpoint,
		"client", downstream.RemoteAddr().String(),
		"protocol", "TLS",
		"sni", sni,
		"duration", time.Since(start).String(),
		"bytes_received", received+int64(len(recorded)),
		"bytes_sent", sent,
	)
}
