// Package tcp is the data-plane raw stream path: it forwards downstream
// TCP connections to backend endpoints selected per connection
// (docs/spec/traffic.md). Bytes flow in both directions, uninterpreted,
// until either side closes. It is deliberately not an actor — it is the
// engine the tcpserver actors drive.
package tcp

import (
	"log/slog"

	"io"
	"net"

	"sync"

	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var connectionsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "krouter_dataplane_tcp_connections_total",
		Help: "TCP connections handled by the data plane, by result.",
	},
	[]string{"result"}, // forwarded | refused | error
)

var activeConnections = promauto.NewGauge(
	prometheus.GaugeOpts{
		Name: "krouter_dataplane_tcp_active_connections",
		Help: "TCP connections currently forwarded by the data plane.",
	},
)

var bytesTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "krouter_dataplane_tcp_bytes_total",
		Help: "Bytes forwarded by the data plane, by direction.",
	},
	[]string{"direction"}, // downstream_to_backend | backend_to_downstream
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
// an internal listener port, applying route weights, endpoint eligibility
// and the class load-balancing algorithm (docs/spec/traffic.md).
type Picker interface {
	PickTCP(port int32) (Selection, bool)
}

// Forwarder is the raw stream engine shared by every tcpserver actor.
type Forwarder struct {
	picker      Picker
	dialTimeout time.Duration
}

func NewForwarder(picker Picker) *Forwarder {
	return &Forwarder{
		picker:      picker,
		dialTimeout: 10 * time.Second,
	}
}

// Serve forwards one accepted downstream connection. Backends without a
// selectable endpoint refuse the connection (docs/spec/failure-modes.md).
func (f *Forwarder) Serve(downstream net.Conn, port int32) {
	defer downstream.Close()

	start := time.Now()

	selection, ok := f.picker.PickTCP(port)
	if !ok {
		connectionsTotal.WithLabelValues("refused").Inc()
		slog.Warn("tcp connection refused",
			"port", port,
			"client", downstream.RemoteAddr().String(),
		)

		return
	}

	backend, err := net.DialTimeout("tcp", selection.Endpoint, f.dialTimeout)
	if err != nil {
		connectionsTotal.WithLabelValues("error").Inc()
		slog.Error("tcp backend dial failed",
			"port", port,
			"endpoint", selection.Endpoint,
			"error", err,
		)

		return
	}
	defer backend.Close()

	activeConnections.Inc()
	defer activeConnections.Dec()

	received, sent := Splice(downstream, backend)

	bytesTotal.WithLabelValues("downstream_to_backend").Add(float64(received))
	bytesTotal.WithLabelValues("backend_to_downstream").Add(float64(sent))

	connectionsTotal.WithLabelValues("forwarded").Inc()

	// One access-log event per closed connection (docs/spec/observability.md).
	slog.Info("tcp connection closed",
		"gateway", selection.Gateway,
		"route", selection.Route,
		"backend", selection.Backend,
		"endpoint", selection.Endpoint,
		"client", downstream.RemoteAddr().String(),
		"protocol", "TCP",
		"duration", time.Since(start).String(),
		"bytes_received", received,
		"bytes_sent", sent,
	)
}

// Splice copies bytes in both directions until each side closes, using
// half-closes so a one-way shutdown drains cleanly. It returns the bytes
// received from the downstream and sent back to it. It is shared with the
// TLS passthrough transport.
func Splice(downstream, backend net.Conn) (received, sent int64) {
	var wg sync.WaitGroup

	wg.Go(func() {
		received, _ = io.Copy(backend, downstream)
		closeWrite(backend)
	})

	wg.Go(func() {
		sent, _ = io.Copy(downstream, backend)
		closeWrite(downstream)
	})

	wg.Wait()

	return received, sent
}

func closeWrite(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.CloseWrite()

		return
	}

	conn.Close()
}
