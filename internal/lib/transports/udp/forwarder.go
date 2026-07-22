// Package udp is the data-plane datagram path: it forwards downstream UDP
// datagrams to backend endpoints, associated into flows by client source
// address (docs/spec/traffic.md). A flow keeps its selected backend until
// it has been idle for a bounded period; backend responses are relayed to
// the flow's client. It is deliberately not an actor — it is the engine
// the udpserver actors drive.
package udp

import (
	"log/slog"

	"net"

	"sync"

	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var flowsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "krouter_dataplane_udp_flows_total",
		Help: "UDP flows handled by the data plane, by result.",
	},
	[]string{"result"}, // forwarded | refused | error
)

var activeFlows = promauto.NewGauge(
	prometheus.GaugeOpts{
		Name: "krouter_dataplane_udp_active_flows",
		Help: "UDP flows currently forwarded by the data plane.",
	},
)

var bytesTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "krouter_dataplane_udp_bytes_total",
		Help: "Bytes forwarded by the data plane, by direction.",
	},
	[]string{"direction"}, // downstream_to_backend | backend_to_downstream
)

// idleTimeout bounds the lifetime of a silent flow (docs/spec/traffic.md).
const idleTimeout = 60 * time.Second

// maxDatagram is the read buffer size for one datagram.
const maxDatagram = 64 * 1024

// Selection identifies the backend endpoint chosen for one flow, with the
// identities required by the flow log (docs/spec/observability.md).
type Selection struct {
	Endpoint string // host:port
	Gateway  string // namespace/name
	Route    string // namespace/name
	Backend  string // namespace/name:port
}

// Picker selects a backend endpoint for one new flow on an internal
// listener port, applying route weights, endpoint eligibility and the
// class load-balancing algorithm (docs/spec/traffic.md).
type Picker interface {
	PickUDP(port int32) (Selection, bool)
}

// Forwarder is the datagram engine shared by every udpserver actor.
type Forwarder struct {
	picker Picker
}

func NewForwarder(picker Picker) *Forwarder {
	return &Forwarder{picker: picker}
}

// flow is one client source address pinned to one backend endpoint.
type flow struct {
	upstream  *net.UDPConn
	client    *net.UDPAddr
	selection Selection
	started   time.Time

	mu       sync.Mutex
	received int64 // bytes downstream -> backend
	sent     int64 // bytes backend -> downstream
}

// Serve runs the datagram loop on one bound listener until the listener is
// closed. Datagrams from unknown sources open a flow (or are dropped when
// no backend endpoint is selectable, docs/spec/failure-modes.md); known
// sources reuse their flow's backend.
func (f *Forwarder) Serve(conn *net.UDPConn, port int32) {
	var mu sync.Mutex
	flows := map[string]*flow{}

	defer func() {
		mu.Lock()
		defer mu.Unlock()

		for _, fl := range flows {
			fl.upstream.Close()
		}
	}()

	buf := make([]byte, maxDatagram)

	for {
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			// The listener was closed by Stop.
			return
		}

		key := client.String()

		mu.Lock()
		fl, ok := flows[key]
		mu.Unlock()

		if !ok {
			fl = f.openFlow(conn, client, port)
			if fl == nil {
				continue
			}

			mu.Lock()
			flows[key] = fl
			mu.Unlock()

			activeFlows.Inc()

			go func() {
				f.relayResponses(conn, fl)

				mu.Lock()
				delete(flows, key)
				mu.Unlock()

				activeFlows.Dec()
				f.logFlow(fl)
			}()
		}

		if _, err := fl.upstream.Write(buf[:n]); err != nil {
			continue
		}

		fl.mu.Lock()
		fl.received += int64(n)
		fl.mu.Unlock()

		bytesTotal.WithLabelValues("downstream_to_backend").Add(float64(n))
		fl.upstream.SetReadDeadline(time.Now().Add(idleTimeout))
	}
}

// openFlow selects a backend endpoint and connects the upstream socket.
func (f *Forwarder) openFlow(conn *net.UDPConn, client *net.UDPAddr, port int32) *flow {
	selection, ok := f.picker.PickUDP(port)
	if !ok {
		flowsTotal.WithLabelValues("refused").Inc()
		slog.Warn("udp datagram dropped", "port", port, "client", client.String())

		return nil
	}

	upstream, err := net.Dial("udp", selection.Endpoint)
	if err != nil {
		flowsTotal.WithLabelValues("error").Inc()
		slog.Error("udp backend dial failed",
			"port", port,
			"endpoint", selection.Endpoint,
			"error", err,
		)

		return nil
	}

	udpUpstream := upstream.(*net.UDPConn)
	udpUpstream.SetReadDeadline(time.Now().Add(idleTimeout))

	return &flow{
		upstream:  udpUpstream,
		client:    client,
		selection: selection,
		started:   time.Now(),
	}
}

// relayResponses copies backend datagrams back to the flow's client until
// the flow has been idle for the bounded period (docs/spec/traffic.md).
func (f *Forwarder) relayResponses(conn *net.UDPConn, fl *flow) {
	defer fl.upstream.Close()

	buf := make([]byte, maxDatagram)

	for {
		n, err := fl.upstream.Read(buf)
		if err != nil {
			// Idle deadline reached, or the listener is stopping.
			return
		}

		if _, err := conn.WriteToUDP(buf[:n], fl.client); err != nil {
			return
		}

		fl.mu.Lock()
		fl.sent += int64(n)
		fl.mu.Unlock()

		bytesTotal.WithLabelValues("backend_to_downstream").Add(float64(n))
		fl.upstream.SetReadDeadline(time.Now().Add(idleTimeout))
	}
}

// logFlow writes one event per expired flow (docs/spec/observability.md).
func (f *Forwarder) logFlow(fl *flow) {
	flowsTotal.WithLabelValues("forwarded").Inc()

	fl.mu.Lock()
	received, sent := fl.received, fl.sent
	fl.mu.Unlock()

	slog.Info("udp flow expired",
		"gateway", fl.selection.Gateway,
		"route", fl.selection.Route,
		"backend", fl.selection.Backend,
		"endpoint", fl.selection.Endpoint,
		"client", fl.client.String(),
		"protocol", "UDP",
		"duration", time.Since(fl.started).String(),
		"bytes_received", received,
		"bytes_sent", sent,
	)
}
