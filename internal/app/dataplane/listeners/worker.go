package listeners

import (
	"log/slog"

	"sync"

	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/app/dataplane/listeners/portserver"
	"github.com/link-society/krouter/internal/app/dataplane/listeners/tcpserver"
	"github.com/link-society/krouter/internal/app/dataplane/listeners/tlsserver"
	"github.com/link-society/krouter/internal/lib/transports/http/proxy"
	"github.com/link-society/krouter/internal/lib/transports/http/routing"
	"github.com/link-society/krouter/internal/lib/transports/tcp"
	"github.com/link-society/krouter/internal/lib/transports/tls"
)

// worker reconciles the listener children against the published tables.
// It is the only goroutine touching the children map.
type worker struct {
	in           actor.MailboxReceiver[*routing.Tables]
	handler      *proxy.Handler
	forwarder    *tcp.Forwarder
	tlsForwarder *tls.Forwarder

	children map[int32]actor.Actor
	specs    map[int32]routing.PortSpec
}

var _ actor.Worker = (*worker)(nil)

func (w *worker) DoWork(ctx actor.Context) actor.WorkerStatus {
	select {
	case <-ctx.Done():
		w.stopAll()

		return actor.WorkerEnd

	case tables := <-w.in.ReceiveC():
		w.reconcile(tables)

		return actor.WorkerContinue
	}
}

func (w *worker) reconcile(tables *routing.Tables) {
	ports := tables.Ports()

	// Stop children whose port disappeared or changed kind: new accepts
	// stop while existing connections finish within normal server limits
	// (docs/spec/traffic.md).
	for port, srv := range w.children {
		spec, ok := ports[port]
		if ok && spec == w.specs[port] {
			continue
		}

		slog.Info("stopping listener", "port", port)
		delete(w.children, port)
		delete(w.specs, port)
		srv.Stop()
	}

	// Start a child actor for every new port.
	for port, spec := range ports {
		if _, ok := w.children[port]; ok {
			continue
		}

		var srv actor.Actor
		var err error

		switch {
		case spec.TCP:
			srv, err = tcpserver.New(port, w.forwarder)

		case spec.TLSPassthrough:
			srv, err = tlsserver.New(port, w.tlsForwarder)

		default:
			srv, err = portserver.New(port, spec.TLS, w.handler)
		}

		if err != nil {
			slog.Error("failed to start listener", "port", port, "error", err)
			continue
		}

		srv.Start()
		w.children[port] = srv
		w.specs[port] = spec
	}
}

// stopAll drains every listener on supervisor shutdown (docs/spec/traffic.md).
// Stop is synchronous, so the children drain in parallel to stay within the
// pod's termination grace period.
func (w *worker) stopAll() {
	var wg sync.WaitGroup

	for port, srv := range w.children {
		delete(w.children, port)
		delete(w.specs, port)
		wg.Go(srv.Stop)
	}

	wg.Wait()
}
