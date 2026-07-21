package listeners

import (
	"log/slog"

	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/app/dataplane/listeners/portserver"
	"github.com/link-society/krouter/internal/lib/http/proxy"
	"github.com/link-society/krouter/internal/lib/http/routing"
)

// worker reconciles the portserver children against the published tables.
// It is the only goroutine touching the children map.
type worker struct {
	in      actor.MailboxReceiver[*routing.Tables]
	handler *proxy.Handler

	children map[int32]*portserver.Server
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

	// Stop children whose port disappeared: new accepts stop while existing
	// connections finish within normal server limits (docs/spec/traffic.md).
	for port, srv := range w.children {
		if _, ok := ports[port]; ok {
			continue
		}

		slog.Info("stopping listener", "port", port)
		delete(w.children, port)
		srv.Stop()
	}

	// Start a child actor for every new port.
	for port, withTLS := range ports {
		if _, ok := w.children[port]; ok {
			continue
		}

		srv, err := portserver.New(port, withTLS, w.handler)
		if err != nil {
			slog.Error("failed to start listener", "port", port, "error", err)
			continue
		}

		srv.Start()
		w.children[port] = srv
	}
}

// stopAll drains every listener on supervisor shutdown (docs/spec/traffic.md).
func (w *worker) stopAll() {
	for port, srv := range w.children {
		delete(w.children, port)
		srv.Stop()
	}
}
