// Package listeners is the dynamic supervisor of the data-plane internal
// listeners (docs/spec/architecture.md): one portserver (HTTP), tcpserver
// (TCP) or tlsserver (TLS passthrough) child actor per allocated port.
// Children are only started or stopped when their port appears, disappears
// or changes kind, so reloads that keep a port never touch its connections
// (docs/spec/traffic.md, docs/spec/performance.md).
package listeners

import (
	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/lib/transports/http/proxy"
	"github.com/link-society/krouter/internal/lib/transports/http/routing"
	"github.com/link-society/krouter/internal/lib/transports/tcp"
	"github.com/link-society/krouter/internal/lib/transports/tls"
)

// Manager is the dynamic supervisor actor.
type Manager struct {
	actor.Actor
}

var _ actor.Actor = (*Manager)(nil)

func New(in actor.MailboxReceiver[*routing.Tables], state *routing.State) *Manager {
	w := &worker{
		in:           in,
		handler:      proxy.NewHandler(state),
		forwarder:    tcp.NewForwarder(state),
		tlsForwarder: tls.NewForwarder(state),
		children:     map[int32]actor.Actor{},
		specs:        map[int32]routing.PortSpec{},
	}

	return &Manager{Actor: actor.New(w)}
}
