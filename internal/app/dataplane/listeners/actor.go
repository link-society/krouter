// Package listeners is the dynamic supervisor of the data-plane internal
// listeners (docs/spec/architecture.md): one portserver child actor per allocated port.
// Children are only started or stopped when their port appears or
// disappears, so reloads that keep a port never touch its connections
// (docs/spec/traffic.md, docs/spec/performance.md).
package listeners

import (
	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/app/dataplane/listeners/portserver"
	"github.com/link-society/krouter/internal/lib/http/proxy"
	"github.com/link-society/krouter/internal/lib/http/routing"
)

// Manager is the dynamic supervisor actor.
type Manager struct {
	actor.Actor
}

var _ actor.Actor = (*Manager)(nil)

func New(in actor.MailboxReceiver[*routing.Tables], state *routing.State) *Manager {
	w := &worker{
		in:       in,
		handler:  proxy.NewHandler(state),
		children: map[int32]*portserver.Server{},
	}

	return &Manager{Actor: actor.New(w)}
}
