// Package loader is the single-writer actor of the routing tables. For
// every raw configuration snapshot it loads each Gateway's desired
// generation, verifies identity and checksums (docs/spec/configuration.md), activates it
// atomically, and falls back to the last valid generation on failure
// (docs/spec/configuration.md). Errors in one Gateway never invalidate another (docs/spec/architecture.md).
package loader

import (
	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/app/dataplane/configwatcher"
	"github.com/link-society/krouter/internal/lib/transports/http/routing"
)

// Loader is the table loading actor.
type Loader struct {
	actor.Actor
}

var _ actor.Actor = (*Loader)(nil)

func New(
	state *routing.State,
	in actor.MailboxReceiver[configwatcher.RawConfig],
	tablesOut actor.MailboxSender[*routing.Tables],
	namespaces actor.MailboxSender[map[string]bool],
) *Loader {
	w := &worker{
		in:         in,
		tablesOut:  tablesOut,
		namespaces: namespaces,
		state:      state,
		applied:    map[string]*routing.GatewayTable{},
	}

	return &Loader{Actor: actor.New(w)}
}
