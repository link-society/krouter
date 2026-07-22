// Package dataplane is the shared data-plane supervisor (docs/spec/architecture.md). The
// package hierarchy mirrors the supervision tree:
//
//	dataplane (supervisor)
//	 ├─ configwatcher/       — polls generated config, mails snapshots
//	 ├─ loader/              — verifies generations, owns the routing tables
//	 ├─ resolver/            — owns backend discovery
//	 ├─ listeners/           — dynamic supervisor
//	 │   └─ portserver/      — one child actor per internal port
//	 └─ mgmt                 — management server actor
//
// Actors communicate through mailboxes and publish immutable snapshots of
// the routing domain (lib/transports/http/routing) for the request path
// (lib/transports/http/proxy, lib/transports/tcp); there is no shared
// mutable state.
package dataplane

import (
	"k8s.io/client-go/kubernetes"

	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/app/dataplane/configwatcher"
	"github.com/link-society/krouter/internal/app/dataplane/listeners"
	"github.com/link-society/krouter/internal/app/dataplane/loader"
	"github.com/link-society/krouter/internal/app/dataplane/resolver"
	"github.com/link-society/krouter/internal/app/mgmt"
	"github.com/link-society/krouter/internal/config"
	"github.com/link-society/krouter/internal/lib/transports/http/routing"
)

func NewRoot(cfg *config.Settings, client kubernetes.Interface, state *routing.State) actor.Actor {
	rawMailbox := actor.NewMailbox[configwatcher.RawConfig]()
	tablesMailbox := actor.NewMailbox[*routing.Tables]()
	namespacesMailbox := actor.NewMailbox[map[string]bool]()

	return actor.Combine(
		rawMailbox,
		tablesMailbox,
		namespacesMailbox,
		configwatcher.New(cfg, client, rawMailbox),
		loader.New(state, rawMailbox, tablesMailbox, namespacesMailbox),
		resolver.New(client, namespacesMailbox, state.Endpoints),
		listeners.New(tablesMailbox, state),
		mgmt.New(cfg, state.Readyz),
	).Build()
}
