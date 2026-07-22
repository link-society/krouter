// Package resolver is the backend discovery actor: it watches Services and
// EndpointSlices in the namespaces declared by the loader actor and
// publishes endpoint snapshots for the request path (docs/spec/traffic.md).
package resolver

import (
	"k8s.io/client-go/kubernetes"

	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/lib/snapshot"
	"github.com/link-society/krouter/internal/lib/transports/http/routing"
)

// Resolver is the backend discovery actor.
type Resolver struct {
	actor.Actor
}

var _ actor.Actor = (*Resolver)(nil)

func New(
	client kubernetes.Interface,
	in actor.MailboxReceiver[map[string]bool],
	out *snapshot.Store[*routing.EndpointsIndex],
) *Resolver {
	w := &worker{
		client:     client,
		in:         in,
		out:        out,
		namespaces: map[string]bool{},
	}

	return &Resolver{Actor: actor.New(w)}
}
