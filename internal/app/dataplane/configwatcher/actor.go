// Package configwatcher is the actor watching controller-generated
// configuration in the system namespace (docs/spec/architecture.md): it polls ConfigMaps
// and Secrets and mails a consistent snapshot to the loader actor whenever
// anything changed.
package configwatcher

import (
	"k8s.io/client-go/kubernetes"

	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/config"
)

// Watcher is the configuration watcher actor.
type Watcher struct {
	actor.Actor
}

var _ actor.Actor = (*Watcher)(nil)

func New(
	cfg *config.Settings,
	client kubernetes.Interface,
	out actor.MailboxSender[RawConfig],
) *Watcher {
	w := &worker{
		client:    client,
		namespace: cfg.SystemNamespace,
		out:       out,
	}

	return &Watcher{Actor: actor.New(w)}
}
