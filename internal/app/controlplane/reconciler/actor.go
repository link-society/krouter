// Package reconciler is the control-plane's single-writer actor: it drives
// one gatewayapi engine pass every two seconds, serialized like a
// gen_server. All domain logic lives in the gatewayapi package.
package reconciler

import (
	"k8s.io/client-go/kubernetes"

	extclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"

	gwclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/config"
	"github.com/link-society/krouter/internal/lib/k8s/gatewayapi"
	"github.com/link-society/krouter/internal/lib/snapshot"
)

// Reconciler is the reconciliation actor.
type Reconciler struct {
	actor.Actor
}

var _ actor.Actor = (*Reconciler)(nil)

func New(
	cfg *config.Settings,
	client kubernetes.Interface,
	gwClient gwclient.Interface,
	extClient extclient.Interface,
	acks *snapshot.Store[gatewayapi.AckState],
) *Reconciler {
	w := &worker{
		engine: gatewayapi.NewEngine(cfg, client, gwClient, extClient),
		acks:   acks,
	}

	return &Reconciler{Actor: actor.New(w)}
}
