// Package ackpoller is the actor polling every data-plane pod's management
// endpoint for its applied configuration generations (docs/spec/architecture.md, docs/spec/status.md).
// It publishes the acknowledgement state read by the reconciler actor.
package ackpoller

import (
	"net/http"

	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/config"
	"github.com/link-society/krouter/internal/lib/k8s/gatewayapi"
	"github.com/link-society/krouter/internal/lib/snapshot"
)

// Poller is the acknowledgement polling actor.
type Poller struct {
	actor.Actor
}

var _ actor.Actor = (*Poller)(nil)

func New(
	cfg *config.Settings,
	client kubernetes.Interface,
	out *snapshot.Store[gatewayapi.AckState],
) *Poller {
	w := &worker{
		client:     client,
		settings:   cfg,
		httpClient: &http.Client{Timeout: 2 * time.Second},
		out:        out,
	}

	return &Poller{Actor: actor.New(w)}
}
