// Package controlplane is the control-plane supervisor (docs/spec/architecture.md). The
// package hierarchy mirrors the supervision tree:
//
//	controlplane (supervisor)
//	 ├─ ackpoller/  — polls data-plane pods for applied generations
//	 ├─ reconciler/ — drives the gatewayapi engine, single writer
//	 └─ mgmt        — management server actor
package controlplane

import (
	"k8s.io/client-go/kubernetes"

	extclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"

	gwclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/app/controlplane/ackpoller"
	"github.com/link-society/krouter/internal/app/controlplane/reconciler"
	"github.com/link-society/krouter/internal/app/mgmt"
	"github.com/link-society/krouter/internal/config"
	"github.com/link-society/krouter/internal/lib/k8s/gatewayapi"
	"github.com/link-society/krouter/internal/lib/snapshot"
)

func NewRoot(
	cfg *config.Settings,
	client kubernetes.Interface,
	gwClient gwclient.Interface,
	extClient extclient.Interface,
) actor.Actor {
	acks := snapshot.New(gatewayapi.EmptyAckState())

	readyz := func() ([]byte, int) { return []byte(`{"ready":true}`), 200 }

	return actor.Combine(
		ackpoller.New(cfg, client, acks),
		reconciler.New(cfg, client, gwClient, extClient, acks),
		mgmt.New(cfg, readyz),
	).Build()
}
