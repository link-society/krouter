package wiring

import (
	"go.uber.org/fx"

	"github.com/link-society/krouter/internal/lib/k8s/client"
)

var k8sModule = fx.Module("k8s",
	fx.Provide(
		client.NewRestConfig,
		client.NewKubernetesClient,
		client.NewGatewayClient,
		client.NewExtensionsClient,
	),
)
