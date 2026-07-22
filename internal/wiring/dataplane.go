package wiring

import (
	"go.uber.org/fx"

	"github.com/link-society/krouter/internal/app/dataplane"
	"github.com/link-society/krouter/internal/lib/transports/http/routing"
)

var dataPlaneModule = fx.Module("dataplane",
	fx.Provide(
		routing.NewState,
		dataplane.NewRoot,
	),
	fx.Invoke(supervise),
)
