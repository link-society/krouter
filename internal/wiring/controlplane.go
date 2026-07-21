package wiring

import (
	"go.uber.org/fx"

	"github.com/link-society/krouter/internal/app/controlplane"
)

var controlPlaneModule = fx.Module("controlplane",
	fx.Provide(controlplane.NewRoot),
	fx.Invoke(supervise),
)
