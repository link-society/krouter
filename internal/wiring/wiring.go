// Package wiring is the composition root: every fx definition lives here.
// It assembles the dependency graph and runs the selected plane's actor
// supervision tree under the fx application lifecycle — mirroring an OTP
// application starting its root supervisor.
package wiring

import (
	"fmt"
	"log/slog"

	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"

	"github.com/link-society/krouter/internal/config"
)

// New assembles the fx application for the configured mode (docs/spec/deployment.md).
func New(cfg *config.Settings, logger *slog.Logger) (*fx.App, error) {
	var plane fx.Option

	switch cfg.Mode {
	case config.ModeControlPlane:
		plane = controlPlaneModule

	case config.ModeDataPlane:
		plane = dataPlaneModule

	default:
		return nil, fmt.Errorf(
			"KROUTER_MODE must be 'controlplane' or 'dataplane' (got %q)",
			cfg.Mode,
		)
	}

	return fx.New(
		fx.Supply(cfg),
		fx.WithLogger(func() fxevent.Logger {
			return &fxevent.SlogLogger{Logger: logger}
		}),
		k8sModule,
		plane,
	), nil
}
