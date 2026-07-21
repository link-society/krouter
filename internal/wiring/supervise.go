package wiring

import (
	"context"

	"github.com/vladopajic/go-actor/actor"

	"go.uber.org/fx"
)

// supervise runs a plane's root actor under the fx lifecycle: started when
// the application starts, stopped in reverse order on shutdown — like an
// OTP application supervising its root.
func supervise(lc fx.Lifecycle, root actor.Actor) {
	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			root.Start()

			return nil
		},
		OnStop: func(context.Context) error {
			root.Stop()

			return nil
		},
	})
}
