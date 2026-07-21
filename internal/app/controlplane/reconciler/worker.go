package reconciler

import (
	"time"

	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/lib/k8s/gatewayapi"
	"github.com/link-society/krouter/internal/lib/snapshot"
)

// worker runs one engine pass every two seconds with the latest published
// acknowledgement state.
type worker struct {
	engine *gatewayapi.Engine
	acks   *snapshot.Store[gatewayapi.AckState]
}

var _ actor.Worker = (*worker)(nil)

func (w *worker) DoWork(ctx actor.Context) actor.WorkerStatus {
	w.engine.Sync(ctx, w.acks.Load())

	select {
	case <-ctx.Done():
		return actor.WorkerEnd

	case <-time.After(2 * time.Second):
		return actor.WorkerContinue
	}
}
