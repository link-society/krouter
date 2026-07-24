package reconciler

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/lib/k8s/gatewayapi"
	"github.com/link-society/krouter/internal/lib/snapshot"
)

var reconcileDuration = promauto.NewHistogram(
	prometheus.HistogramOpts{
		Name:    "krouter_controlplane_reconcile_duration_seconds",
		Help:    "Duration of one full reconciliation pass.",
		Buckets: prometheus.DefBuckets,
	},
)

// worker runs one engine pass every two seconds with the latest published
// acknowledgement state, and publishes the resulting topology snapshot for
// the dashboard.
type worker struct {
	engine *gatewayapi.Engine
	acks   *snapshot.Store[gatewayapi.AckState]
	topo   *snapshot.Store[*gatewayapi.Topology]
}

var _ actor.Worker = (*worker)(nil)

// syncInterval paces the level-triggered full sync (docs/spec/architecture.md):
// a shorter interval only trades API server load for status latency.
const syncInterval = 2 * time.Second

func (w *worker) DoWork(ctx actor.Context) actor.WorkerStatus {
	start := time.Now()

	if topo := w.engine.Sync(ctx, w.acks.Load()); topo != nil {
		w.topo.Publish(topo)
	}

	reconcileDuration.Observe(time.Since(start).Seconds())

	select {
	case <-ctx.Done():
		return actor.WorkerEnd

	case <-time.After(syncInterval):
		return actor.WorkerContinue
	}
}
