package loader

import (
	"fmt"
	"log/slog"

	"encoding/json"

	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/app/dataplane/configwatcher"
	"github.com/link-society/krouter/internal/lib/k8s/compiled"
	"github.com/link-society/krouter/internal/lib/transports/http/routing"
)

// worker rebuilds and publishes the routing tables for every configuration
// snapshot received from the watcher actor.
type worker struct {
	in         actor.MailboxReceiver[configwatcher.RawConfig]
	tablesOut  actor.MailboxSender[*routing.Tables]
	namespaces actor.MailboxSender[map[string]bool]

	state   *routing.State
	applied map[string]*routing.GatewayTable
}

var _ actor.Worker = (*worker)(nil)

func (w *worker) DoWork(ctx actor.Context) actor.WorkerStatus {
	select {
	case <-ctx.Done():
		return actor.WorkerEnd

	case raw := <-w.in.ReceiveC():
		w.rebuild(ctx, raw)

		return actor.WorkerContinue
	}
}

func (w *worker) rebuild(ctx actor.Context, raw configwatcher.RawConfig) {
	applied := map[string]*routing.GatewayTable{}
	statuses := map[string]routing.GatewayStatus{}
	previousStatuses := w.state.Statuses.Load()

	for _, cm := range raw.ConfigMaps {
		if cm.Labels[compiled.LabelRole] != compiled.RoleManifest {
			continue
		}

		uid := cm.Labels[compiled.LabelGatewayUID]
		if uid == "" {
			continue
		}

		manifest := &compiled.Manifest{}
		status := routing.GatewayStatus{}

		err := json.Unmarshal([]byte(cm.Data[compiled.ManifestKey]), manifest)
		if err == nil {
			status.DesiredGeneration = manifest.Generation

			// Generations are content-addressed: reuse the live table when
			// the desired generation is already applied, so long-lived state
			// (weighted round-robin counters) survives watcher ticks and
			// only real changes swap tables (docs/spec/configuration.md).
			if previous, ok := w.applied[uid]; ok &&
				previous.Generation == manifest.Generation {
				applied[uid] = previous
				status.AppliedGeneration = manifest.Generation
				statuses[uid] = status

				continue
			}

			var table *routing.GatewayTable
			table, err = routing.LoadGeneration(manifest, raw.ConfigMaps, raw.Secrets)
			if err == nil {
				applied[uid] = table
				status.AppliedGeneration = manifest.Generation
			}
		} else {
			err = fmt.Errorf("invalid manifest: %w", err)
		}

		if err != nil {
			// Last-valid behavior (docs/spec/configuration.md): keep serving the previous
			// generation and report the error through readiness.
			slog.Warn("cannot load desired generation", "gateway", uid, "error", err)

			status.LastError = err.Error()

			if previous, ok := w.applied[uid]; ok {
				applied[uid] = previous
				status.AppliedGeneration = previous.Generation
			} else if prev, ok := previousStatuses[uid]; ok {
				status.AppliedGeneration = prev.AppliedGeneration
			}
		}

		statuses[uid] = status
	}

	w.applied = applied

	merged := routing.MergeTables(applied)

	w.state.Tables.Publish(merged)
	w.state.Statuses.Publish(statuses)

	w.tablesOut.Send(ctx, merged)
	w.namespaces.Send(ctx, merged.Backends())
}
