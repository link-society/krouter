package configwatcher

import (
	"context"
	"log/slog"

	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// worker polls the generated configuration every second and mails a new
// RawConfig whenever anything changed.
type worker struct {
	client    kubernetes.Interface
	namespace string
	out       actor.MailboxSender[RawConfig]

	lastSnapshot string
}

var _ actor.Worker = (*worker)(nil)

func (w *worker) DoWork(ctx actor.Context) actor.WorkerStatus {
	w.poll(ctx)

	select {
	case <-ctx.Done():
		return actor.WorkerEnd

	case <-time.After(time.Second):
		return actor.WorkerContinue
	}
}

func (w *worker) poll(ctx context.Context) {
	selector := compiled.LabelManagedBy + "=" + compiled.ManagedByValue

	cmList, err := w.client.CoreV1().ConfigMaps(w.namespace).
		List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		slog.Warn("config watcher: list configmaps failed", "error", err)
		return
	}

	secretList, err := w.client.CoreV1().Secrets(w.namespace).
		List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		slog.Warn("config watcher: list secrets failed", "error", err)
		return
	}

	snapshot := ""
	for _, cm := range cmList.Items {
		snapshot += cm.Name + "/" + cm.ResourceVersion + ";"
	}
	for _, secret := range secretList.Items {
		snapshot += secret.Name + "/" + secret.ResourceVersion + ";"
	}

	if snapshot == w.lastSnapshot {
		return
	}

	raw := RawConfig{
		ConfigMaps: map[string]*corev1.ConfigMap{},
		Secrets:    map[string]*corev1.Secret{},
	}

	for i := range cmList.Items {
		raw.ConfigMaps[cmList.Items[i].Name] = &cmList.Items[i]
	}

	for i := range secretList.Items {
		raw.Secrets[secretList.Items[i].Name] = &secretList.Items[i]
	}

	if err := w.out.Send(ctx, raw); err != nil {
		return
	}

	w.lastSnapshot = snapshot
}
