package resolver

import (
	"context"
	"log/slog"

	"time"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/lib/snapshot"
	"github.com/link-society/krouter/internal/lib/transports/http/routing"
)

// worker polls Services and EndpointSlices in the declared namespaces and
// publishes the endpoints index.
type worker struct {
	client kubernetes.Interface
	in     actor.MailboxReceiver[map[string]bool]
	out    *snapshot.Store[*routing.EndpointsIndex]

	namespaces map[string]bool
}

var _ actor.Worker = (*worker)(nil)

func (w *worker) DoWork(ctx actor.Context) actor.WorkerStatus {
	select {
	case <-ctx.Done():
		return actor.WorkerEnd

	case namespaces := <-w.in.ReceiveC():
		w.namespaces = namespaces
		w.poll(ctx)

		return actor.WorkerContinue

	case <-time.After(time.Second):
		w.poll(ctx)

		return actor.WorkerContinue
	}
}

func (w *worker) poll(ctx context.Context) {
	index := routing.NewEndpointsIndex()

	for ns := range w.namespaces {
		svcList, err := w.client.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			slog.Warn("resolver: list services failed", "namespace", ns, "error", err)
			continue
		}

		for i := range svcList.Items {
			svc := &svcList.Items[i]
			index.Services[ns+"/"+svc.Name] = svc
		}

		sliceList, err := w.client.DiscoveryV1().EndpointSlices(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			slog.Warn("resolver: list endpointslices failed", "namespace", ns, "error", err)
			continue
		}

		for i := range sliceList.Items {
			slice := &sliceList.Items[i]

			svcName := slice.Labels[discoveryv1.LabelServiceName]
			if svcName == "" {
				continue
			}

			key := ns + "/" + svcName
			index.Slices[key] = append(index.Slices[key], slice)
		}
	}

	w.out.Publish(index)
}
