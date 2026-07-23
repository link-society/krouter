package ackpoller

import (
	"context"
	"fmt"
	"log/slog"

	"encoding/json"

	"net/http"

	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/config"
	"github.com/link-society/krouter/internal/lib/k8s/gatewayapi"
	"github.com/link-society/krouter/internal/lib/snapshot"
)

// worker polls the data-plane pods every second and publishes the
// acknowledgement snapshot.
type worker struct {
	client     kubernetes.Interface
	settings   *config.Settings
	httpClient *http.Client
	out        *snapshot.Store[gatewayapi.AckState]
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

func podIsReady(pod *corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodRunning || pod.Status.PodIP == "" {
		return false
	}

	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodReady {
			return cond.Status == corev1.ConditionTrue
		}
	}

	return false
}

func (w *worker) poll(ctx context.Context) {
	podList, err := w.client.CoreV1().Pods(w.settings.SystemNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/name=krouter,app.kubernetes.io/component=dataplane",
	})
	if err != nil {
		slog.Warn("ack poller: list pods failed", "error", err)
		return
	}

	state := gatewayapi.EmptyAckState()

	for i := range podList.Items {
		pod := &podList.Items[i]

		ack := gatewayapi.PodAck{
			IP:       pod.Status.PodIP,
			HostIP:   pod.Status.HostIP,
			NodeName: pod.Spec.NodeName,
			Gateways: map[string]gatewayapi.GatewayAck{},
		}

		if podIsReady(pod) {
			body, err := w.fetch(ctx, pod.Status.PodIP)
			if err == nil {
				ack.Healthy = true
				ack.Gateways = body
			}
		}

		state.Pods[pod.Name] = ack
	}

	w.out.Publish(state)
}

func (w *worker) fetch(ctx context.Context, ip string) (map[string]gatewayapi.GatewayAck, error) {
	url := fmt.Sprintf("http://%s:%d/readyz", ip, w.settings.ManagementPort)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body := struct {
		Ready    bool                             `json:"ready"`
		Gateways map[string]gatewayapi.GatewayAck `json:"gateways"`
	}{}

	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}

	if !body.Ready {
		return nil, fmt.Errorf("pod not ready")
	}

	return body.Gateways, nil
}
