// Package conformance runs the official Gateway API conformance suite
// against a live cluster running krouter.
//
// The conformance target (docs/spec/overview.md, docs/spec/acceptance.md criteria 1,
// 14 and 15) is: all Core tests of the GATEWAY-HTTP, GATEWAY-GRPC and
// GATEWAY-TLS profiles, Gateway API v1.5.1. TCPRoute has no conformance
// profile in this release (docs/spec/acceptance.md criterion 13); it is
// verified by the e2e suite instead.
// The profile is therefore forced here rather than left to a flag.
//
// The suite dials the addresses published on Gateway status, which are
// cluster-internal. Run it through `task tests:conformance`, which compiles
// this test into a static binary and executes it inside the cluster (the
// suite manifests are embedded in the binary and the Kubernetes client picks
// up the in-cluster config).
package conformance

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/gateway-api/apis/v1beta1"
	"sigs.k8s.io/gateway-api/conformance"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
)

func TestConformance(t *testing.T) {
	opts := conformance.DefaultOptions(t)

	// docs/spec/acceptance.md criteria 1, 14 and 15: the GATEWAY-HTTP,
	// GATEWAY-GRPC and GATEWAY-TLS Core profiles must pass in full.
	opts.ConformanceProfiles = sets.New(
		suite.GatewayHTTPConformanceProfileName,
		suite.GatewayGRPCConformanceProfileName,
		suite.GatewayTLSConformanceProfileName,
	)

	// No feature is declared manually: the suite infers the supported
	// feature set from GatewayClass status.supportedFeatures, which the
	// control plane publishes (docs/spec/status.md, docs/spec/acceptance.md
	// criterion 18). This also verifies the published set stays accurate:
	// an over-declared feature fails its conformance tests.

	// Static Gateway addresses (docs/spec/frontend.md Gateway addresses):
	// usable = a node address serving a data-plane pod, unusable = a
	// TEST-NET-3 address no node owns.
	opts.UsableNetworkAddresses = []v1beta1.GatewaySpecAddress{{
		Type:  ptrTo(v1beta1.IPAddressType),
		Value: dataplaneHostIP(t, opts.Client),
	}}
	opts.UnusableNetworkAddresses = []v1beta1.GatewaySpecAddress{{
		Type:  ptrTo(v1beta1.IPAddressType),
		Value: "203.0.113.10",
	}}

	// Implementation metadata (organization, project, ...) and the
	// GatewayClass name are provided as flags by `task tests:conformance`.

	conformance.RunConformanceWithOptions(t, opts)
}

// dataplaneHostIP returns the node address of one running krouter
// data-plane pod: the generated NodePort Services serve on node addresses
// (docs/spec/frontend.md).
func dataplaneHostIP(t *testing.T, c client.Client) string {
	pods := corev1.PodList{}

	err := c.List(context.Background(), &pods,
		client.InNamespace("krouter-system"),
		client.MatchingLabels{"app.kubernetes.io/component": "dataplane"},
	)
	if err != nil {
		t.Fatalf("listing data-plane pods: %v", err)
	}

	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning && pod.Status.HostIP != "" {
			return pod.Status.HostIP
		}
	}

	t.Fatal("no running data-plane pod with a host IP")

	return ""
}

func ptrTo[T any](v T) *T { return &v }
