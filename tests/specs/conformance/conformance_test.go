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
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"

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

	// Implementation metadata (organization, project, ...) and the
	// GatewayClass name are provided as flags by `task tests:conformance`.

	conformance.RunConformanceWithOptions(t, opts)
}
