// Package conformance runs the official Gateway API conformance suite
// against a live cluster running krouter.
//
// The conformance target (docs/spec/overview.md, docs/spec/acceptance.md criterion 1
// and criterion 14) is: all Core tests of the GATEWAY-HTTP and GATEWAY-TLS
// profiles, Gateway API v1.5.1. TCPRoute has no conformance profile in this
// release (docs/spec/acceptance.md criterion 13); it is verified by the e2e
// suite instead.
// The profile is therefore forced here rather than left to a flag.
//
// The suite dials the addresses published on Gateway status, which are only
// routable from the kind docker network. Run it through `task
// tests:conformance`, which executes this test inside a container attached to
// that network.
package conformance

import (
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"

	"sigs.k8s.io/gateway-api/conformance"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
)

func TestConformance(t *testing.T) {
	opts := conformance.DefaultOptions(t)

	// docs/spec/acceptance.md criteria 1 and 14: the GATEWAY-HTTP and
	// GATEWAY-TLS Core profiles must pass in full.
	opts.ConformanceProfiles = sets.New(
		suite.GatewayHTTPConformanceProfileName,
		suite.GatewayTLSConformanceProfileName,
	)

	// Core-only target: Extended features are out of scope
	// (docs/spec/overview.md) unless a Core test requires them, so nothing is enabled here.
	// Implementation metadata (organization, project, ...) and the
	// GatewayClass name are provided as flags by `task tests:conformance`.

	conformance.RunConformanceWithOptions(t, opts)
}
