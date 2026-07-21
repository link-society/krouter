// Package conformance runs the official Gateway API conformance suite
// against a live cluster running krouter.
//
// The POC conformance target (docs/spec/overview.md, docs/spec/acceptance.md criterion 1) is: all Core
// tests of the GATEWAY-HTTP profile, Gateway API v1.5.1 Standard channel.
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

	// docs/spec/acceptance.md criterion 1: the GATEWAY-HTTP Core profile must pass in full.
	opts.ConformanceProfiles = sets.New(suite.GatewayHTTPConformanceProfileName)

	// Core-only target: Extended features are out of scope for the POC
	// (docs/spec/overview.md) unless a Core test requires them, so nothing is enabled here.
	// Implementation metadata (organization, project, ...) and the
	// GatewayClass name are provided as flags by `task tests:conformance`.

	conformance.RunConformanceWithOptions(t, opts)
}
