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
	"sigs.k8s.io/gateway-api/pkg/features"
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

	// krouter does not publish GatewayClass status.supportedFeatures (an
	// Experimental field), so the suite cannot infer the feature set and it
	// is declared here instead: the Core features of the profiles above are
	// implied by the profile selection, and the Extended features below
	// match the supported scope (docs/spec/overview.md,
	// docs/spec/traffic.md, docs/spec/acceptance.md criterion 16).
	opts.SupportedFeatures = sets.New(
		features.SupportGateway,
		features.SupportHTTPRoute,
		features.SupportGRPCRoute,
		features.SupportTLSRoute,

		// Extended HTTPRoute filters (docs/spec/acceptance.md criterion 16).
		features.SupportHTTPRouteResponseHeaderModification,
		features.SupportHTTPRouteHostRewrite,
		features.SupportHTTPRoutePathRewrite,
		features.SupportHTTPRoutePathRedirect,
		features.SupportHTTPRouteSchemeRedirect,
		features.SupportHTTPRoutePortRedirect,
		features.SupportHTTPRoute303RedirectStatusCode,
		features.SupportHTTPRoute307RedirectStatusCode,
		features.SupportHTTPRoute308RedirectStatusCode,
		features.SupportHTTPRouteRequestMirror,
		features.SupportHTTPRouteRequestMultipleMirrors,
		features.SupportHTTPRouteRequestPercentageMirror,

		// HTTPRoute rule timeouts (docs/spec/acceptance.md criterion 17).
		features.SupportHTTPRouteRequestTimeout,
		features.SupportHTTPRouteBackendTimeout,
	)

	// Implementation metadata (organization, project, ...) and the
	// GatewayClass name are provided as flags by `task tests:conformance`.

	conformance.RunConformanceWithOptions(t, opts)
}
