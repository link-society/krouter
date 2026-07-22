# Overview

## Purpose

krouter is a Kubernetes Gateway API implementation and HTTP/HTTPS reverse
proxy.

krouter implements the Gateway API `GATEWAY-HTTP`, `GATEWAY-GRPC`, and
`GATEWAY-TLS` Core conformance profiles, plus TCPRoute support. The
architecture MUST remain extensible to the other Standard Gateway API route
types and features without introducing krouter-specific Kubernetes custom
resources.

## Design principles

1. Use standard Kubernetes and Gateway API resources wherever possible.
2. Define no krouter-specific CRDs.
3. Require the Gateway API CRDs to be installed before krouter.
4. Keep the control plane out of the request path.
5. Keep the data plane stateless and able to serve its last valid
   configuration during control-plane failures.
6. Apply routing updates atomically without interrupting active connections.
7. Share compute between Gateways by default. Operators requiring compute
   isolation install another krouter instance with a different
   GatewayClass/controller name.
8. Ship one executable and one container image for both components.

## Scope and compatibility

| Item | Requirement |
|---|---|
| Kubernetes | v1.31 or newer |
| Gateway API | v1.5.1, Experimental channel CRDs (the Standard resources plus `TCPRoute`, `TLSRoute`, and `UDPRoute`) |
| Conformance target | All Core tests in `GATEWAY-HTTP`, `GATEWAY-GRPC`, and `GATEWAY-TLS`; TCPRoute and UDPRoute have no conformance profile in v1.5.1 and are verified by the krouter test suite (plus the provisional UDPRoute conformance test) |
| Route types | HTTPRoute, GRPCRoute, TCPRoute, TLSRoute, and UDPRoute |
| Client protocols | HTTP/1.1, HTTP/2 (including gRPC), raw TCP, TLS passthrough, and UDP |
| Backend protocol | HTTP/1.1; cleartext HTTP/2 (h2c) for GRPCRoute backends; raw TCP for TCPRoute backends; uninterpreted TLS for TLSRoute backends; UDP datagrams for UDPRoute backends; HTTPS to backends covered by a BackendTLSPolicy |
| Listeners | HTTP, HTTPS with TLS termination, TCP, TLS in Passthrough mode, and UDP |
| Backend discovery | Kubernetes Services and EndpointSlices |
| Backend health | EndpointSlice conditions only |
| Authentication | Out of scope |
| Rate limiting | Out of scope |
| Experimental Gateway API features | Out of scope, except TCPRoute (`v1alpha2`), TLSRoute (`v1`), UDPRoute (`v1alpha2`), and BackendTLSPolicy (`v1alpha3`) |
| Standard-channel Extended features | HTTPRoute filters (response header modification, URL rewriting, redirect path/scheme/port and alternative status codes, request mirroring) and HTTPRoute rule timeouts are supported and verified by their Extended conformance tests; other Extended features are out of scope |

The control plane MUST inspect the `gateway.networking.k8s.io/bundle-version`
annotation on installed Gateway API CRDs and publish the GatewayClass
`SupportedVersion` condition. Unsupported bundles MUST NOT be reconciled as
if they were compatible.

TCPRoute, TLSRoute, and UDPRoute support requires the corresponding
Experimental-channel CRDs. When such a CRD is not installed, krouter MUST
reconcile the remaining resources normally and MUST NOT crash or degrade
HTTP behavior; the affected listeners then receive a negative condition for
lack of an attachable route kind.

TLS listeners are supported in `Passthrough` mode only: krouter routes on
the SNI value and never holds the certificate. TLS listeners in
`Terminate` mode are out of scope.

## Explicitly deferred work

- TLS listeners in `Terminate` mode (TLSRoute is passthrough-only).
- Gateway API Standard Extended features other than the supported
  HTTPRoute filters: CORS, HTTP method and query-parameter matching,
  per-backendRef filters, named rules, and non-default backend protocols.
- BackendTLSPolicy `subjectAltNames` validation and `options`.
- Experimental-channel resources and fields other than TCPRoute,
  TLSRoute, UDPRoute, and BackendTLSPolicy.
- Authentication and authorization policies.
- Rate limiting.
- Active backend health checks.
- Per-Gateway compute isolation inside one installation.
- Trusted upstream proxy configuration and Proxy Protocol.
- Distributed or multi-replica control plane.
- Custom krouter policies or CRDs.
