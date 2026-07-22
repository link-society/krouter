# Overview

## Purpose

krouter is a Kubernetes Gateway API implementation and HTTP/HTTPS reverse
proxy.

krouter implements the Gateway API `GATEWAY-HTTP` and `GATEWAY-TLS` Core
conformance profiles, plus TCPRoute support. The architecture MUST remain
extensible to the other Standard Gateway API route types and features
without introducing krouter-specific Kubernetes custom resources.

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
| Gateway API | v1.5.1, Experimental channel CRDs (the Standard resources plus `TCPRoute` and `TLSRoute`) |
| Conformance target | All Core tests in `GATEWAY-HTTP` and `GATEWAY-TLS`; TCPRoute has no conformance profile in v1.5.1 and is verified by the krouter test suite |
| Route types | HTTPRoute, TCPRoute, and TLSRoute |
| Client protocols | HTTP/1.1, HTTP/2, raw TCP, and TLS passthrough |
| Backend protocol | HTTP/1.1; raw TCP for TCPRoute backends; uninterpreted TLS for TLSRoute backends |
| Listeners | HTTP, HTTPS with TLS termination, TCP, and TLS in Passthrough mode |
| Backend discovery | Kubernetes Services and EndpointSlices |
| Backend health | EndpointSlice conditions only |
| Authentication | Out of scope |
| Rate limiting | Out of scope |
| Experimental Gateway API features | Out of scope, except TCPRoute (`v1alpha2`) and TLSRoute (`v1`) |
| Standard-channel Extended features | Out of scope unless required by a Core conformance test |

The control plane MUST inspect the `gateway.networking.k8s.io/bundle-version`
annotation on installed Gateway API CRDs and publish the GatewayClass
`SupportedVersion` condition. Unsupported bundles MUST NOT be reconciled as
if they were compatible.

TCPRoute and TLSRoute support requires the corresponding
Experimental-channel CRDs. When such a CRD is not installed, krouter MUST
reconcile the remaining resources normally and MUST NOT crash or degrade
HTTP behavior; the affected listeners then receive a negative condition for
lack of an attachable route kind.

TLS listeners are supported in `Passthrough` mode only: krouter routes on
the SNI value and never holds the certificate. TLS listeners in
`Terminate` mode are out of scope.

## Explicitly deferred work

- GRPCRoute and UDPRoute.
- TLS listeners in `Terminate` mode (TLSRoute is passthrough-only).
- Gateway API Standard Extended features not required by Core conformance.
- Experimental-channel resources and fields other than TCPRoute and
  TLSRoute.
- Authentication and authorization policies.
- Rate limiting.
- Active backend health checks.
- Per-Gateway compute isolation inside one installation.
- Trusted upstream proxy configuration and Proxy Protocol.
- Distributed or multi-replica control plane.
- Custom krouter policies or CRDs.
