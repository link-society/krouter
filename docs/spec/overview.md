# Overview

## Purpose

krouter is a Kubernetes Gateway API implementation and HTTP/HTTPS reverse
proxy.

krouter implements the Gateway API `GATEWAY-HTTP` Core conformance
profile, plus TCPRoute support. The architecture MUST remain extensible to
the other Standard Gateway API route types and features without introducing
krouter-specific Kubernetes custom resources.

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
| Gateway API | v1.5.1, Standard channel, plus the Experimental `TCPRoute` CRD |
| Conformance target | All Core tests in `GATEWAY-HTTP`; TCPRoute has no conformance profile in v1.5.1 and is verified by the krouter test suite |
| Route types | HTTPRoute and TCPRoute |
| Client protocols | HTTP/1.1, HTTP/2, and raw TCP |
| Backend protocol | HTTP/1.1; raw TCP for TCPRoute backends |
| Listeners | HTTP, HTTPS with TLS termination, and TCP |
| Backend discovery | Kubernetes Services and EndpointSlices |
| Backend health | EndpointSlice conditions only |
| Authentication | Out of scope |
| Rate limiting | Out of scope |
| Experimental Gateway API features | Out of scope, except TCPRoute (`v1alpha2`) |
| Standard-channel Extended features | Out of scope unless required by a Core conformance test |

The control plane MUST inspect the `gateway.networking.k8s.io/bundle-version`
annotation on installed Gateway API CRDs and publish the GatewayClass
`SupportedVersion` condition. Unsupported bundles MUST NOT be reconciled as
if they were compatible.

TCPRoute support requires the Experimental-channel `TCPRoute` CRD. When
that CRD is not installed, krouter MUST reconcile the remaining resources
normally and MUST NOT crash or degrade HTTP behavior; TCP listeners then
receive a negative condition for lack of an attachable route kind.

## Explicitly deferred work

- GRPCRoute, TLSRoute, and UDPRoute.
- Gateway API Standard Extended features not required by Core conformance.
- Experimental-channel resources and fields other than TCPRoute.
- Authentication and authorization policies.
- Rate limiting.
- Active backend health checks.
- Per-Gateway compute isolation inside one installation.
- Trusted upstream proxy configuration and Proxy Protocol.
- Distributed or multi-replica control plane.
- Custom krouter policies or CRDs.
