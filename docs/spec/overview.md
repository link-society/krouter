# Overview

## Purpose

krouter is a Kubernetes Gateway API implementation and HTTP/HTTPS reverse
proxy.

krouter implements the Gateway API `GATEWAY-HTTP` Core conformance
profile. The architecture MUST remain extensible to the other Standard
Gateway API route types and features without introducing krouter-specific
Kubernetes custom resources.

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
| Gateway API | v1.5.1, Standard channel |
| Conformance target | All Core tests in `GATEWAY-HTTP` |
| Client protocols | HTTP/1.1 and HTTP/2 |
| Backend protocol | HTTP/1.1 |
| Listeners | HTTP and HTTPS with TLS termination |
| Backend discovery | Kubernetes Services and EndpointSlices |
| Backend health | EndpointSlice conditions only |
| Authentication | Out of scope |
| Rate limiting | Out of scope |
| Experimental Gateway API features | Out of scope |
| Standard-channel Extended features | Out of scope unless required by a Core conformance test |

The control plane MUST inspect the `gateway.networking.k8s.io/bundle-version`
annotation on installed Gateway API CRDs and publish the GatewayClass
`SupportedVersion` condition. Unsupported bundles MUST NOT be reconciled as
if they were compatible.

## Explicitly deferred work

- GRPCRoute, TLSRoute, TCPRoute, and UDPRoute.
- Gateway API Standard Extended features not required by Core conformance.
- Experimental-channel resources and fields.
- Authentication and authorization policies.
- Rate limiting.
- Active backend health checks.
- Per-Gateway compute isolation inside one installation.
- Trusted upstream proxy configuration and Proxy Protocol.
- Distributed or multi-replica control plane.
- Custom krouter policies or CRDs.
