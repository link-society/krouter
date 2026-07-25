# Overview

## Purpose

krouter is a Kubernetes Gateway API implementation and HTTP/HTTPS reverse
proxy.

krouter implements the Gateway API `GATEWAY-HTTP`, `GATEWAY-GRPC`,
`GATEWAY-TLS`, `GATEWAY-TCP`, and `GATEWAY-UDP` Core conformance profiles.
The architecture MUST remain extensible to the other Standard Gateway API
route types and features without introducing krouter-specific Kubernetes
custom resources.

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
| Gateway API | v1.6.1; every resource krouter consumes ships with the Standard channel CRDs (TCPRoute, UDPRoute, TLSRoute, BackendTLSPolicy, and ListenerSet graduated in v1.6) |
| Conformance target | Every test in the `GATEWAY-HTTP`, `GATEWAY-GRPC`, `GATEWAY-TLS`, `GATEWAY-TCP`, and `GATEWAY-UDP` profiles, Core and Extended: the suite MUST skip only Mesh-profile tests |
| Route types | HTTPRoute, GRPCRoute, TCPRoute, TLSRoute, and UDPRoute |
| Client protocols | HTTP/1.1, HTTP/2 (including gRPC), raw TCP, TLS passthrough, and UDP |
| Backend protocol | HTTP/1.1; cleartext HTTP/2 (h2c) for GRPCRoute backends and Service ports declaring `appProtocol: kubernetes.io/h2c`; WebSocket upgrade passthrough (incl. `appProtocol: kubernetes.io/ws`); raw TCP for TCPRoute backends; uninterpreted TLS for TLSRoute backends; UDP datagrams for UDPRoute backends; HTTPS to backends covered by a BackendTLSPolicy |
| Listeners | HTTP, HTTPS with TLS termination, TCP, TLS in Passthrough or Terminate mode (mixed on one port), and UDP |
| Backend discovery | Kubernetes Services and EndpointSlices |
| Backend health | EndpointSlice conditions only |
| Authentication | Out of scope |
| Rate limiting | Per-rule token buckets via the `ExtensionRef` filter (docs/spec/extensions.md); enforcement is per data-plane pod |
| Web application firewall | Coraza with the embedded OWASP Core Rule Set via the `ExtensionRef` filter (docs/spec/extensions.md) |
| Experimental Gateway API features | Out of scope; TCPRoute (`v1`), TLSRoute (`v1`), UDPRoute (`v1`), BackendTLSPolicy (`v1`), and ListenerSet (`v1`) are Standard as of Gateway API v1.6 |
| Standard-channel Extended features | HTTPRoute filters (response header modification, URL rewriting, redirect path/scheme/port and alternative status codes, request mirroring), HTTPRoute rule timeouts, named route rules (HTTPRoute and GRPCRoute), and Gateways whose `spec.addresses` entries carry no value are supported and verified by their Extended conformance tests; the remaining Extended features are listed under deferred work |

The control plane MUST inspect the `gateway.networking.k8s.io/bundle-version`
annotation on installed Gateway API CRDs and publish the GatewayClass
`SupportedVersion` condition. Unsupported bundles MUST NOT be reconciled as
if they were compatible.

TCPRoute, TLSRoute, and UDPRoute support requires the corresponding CRDs.
When such a CRD is not installed, krouter MUST reconcile the remaining
resources normally and MUST NOT crash or degrade HTTP behavior; the
affected listeners then receive a negative condition for lack of an
attachable route kind.

TLS listeners support `Passthrough` mode (krouter routes on the SNI value
and never holds the certificate) and `Terminate` mode, where krouter
terminates the session with the listener certificate and forwards the
decrypted stream to TLSRoute backends. Both modes MAY share one port
(mixed termination), selected per connection by SNI.

## Explicitly deferred work

- Gateway API Standard Extended features other than the supported
  HTTPRoute filters (including CORS), rule timeouts, named rules,
  Gateway addresses (value-less and static), parentRef port matching,
  method and query-parameter matching, listener isolation,
  misdirected-request detection, backend protocol selection,
  per-backendRef filters, infrastructure metadata propagation, and
  client-certificate validation (frontend and backend).
- BackendTLSPolicy `options`.
- Policy attachment to ListenerSets.
- Experimental-channel resources and fields.
- Authentication and authorization policies.
- Distributed (cluster-coordinated) rate limiting, WAF response-phase
  inspection, and in-tunnel WebSocket enforcement
  (docs/spec/extensions.md).
- Active backend health checks.
- Per-Gateway compute isolation inside one installation.
- Trusted upstream proxy configuration and Proxy Protocol.
- Distributed or multi-replica control plane.
- Custom krouter policies or CRDs.
