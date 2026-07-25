---
title: "Routing"
description: "Route kinds, attachment, matching precedence, filters, and cross-namespace policies."
weight: 3
---

## Route kinds

| Kind | Version | Traffic |
|---|---|---|
| [HTTPRoute](https://gateway-api.sigs.k8s.io/api-types/httproute/) | `v1` | HTTP/1.1 and HTTP/2, host + path + method + header + query matching |
| [GRPCRoute](https://gateway-api.sigs.k8s.io/api-types/grpcroute/) | `v1` | gRPC with service/method and header matching, h2c to backends |
| TLSRoute | `v1` | SNI-routed TLS, passthrough or terminated |
| TCPRoute | `v1` | Raw TCP streams |
| UDPRoute | `v1` | UDP datagram flows |

Backends are regular
[Services](https://kubernetes.io/docs/concepts/services-networking/service/);
krouter selects ready endpoints straight from
[EndpointSlices](https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/),
so readiness changes take effect without restarts (see
[Pod readiness](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-readiness-gate)).

## Attachment

Routes attach to Gateways through
[parentRefs](https://gateway-api.sigs.k8s.io/concepts/api-overview/#attaching-routes-to-gateways):

- `sectionName` pins one listener by name, `port` pins listeners by port
  (combined, both must match).
- The Gateway side controls admission with
  [allowedRoutes](https://gateway-api.sigs.k8s.io/api-types/gateway/#allowedroutes):
  namespaces (`Same`, `All`, or a
  [label selector](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors))
  and route kinds.
- Every attachment decision is reported on the route's `status.parents`
  with the standard conditions and reasons (`Accepted`, `ResolvedRefs`,
  `NoMatchingParent`, `NotAllowedByListeners`, ...).

## Matching precedence

HTTPRoute rules follow the upstream precedence exactly: most specific
listener hostname, most specific route hostname, exact-over-prefix path
(longest wins), method, most headers, most query parameters, then oldest
route. Requests that match nothing get `404` (HTTP) or `UNIMPLEMENTED`
(gRPC).

## Filters

All Standard-channel filters are supported with upstream semantics:

- `RequestHeaderModifier` / `ResponseHeaderModifier`: also per
  `backendRefs[].filters`, applied only to that backend's share.
- `RequestRedirect`: scheme, hostname, port, path, and status codes.
- `URLRewrite`: hostname and path replacement.
- `RequestMirror`: one or many mirrors, with percentage sampling.
- `CORS`: preflights answered at the gateway, wildcard and credentialed
  origins handled per the
  [Fetch specification](https://fetch.spec.whatwg.org/#http-cors-protocol).

Weighted `backendRefs` split traffic for
[canary-style rollouts](https://kubernetes.io/docs/concepts/cluster-administration/manage-deployment/#canary-deployments),
and `rules[].timeouts` enforces request and backend deadlines. A route
using anything krouter does not support is rejected in full with
`UnsupportedValue` (never partially applied).

## Cross-namespace references

Any reference crossing a namespace boundary (route backends, listener
certificates, CA bundles) requires a
[ReferenceGrant](https://gateway-api.sigs.k8s.io/api-types/referencegrant/)
in the target namespace. This keeps namespace isolation under the control
of the namespace owner, complementing Kubernetes
[multi-tenancy practices](https://kubernetes.io/docs/concepts/security/multi-tenancy/).

The [multi-team tutorial](/docs/tutorials/multi-team/) walks through a
complete setup.
