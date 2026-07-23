# krouter Specification

krouter (Kubernetes Router) is a Kubernetes Gateway API implementation and
HTTP/HTTPS reverse proxy.

Status: Draft 0.2

## Conformance language

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY in these documents
are to be interpreted as described in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## Document map

Read the documents in this order for a complete picture; each one is also
self-contained enough to be consulted on its own.

| Document | Contents |
|---|---|
| [overview.md](overview.md) | Purpose, design principles, scope and compatibility, deferred work |
| [deployment.md](deployment.md) | Distribution artifacts, runtime settings, multi-instance isolation |
| [architecture.md](architecture.md) | Component model, control and data planes, reconciliation loop, invariants |
| [frontend.md](frontend.md) | Per-Gateway Services, mirrored EndpointSlices, internal listener ports |
| [parameters.md](parameters.md) | GatewayClass and Gateway parameters without custom resources |
| [configuration.md](configuration.md) | Compiled configuration model, atomic publication, last-valid behavior, ownership and garbage collection |
| [traffic.md](traffic.md) | Request path, connection lifecycle, hot reload, backend discovery, HTTP behavior |
| [security.md](security.md) | TLS material handling, RBAC, workload hardening |
| [status.md](status.md) | Gateway API status ownership and data-plane acknowledgement |
| [observability.md](observability.md) | Health endpoints, logging, metrics |
| [failure-modes.md](failure-modes.md) | Required behavior under failure |
| [performance.md](performance.md) | Performance requirements and comparative benchmarks |
| [acceptance.md](acceptance.md) | Acceptance criteria |

## Authoritative references

- [Gateway API v1.5.1 release](https://github.com/kubernetes-sigs/gateway-api/releases/tag/v1.5.1)
- [Gateway API specification](https://gateway-api.sigs.k8s.io/reference/api-spec/)
- [Gateway API implementer's guide](https://gateway-api.sigs.k8s.io/guides/implementers-guide/)
- [Gateway API conformance](https://gateway-api.sigs.k8s.io/concepts/conformance/)
- [Kubernetes Services without selectors](https://kubernetes.io/docs/concepts/services-networking/service/#services-without-selectors)
- [Kubernetes EndpointSlices](https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/)
