---
title: "Observability"
description: "The live dashboard, Prometheus metrics, access logs, and failure behavior."
weight: 5
---

## Live dashboard

The control plane embeds a dashboard showing every gateway, route and
backend as a live topology map; degraded paths (missing backends, rejected
routes) are highlighted, and clicking any node shows the underlying YAML.

```sh
kubectl -n krouter-system port-forward svc/krouter-dashboard 8080
```

Then open <http://localhost:8080>. See
[port forwarding](https://kubernetes.io/docs/tasks/access-application-cluster/port-forward-access-application-cluster/)
for how `port-forward` works; for permanent access, put the dashboard
Service behind a Gateway like any other backend.

## Metrics

Both planes expose Prometheus metrics on their management port (`:9090`,
path `/metrics`). krouter ships as one binary, so every name below is
registered on both endpoints, but the `krouter_dataplane_*` series only
move on data-plane pods. Scrape them with your Prometheus installation as
described in the
[Kubernetes monitoring docs](https://kubernetes.io/docs/tasks/debug/debug-cluster/resource-usage-monitoring/).

| Metric | Type | Labels | Description |
|---|---|---|---|
| `krouter_dataplane_requests_total` | Counter | `class`: `1xx` to `5xx` | HTTP and gRPC requests handled, by response status class. |
| `krouter_dataplane_ratelimit_decisions_total` | Counter | `result`: `allowed`, `limited` | [Rate limiting](/docs/extensions/) decisions on rules carrying a limit. |
| `krouter_dataplane_waf_decisions_total` | Counter | `result`: `allowed`, `denied`, `error` | [WAF](/docs/extensions/) decisions on rules carrying a ruleset. |
| `krouter_dataplane_tcp_connections_total` | Counter | `result`: `forwarded`, `refused`, `error` | TCP connections handled, by outcome. |
| `krouter_dataplane_tcp_active_connections` | Gauge | — | TCP connections currently forwarded. |
| `krouter_dataplane_tcp_bytes_total` | Counter | `direction`: `downstream_to_backend`, `backend_to_downstream` | Bytes forwarded on TCP routes, by direction. |
| `krouter_dataplane_tls_connections_total` | Counter | `result`: `forwarded`, `refused`, `error` | TLS passthrough connections handled, by outcome. |
| `krouter_dataplane_tls_active_connections` | Gauge | — | TLS passthrough connections currently forwarded. |
| `krouter_dataplane_udp_flows_total` | Counter | `result`: `forwarded`, `refused`, `error` | UDP flows handled, by outcome. |
| `krouter_dataplane_udp_active_flows` | Gauge | — | UDP flows currently forwarded. |
| `krouter_dataplane_udp_bytes_total` | Counter | `direction`: `downstream_to_backend`, `backend_to_downstream` | Bytes forwarded on UDP routes, by direction. |

The endpoints also export the standard
[Go runtime and process collectors](https://prometheus.io/docs/guides/go-application/)
(`go_*`, `process_*`) and the `promhttp_*` handler metrics. Label
cardinality is bounded by design: raw paths, client IPs, arbitrary
headers, and endpoint IPs are never metric labels.

The same port serves `/livez` and `/readyz`, wired into the manifest's
[liveness and readiness probes](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/).

## Logs

krouter writes structured JSON logs to stdout, one access-log event per
request (HTTP/gRPC) or per connection/flow (TCP, TLS, UDP), including the
matched gateway, route, backend, timing and status. A request rejected by
an [extension](/docs/extensions/) additionally records the rejecting
extension and, for WAF denials, the interrupting rule identifier. Collect
them with any
[cluster-level logging](https://kubernetes.io/docs/concepts/cluster-administration/logging/)
pipeline. The log level is set with the `KROUTER_LOG_LEVEL` environment
variable.

## Failure behavior

- A rejected configuration generation never interrupts serving: the last
  valid one stays active, and the rejection is visible in status
  conditions and the dashboard.
- Unresolvable backends answer `500` for their traffic share; a rejected
  BackendTLSPolicy fails closed with `502` (never a silent cleartext
  fallback).
- Data-plane pods keep serving from their last applied configuration even
  if the control plane is down.

Status is always written to the resources themselves: `kubectl describe
gateway my-gw` tells you what krouter thinks, using only upstream
condition types and reasons.
