---
title: "Observability"
description: "The live dashboard, Prometheus metrics, access logs, and failure behavior."
weight: 4
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
path `/metrics`): request totals by class, active connections per
transport, reload counters, and per-flow UDP/TCP/TLS gauges. Scrape them
with your Prometheus installation as described in the
[Kubernetes monitoring docs](https://kubernetes.io/docs/tasks/debug/debug-cluster/resource-usage-monitoring/).

The same port serves `/livez` and `/readyz`, wired into the manifest's
[liveness and readiness probes](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/).

## Logs

krouter writes structured JSON logs to stdout, one access-log event per
request (HTTP/gRPC) or per connection/flow (TCP, TLS, UDP), including the
matched gateway, route, backend, timing and status. Collect them with any
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
