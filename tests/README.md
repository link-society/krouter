# krouter test suites

Black-box test suites derived from the krouter specification
([docs/spec/](../docs/spec/README.md)). References below point to the
individual specification documents.

All automation goes through [Task](https://taskfile.dev); `task --list` is
the authoritative list of commands.

## Prerequisites

- Go, Docker, [kind](https://kind.sigs.k8s.io), kubectl
- Python with [PDM](https://pdm-project.org) (the test tasks set up the
  environment automatically)
- Helm (benchmark suite only, to install Traefik)

## Quick start

```sh
task k8s:up             # create the kind cluster, install the Gateway API CRDs
task k8s:deploy         # build the image, load it into kind, deploy krouter
task tests:unit         # Go unit tests
task tests:e2e          # end-to-end suite
task tests:conformance  # official Gateway API conformance profile
task tests:performance  # concurrent-connection release gate
task tests:bench:all    # krouter vs NGINX Gateway Fabric vs Traefik
task k8s:down
```

## The suites

- **Unit** — pure logic tested with `go test`, next to the package it
  belongs to (see below).
- **Conformance** — the official Gateway API conformance suite, running the
  Core profile required by the spec (docs/spec/overview.md, docs/spec/acceptance.md criterion 1). It is executed inside a
  container attached to the kind docker network, because the suite dials
  Gateway addresses that are not routable from the host.
- **End-to-end** — pytest suite driving a real krouter installation solely
  through the Kubernetes API and published entry points, like an operator
  would.
- **Performance** — the 10,000 simultaneous-connection release gate (docs/spec/performance.md,
  docs/spec/acceptance.md criterion 10), driven by a purpose-built load generator that holds connections
  across configuration reloads and counts every disconnect.
- **Benchmark** — reproducible side-by-side comparison of krouter, NGINX
  Gateway Fabric and Traefik (docs/spec/performance.md, docs/spec/acceptance.md criterion 11): identical cluster, backend,
  Gateway resources, request mix and load generator for every
  implementation.

## Acceptance criteria mapping (docs/spec/acceptance.md)

| # | Criterion | Suite |
|---|---|---|
| 1 | Core conformance profile passes in full | `task tests:conformance` |
| 2 | HTTP/1.1 + HTTP/2 through HTTP/HTTPS listeners | `task tests:e2e` |
| 3 | Cross-namespace attachment + ReferenceGrant | `task tests:e2e` |
| 4 | Same external ports on multiple Gateways, no leakage | `task tests:e2e` |
| 5 | Atomic activation on every healthy data-plane pod | `task tests:e2e` |
| 6 | Rejected generation keeps last valid serving | `task tests:e2e` |
| 7 | Connections survive config/cert reloads | `task tests:e2e` |
| 8 | EndpointSlice readiness changes selection, no restarts | `task tests:e2e` |
| 9 | Status/conditions accuracy | `task tests:e2e` |
| 10 | 10,000 concurrent connections | `task tests:performance` |
| 11 | Reproducible NGINX/Traefik benchmarks | `task tests:bench:all` |
| 12 | Standard manifest + CRDs only | `task tests:e2e` |

The e2e suite is organized as one test module per criterion (plus one for
the installation contract of docs/spec/deployment.md, docs/spec/security.md, docs/spec/observability.md); discover them with
`pytest --collect-only`.

## What belongs in Go unit tests

Pure logic must be tested next to its package with `go test` rather than
through kind. As the implementation lands, that includes at minimum:

- HCL parameter parsing/validation, unknown-field rejection (docs/spec/parameters.md)
- Internal listener port allocation, persistence/reconstruction, exhaustion
  (docs/spec/frontend.md, docs/spec/failure-modes.md)
- Compiled-configuration generation, checksums, manifest commit marker (docs/spec/configuration.md)
- Round-robin and weighted endpoint selection (docs/spec/traffic.md)
- Forwarded/X-Forwarded-* header regeneration (docs/spec/traffic.md)
- Route matching precedence beyond what conformance covers (docs/spec/traffic.md)
- EndpointSlice mirroring/splitting logic (docs/spec/frontend.md)
- Status condition computation, generation acknowledgement aggregation (docs/spec/status.md)

## Installation contract

The suites assume the resource names, labels and environment variables that
the standard installation manifest establishes (docs/spec/deployment.md). These assumptions are
centralized in the shared test library's configuration module and every one
of them can be overridden through environment variables to target a
differently configured installation (docs/spec/deployment.md).

## Test backends

Routes under test forward to [MockServer](https://www.mock-server.com)
backends. Each backend pod identifies itself in its responses (driving the
balancing, isolation and readiness assertions), can be flipped ready/unready
at runtime without terminating it, records received requests so forwarded
headers can be asserted, and can delay responses to keep requests in flight
while a reload happens.

## Environment notes

- Suites that must reach Gateway or node addresses directly (conformance,
  load generation) run inside containers attached to the kind docker
  network, since kind nodes are not routable from the host (notably on
  macOS).
- The e2e suite reaches Gateways through deterministic NodePorts, requested
  via Gateway infrastructure parameters (docs/spec/parameters.md) and published to the host by
  the kind cluster configuration.
- Everything generated at runtime (reports, results, kubeconfigs) is written
  to a git-ignored results directory; `task tests:clean` removes it.
- Upstream versions used by the benchmark installs are pinned in the
  benchmark configuration.
