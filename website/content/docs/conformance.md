---
title: "Conformance & testing"
description: "How krouter is verified: official conformance, e2e, performance gates, and the published report."
weight: 5
---

krouter treats the official
[Gateway API conformance suite](https://gateway-api.sigs.k8s.io/concepts/conformance/)
as its contract: **every non-mesh test in the `GATEWAY-HTTP`,
`GATEWAY-GRPC` and `GATEWAY-TLS` profiles passes**, Core and Extended. The
supported feature set is not hand-declared either: the suite infers it
from what krouter publishes in `GatewayClass.status.supportedFeatures`, so
an over-claimed feature would fail its own tests.

## The report

Every build runs four suites and publishes a single self-contained report:

<p><a class="button is-link" href="/report/report.html">Open the latest test report</a></p>

| Suite | What it proves |
|---|---|
| Unit | Pure routing/compilation logic |
| End-to-end | A real installation driven only through the Kubernetes API: atomic reloads, readiness handling, cross-namespace policies, all five protocols |
| Conformance | The official Gateway API suite, executed in-cluster |
| Performance | 10,000 concurrent connections held across a configuration reload with zero disconnects |

## Running it yourself

The repository automates everything with [Task](https://taskfile.dev)
against a local [kind](https://kind.sigs.k8s.io) cluster:

```sh
task k8s:up          # create the cluster, install the Gateway API CRDs
task k8s:deploy      # build, load and deploy krouter
task tests:report    # run all suites and build the HTML/JUnit report
```

The report lands in `tests/results/report/report.html`, and the raw
conformance report (the upstream YAML format used for
[conformance submissions](https://gateway-api.sigs.k8s.io/implementations/))
in `tests/results/conformance/report.yaml`.

## What is intentionally out of scope

krouter is a gateway, not a service mesh: the `MESH` profile tests are the
only skipped conformance tests. Rate limiting, authentication policies,
retries and active health checks are also out of scope today; the
[comparison table](/#how-krouter-compares) lists which alternatives cover
those.
