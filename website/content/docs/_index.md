---
title: "Documentation"
description: "Everything a DevOps engineer needs to install, configure and operate krouter."
---

krouter is a [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io)
implementation and reverse proxy. It routes HTTP, gRPC, TCP, UDP and TLS
traffic, is configured entirely through standard Kubernetes resources (no
custom CRDs), and applies every configuration change without dropping
connections.

If you are new to the Gateway API itself, start with the upstream
[API overview](https://gateway-api.sigs.k8s.io/concepts/api-overview/): the
[Gateway](https://gateway-api.sigs.k8s.io/api-types/gateway/),
[HTTPRoute](https://gateway-api.sigs.k8s.io/api-types/httproute/) and
[GatewayClass](https://gateway-api.sigs.k8s.io/api-types/gatewayclass/)
concepts carry over to krouter unchanged. General Kubernetes concepts used
throughout these pages are covered by the official
[Kubernetes documentation](https://kubernetes.io/docs/home/).

## How krouter is put together

- A **control plane** (single-replica
  [Deployment](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/))
  watches Gateway API resources, validates them, compiles configuration and
  publishes status. It also serves the live dashboard.
- A **data plane**
  ([DaemonSet](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/))
  serves the actual traffic on every node. Data-plane pods never talk to
  the Kubernetes API for routing decisions on the hot path.
- For every Gateway, krouter generates a regular
  [Service](https://kubernetes.io/docs/concepts/services-networking/service/)
  (NodePort by default) fronting the shared data plane.

Configuration changes are compiled into immutable generations and applied
atomically: a broken change is rejected in full and the last valid
configuration keeps serving.

## Where to go next

- [Installation](/docs/installation/): prerequisites and deployment.
- [Configuration](/docs/configuration/): GatewayClass, parameters,
  listeners and TLS material.
- [Routing](/docs/routing/): route kinds, matching, filters and
  cross-namespace policies.
- [Observability](/docs/observability/): dashboard, metrics and logs.
- [Conformance & testing](/docs/conformance/): how krouter is verified,
  including the full [test report](/report/report.html).
- [Tutorials](/docs/tutorials/): hands-on walkthroughs from a first route
  to full mutual TLS.
