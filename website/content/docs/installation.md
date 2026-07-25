---
title: "Installation"
description: "Install the Gateway API CRDs, deploy krouter, and verify the installation."
weight: 1
---

## Prerequisites

- A Kubernetes cluster, **v1.31 or newer**. Any conformant distribution
  works; see the official
  [getting started guide](https://kubernetes.io/docs/setup/) if you need a
  cluster, or [kind](https://kind.sigs.k8s.io) for a local one.
- [kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl) configured
  against that cluster, with permission to create cluster-scoped resources
  (see [Using RBAC authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)).

## 1. Install the Gateway API CRDs

krouter deliberately does not bundle the Gateway API
[CustomResourceDefinitions](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/):
they are cluster-wide, versioned upstream, and often shared with other
controllers. Install the **v1.6.1 Standard channel**: since Gateway API
v1.6 it carries everything krouter uses, including `TCPRoute`,
`UDPRoute`, `TLSRoute`, `BackendTLSPolicy` and `ListenerSet`:

```sh
kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.1/standard-install.yaml
```

> Server-side apply is recommended: the larger CRDs exceed the
> annotation size limit used by client-side apply. See
> [Server-Side Apply](https://kubernetes.io/docs/reference/using-api/server-side-apply/)
> for background, and the upstream
> [installation guide](https://gateway-api.sigs.k8s.io/guides/#installing-gateway-api)
> for channel details.

The Experimental channel works too: krouter ignores the resources it
does not implement, and detects missing CRDs by degrading gracefully.

## 2. Deploy krouter

Everything (namespace, RBAC, control-plane Deployment, data-plane
DaemonSet and dashboard Service) is one static manifest:

```sh
kubectl apply -f https://raw.githubusercontent.com/link-society/krouter/main/k8s/krouter.yaml
```

The manifest creates the `krouter-system`
[namespace](https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/)
and follows the
[Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
`restricted` profile: non-root, read-only root filesystem, no added
capabilities.

## 3. Register the GatewayClass

A [GatewayClass](https://gateway-api.sigs.k8s.io/api-types/gatewayclass/)
ties Gateways to krouter's controller name:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: krouter
spec:
  controllerName: link-society.com/krouter
```

## 4. Verify

```sh
kubectl -n krouter-system rollout status deployment/krouter-controlplane
kubectl -n krouter-system rollout status daemonset/krouter-dataplane
kubectl get gatewayclass krouter
```

The GatewayClass should report `Accepted: True`, along with the exact
Gateway API feature set krouter supports in `status.supportedFeatures` and
a `SupportedVersion` condition confirming the installed CRD bundle.

Continue with [Configuration](/docs/configuration/), or jump straight into
the [first tutorial](/docs/tutorials/hello-http/).
