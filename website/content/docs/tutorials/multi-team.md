---
title: "Multi-team gateways"
description: "Share one gateway safely across namespaces with allowedRoutes, ReferenceGrants and ListenerSets."
weight: 7
params:
  level: "Advanced"
---

**Use case:** a platform team owns the edge; application teams attach
routes (and even whole listeners) from their own
[namespaces](https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/),
without being able to step on each other. This mirrors the Gateway API's
[role-oriented design](https://gateway-api.sigs.k8s.io/concepts/roles-and-personas/).

## Open a gateway to selected namespaces

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: shared-edge
  namespace: platform
spec:
  gatewayClassName: krouter
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      tls:
        certificateRefs: [{ name: wildcard-cert }]
      allowedRoutes:
        namespaces:
          from: Selector
          selector:
            matchLabels:
              edge-access: "granted"
```

Label the namespaces that may attach routes (see
[labels and selectors](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/)):

```sh
kubectl label namespace team-a edge-access=granted
```

Team A then writes a normal HTTPRoute in `team-a` with
`parentRefs: [{name: shared-edge, namespace: platform}]`. Per-listener
`attachedRoutes` counts in the Gateway status show who attached what.

## Authorize cross-namespace references

Any reference crossing namespaces needs an explicit
[ReferenceGrant](https://gateway-api.sigs.k8s.io/api-types/referencegrant/)
**in the target namespace** (the owner of the data stays in control):

```yaml
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-edge-routes
  namespace: team-b-backends
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      namespace: team-a
  to:
    - group: ""
      kind: Service
```

The same mechanism covers listener certificates, CA bundles and mirror
targets.

## Delegate whole listeners with ListenerSets

Teams that need their own listeners (their own ports, hostnames and
certificates) get a `ListenerSet` instead of write access to the Gateway:

```yaml
# Platform side: opt in explicitly (default is: none allowed).
spec:
  allowedListeners:
    namespaces:
      from: Selector
      selector:
        matchLabels:
          edge-listeners: "granted"
```

```yaml
# Team side:
apiVersion: gateway.networking.k8s.io/v1
kind: ListenerSet
metadata:
  name: team-a-listeners
  namespace: team-a
spec:
  parentRef:
    name: shared-edge
    namespace: platform
    kind: Gateway
    group: gateway.networking.k8s.io
  listeners:
    - name: https
      protocol: HTTPS
      port: 8443
      hostname: team-a.example.com
      tls:
        certificateRefs: [{ name: team-a-cert }]
```

krouter merges set listeners with the Gateway's own, rejects conflicts
deterministically (`ProtocolConflict`, `HostnameConflict`), reports status
per entry on the ListenerSet, and counts accepted sets in the Gateway's
`attachedListenerSets`. Routes may target the set directly with
`parentRefs: [{kind: ListenerSet, name: team-a-listeners}]`.

That's the full tour, from one route to a multi-tenant edge. For the
guarantees behind all of it, read the
[conformance page](/docs/conformance/) and the
[test report](/report/report.html).
