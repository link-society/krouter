---
title: "L4: TCP, UDP and TLS"
description: "Forward raw TCP streams, UDP flows, and TLS by SNI (passthrough or terminated at the gateway)."
weight: 5
params:
  level: "Intermediate"
---

**Use case:** expose non-HTTP workloads (databases, DNS, MQTT, anything)
through the same gateway infrastructure.

These route kinds are GA since Gateway API v1.6 and ship with the
[Standard channel](https://gateway-api.sigs.k8s.io/concepts/versioning/#release-channels),
installed in the [installation guide](/docs/installation/).

## Raw TCP

One TCP listener forwards to one backend pool; the backend is chosen per
connection:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge-l4
spec:
  gatewayClassName: krouter
  listeners:
    - name: postgres
      protocol: TCP
      port: 5432
      allowedRoutes:
        namespaces:
          from: Same
---
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata:
  name: postgres
spec:
  parentRefs:
    - name: edge-l4
      sectionName: postgres
  rules:
    - backendRefs:
        - name: postgres
          port: 5432
```

Established connections survive configuration reloads: they keep their
selected backend until either side closes.

## UDP flows

```yaml
listeners:
  - name: dns
    protocol: UDP
    port: 53
```

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: UDPRoute
metadata:
  name: dns
spec:
  parentRefs:
    - name: edge-l4
      sectionName: dns
  rules:
    - backendRefs:
        - name: coredns
          port: 53
```

Datagrams from one client stick to one backend (per-flow association with
idle expiry), so request/response protocols like
[DNS](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/)
behave correctly.

## TLS by SNI (passthrough)

The gateway routes on the SNI value without ever decrypting; your backend
keeps sole ownership of the TLS session:

```yaml
listeners:
  - name: tls
    protocol: TLS
    port: 8443
    tls:
      mode: Passthrough
```

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: TLSRoute
metadata:
  name: vault
spec:
  parentRefs:
    - name: edge-l4
      sectionName: tls
  hostnames:
    - vault.example.com
  rules:
    - backendRefs:
        - name: vault
          port: 8200
```

Connections whose SNI matches no route are refused before any handshake
completes.

## TLS terminated at the gateway

Switch the mode and reference a certificate: krouter terminates the
session and forwards the decrypted stream as raw TCP. Both modes can even
share one port, selected per connection by SNI:

```yaml
listeners:
  - name: tls-terminate
    protocol: TLS
    port: 8443
    hostname: legacy.example.com
    tls:
      mode: Terminate
      certificateRefs:
        - name: legacy-cert
```

**Next:** [lock it down with mutual TLS](/docs/tutorials/mutual-tls/).
