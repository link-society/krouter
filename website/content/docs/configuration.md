---
title: "Configuration"
description: "GatewayClass parameters, Gateway infrastructure, listeners, and TLS material."
weight: 2
---

krouter is configured **only** through standard Kubernetes objects. The two
Gateway API parameter hooks both point at core
[ConfigMaps](https://kubernetes.io/docs/concepts/configuration/configmap/)
containing a `krouter.hcl` key.

## GatewayClass parameters

`GatewayClass.spec.parametersRef` tunes proxy behavior shared by the class:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: krouter-class-params
  namespace: krouter-system
data:
  krouter.hcl: |
    version = 1

    load_balancing {
      algorithm = "round_robin"
    }
```

The GatewayClass links to it with `parametersRef` (the `namespace` field is
required because ConfigMaps are namespaced):

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: krouter
spec:
  controllerName: link-society.com/krouter
  parametersRef:
    group: ""
    kind: ConfigMap
    name: krouter-class-params
    namespace: krouter-system
```

Invalid or missing parameters surface as the standard `InvalidParameters`
status reason (they never crash the controller).

## Gateway infrastructure parameters

`Gateway.spec.infrastructure.parametersRef` shapes the
[Service](https://kubernetes.io/docs/concepts/services-networking/service/)
krouter generates for that Gateway:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: edge-params
  namespace: my-team
data:
  krouter.hcl: |
    version = 1

    service {
      type                    = "NodePort"      # or LoadBalancer / ClusterIP
      external_traffic_policy = "Local"

      annotations = {
        "example.com/setting" = "value"
      }

      node_ports = {
        "http" = 30080   # listener name -> requested NodePort
      }
    }

    client_ip {
      # Networks whose forwarded headers are trusted (empty by default).
      trusted_proxies = ["10.0.0.0/8"]
    }
```

The Gateway links to it with `spec.infrastructure.parametersRef`; the
ConfigMap must live in the Gateway's own namespace:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: my-team
spec:
  gatewayClassName: krouter
  infrastructure:
    parametersRef:
      group: ""
      kind: ConfigMap
      name: edge-params
  listeners:
    - name: http
      protocol: HTTP
      port: 80
```

- The default is a `NodePort` Service with
  [`externalTrafficPolicy: Local`](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/#preserving-the-client-source-ip),
  which preserves client source IPs.
- `LoadBalancer` works with any compatible
  [cloud load balancer](https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer)
  implementation, including `load_balancer_class`.
- Labels and annotations declared under `Gateway.spec.infrastructure` are
  propagated to the generated Service.

### Client IP behind another proxy

When a CDN, a cloud load balancer or another reverse proxy sits in front
of a Gateway, the connection krouter terminates comes from that hop, not
from the client. `client_ip.trusted_proxies` lists the networks allowed to
speak for their clients:

- A request from a peer in that list has its
  [`X-Forwarded-For`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For)
  chain walked from right to left, and the first address outside the list
  is the client. The chain reaches backends with the peer appended, and
  the `X-Forwarded-Host`, `X-Forwarded-Proto` and `Forwarded` values the
  peer sent are passed through.
- A request from any other peer keeps today's behavior: the peer is the
  client and those headers are regenerated from the connection, so a
  spoofed value never reaches a backend.
- The resolved address is what the access log reports, what the
  `client_ip` rate limiting key buckets by, and what the WAF inspects as
  the remote address.

The list is empty by default, which means no peer is trusted. Only list
intermediaries clients cannot bypass: trusting a network reachable
directly lets any client pick its own client IP.

## Listeners

Each Gateway declares its
[listeners](https://gateway-api.sigs.k8s.io/api-types/gateway/#gateway-listeners):

| Protocol | What krouter does |
|---|---|
| `HTTP` | HTTP/1.1 and cleartext HTTP/2 |
| `HTTPS` | TLS termination with the referenced certificates, HTTP/1.1 + HTTP/2 |
| `TLS` | `Passthrough` (route by SNI, never decrypt) or `Terminate`; both may share a port |
| `TCP` | Raw stream forwarding |
| `UDP` | Per-flow datagram forwarding |

Listeners on one port are isolated by hostname: a request is served
exclusively by the most specific matching listener. Gateways may also
delegate listeners to
[ListenerSets](https://gateway-api.sigs.k8s.io/api-types/listenerset/) via
`allowedListeners`.

## TLS material

HTTPS and TLS-Terminate listeners reference standard
[TLS Secrets](https://kubernetes.io/docs/concepts/configuration/secret/#tls-secrets)
(`kubernetes.io/tls`). krouter copies only the referenced material into its
own namespace, rotates it atomically, and never terminates connections
still using the previous certificate.

Client-certificate validation (frontend mTLS) and backend TLS policies are
covered in the [mutual TLS tutorial](/docs/tutorials/mutual-tls/).

## Ports and addresses

- Listeners may use any valid port, including registered ports like 8080.
- `spec.addresses` entries without a value are assigned by krouter; static
  `IPAddress` values must be addresses of nodes running the data plane
  (see [Node addresses](https://kubernetes.io/docs/concepts/architecture/nodes/#addresses)).
