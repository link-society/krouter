---
title: "Routing gRPC"
description: "GRPCRoute with method and header matching, and cleartext HTTP/2 to your backends."
weight: 4
params:
  level: "Intermediate"
---

**Use case:** expose gRPC services through the same Gateway as your HTTP
traffic, routing by gRPC service and method.

## 1. A gRPC backend

Any gRPC server works. Give its Service port the
[appProtocol](https://kubernetes.io/docs/concepts/services-networking/service/#application-protocol)
`kubernetes.io/h2c` if you also want plain HTTPRoutes to reach it over
HTTP/2:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: greeter
spec:
  selector: { app: greeter }
  ports:
    - port: 9000
      appProtocol: kubernetes.io/h2c
```

GRPCRoute backends always speak cleartext HTTP/2 (h2c) with trailers
preserved — streaming and rich error details work end to end.

## 2. Attach a GRPCRoute

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata:
  name: greeter
spec:
  parentRefs:
    - name: edge
  hostnames:
    - grpc.example.com
  rules:
    - matches:
        - method:
            service: helloworld.Greeter
            method: SayHello
      backendRefs:
        - name: greeter
          port: 9000
    - backendRefs:            # everything else on this hostname
        - name: greeter
          port: 9000
```

Method matches take precedence over the catch-all rule; header matches
combine with methods exactly like HTTPRoute headers.

## 3. Call it

With [grpcurl](https://github.com/fullstorydev/grpcurl):

```sh
GW_IP=$(kubectl get gateway edge -o jsonpath='{.status.addresses[0].value}')
grpcurl -plaintext -authority grpc.example.com \
  -d '{"name": "world"}' "$GW_IP:80" helloworld.Greeter/SayHello
```

gRPC works on HTTP listeners (cleartext HTTP/2) and HTTPS listeners alike.
Unmatched gRPC calls receive a proper `UNIMPLEMENTED` gRPC status instead
of an HTTP error page.

**Next:** [route raw TCP, UDP and TLS](/docs/tutorials/l4-routing/).
