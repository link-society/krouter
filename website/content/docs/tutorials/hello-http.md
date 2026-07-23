---
title: "Hello, HTTP"
description: "Expose a web application through your first Gateway and HTTPRoute."
weight: 1
params:
  level: "Beginner"
---

**Use case:** you have a web application in the cluster and want to reach
it from outside.

## 1. Deploy something to route to

A minimal [Deployment](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/)
and [Service](https://kubernetes.io/docs/concepts/services-networking/service/):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hello
spec:
  replicas: 2
  selector:
    matchLabels: { app: hello }
  template:
    metadata:
      labels: { app: hello }
    spec:
      containers:
        - name: hello
          image: ghcr.io/mendhak/http-https-echo:37
          ports:
            - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: hello
spec:
  selector: { app: hello }
  ports:
    - port: 80
      targetPort: 8080
```

## 2. Create a Gateway

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
spec:
  gatewayClassName: krouter
  listeners:
    - name: http
      protocol: HTTP
      port: 80
      allowedRoutes:
        namespaces:
          from: Same
```

krouter generates a NodePort Service for it and reports the address in
`status.addresses`:

```sh
kubectl get gateway edge -o wide
```

## 3. Attach an HTTPRoute

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: hello
spec:
  parentRefs:
    - name: edge
  hostnames:
    - hello.example.com
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - name: hello
          port: 80
```

## 4. Test it

```sh
GW_IP=$(kubectl get gateway edge -o jsonpath='{.status.addresses[0].value}')
curl -H 'Host: hello.example.com' "http://$GW_IP/"
```

Run it a few times: responses alternate between the two pods — that is the
round-robin balancing across ready
[EndpointSlice](https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/)
endpoints.

Check what krouter reported back:

```sh
kubectl describe httproute hello   # Accepted / ResolvedRefs conditions
```

**Next:** [serve it over HTTPS](/docs/tutorials/tls-termination/).
