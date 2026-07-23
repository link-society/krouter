---
title: "TLS termination"
description: "Serve HTTPS with certificates from a standard Kubernetes Secret, rotated without downtime."
weight: 2
params:
  level: "Beginner"
---

**Use case:** the `hello` application from the
[first tutorial](/docs/tutorials/hello-http/) must be served over HTTPS.

## 1. Create a TLS Secret

Store your certificate in a standard
[TLS Secret](https://kubernetes.io/docs/concepts/configuration/secret/#tls-secrets).
For a quick self-signed test certificate:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout tls.key -out tls.crt -subj '/CN=hello.example.com'

kubectl create secret tls hello-cert --cert=tls.crt --key=tls.key
```

In production you would let
[cert-manager](https://cert-manager.io/docs/usage/gateway/) create this
Secret from the Gateway itself.

## 2. Add an HTTPS listener

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
    - name: https
      protocol: HTTPS
      port: 443
      hostname: hello.example.com
      tls:
        certificateRefs:
          - name: hello-cert
      allowedRoutes:
        namespaces:
          from: Same
```

The existing HTTPRoute attaches to both listeners automatically (its
hostname intersects both). To serve HTTPS only, add
`sectionName: https` to its `parentRefs`.

## 3. Test it

```sh
GW_IP=$(kubectl get gateway edge -o jsonpath='{.status.addresses[0].value}')
curl --resolve hello.example.com:443:$GW_IP -k https://hello.example.com/
```

HTTP/2 is negotiated automatically; `curl -v` shows `ALPN: server accepted h2`.

## 4. Rotate without downtime

Update the Secret with a new certificate — krouter picks it up, activates
it atomically for new handshakes, and never terminates connections still
using the previous one:

```sh
kubectl create secret tls hello-cert --cert=new.crt --key=new.key \
  --dry-run=client -o yaml | kubectl apply -f -
```

A redirect rule is a nice finishing touch — send HTTP traffic to HTTPS
with a `RequestRedirect` filter on the `http` listener; the
[traffic management tutorial](/docs/tutorials/traffic-management/) shows
how.

**Next:** [shape your traffic](/docs/tutorials/traffic-management/).
