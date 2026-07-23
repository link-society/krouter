---
title: "Traffic management"
description: "Canary releases with weights, redirects, rewrites, header filters, mirrors, timeouts and CORS."
weight: 3
params:
  level: "Intermediate"
---

**Use case:** roll out a new version of a service gradually, while keeping
old URLs working and observing the new version with mirrored traffic.

## Canary with weighted backends

Split traffic 90/10 between two Services (the pattern behind
[canary deployments](https://kubernetes.io/docs/concepts/cluster-administration/manage-deployment/#canary-deployments)):

```yaml
rules:
  - backendRefs:
      - name: hello
        port: 80
        weight: 90
      - name: hello-canary
        port: 80
        weight: 10
```

Adjust the weights over time; each change applies atomically without
disturbing established connections.

## Redirect old URLs

```yaml
rules:
  - matches:
      - path: { type: PathPrefix, value: /old }
    filters:
      - type: RequestRedirect
        requestRedirect:
          path:
            type: ReplacePrefixMatch
            replacePrefixMatch: /new
          statusCode: 301
```

The same filter with `scheme: https` implements HTTP→HTTPS redirects.

## Rewrite paths and tag requests

```yaml
rules:
  - matches:
      - path: { type: PathPrefix, value: /api }
    filters:
      - type: URLRewrite
        urlRewrite:
          path:
            type: ReplacePrefixMatch
            replacePrefixMatch: /
      - type: RequestHeaderModifier
        requestHeaderModifier:
          set:
            - name: X-Gateway
              value: krouter
    backendRefs:
      - name: api
        port: 80
```

Header modifiers also exist per backend (`backendRefs[].filters`), useful
to tag which side of a canary handled a request.

## Mirror traffic to a shadow deployment

```yaml
filters:
  - type: RequestMirror
    requestMirror:
      backendRef:
        name: hello-shadow
        port: 80
      percent: 20
```

Mirrored requests never influence the client response: failures and
responses from the mirror are discarded.

## Enforce timeouts

```yaml
rules:
  - timeouts:
      request: 5s
      backendRequest: 2s
    backendRefs:
      - name: hello
        port: 80
```

Exceeding the deadline answers `504 Gateway Timeout`.

## CORS for browser clients

```yaml
filters:
  - type: CORS
    cors:
      allowOrigins: ["https://app.example.com"]
      allowMethods: [GET, POST]
      allowCredentials: true
      maxAge: 3600
```

Preflight `OPTIONS` requests are answered directly at the gateway (they
never reach your backends).

**Next:** [route gRPC services](/docs/tutorials/grpc/).
