---
title: "Rate limiting"
description: "Throttle clients per route with token buckets configured from ConfigMaps: keys, bursts and per-route overrides."
weight: 8
params:
  level: "Intermediate"
---

**Use case:** an API endpoint is getting hammered (a misbehaving client,
a brute-force attempt, a scraper) and you want to throttle requests
before they reach the backend.

This tutorial reuses the `hello` Service and `edge` Gateway from
[Hello, HTTP](/docs/tutorials/hello-http/).

## 1. Attach a rate limit

Rate limiting is an [extension](/docs/extensions/): a ConfigMap holding a
`ratelimit.hcl` document, attached to a route rule with an `ExtensionRef`
filter. The filter and the ConfigMap it points to travel together:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: hello-limits
data:
  ratelimit.hcl: |
    version = 1

    rate_limit {
      requests = 3
      window   = "1m"
      key      = "client_ip"
    }
---
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
    - filters:
        - type: ExtensionRef
          extensionRef:
            group: ""
            kind: ConfigMap
            name: hello-limits
      backendRefs:
        - name: hello
          port: 80
```

Each `(rule, client)` pair gets a token bucket: `requests` tokens are
added per `window`, a request consumes one, and an empty bucket rejects.
The optional `burst` sets the bucket capacity (defaulting to `requests`)
for clients that legitimately arrive in spikes. Like the WAF, the filter
attaches per rule: only the matching rule is limited.

## 2. Trip it

Three requests per minute is easy to exhaust by hand:

```sh
GW_IP=$(kubectl get gateway edge -o jsonpath='{.status.addresses[0].value}')
for i in $(seq 1 5); do
  curl -s -o /dev/null -w '%{http_code}\n' \
    -H 'Host: hello.example.com' "http://$GW_IP/"
done
```

The first three print `200`, the rest `429`. A limited response tells
the client when to come back:

```sh
curl -i -H 'Host: hello.example.com' "http://$GW_IP/"
```

The `Retry-After` header carries the whole seconds until the next token.
The rejection status is configurable with `status` (any 4xx or 5xx) if
`429 Too Many Requests` does not fit your API.

## 3. Key by client identity

`key = "client_ip"` buckets by the downstream TCP peer address.
Forwarded headers are not consulted, since krouter has no trusted-proxy
configuration. When clients authenticate, bucket them by what identifies
them instead:

```hcl
version = 1

rate_limit {
  requests = 3
  window   = "1m"
  key      = "header:X-API-Key"
}
```

Each distinct header value gets its own bucket; requests without the
header share one anonymous bucket. Verify with two identities:

```sh
for key in alice bob; do
  for i in $(seq 1 4); do
    curl -s -o /dev/null -w "$key: %{http_code}\n" \
      -H 'Host: hello.example.com' -H "X-API-Key: $key" "http://$GW_IP/"
  done
done
```

`alice` and `bob` each get three `200`s before their own `429`.

## 4. Share a base, override per route

Several `ExtensionRef` filters on one rule compose in filter list order.
Unlike WAF directives (which concatenate), `ratelimit.hcl` documents
merge attribute by attribute: a later document overrides the attributes
it sets and inherits the rest. A platform-wide default can then be
tightened where it matters:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: api-limits          # shared by many routes
data:
  ratelimit.hcl: |
    version = 1

    rate_limit {
      requests = 100
      window   = "1m"
      key      = "client_ip"
    }
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: login-limits        # stricter, for the login rule only
data:
  ratelimit.hcl: |
    version = 1

    rate_limit {
      requests = 5
    }
```

```yaml
      filters:
        - type: ExtensionRef
          extensionRef:
            group: ""
            kind: ConfigMap
            name: api-limits
        - type: ExtensionRef
          extensionRef:
            group: ""
            kind: ConfigMap
            name: login-limits
```

The login rule ends up with `requests = 5` and inherits `window` and
`key` from the base. The merged result must define at least `requests`
and `window`; an incomplete merge sets `ResolvedRefs` to `False` with
reason `InvalidExtensionRef` and the rule fails closed with `500`,
exactly like a broken WAF program.

## 5. What to know in production

- Enforcement is local to each data-plane pod and there is no
  cluster-wide coordination: with N pods behind one address, a client
  can consume up to N times the configured rate. Size `requests`
  accordingly.
- Buckets are local to a configuration generation: editing the ConfigMap
  compiles a new one and counters start fresh, exactly like round-robin
  counters on a table swap. Idle buckets are reclaimed, so memory does
  not grow with the number of distinct clients.
- Rate limiting runs before the WAF (a limited request consumes no WAF
  CPU) and before any other filter; a limited request is never mirrored,
  redirected or forwarded.
- Decisions are observable as
  `krouter_dataplane_ratelimit_decisions_total` and in the access log;
  see [Observability](/docs/observability/).

**Next:** [put a web application firewall in front](/docs/tutorials/waf/).
