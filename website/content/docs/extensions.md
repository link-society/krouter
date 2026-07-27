---
title: "Extensions"
description: "Per-rule rate limiting and Coraza WAF, attached with the ExtensionRef filter and configured from plain ConfigMaps."
weight: 4
---

krouter extends route rules through the Gateway API
[ExtensionRef filter](https://gateway-api.sigs.k8s.io/api-types/httproute/#filters-optional),
without defining any custom resource. An extension is a plain
[ConfigMap](https://kubernetes.io/docs/concepts/configuration/configmap/)
holding [HCL](https://github.com/hashicorp/hcl) documents, referenced from
an HTTPRoute or GRPCRoute rule. The ConfigMap lives in the route's own
namespace (`LocalObjectReference` semantics, so cross-namespace references
are not expressible) and carries one or both of these keys:

| Key | Contents |
|---|---|
| `ratelimit.hcl` | Token-bucket rate limiting |
| `waf.hcl` | Coraza web application firewall ruleset |

The filter and the ConfigMap it points to always travel together:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: api
  namespace: shop
spec:
  parentRefs:
    - name: public
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /api
      filters:
        - type: ExtensionRef
          extensionRef:
            group: ""
            kind: ConfigMap
            name: api-protection
      backendRefs:
        - name: api
          port: 8080
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: api-protection
  namespace: shop
data:
  ratelimit.hcl: |
    version = 1

    rate_limit {
      requests = 100
      window   = "1m"
      key      = "client_ip"
    }
  waf.hcl: |
    version = 1

    waf {
      directives = <<-EOT
        Include @coraza.conf-recommended
        Include @crs-setup.conf.example
        Include @owasp_crs/*.conf
        SecRuleEngine On
      EOT
    }
```

## Rate limiting

`ratelimit.hcl` configures a token bucket applied per rule and per client
key:

- `requests` and `window` set the refill rate (tokens added per window);
  `burst` is the optional bucket capacity (defaulting to `requests`).
- `key` buckets requests by `client_ip` (the resolved client address: the
  downstream peer, or what its forwarded chain says when the Gateway
  [trusts that peer](/docs/configuration/#client-ip-behind-another-proxy))
  or by `header:<Name>` (the first value of that request header, with a
  shared anonymous bucket for requests lacking it).
- A rejected request is answered with `status` (default `429`) and a
  [Retry-After](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Retry-After)
  header carrying the whole seconds until the next token.

Enforcement is local to each data-plane pod: there is no cluster-wide
coordination, so the effective limit is per pod and you should size
`requests` accordingly. Buckets are local to a configuration generation
and reset when the affected route changes, exactly like round-robin
counters on a table swap.

## Web application firewall

`waf.hcl` carries a [Coraza](https://coraza.io) (SecLang) ruleset. The
[OWASP Core Rule Set](https://coreruleset.org) and the Coraza recommended
configuration are embedded in the krouter binary and reachable through
the `@`-includes shown above; any other `Include` path reads rule files
from the pod filesystem, provided at deployment time by extending the
image or mounting volumes (see
[the WAF tutorial](/docs/tutorials/waf/) for both recipes).

- The request phases (request headers, then request body) are inspected
  before any byte reaches a backend. On HTTPRoute rules the body is
  buffered and inspected up to the engine's limits (`SecRequestBodyLimit`
  and related directives), then replayed to the backend unchanged. On
  GRPCRoute rules the request message is buffered and inspected the same
  way, which suits unary calls; for streaming calls the buffering adds
  latency, so scope the WAF to unary services. The stock CRS also rejects
  the `application/grpc` content type at the header phase (rule 920420)
  unless a later fragment allows it.
- A matching deny rule interrupts the request: the client receives the
  interruption's status (`403` when the ruleset sets none) and the backend
  never sees the request.
- Response phases are not inspected, which preserves response streaming.

[WebSocket](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API)
upgrades are inspected on the handshake request itself, before the
connection is hijacked into a tunnel; once the tunnel is established its
frames are neither inspected nor counted.

## Composition and status

Several `ExtensionRef` filters on one rule compose in filter list order,
which is the modularity mechanism: a base ConfigMap can be shared by many
routes and refined by later, route-specific ones.

- `ratelimit.hcl` documents merge attribute by attribute (a later document
  overrides the attributes it sets and inherits the rest).
- `waf.hcl` documents concatenate their directives into one ruleset, so a
  base ConfigMap can carry the CRS include and a later one the
  application-specific tuning.

Extensions follow the same fail-closed contract as the rest of the Gateway
API:

- A reference with any group other than core or any kind other than
  `ConfigMap`, or an `ExtensionRef` under `backendRefs[].filters`, rejects
  the route in full with reason `UnsupportedValue`.
- A referenced ConfigMap that is missing, carries neither key, holds
  invalid HCL, produces an incomplete merged rate-limit configuration, or
  whose concatenated WAF directives fail to build keeps the route accepted
  but sets `ResolvedRefs` to `False` with reason `InvalidExtensionRef`.
  Requests matching the affected rule are answered `500`, never silently
  skipped, mirroring how unresolvable backends behave.

The control plane validates a WAF ruleset by building the engine once at
compile time, so a broken program surfaces as `InvalidExtensionRef` before
any request reaches it.

## Enforcement order

For a request matched to a rule carrying extensions, enforcement runs rate
limiting first (cheapest, so a limited request consumes no WAF CPU), then
the WAF request phases, then every other filter and gateway-produced
response (CORS answers, redirects, mirrors, header modifiers, forwarding).
A request rejected by an extension is never mirrored, redirected, answered
with CORS headers, or forwarded.

See [Observability](/docs/observability/) for the decision metrics and the
access-log fields that record extension rejections.
