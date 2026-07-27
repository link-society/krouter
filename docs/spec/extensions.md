# Extensions

krouter extends HTTPRoute and GRPCRoute rules through the Gateway API
`ExtensionRef` filter, without defining any custom resource
(docs/spec/overview.md design principles). An extension is a core
ConfigMap holding HCL documents, referenced from a route rule:

```yaml
filters:
  - type: ExtensionRef
    extensionRef:
      group: ""
      kind: ConfigMap
      name: my-extension
```

The ConfigMap lives in the route's namespace (`LocalObjectReference`
semantics; cross-namespace references are not expressible). It carries one
or both of these keys:

| Key | Contents |
|---|---|
| `ratelimit.hcl` | Rate limiting configuration (see below) |
| `waf.hcl` | Coraza web application firewall configuration (see below) |

Other keys are ignored. A referenced ConfigMap carrying neither key is
invalid.

## Resolution and status

- `extensionRef` with any group other than `""` (core) or any kind other
  than `ConfigMap` is a filter value outside the supported set: the route
  MUST be rejected with reason `UnsupportedValue` and MUST NOT be
  partially applied (docs/spec/traffic.md Routing and filters).
- A rule MAY carry several `ExtensionRef` filters; they compose, in
  filter list order. Documents of the same key merge: `ratelimit.hcl`
  documents merge attribute by attribute (a later document overrides the
  attributes it sets and inherits the rest), and `waf.hcl` documents
  concatenate their directives into one ruleset (see below). This is the
  modularity mechanism: a base ConfigMap can be shared by many routes and
  refined by later, route-specific ones.
- `ExtensionRef` in `backendRefs[].filters` MUST be rejected with reason
  `UnsupportedValue`, like every non-header per-backendRef filter.
- A referenced ConfigMap that is missing, carries neither key, or holds
  invalid HCL keeps the route accepted (the filter type is supported;
  its target is broken) but MUST set the route's `ResolvedRefs`
  condition to `False` with reason `InvalidExtensionRef` and a message
  naming the ConfigMap and the error. The same handling applies when the
  merged rate-limit configuration is incomplete or when the concatenated
  WAF directives fail to build. Requests matching the affected rules
  MUST be answered `500 Internal Server Error`: per the upstream API, an
  unresolvable filter is never skipped. This mirrors the fail-closed
  behavior of unresolvable backends (docs/spec/traffic.md) and of
  rejected BackendTLSPolicies.

## Configuration lifecycle

Extension ConfigMaps are source configuration, exactly like parameter
ConfigMaps and certificate Secrets:

- The control plane reads them during reconciliation and compiles their
  content into the generated per-route configuration
  (docs/spec/configuration.md). Generations are content-addressed, so
  editing an extension ConfigMap produces a new generation that the data
  plane applies atomically, with the usual last-valid behavior on load
  failure.
- The data plane MUST NOT read source ConfigMaps (docs/spec/security.md):
  it consumes only the compiled copy.
- Rate limiter state is local to each compiled generation: buckets reset
  when the affected route's configuration changes, exactly as
  round-robin counters do on table swap (docs/spec/traffic.md Connection
  lifecycle and hot reload).

## Rate limiting

`ratelimit.hcl` schema (HCL native syntax, unknown or invalid fields
rejected, like every krouter HCL document, docs/spec/parameters.md):

```hcl
version = 1

rate_limit {
  requests = 100          # tokens added per window, > 0
  window   = "1m"         # Go duration, > 0
  burst    = 100          # optional bucket capacity, default = requests
  key      = "client_ip"  # "client_ip" or "header:<Header-Name>"
  status   = 429          # optional rejection status, 400-599
}
```

Semantics:

- Every attribute is optional in any single document: the documents
  reaching a rule merge in filter list order, a later document
  overriding the attributes it sets. The merged result MUST define at
  least `requests` and `window`; an incomplete merged configuration
  follows the `InvalidExtensionRef` handling.
- Token bucket per `(rule, client key)`: capacity `burst`, refilled at
  `requests` per `window`. A request consumes one token; an empty bucket
  rejects the request.
- `key = "client_ip"` buckets by the resolved client IP
  (docs/spec/traffic.md Forwarding headers): the downstream peer
  address, or the address the forwarded chain attributes the request to
  when that peer is a trusted proxy.
- `key = "header:<Name>"` buckets by the first value of that request
  header. Requests without the header share one anonymous bucket.
- Rejected requests are answered with `status` (default `429 Too Many
  Requests`) and a `Retry-After` header carrying the whole seconds until
  the next token (at least 1).
- Enforcement is local to each data-plane pod. There is no cluster-wide
  coordination: the effective limit is per pod, and operators MUST size
  `requests` accordingly. Distributed rate limiting is deferred work.
- Idle buckets MUST be reclaimed; memory MUST NOT grow unboundedly with
  the number of distinct client keys.

## Web application firewall

`waf.hcl` schema:

```hcl
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

Semantics:

- `directives` is a Coraza (SecLang) ruleset. The OWASP Core Rule Set and
  the Coraza recommended configuration are embedded in the krouter binary
  and reachable through the `@`-includes shown above. Any other `Include`
  path resolves against the pod filesystem, so operators MAY bring their
  own rule files by extending the container image or mounting volumes;
  both are deployment-level changes (Dockerfile, Kustomize), not Gateway
  API configuration. Included files MUST be present on the control-plane
  pod (which validates the program) and on every data-plane pod (which
  enforces it); running both from one extended image satisfies this by
  construction.
- Rule files are read when an engine builds, not watched: editing a
  mounted file in place does NOT produce a new configuration generation.
  Rolling the pods (or changing the ConfigMap directives) applies new
  file contents. A file missing on a data-plane pod fails that pod's
  engine build and the affected rule fails closed, per the
  `InvalidExtensionRef` request handling.
- The `waf.hcl` documents reaching a rule concatenate their `directives`
  in filter list order into one SecLang program: later fragments MAY add
  rules and exclusions or override engine settings, per SecLang
  semantics. A base ConfigMap can carry the CRS include and a later one
  the application-specific tuning.
- The control plane MUST validate the concatenated program by building
  the engine once at compile time; errors follow the
  `InvalidExtensionRef` handling above.
- Request phases (request headers, then request body) are enforced before
  any response is produced and before any byte reaches a backend. On
  HTTPRoute rules the request body is buffered and inspected up to the
  engine's body limits (`SecRequestBodyLimit` and related directives
  apply; this is the explicit exception to the no-buffering default of
  docs/spec/traffic.md Protocol handling).
- A matching deny rule interrupts the request: the client receives the
  interruption's status code (`403 Forbidden` when the ruleset does not
  set one) and the backend never sees the request.
- Response phases are NOT inspected: response header and body inspection
  is deferred work, preserving response streaming.
- On GRPCRoute rules the request-header phase is enforced and the request
  message is buffered and inspected up to the engine's body limits, the
  same explicit exception to the no-buffering default that HTTPRoute
  bodies use. This suits unary calls (the client half-closes, so the
  buffered message ends promptly); for client-streaming or bidirectional
  calls the buffering can add latency, so operators SHOULD scope the WAF
  ExtensionRef to unary services. The default CRS also rejects the
  `application/grpc` content type at the request-header phase (rule
  920420), so a stock ruleset denies gRPC traffic before the message is
  read unless the allowed-content-type list is tuned.

## WebSocket and upgrade requests

WebSocket upgrades traverse the proxy end to end
(docs/spec/traffic.md Protocol handling). Extension enforcement MUST
happen on the upgrade (handshake) request itself, before the connection
is hijacked into a tunnel:

- Rate limiting counts the handshake as one request; a limited handshake
  is rejected with the configured status and no upgrade happens.
- The WAF inspects the handshake request (method, path, query, headers;
  upgrade requests carry no body) and a deny interrupts it before any
  backend connection exists.
- Once the tunnel is established, WebSocket frames are NOT inspected or
  counted; in-tunnel enforcement is deferred work.

## Request path integration

For a request matched to a rule carrying extensions, enforcement order is:

1. Rate limiting (cheapest first; a limited request consumes no WAF CPU).
2. WAF request phases.
3. Every other filter and gateway-produced response (CORS preflight
   answers, redirects, mirrors, header modifiers, forwarding).

A request rejected by an extension MUST NOT be mirrored, redirected,
answered with CORS headers, or forwarded.

## Observability

- `krouter_dataplane_ratelimit_decisions_total{result}` with result
  `allowed` or `limited`.
- `krouter_dataplane_waf_decisions_total{result}` with result `allowed`,
  `denied`, or `error`.
- Rejected requests appear in the access log with the produced status and
  a field naming the rejecting extension (`ratelimit` or `waf`) and, for
  WAF denials, the interrupting rule identifier.
- Label rules of docs/spec/observability.md apply: no client keys, IPs,
  or paths as metric labels.

## Verification

- End-to-end tests MUST cover: WebSocket upgrade passthrough with and
  without extensions; rate limit exhaustion, `Retry-After`, per-header
  keys, and recovery; modular merging (a partial `ratelimit.hcl`
  overriding a base one, and a `waf.hcl` fragment layered over a base
  ruleset); WAF denial of hostile requests and acceptance of clean ones;
  WAF and rate limiting on WebSocket handshakes (denied before any
  upgrade); fail-closed `500` plus `ResolvedRefs=False` for broken
  extension ConfigMaps; and hot reload of extension configuration.
- The WAF MUST additionally be exercised with
  [gotestwaf](https://github.com/wallarm/gotestwaf) against a
  CRS-protected route, runnable locally, producing a report under
  `tests/results/`; the run fails below an agreed blocking threshold.
