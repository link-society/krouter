# Traffic

The data-plane request path, its lifecycle guarantees, and the required
HTTP, gRPC, TCP, and TLS passthrough behavior.

## Request path

```mermaid
sequenceDiagram
    participant C as Client
    participant L as Internal listener
    participant RT as Routing table (active generation)
    participant E as Endpoint selection
    participant B as Backend endpoint

    C->>L: HTTP/1.1 or HTTP/2 request (TLS terminated if HTTPS)
    L->>RT: match hostname, then route, then rule
    RT->>RT: apply filters, regenerate forwarding headers
    RT->>E: weighted backend, eligible endpoints
    E->>B: HTTP/1.1 request (streamed)
    B-->>C: response (streamed through the proxy)
```

## gRPC routing

gRPC traffic is HTTP/2 traffic: GRPCRoutes attach to HTTP and HTTPS
listeners, alongside HTTPRoutes, with the same hostname semantics.

- Method matches select by gRPC service and method (exact matching for the
  Core profile), evaluated on their canonical HTTP/2 request form; header
  matches and the supported filters behave as for HTTPRoute rules.
- Backend endpoints receive gRPC over cleartext HTTP/2 (h2c), selected per
  request with the same weights, eligibility rules and load-balancing
  algorithm as every other route type.
- Streaming in every direction (unary, server, client, bidirectional) MUST
  flow without buffering, and gRPC trailers MUST be preserved end to end.
- A gRPC request matching no rule receives the gRPC `UNIMPLEMENTED`
  status, as required by the Gateway API.

## TCP forwarding

A TCP listener forwards raw byte streams; nothing is interpreted or
rewritten.

- A TCPRoute attaches to a TCP listener and carries no hostname, path,
  header, or filter semantics: every connection accepted by the listener
  is forwarded to one of the route's backend endpoints.
- Rules carry no matching semantics on L4 routes, so a route declaring
  more than one rule is ambiguous: the v1 CRD schema rejects it at
  admission, and krouter MUST reject any such object that reaches it
  anyway (reason `UnsupportedValue`), never partially applying it.
- When several routes attach to one listener, the oldest route (then the
  lexically smallest namespaced name) serves it, deterministically on
  every data-plane pod.
- The backend endpoint is selected once per downstream connection, applying
  Gateway API backend weights and the GatewayClass load-balancing algorithm
  over eligible endpoints, exactly as for HTTP backends.
- Bytes flow in both directions until either side closes the connection.
- An established connection keeps its selected backend across configuration
  reloads; listener removal stops new accepts while established connections
  finish.

## UDP forwarding

A UDP listener forwards datagrams; nothing is interpreted or rewritten.

- A UDPRoute attaches to a UDP listener and carries no hostname, path,
  header, or filter semantics: every datagram received by the listener is
  forwarded to one of the route's backend endpoints.
- Multi-rule routes and several routes on one listener follow the TCP
  forwarding semantics: more than one rule is rejected as ambiguous, and
  the oldest route serves the listener.
- Datagrams are associated into flows by client source address: a flow
  keeps its selected backend endpoint until it has been idle for a bounded
  period, and responses from the backend are relayed to the flow's client.
- The backend endpoint is selected once per flow, applying Gateway API
  backend weights and the GatewayClass load-balancing algorithm over
  eligible endpoints, exactly as for TCP connections.
- Established flows keep their selected backend across configuration
  reloads; listener removal stops the listener and expires its flows.

## TLS passthrough and termination

A TLS listener in `Passthrough` mode routes on the SNI value of the
ClientHello and forwards the connection still encrypted; krouter never
terminates the session and never holds the certificate (the backend owns
TLS end to end).

- A TLSRoute attaches to a TLS passthrough listener; its hostnames are
  matched against the SNI value with the same exact-then-wildcard
  precedence as HTTP hostname matching.
- The listener's own hostname restricts which SNI values it serves, as for
  HTTP listeners.
- Once a route is selected, the backend endpoint is chosen once per
  downstream connection, applying the same weights, eligibility rules and
  load-balancing algorithm as every other route type.
- The forwarded stream includes the ClientHello: the backend performs the
  TLS handshake with the original client bytes.
- A connection whose SNI matches no route MUST be refused without
  completing a handshake.
- Established connections keep their selected backend across configuration
  reloads, exactly as for TCP forwarding.

A TLS listener in `Terminate` mode terminates the session at the gateway
with the listener's `certificateRefs` material, then forwards the
decrypted stream to the selected TLSRoute backend with raw TCP semantics.
Route selection by SNI, refusal of unmatched SNI values, per-connection
backend choice, and reload behavior are identical to passthrough.

`Passthrough` and `Terminate` listeners MAY share one port (mixed
termination): the SNI value selects the listener, which decides per
connection whether the session terminates at the gateway.

## Backend TLS

A BackendTLSPolicy targeting a backend Service (optionally narrowed to one
Service port by `sectionName`) upgrades connections from the gateway to
that backend to TLS:

- The `validation.hostname` value is sent as SNI and verified against the
  backend certificate.
- `validation.subjectAltNames` entries (`Hostname` or `URI`), when present,
  replace hostname verification: the backend certificate MUST match at
  least one of them, and `validation.hostname` is then only used for SNI.
- The certificate chain is verified against `caCertificateRefs` ConfigMaps
  (key `ca.crt`) or, with `wellKnownCACertificates: System`, the system
  trust store.
- Verification failures MUST fail closed: the request is answered with a
  bad-gateway response, never sent in cleartext.
- A policy with an unresolvable or invalid CA reference is rejected
  (`Accepted=False`/`NoValidCACertificate`,
  `ResolvedRefs=False`/`InvalidKind` or `InvalidCACertificateRef`) and its
  backends fail closed.
- Two policies targeting the same Service and port conflict: the oldest
  wins and later ones are rejected with reason `Conflicted`.
- Policy status is reported per Gateway ancestor with this installation's
  controller name.

`Gateway.spec.tls.backend.clientCertificateRef` MAY reference a
`kubernetes.io/tls` Secret; its keypair is then presented as the client
certificate on every backend TLS connection of that Gateway. The Gateway
publishes a `ResolvedRefs` condition: an unresolvable, malformed, or
wrongly typed reference sets it to False with reason
`InvalidClientCertificateRef`; a cross-namespace reference without a
ReferenceGrant sets reason `RefNotPermitted`. The Gateway stays accepted,
and backend TLS connections proceed without a client certificate.

`options` is out of scope: policies using it are rejected as invalid
rather than partially applied.

## Connection lifecycle and hot reload

- Configuration reloads occur in process.
- Existing accepted connections and active requests continue using the
  objects that accepted them.
- New requests use the newly activated routing table.
- Old transports, certificates, and routing objects are released only after
  no active request depends on them.
- Listener removal stops new accepts while allowing existing connections to
  finish within normal server limits.
- The termination signal triggers graceful shutdown that completes within
  the pod's Kubernetes termination grace period.

No pod restart is used to apply a Route, Gateway, certificate, or
EndpointSlice change.

## Backend discovery and balancing

For every accepted backend Service reference, the data plane:

1. Resolves the selected Service port.
2. Watches EndpointSlices associated with that Service.
3. Selects endpoints whose conditions make them eligible for new traffic.
4. Excludes unready and terminating endpoints from new requests.
5. Applies Gateway API backend weights before selecting an endpoint.
6. Selects an endpoint using the GatewayClass load-balancing algorithm.

The default is round-robin. Active health checks are not performed.
Kubernetes workload probes and EndpointSlice conditions remain the source of
backend health.

The control plane MUST enforce ReferenceGrant rules before granting the data
plane access to or compiling a cross-namespace backend reference.

## Protocol handling

- Accept HTTP/1.1 and HTTP/2 downstream connections on HTTP and HTTPS
  listeners.
- Accept raw TCP connections on TCP listeners and forward them without
  interpretation.
- Accept UDP datagrams on UDP listeners and forward them per flow without
  interpretation.
- Accept TLS connections on TLS passthrough listeners, route by SNI, and
  forward them still encrypted.
- Use HTTP/1.1 for connections to backend endpoints of HTTP routes, and
  cleartext HTTP/2 (h2c) with preserved trailers for gRPC routes.
- Honor the backend Service port `appProtocol`: `kubernetes.io/h2c`
  backends are dialed with cleartext HTTP/2, and `kubernetes.io/ws`
  backends over HTTP/1.1 with standard upgrade passthrough. WebSocket
  upgrades MUST traverse the proxy end to end.
- Terminate HTTPS using certificates referenced by Gateway listeners.
- Support standard HTTP upgrade behavior required by the Core conformance
  profile.
- Preserve streaming; the proxy MUST NOT buffer complete request or
  response bodies by default.

## Routing and filters

krouter implements the exact matching, precedence, backend weighting,
listener isolation, reference resolution, and filter behavior required by
the Gateway API v1.6.1 `GATEWAY-HTTP`, `GATEWAY-GRPC`, `GATEWAY-TLS`,
`GATEWAY-TCP`, and `GATEWAY-UDP` Core conformance profiles.

Route `parentRefs` MAY pin listeners by `port` in addition to
`sectionName`. A parentRef carrying only `port` attaches to every listener
of the referenced parent with that port; carrying both, the named listener
MUST also have that port. A parentRef whose port matches no listener MUST
NOT be accepted (reason `NoMatchingParent`).

HTTPRoute matches support paths (`Exact` and `PathPrefix`), methods,
headers (`Exact`), and query parameters (`Exact`, first value of the
parameter). Precedence between matching rules follows the upstream order:
path specificity, then method presence, then number of matched headers,
then number of matched query parameters. Match types outside this set MUST
be rejected with reason `UnsupportedValue`.

HTTP listeners are isolated by hostname: a request is served exclusively
by the most specific listener whose hostname matches the request authority
among the listeners sharing the port. Routes attached to less specific
listeners MUST NOT serve such requests, even when their own hostnames and
matches would apply.

On HTTPS listeners sharing a port, a request whose authority is owned by a
different listener than the one selected by the connection's SNI MUST be
answered `421 Misdirected Request`, so clients retry on a fresh
connection. Authorities owned by the SNI-selected listener itself
(including every authority when that listener has no hostname) are routed
normally.

The following HTTPRoute rule filters MUST be supported with the upstream
Gateway API semantics:

- `RequestHeaderModifier` and `ResponseHeaderModifier`: add, set, and
  remove headers on the proxied request or response.
- `RequestRedirect`: scheme, hostname, port, path replacement
  (`ReplaceFullPath` and `ReplacePrefixMatch`), and the status codes
  permitted by the API. Unset values MUST be inherited from the incoming
  request (an unset port inherits the incoming listener port unless the
  scheme is changed, in which case the new scheme's default port applies)
  and default scheme ports MUST be omitted from the `Location` header.
- `URLRewrite`: hostname replacement and path replacement
  (`ReplaceFullPath` and `ReplacePrefixMatch`) before forwarding.
- `RequestMirror`: a copy of the request is delivered to a single
  endpoint of the mirror backend without influencing the client response;
  mirror failures and responses MUST be ignored. Several mirrors on one
  rule and percentage or fraction sampling MUST be honored.
- `CORS`: preflight requests (`OPTIONS` with `Origin` and
  `Access-Control-Request-Method`) are answered directly by the gateway;
  matching requests receive the configured `Access-Control-*` response
  headers. Origins match exactly, by `*`, or by wildcard host patterns
  (one or more leading labels). Non-matching origins receive no CORS
  headers. Wildcard allow-lists are answered by echoing the requested
  values, so replies stay valid for credentialed requests;
  `Access-Control-Allow-Credentials` is only ever emitted when configured.
  `maxAge` defaults to 5 seconds.

GRPCRoute rules support `RequestHeaderModifier`, `ResponseHeaderModifier`,
and `RequestMirror` with the same semantics.

HTTPRoute and GRPCRoute rules additionally support `ExtensionRef` filters
referencing core ConfigMaps and Secrets, enabling per-rule rate limiting,
WAF inspection (docs/spec/extensions.md), and authentication
(docs/spec/authentication.md).

Backend references MAY carry their own filters (`backendRefs[].filters`):
`RequestHeaderModifier` and `ResponseHeaderModifier` are supported and
apply only to traffic forwarded to that backend, after the rule-level
filters. Requests mirrored by a rule-level `RequestMirror` MUST NOT be
affected by per-backendRef filters. Any other per-backendRef filter type
rejects the route with `UnsupportedValue`.

HTTPRoute and GRPCRoute rules MAY be named (`rules[].name`). Rule names
MUST be accepted and preserved; they carry no routing behavior.

A route using any other filter type, or a filter value outside the
supported set, MUST be rejected with reason `UnsupportedValue` and MUST NOT
be partially applied.

No implementation-specific annotations are interpreted, and no custom
resources are defined: route extensions are limited to the `ExtensionRef`
contract of docs/spec/extensions.md.

## Timeouts

HTTPRoute `rules[].timeouts` MUST be honored with the upstream Gateway API
semantics:

- `request` bounds the time from the start of the downstream request to
  the start of the gateway's response; exceeding it answers
  `504 Gateway Timeout`.
- `backendRequest` bounds one request to a backend endpoint and MUST NOT
  exceed the effective `request` timeout.
- A zero duration disables the corresponding timeout.
- Timeouts apply per rule; rules without timeouts keep the default
  behavior (no timeout beyond ordinary server limits).

## Forwarding headers

krouter tells trusted downstream peers from untrusted ones through the
`client_ip.trusted_proxies` Gateway infrastructure parameter
([parameters.md](parameters.md)). No peer is trusted by default.

The client IP of a request MUST be resolved as follows:

- When the peer address is not covered by `trusted_proxies`, the client
  IP is the peer address and every forwarded header the peer sent is
  untrusted.
- Otherwise the `X-Forwarded-For` chain is walked from right to left and
  the first address not covered by `trusted_proxies` is the client IP.
  When every address in the chain is trusted, the leftmost one is used.
  When an entry is not a valid IP address, the walk stops and the
  nearest trusted address examined so far is used, so the resolved value
  is always an address krouter itself observed or a trusted proxy
  vouched for. An implementation MAY bound the number of entries it
  examines, provided the bound is at least 16.
- Only `X-Forwarded-For` is consulted. `Forwarded` (RFC 7239) is not
  parsed for resolution.

The resolved client IP is the one reported in the access log
([observability.md](observability.md)), the one the `client_ip` rate
limiting key buckets by, and the one the WAF sees as the connection's
remote address ([extensions.md](extensions.md)).

Outbound headers follow the same trust decision:

- From an untrusted peer, krouter regenerates spoof-sensitive
  `Forwarded` and `X-Forwarded-*` values from the actual downstream
  connection, discarding whatever the peer sent.
- From a trusted peer, the received `X-Forwarded-For` chain is preserved
  with the peer address appended, and the received `X-Forwarded-Host`,
  `X-Forwarded-Proto`, and `Forwarded` values are passed through
  unchanged.

Standard HTTPRoute `RequestHeaderModifier` filters run afterward and MAY
add, replace, or remove those headers for a rule.

Trusting a peer changes nothing else: `RequestRedirect` scheme
inheritance and misdirected-request detection keep describing the
connection krouter actually terminated. TCP, TLS passthrough, and UDP
listeners carry no forwarded headers: their client address is the
connection peer, or the address the preamble below names.

## Proxy protocol

A load balancer that forwards TCP without terminating HTTP cannot use
`X-Forwarded-For`. The
[PROXY protocol](https://www.haproxy.org/download/2.1/doc/proxy-protocol.txt)
carries the original addresses in a preamble sent before any other byte of
the connection. Listeners named in the `client_ip.proxy_protocol` Gateway
infrastructure parameter ([parameters.md](parameters.md)) MUST require one:

- Every connection MUST begin with a version 1 or version 2 preamble. Both
  versions MUST be accepted, and the version detected from the first bytes.
- A preamble MUST be honored only when the connection peer is covered by
  `trusted_proxies`. From any other peer the connection MUST be closed
  ([security.md](security.md) Client IP trust).
- A connection that does not begin with a preamble MUST be closed, without
  a response of any kind. There is none to give: no request has been read,
  and on an HTTPS or TLS listener no handshake has happened yet.
- The source address a preamble carries replaces the peer address for the
  rest of the connection. Everything describing the client uses it: the
  access log, the `client_ip` rate limiting key, the WAF's remote address,
  and the entry appended to `X-Forwarded-For`. Forwarded-header resolution
  then applies on top of it against the same trust list, so a load balancer
  followed by an HTTP proxy still resolves to the client the last one
  names.
- A version 2 `LOCAL` preamble and a version 1 `UNKNOWN` preamble carry no
  client address: the connection proceeds with the peer address. Load
  balancer health checks use them.
- Only TCP over IPv4 and IPv6 is supported. Any other address family or
  transport in a preamble is a protocol violation and MUST close the
  connection.
- Reading the preamble MUST be bounded: the version 1 line is at most 107
  bytes, the version 2 header is 16 bytes plus its declared length, and
  type-length-value blocks are skipped without being interpreted. A
  preamble that does not arrive complete within a deadline MUST close the
  connection.

Requiring a preamble is a property of the listener, not of the routes
attached to it: it is consumed before any hostname, path, or SNI is known,
so every client of that listener MUST send one. In-cluster clients are
included. Reaching a Gateway listener means taking the same path as any
other client, whether or not the packets ever leave the cluster.

HTTP, HTTPS, TCP, and TLS listeners MAY require a preamble. UDP listeners
have no connection to prefix. The management endpoints and the dashboard
([observability.md](observability.md)) never read one, whatever the
Gateways served by the same data-plane pod require.

Configuring the load balancer to send the preamble is deployment work.
krouter adds no provider-specific annotation to the generated Service;
operators declare them through `service.annotations`
([parameters.md](parameters.md)).
