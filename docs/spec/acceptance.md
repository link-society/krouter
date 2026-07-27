# Acceptance criteria

The implementation is accepted when:

1. The Gateway API v1.6.1 `GATEWAY-HTTP` Core conformance suite passes in
   full.
2. HTTP/1.1 and HTTP/2 work through HTTP and HTTPS listeners.
3. Cross-namespace Route attachment and backend access obey namespace
   selectors and ReferenceGrant.
4. Multiple Gateways may expose the same external listener ports through
   separate Services without routing leakage.
5. A Gateway update activates atomically on every healthy data-plane pod.
6. A rejected data-plane generation leaves the last valid generation
   serving.
7. Active connections survive configuration and certificate reloads.
8. EndpointSlice readiness changes alter backend selection without a pod
   restart.
9. Gateway API status and observed generations accurately reflect
   acceptance, reference resolution, and data-plane programming.
10. A data-plane pod passes the 10,000 concurrent-connection test.
11. Side-by-side NGINX and Traefik benchmark results are reproducible and
    published.
12. The installation requires only the standard manifest plus preinstalled
    Gateway API CRDs.
13. TCP listeners forward raw streams to TCPRoute backends with the same
    atomic-update, last-valid, and connection-survival guarantees as HTTP
    traffic, and the `GATEWAY-TCP` Core conformance tests pass.
14. TLS passthrough listeners route by SNI to TLSRoute backends without
    terminating the session, with the same guarantees as TCP forwarding,
    and the `GATEWAY-TLS` Core conformance tests pass.
15. GRPCRoute traffic (method and header matching, h2c backend
    forwarding, streaming and trailer preservation) passes the
    `GATEWAY-GRPC` Core conformance tests, with the same guarantees as
    HTTP traffic.
16. The supported Extended HTTPRoute filters (response header
    modification, URL rewriting, redirect path/scheme/port and
    alternative status codes, and request mirroring) pass the
    corresponding Extended conformance tests.
17. HTTPRoute rule timeouts (`request` and `backendRequest`) pass the
    corresponding Extended conformance tests.
18. The GatewayClass publishes `status.supportedFeatures`, and the
    conformance suite derives its feature set from it without manual
    declaration.
19. UDP listeners forward datagrams to UDPRoute backends with per-flow
    backend association and the same atomic-update and last-valid
    guarantees as TCP traffic, and the `GATEWAY-UDP` Core conformance
    tests pass.
20. BackendTLSPolicy re-encryption (SNI, CA verification, fail-closed
    mismatches, conflict resolution, and ancestor status) passes the
    corresponding conformance tests.
21. ListenerSet attachment (allowed-listeners gating, listener merging
    with conflict rejection, per-set route binding, ReferenceGrant
    semantics, and set statuses) passes the corresponding conformance
    tests.
22. The Gateway API conformance suite passes every non-Mesh test in the
    `GATEWAY-HTTP`, `GATEWAY-GRPC`, `GATEWAY-TLS`, `GATEWAY-TCP`, and
    `GATEWAY-UDP` profiles: the only skipped tests are those requiring
    the `MESH` profile, the HTTPRoute retry tests (retries are deferred
    work), and the "not supported" tests that skip themselves because
    krouter supports the corresponding feature (TLSRoute Terminate and
    mixed termination).
23. WebSocket upgrades traverse the proxy end to end on HTTP and HTTPS
    listeners, verified by end-to-end tests exchanging frames through
    the gateway, surviving configuration reloads.
24. `ExtensionRef` rate limiting enforces the configured token buckets
    (exhaustion, `Retry-After`, per-header keys, recovery, WebSocket
    handshakes), merges partial documents in filter order, fails closed
    on broken references, and reloads on ConfigMap edits, verified by
    end-to-end tests.
25. `ExtensionRef` WAF inspection denies hostile requests and passes
    clean traffic (HTTP, gRPC headers, WebSocket handshakes before any
    hijack), composes layered directive fragments in filter order,
    fails closed on broken references, and the gotestwaf suite scores
    at or above the agreed threshold against a CRS-protected route,
    runnable locally.
26. Client IP resolution honors `X-Forwarded-For` only from peers listed
    in the Gateway's `client_ip.trusted_proxies` parameter: the resolved
    address drives the access log and `client_ip` rate limiting buckets,
    a trusted chain reaches backends with the peer appended, values sent
    by an untrusted peer are discarded, and a malformed prefix is
    reported as `InvalidParameters`, verified by end-to-end tests.
