# Acceptance criteria

The implementation is accepted when:

1. The Gateway API v1.5.1 `GATEWAY-HTTP` Core conformance suite passes in
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
    traffic. TCPRoute has no conformance profile in Gateway API v1.5.1;
    the krouter end-to-end suite is the verification.
