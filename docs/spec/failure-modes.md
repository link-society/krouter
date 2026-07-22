# Failure modes

| Failure | Required behavior |
|---|---|
| Control plane unavailable | Existing traffic continues; reconciliation and frontend endpoint updates pause |
| Desired configuration cannot be compiled | Publish negative status; do not publish a broken generation |
| Data plane rejects desired generation | Continue last valid generation; report error; keep Programmed false |
| Source TLS Secret missing/invalid | Set ResolvedRefs false; do not expose key material; publish safe configuration |
| Backend has no ready endpoints | Return the Gateway API/conformance-required unavailable response (HTTP, or the equivalent gRPC status), refuse the connection (TCP and TLS passthrough), or drop the datagram (UDP); keep watching EndpointSlices |
| One data-plane pod unhealthy | Remove it from frontend EndpointSlices; healthy nodes continue |
| Generated resource manually deleted | Recreate it idempotently |
| Internal port range exhausted | Reject programming the affected listener/Gateway without disturbing existing allocations |

All reconciliations MUST be idempotent and tolerate duplicate Kubernetes
watch events.
