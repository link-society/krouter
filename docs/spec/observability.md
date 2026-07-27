# Observability

## Management endpoints

Both components expose on their management port:

- `/livez`
- `/readyz`
- `/metrics`

The data-plane readiness response also exposes generation acknowledgement
(see [status.md](status.md)). Liveness MUST report process health, not
configuration validity; an invalid desired generation MUST NOT restart a
pod that is serving a last-valid generation.

## Logging

Both components write structured, line-oriented text logs to standard
output, filtered by the configured minimum level.

The data plane writes one access-log event per completed request containing
at least:

- Gateway namespace/name.
- Route namespace/name.
- Selected backend Service and endpoint.
- HTTP method and authority.
- Response status.
- Duration.
- Bytes received and sent.
- HTTP protocol.
- Actual client IP: the peer address, or the address the trusted proxy
  chain attributes the request to ([traffic.md](traffic.md) Forwarding
  headers).
- Error classification when applicable.

For TCP and TLS passthrough listeners, the data plane writes one event per
closed connection with the same fields minus the HTTP-specific ones (plus
the SNI value for TLS passthrough); UDP listeners write one event per
expired flow. gRPC requests are logged like HTTP
requests, additionally carrying the gRPC status code.

## Metrics

Prometheus metrics MUST cover at least:

- Requests, responses, errors, active requests, and active connections.
- Request duration and transferred bytes.
- Backend selection and connection errors.
- Configuration generation success/failure and reload duration.
- Control-plane reconciliation errors and duration.
- Desired/applied generation divergence.

Metric labels MUST use bounded Kubernetes identities and status classes;
raw paths, client IPs, arbitrary headers, and endpoint IPs MUST NOT be
metric labels.
