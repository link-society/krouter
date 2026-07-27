# Security

## TLS material

- The control plane validates every listener certificate reference and
  applicable ReferenceGrant.
- Only referenced certificate/key data is copied into the generated TLS
  Secret in `krouter-system`.
- Source Secret changes create a new Gateway configuration generation.
- The data plane never receives read permission for arbitrary source
  Secrets.
- A certificate update is activated atomically and MUST NOT terminate
  connections using the previous certificate.
- Generated Secrets MUST NOT appear in logs, metrics, ConfigMaps, or status
  messages.
- TLS passthrough listeners carry no certificate reference: krouter reads
  the SNI value from the ClientHello without decrypting anything, and the
  backend owns the TLS session end to end.

## Frontend client certificate validation

`Gateway.spec.tls.frontend` configures client-certificate validation for
HTTPS listeners: `default.validation` applies to every HTTPS listener, and
`perPort` entries override it for their port.

- `caCertificateRefs` MUST reference core ConfigMaps (key `ca.crt`);
  cross-namespace references require a ReferenceGrant. Invalid references
  set the listener `ResolvedRefs` condition to False with reason
  `InvalidCACertificateRef`, `InvalidCACertificateKind`, or
  `RefNotPermitted`, and the listener is rejected with
  `Accepted=False`/`NoValidCACertificate`.
- Mode `AllowValidOnly` (default) requires a client certificate verified
  against the configured CAs; handshakes without one fail.
- Mode `AllowInsecureFallback` accepts connections with missing or invalid
  client certificates. While any listener uses it, the Gateway publishes
  the `InsecureFrontendValidationMode` condition with reason
  `ConfigurationChanged`; the condition is removed when the mode returns
  to `AllowValidOnly`.

## Client IP trust

Forwarded headers are attacker-controlled unless an intermediary rewrites
them. krouter therefore honors `X-Forwarded-For` only from peers covered
by the `client_ip.trusted_proxies` Gateway infrastructure parameter
([parameters.md](parameters.md), [traffic.md](traffic.md) Forwarding
headers), and trusts no peer by default.

Operators MUST list only intermediaries that append to or overwrite the
chain themselves. Trusting a network clients can reach directly lets any
client pick its own client IP, which defeats the access log, rate
limiting keys, and every policy derived from them. The list is a Gateway
infrastructure parameter because the trust decision follows the
deployment topology in front of that Gateway: it belongs to the cluster
operator owning the Gateway, not to the teams owning the routes attached
to it.

The proxy protocol preamble ([traffic.md](traffic.md)) answers the same
question at connection level and uses the same list. A listener therefore
cannot require a preamble unless `trusted_proxies` is set, and a preamble
arriving from any other peer closes the connection rather than being
ignored: on a listener that requires one, such a connection is either a
misconfiguration or an attempt to choose a client address, and neither
should be served.

## RBAC

The installation follows least privilege within the constraints of a
cluster-wide Gateway controller.

### Control-plane permissions

The control plane may:

- Read the Gateway API and Kubernetes resources it reconciles.
- Update status only for Gateway API resources owned by its controller
  name.
- Create/update/delete generated Services, EndpointSlices, RoleBindings,
  ConfigMaps, and Secrets.
- Read referenced Secrets to produce generated TLS Secrets.

### Data-plane permissions

The data plane may:

- Read controller-generated ConfigMaps and Secrets in `krouter-system`.
- Read Services and EndpointSlices only in namespaces containing an
  accepted backend used by at least one owned Gateway.
- Read no source TLS Secrets.
- Write no Gateway API resources or statuses.

The control plane manages namespace-scoped RoleBindings for backend
discovery. It removes access when no accepted configuration owned by the
installation uses that namespace.

## Workload hardening

Both workloads SHOULD run as non-root, use a read-only root filesystem,
drop Linux capabilities, disallow privilege escalation, and use the default
seccomp profile.
