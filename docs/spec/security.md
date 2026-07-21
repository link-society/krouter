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
