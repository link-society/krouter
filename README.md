# krouter

**krouter** (Kubernetes Router) is a [Kubernetes Gateway
API](https://gateway-api.sigs.k8s.io) implementation and HTTP/HTTPS reverse
proxy. It uses standard Kubernetes resources only — no custom resource
definitions — ships as a single binary and container image, applies
configuration changes without dropping connections, and embeds a live
dashboard of your gateways, routes and backends.

The design, behavior and guarantees are described in the
[specification](docs/spec/README.md).

## Prerequisites

- A recent [Go](https://go.dev) toolchain (see [go.mod](go.mod))
- [Task](https://taskfile.dev) — all automation goes through it
- [Docker](https://www.docker.com) — container image builds
- [kind](https://kind.sigs.k8s.io) and `kubectl` — local test cluster
- [Python](https://www.python.org) with [PDM](https://pdm-project.org) —
  end-to-end test suites only
- [Helm](https://helm.sh) — comparative benchmarks only

`task --list` is the authoritative list of available commands.

## Building

```sh
task build         # compile the krouter binary
task docker:build  # build the container image
```

## Deploying

krouter requires the Gateway API CRDs (Standard channel) to be installed
first; its own manifest deliberately does not install them.

For a local kind-based environment:

```sh
task k8s:up      # create the cluster and install the Gateway API CRDs
task k8s:deploy  # build the image, load it, apply the static manifest
```

For any other cluster, install the Gateway API CRDs and apply the static
installation manifest from the [k8s](k8s/) directory with `kubectl apply`.
Everything — namespace, RBAC, control-plane Deployment, data-plane
DaemonSet, dashboard Service — is contained in that single manifest, as
required by the [deployment specification](docs/spec/deployment.md).

### Trying it out

A self-contained example topology is provided:

```sh
kubectl apply -f k8s/demo.yaml
kubectl -n krouter-system port-forward svc/krouter-dashboard 8080
```

Then open <http://localhost:8080> to explore the demo Gateway, its routes
and backends in the dashboard.

## Testing

Unit, end-to-end, official Gateway API conformance, performance-gate and
comparative benchmark suites are documented in
[tests/README.md](tests/README.md):

```sh
task tests:unit
task tests:e2e
task tests:conformance
task tests:performance
task tests:bench:all
```

## License

krouter is released under the [MIT License](LICENSE.txt).
