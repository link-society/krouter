"""
Builders for Gateway API resources and krouter parameter ConfigMaps.

Parameters use core ConfigMaps holding a `krouter.hcl` key in HCL native
syntax (docs/spec/parameters.md) — no krouter CRDs exist by design (docs/spec/overview.md).
"""

from e2elib import config


# ------------------------------------------------------------ parameters --

def infra_params_hcl(
    service_type: str = "NodePort",
    external_traffic_policy: str = "Local",
    node_ports: dict[str, int] | None = None,
    annotations: dict[str, str] | None = None,
) -> str:
    """
    Gateway infrastructure parameters (docs/spec/parameters.md).
    """

    lines = [
        "version = 1",
        "",
        "service {",
        f'  type                    = "{service_type}"',
        f'  external_traffic_policy = "{external_traffic_policy}"',
    ]

    if annotations:
        lines.append("")
        lines.append("  annotations = {")

        for key, value in sorted(annotations.items()):
            lines.append(f'    "{key}" = "{value}"')

        lines.append("  }")

    if node_ports:
        lines.append("")
        lines.append("  node_ports = {")

        for listener, port in sorted(node_ports.items()):
            lines.append(f'    "{listener}" = {port}')

        lines.append("  }")

    lines.append("}")

    return "\n".join(lines) + "\n"


def gatewayclass_params_hcl(algorithm: str = "round_robin") -> str:
    """
    GatewayClass parameters (docs/spec/parameters.md).
    """

    return (
        "version = 1\n"
        "\n"
        "load_balancing {\n"
        f'  algorithm = "{algorithm}"\n'
        "}\n"
    )


def params_configmap(name: str, namespace: str, hcl: str) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": namespace},
        "data": {"krouter.hcl": hcl},
    }


# ------------------------------------------------------- gateway objects --

def gateway_class(
    name: str,
    controller_name: str = config.CONTROLLER_NAME,
    params_ref: dict | None = None,
) -> dict:
    spec: dict = {"controllerName": controller_name}

    if params_ref:
        spec["parametersRef"] = {
            "group": "",
            "kind": "ConfigMap",
            **params_ref,
        }

    return {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GatewayClass",
        "metadata": {"name": name},
        "spec": spec,
    }


def listener(
    name: str,
    port: int,
    protocol: str,
    hostname: str | None = None,
    tls_secret: str | tuple[str, str] | None = None,
    allowed_routes: dict | None = None,
) -> dict:
    entry: dict = {"name": name, "port": port, "protocol": protocol}

    if hostname:
        entry["hostname"] = hostname

    if protocol == "HTTPS":
        if isinstance(tls_secret, tuple):
            secret_ns, secret_name = tls_secret
            ref = {"kind": "Secret", "name": secret_name, "namespace": secret_ns}
        else:
            ref = {"kind": "Secret", "name": tls_secret}

        entry["tls"] = {"mode": "Terminate", "certificateRefs": [ref]}

    if protocol == "TLS":
        # Passthrough only (docs/spec/overview.md): krouter never holds the
        # certificate, the backend owns the TLS session.
        entry["tls"] = {"mode": "Passthrough"}

    if allowed_routes:
        entry["allowedRoutes"] = allowed_routes

    return entry


def gateway(
    name: str,
    namespace: str,
    listeners: list[dict],
    gateway_class: str = config.GATEWAY_CLASS,
    infra_params: str | None = None,
) -> dict:
    spec: dict = {"gatewayClassName": gateway_class, "listeners": listeners}

    if infra_params:
        spec["infrastructure"] = {
            "parametersRef": {
                "group": "",
                "kind": "ConfigMap",
                "name": infra_params,
            },
        }

    return {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec,
    }


def backend_ref(
    name: str,
    port: int,
    namespace: str | None = None,
    weight: int | None = None,
) -> dict:
    ref: dict = {"name": name, "port": port}

    if namespace:
        ref["namespace"] = namespace

    if weight is not None:
        ref["weight"] = weight

    return ref


def http_route(
    name: str,
    namespace: str,
    parent_refs: list[dict],
    hostnames: list[str] | None = None,
    rules: list[dict] | None = None,
) -> dict:
    spec: dict = {"parentRefs": parent_refs}

    if hostnames:
        spec["hostnames"] = hostnames

    if rules is not None:
        spec["rules"] = rules

    return {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec,
    }


def tcp_route(
    name: str,
    namespace: str,
    parent_refs: list[dict],
    backend_refs: list[dict],
) -> dict:
    """
    TCPRoute (Experimental channel, docs/spec/overview.md): no hostname,
    path or filter semantics — one rule forwarding raw streams to backends
    (docs/spec/traffic.md).
    """

    return {
        "apiVersion": "gateway.networking.k8s.io/v1alpha2",
        "kind": "TCPRoute",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "parentRefs": parent_refs,
            "rules": [
                {"backendRefs": backend_refs},
            ],
        },
    }


def udp_route(
    name: str,
    namespace: str,
    parent_refs: list[dict],
    backend_refs: list[dict],
) -> dict:
    """
    UDPRoute (Experimental channel, docs/spec/overview.md): no hostname,
    path or filter semantics — one rule forwarding datagrams per client
    flow to backends (docs/spec/traffic.md).
    """

    return {
        "apiVersion": "gateway.networking.k8s.io/v1alpha2",
        "kind": "UDPRoute",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "parentRefs": parent_refs,
            "rules": [
                {"backendRefs": backend_refs},
            ],
        },
    }


def tls_route(
    name: str,
    namespace: str,
    parent_refs: list[dict],
    hostnames: list[str],
    backend_refs: list[dict],
) -> dict:
    """
    TLSRoute (Experimental channel, docs/spec/overview.md): SNI-matched
    passthrough of still-encrypted streams to backends
    (docs/spec/traffic.md).
    """

    return {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "TLSRoute",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "parentRefs": parent_refs,
            "hostnames": hostnames,
            "rules": [
                {"backendRefs": backend_refs},
            ],
        },
    }


def grpc_route(
    name: str,
    namespace: str,
    parent_refs: list[dict],
    hostnames: list[str] | None = None,
    rules: list[dict] | None = None,
) -> dict:
    """
    GRPCRoute (Standard channel, docs/spec/overview.md): method and header
    matched gRPC routing over HTTP/2 (docs/spec/traffic.md).
    """

    spec: dict = {"parentRefs": parent_refs}

    if hostnames:
        spec["hostnames"] = hostnames

    if rules is not None:
        spec["rules"] = rules

    return {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GRPCRoute",
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec,
    }


def parent_ref(
    name: str,
    namespace: str | None = None,
    section_name: str | None = None,
) -> dict:
    ref: dict = {"name": name}

    if namespace:
        ref["namespace"] = namespace

    if section_name:
        ref["sectionName"] = section_name

    return ref


def reference_grant(
    name: str,
    namespace: str,
    from_kind: str,
    from_namespace: str,
    to_kind: str,
    to_name: str | None = None,
) -> dict:
    group_for = {
        "HTTPRoute": "gateway.networking.k8s.io",
        "Gateway": "gateway.networking.k8s.io",
    }

    to: dict = {"group": "", "kind": to_kind}
    if to_name:
        to["name"] = to_name

    return {
        "apiVersion": "gateway.networking.k8s.io/v1beta1",
        "kind": "ReferenceGrant",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "from": [
                {
                    "group": group_for.get(from_kind, ""),
                    "kind": from_kind,
                    "namespace": from_namespace,
                },
            ],
            "to": [to],
        },
    }
