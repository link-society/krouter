"""
Multiple Gateways sharing external listener ports (spec §7, §20.4).

Two Gateways expose the same external port 80 and hostname through separate
generated Services. Traffic must never leak between them, and the generated
frontend objects must follow the provisioning rules of spec §7.
"""

import pytest

from e2elib import backends, config, gateway as gw, kubectl, net, ports
from e2elib.backends import BACKEND_PORT

HOSTNAME = "shared.example.com"


@pytest.fixture(scope="module")
def stack(gateway_class, module_namespace):
    """
    Two Gateways, same external port/hostname, distinct backends.
    """

    ns = module_namespace
    kubectl.apply(backends.mockserver_backend("backend-a", ns), namespace=ns)
    kubectl.apply(backends.mockserver_backend("backend-b", ns), namespace=ns)

    for suffix, node_port, backend in (
        ("a", ports.MULTI_GW_A, "backend-a"),
        ("b", ports.MULTI_GW_B, "backend-b"),
    ):
        kubectl.apply([
            gw.params_configmap(
                f"gw-params-{suffix}",
                ns,
                gw.infra_params_hcl(node_ports={"http": node_port}),
            ),
            gw.gateway(
                f"gw-{suffix}",
                ns,
                [gw.listener("http", 80, "HTTP")],
                infra_params=f"gw-params-{suffix}",
            ),
            gw.http_route(
                f"route-{suffix}",
                ns,
                [gw.parent_ref(f"gw-{suffix}")],
                hostnames=[HOSTNAME],
                rules=[
                    {"backendRefs": [
                        gw.backend_ref(backend, BACKEND_PORT),
                    ]},
                ],
            ),
        ])

    kubectl.wait_condition("gateway", "gw-a", ns, "Programmed", timeout=180)
    kubectl.wait_condition("gateway", "gw-b", ns, "Programmed", timeout=180)
    kubectl.wait_deployment_ready("backend-a", ns)
    kubectl.wait_deployment_ready("backend-b", ns)
    net.wait_http_ok(ports.MULTI_GW_A, host=HOSTNAME)
    net.wait_http_ok(ports.MULTI_GW_B, host=HOSTNAME)

    return ns


def _generated_service(ns: str, gateway_name: str) -> dict:
    """
    The Service owned by the Gateway (spec §7.1).
    """

    for svc in kubectl.get("services", namespace=ns)["items"]:
        for ref in svc["metadata"].get("ownerReferences", []):
            if ref.get("kind") == "Gateway" and ref.get("name") == gateway_name:
                return svc

    raise AssertionError(f"no generated Service owned by Gateway {gateway_name}")


def test_no_routing_leakage_between_gateways(stack):
    """
    Spec §20.4: same external port and hostname, isolated routing.
    """

    for _ in range(10):
        data_a = net.request_json(ports.MULTI_GW_A, host=HOSTNAME)
        data_b = net.request_json(ports.MULTI_GW_B, host=HOSTNAME)
        assert data_a["backend"] == "backend-a", f"gateway A leaked to {data_a['backend']}"
        assert data_b["backend"] == "backend-b", f"gateway B leaked to {data_b['backend']}"


def test_generated_service_shape(stack):
    """
    Spec §7.1: per-Gateway Service, selectorless, NodePort,
    externalTrafficPolicy Local, owned by the Gateway.
    """

    for name in ("gw-a", "gw-b"):
        svc = _generated_service(stack, name)

        assert svc["spec"].get("selector") in (None, {}), \
            "generated Service must have no pod selector"
        assert svc["spec"]["type"] == "NodePort"
        assert svc["spec"]["externalTrafficPolicy"] == "Local"

        owner = [
            ref for ref in svc["metadata"]["ownerReferences"]
            if ref["kind"] == "Gateway"
        ][0]
        assert owner["name"] == name


def test_internal_ports_are_unique_per_gateway(stack):
    """
    Spec §7.3: same external port 80 maps to distinct internal listener
    ports within the configured unprivileged range.
    """

    target_ports = {}
    for name in ("gw-a", "gw-b"):
        svc = _generated_service(stack, name)
        port80 = [p for p in svc["spec"]["ports"] if p["port"] == 80][0]

        target = port80["targetPort"]
        assert isinstance(target, int), "internal listener port must be numeric"
        assert config.INTERNAL_PORT_MIN <= target <= config.INTERNAL_PORT_MAX, \
            f"internal port {target} outside configured range"

        target_ports[name] = target

    assert target_ports["gw-a"] != target_ports["gw-b"], \
        "distinct Gateways must not share an internal listener port"


def test_mirrored_endpointslices(stack):
    """
    Spec §7.2: controller-managed EndpointSlices mirror ready data-plane
    pods with node names for externalTrafficPolicy Local.
    """

    dataplane_ips = {
        pod["status"]["podIP"]
        for pod in kubectl.dataplane_pods()
        if pod["status"].get("podIP")
    }
    assert dataplane_ips, "no data-plane pod IPs found"

    for name in ("gw-a", "gw-b"):
        svc = _generated_service(stack, name)
        svc_name = svc["metadata"]["name"]

        slices = kubectl.get(
            "endpointslices",
            namespace=stack,
            selector=f"kubernetes.io/service-name={svc_name}",
        )["items"]
        assert slices, f"no EndpointSlices for generated Service {svc_name}"

        mirrored_ips = set()
        for slice_ in slices:
            managed_by = slice_["metadata"]["labels"].get(
                "endpointslice.kubernetes.io/managed-by",
                "",
            )
            assert managed_by not in ("", "endpointslice-controller.k8s.io"), \
                "slices must be krouter-managed, not kube-controller-managed"

            owner = [
                ref for ref in slice_["metadata"].get("ownerReferences", [])
                if ref["kind"] == "Service"
            ]
            assert owner and owner[0]["name"] == svc_name, \
                "EndpointSlices must be owned by the generated Service"

            for endpoint in slice_.get("endpoints", []):
                assert endpoint.get("nodeName"), \
                    "endpoints must carry nodeName for externalTrafficPolicy=Local"

                if endpoint.get("conditions", {}).get("ready", False):
                    mirrored_ips.update(endpoint["addresses"])

        assert mirrored_ips == dataplane_ips, (
            f"{svc_name}: mirrored endpoints {mirrored_ips} do not match "
            f"ready data-plane pods {dataplane_ips}"
        )


def test_both_workers_serve_locally(stack):
    """
    externalTrafficPolicy Local + DaemonSet: every worker node answers on
    its own NodePort (spec §6.2/§7.2).
    """

    for worker in (1, 2):
        data = net.request_json(ports.MULTI_GW_A, host=HOSTNAME, worker=worker)
        assert data["backend"] == "backend-a"
