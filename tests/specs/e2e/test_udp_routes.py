"""
UDP listeners and UDPRoute forwarding (docs/spec/traffic.md,
docs/spec/acceptance.md criterion 19).

A UDP listener forwards datagrams to UDPRoute backends, associated into
flows by client source address: a flow keeps its backend endpoint, and
distinct flows are balanced with the class load-balancing algorithm. UDP
routing has no hostname, path or filter semantics.
"""

import pytest

from e2elib import backends, gateway as gw, kubectl, net, ports

EXTERNAL_PORT = 9000
BACKEND = "echo-udp"


@pytest.fixture(scope="module")
def stack(gateway_class, module_namespace):
    """
    Gateway with one UDP listener forwarding to a two-replica echo backend.
    """

    ns = module_namespace
    kubectl.apply(backends.udp_echo_backend(BACKEND, ns, replicas=2), namespace=ns)

    kubectl.apply([
        gw.params_configmap(
            "gw-params",
            ns,
            gw.infra_params_hcl(node_ports={"udp": ports.UDP_ROUTES}),
        ),
        gw.gateway(
            "udp-gw",
            ns,
            [gw.listener("udp", EXTERNAL_PORT, "UDP")],
            infra_params="gw-params",
        ),
        gw.udp_route(
            "echo-route",
            ns,
            [gw.parent_ref("udp-gw")],
            backend_refs=[
                gw.backend_ref(BACKEND, backends.UDP_BACKEND_PORT),
            ],
        ),
    ])

    kubectl.wait_condition("gateway", "udp-gw", ns, "Programmed", timeout=180)
    kubectl.wait_deployment_ready(BACKEND, ns)
    net.wait_udp_ready(ports.UDP_ROUTES)

    return ns


def test_route_accepted_and_resolved(stack):
    """
    UDPRoute parents carry Accepted and ResolvedRefs (docs/spec/status.md).
    """

    kubectl.wait_route_parent_condition(
        "echo-route",
        stack,
        "Accepted",
        kind="udproute",
    )
    kubectl.wait_route_parent_condition(
        "echo-route",
        stack,
        "ResolvedRefs",
        kind="udproute",
    )


def test_datagram_forwarded_and_answered(stack):
    """
    Datagrams reach a backend and its answer returns to the client
    (docs/spec/traffic.md).
    """

    identity = net.udp_identity(ports.UDP_ROUTES)

    assert identity.startswith(BACKEND + "-"), \
        f"answer must identify a backend pod, got {identity!r}"


def test_flow_keeps_its_backend(stack):
    """
    Datagrams from one source address form a flow pinned to one backend
    (docs/spec/traffic.md).
    """

    with net.UdpFlow(ports.UDP_ROUTES) as flow:
        seen = {flow.exchange() for _ in range(8)}

    assert len(seen) == 1, f"one flow must stay on one backend, saw {seen}"


def test_flows_balanced_across_backends(stack):
    """
    Distinct flows are balanced with the class load-balancing algorithm
    (docs/spec/traffic.md).
    """

    # Eventual consistency guard: wait until both replicas serve.
    kubectl.wait_for(
        lambda: len({net.udp_identity(ports.UDP_ROUTES) for _ in range(6)}) == 2 or None,
        timeout=60,
        desc="both UDP backends serving",
    )

    seen = {net.udp_identity(ports.UDP_ROUTES) for _ in range(12)}

    assert len(seen) == 2, f"expected both replicas to serve, saw {seen}"


def test_multi_rule_route_rejected(stack):
    """
    Rules carry no matching semantics on L4 routes: a UDPRoute declaring
    more than one rule is ambiguous. The v1 CRD schema refuses it at
    admission, so the object never reaches krouter (docs/spec/traffic.md).
    """

    rule = {"backendRefs": [gw.backend_ref(BACKEND, backends.UDP_BACKEND_PORT)]}

    with pytest.raises(kubectl.KubectlError, match="must have at most 1 item"):
        kubectl.apply([
            gw.udp_route(
                "multi-rule-route",
                stack,
                [gw.parent_ref("udp-gw")],
                rules=[rule, dict(rule)],
            ),
        ])
