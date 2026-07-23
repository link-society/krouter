"""
TCP listeners and TCPRoute forwarding (docs/spec/traffic.md,
docs/spec/acceptance.md criterion 13).

A TCP listener forwards raw byte streams to TCPRoute backends with the same
per-connection balancing, atomic-update and connection-survival guarantees
as HTTP traffic. TCP routing has no hostname, path or filter semantics.
"""

import uuid

import pytest

from e2elib import backends, gateway as gw, kubectl, net, ports

EXTERNAL_PORT = 9000
BACKEND = "echo-tcp"


@pytest.fixture(scope="module")
def stack(gateway_class, module_namespace):
    """
    Gateway with one TCP listener forwarding to a two-replica echo backend.
    """

    ns = module_namespace
    kubectl.apply(backends.tcp_echo_backend(BACKEND, ns, replicas=2), namespace=ns)

    kubectl.apply([
        gw.params_configmap(
            "gw-params",
            ns,
            gw.infra_params_hcl(node_ports={"tcp": ports.TCP_ROUTES}),
        ),
        gw.gateway(
            "tcp-gw",
            ns,
            [gw.listener("tcp", EXTERNAL_PORT, "TCP")],
            infra_params="gw-params",
        ),
        gw.tcp_route(
            "echo-route",
            ns,
            [gw.parent_ref("tcp-gw")],
            backend_refs=[
                gw.backend_ref(BACKEND, backends.TCP_BACKEND_PORT),
            ],
        ),
    ])

    kubectl.wait_condition("gateway", "tcp-gw", ns, "Programmed", timeout=180)
    kubectl.wait_deployment_ready(BACKEND, ns)
    net.wait_tcp_ready(ports.TCP_ROUTES)

    return ns


def test_route_accepted_and_resolved(stack):
    """
    TCPRoute parents carry Accepted and ResolvedRefs (docs/spec/status.md).
    """

    kubectl.wait_route_parent_condition(
        "echo-route",
        stack,
        "Accepted",
        kind="tcproute",
    )
    kubectl.wait_route_parent_condition(
        "echo-route",
        stack,
        "ResolvedRefs",
        kind="tcproute",
    )


def test_stream_forwarded_and_echoed(stack):
    """
    Bytes flow both ways, uninterpreted (docs/spec/traffic.md).
    """

    with net.TcpStream(ports.TCP_ROUTES) as stream:
        greeting = stream.read_line()
        assert greeting.startswith(BACKEND + "-"), \
            f"greeting must identify a backend pod, got {greeting!r}"

        payload = f"ping-{uuid.uuid4()}"
        assert stream.echo(payload) == payload


def test_many_exchanges_on_one_connection(stack):
    """
    A connection is a single stream to a single backend, not per-message.
    """

    with net.TcpStream(ports.TCP_ROUTES) as stream:
        stream.read_line()

        for index in range(10):
            payload = f"seq-{index}"
            assert stream.echo(payload) == payload


def test_connections_balanced_across_backends(stack):
    """
    The backend endpoint is selected per downstream connection using the
    class load-balancing algorithm (docs/spec/traffic.md).
    """

    # Eventual consistency guard: wait until both replicas serve.
    kubectl.wait_for(
        lambda: len({net.tcp_greeting(ports.TCP_ROUTES) for _ in range(6)}) == 2 or None,
        timeout=60,
        desc="both TCP backends serving",
    )

    seen = {net.tcp_greeting(ports.TCP_ROUTES) for _ in range(12)}

    assert len(seen) == 2, f"expected both replicas to serve, saw {seen}"


def test_connection_survives_reload(stack):
    """
    Established TCP connections keep their backend across configuration
    reloads (docs/spec/traffic.md, docs/spec/acceptance.md criterion 13).
    """

    gateway = kubectl.get("gateway", "tcp-gw", stack)
    gateway_uid = gateway["metadata"]["uid"]

    with net.TcpStream(ports.TCP_ROUTES) as stream:
        stream.read_line()
        assert stream.echo("before-reload") == "before-reload"

        # Publish a new generation for the Gateway by changing the route.
        kubectl.apply(
            gw.tcp_route(
                "echo-route",
                stack,
                [gw.parent_ref("tcp-gw")],
                backend_refs=[
                    gw.backend_ref(BACKEND, backends.TCP_BACKEND_PORT, weight=7),
                ],
            ),
        )

        kubectl.wait_for(
            lambda: net.all_dataplane_pods_acked(gateway_uid) or None,
            timeout=120,
            desc="new generation applied by every data-plane pod",
        )

        # The held connection must still stream through the old objects.
        assert stream.echo("after-reload") == "after-reload"

    # New connections work against the new generation.
    assert net.tcp_greeting(ports.TCP_ROUTES).startswith(BACKEND + "-")


def test_multi_rule_route_rejected(stack):
    """
    Rules carry no matching semantics on L4 routes: a TCPRoute declaring
    more than one rule is ambiguous and MUST be rejected with reason
    UnsupportedValue, never partially applied (docs/spec/traffic.md).
    """

    rule = {"backendRefs": [gw.backend_ref(BACKEND, backends.TCP_BACKEND_PORT)]}

    kubectl.apply([
        gw.tcp_route(
            "multi-rule-route",
            stack,
            [gw.parent_ref("tcp-gw")],
            rules=[rule, dict(rule)],
        ),
    ])

    kubectl.wait_route_parent_condition(
        "multi-rule-route",
        stack,
        "Accepted",
        status="False",
        reason="UnsupportedValue",
        kind="tcproute",
    )
