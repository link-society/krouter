"""
GRPCRoute matching and forwarding (docs/spec/traffic.md gRPC routing,
docs/spec/acceptance.md criterion 15).

GRPCRoutes attach to HTTP listeners alongside HTTPRoutes. Method and header
matches select the backend; requests reach the backends as gRPC over
cleartext HTTP/2; unmatched gRPC requests receive the UNIMPLEMENTED status.

The client is a minimal hand-rolled gRPC unary caller (net.grpc_hello) and
the backends are standard helloworld.Greeter servers replying with their
pod hostname.
"""

import pytest

from e2elib import backends, gateway as gw, kubectl, net, ports

HOST_A = "grpc.example.com"
HOST_B = "grpc-b.example.com"

GRPC_UNIMPLEMENTED = 12


@pytest.fixture(scope="module")
def stack(gateway_class, module_namespace):
    """
    Gateway with one HTTP listener and method/header/hostname-routed
    GRPCRoutes over two greeter backends.
    """

    ns = module_namespace

    kubectl.apply(backends.grpc_greeter_backend("greeter-a", ns), namespace=ns)
    kubectl.apply(backends.grpc_greeter_backend("greeter-b", ns), namespace=ns)

    kubectl.apply([
        gw.params_configmap(
            "gw-params",
            ns,
            gw.infra_params_hcl(node_ports={"http": ports.GRPC_ROUTES}),
        ),
        gw.gateway(
            "grpc-gw",
            ns,
            [gw.listener("http", 80, "HTTP")],
            infra_params="gw-params",
        ),
        # Method match to A; header match overrides to B.
        gw.grpc_route(
            "greeter",
            ns,
            [gw.parent_ref("grpc-gw")],
            hostnames=[HOST_A],
            rules=[
                {
                    "matches": [
                        {"headers": [{"name": "x-echo-target", "value": "b"}]},
                    ],
                    "backendRefs": [
                        gw.backend_ref("greeter-b", backends.GRPC_BACKEND_PORT),
                    ],
                },
                {
                    "matches": [
                        {
                            "method": {
                                "service": "helloworld.Greeter",
                                "method": "SayHello",
                            },
                        },
                    ],
                    "backendRefs": [
                        gw.backend_ref("greeter-a", backends.GRPC_BACKEND_PORT),
                    ],
                },
            ],
        ),
        # Hostname-selected route to B.
        gw.grpc_route(
            "greeter-b",
            ns,
            [gw.parent_ref("grpc-gw")],
            hostnames=[HOST_B],
            rules=[
                {
                    "backendRefs": [
                        gw.backend_ref("greeter-b", backends.GRPC_BACKEND_PORT),
                    ],
                },
            ],
        ),
    ])

    kubectl.wait_condition("gateway", "grpc-gw", ns, "Programmed", timeout=180)
    kubectl.wait_deployment_ready("greeter-a", ns)
    kubectl.wait_deployment_ready("greeter-b", ns)
    net.wait_grpc_ready(ports.GRPC_ROUTES, HOST_A)
    # Both backends must be discoverable before the routing assertions.
    net.wait_grpc_ready(ports.GRPC_ROUTES, HOST_B)

    return ns


def test_route_accepted_and_resolved(stack):
    """
    GRPCRoute parents carry Accepted and ResolvedRefs (docs/spec/status.md).
    """

    for route in ("greeter", "greeter-b"):
        kubectl.wait_route_parent_condition(
            route,
            stack,
            "Accepted",
            kind="grpcroute",
        )
        kubectl.wait_route_parent_condition(
            route,
            stack,
            "ResolvedRefs",
            kind="grpcroute",
        )


def test_method_match_forwards_over_h2c(stack):
    """
    The gRPC request reaches the matched backend as HTTP/2 and completes
    (docs/spec/traffic.md gRPC routing).
    """

    status, reply = net.grpc_hello(ports.GRPC_ROUTES, HOST_A, name="krouter")

    assert status is None, f"expected a successful reply, got grpc-status {status}"
    assert reply.startswith("Hello krouter"), reply
    assert "greeter-a-" in reply, f"method match must select greeter-a, got {reply!r}"


def test_header_match_selects_backend(stack):
    """
    Header matches take precedence per rule order (docs/spec/traffic.md).
    """

    status, reply = net.grpc_hello(
        ports.GRPC_ROUTES,
        HOST_A,
        headers={"x-echo-target": "b"},
    )

    assert status is None, f"expected a successful reply, got grpc-status {status}"
    assert "greeter-b-" in reply, f"header match must select greeter-b, got {reply!r}"


def test_hostname_selects_route(stack):
    """
    Route hostnames select the GRPCRoute (docs/spec/traffic.md).
    """

    status, reply = net.grpc_hello(ports.GRPC_ROUTES, HOST_B)

    assert status is None, f"expected a successful reply, got grpc-status {status}"
    assert "greeter-b-" in reply, f"hostname must select greeter-b, got {reply!r}"


def test_unmatched_method_is_unimplemented(stack):
    """
    A gRPC request matching no rule receives UNIMPLEMENTED
    (docs/spec/traffic.md gRPC routing).
    """

    status, _ = net.grpc_hello(
        ports.GRPC_ROUTES,
        HOST_A,
        path="/helloworld.Greeter/SayGoodbye",
    )

    assert status == GRPC_UNIMPLEMENTED, \
        f"expected grpc-status {GRPC_UNIMPLEMENTED} (UNIMPLEMENTED), got {status}"
