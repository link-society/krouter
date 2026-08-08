"""
WebSocket upgrade passthrough (docs/spec/traffic.md Protocol handling,
docs/spec/acceptance.md criterion 23).

WebSocket upgrades traverse the proxy end to end on HTTP and HTTPS
listeners: the handshake is proxied, the tunnel carries frames in both
directions, and established tunnels survive configuration reloads.
"""

import ssl

import pytest

from e2elib import backends, certs, gateway as gw, kubectl, net, ports

BACKEND = "echo-ws"
WS_HOSTNAME = "ws.example.com"


@pytest.fixture(scope="module")
def ca():
    return certs.make_ca()


@pytest.fixture(scope="module")
def stack(gateway_class, module_namespace, ca):
    """
    Gateway with one HTTP and one HTTPS listener, both routing every path
    to a two-replica WebSocket echo backend.
    """

    ns = module_namespace
    kubectl.apply(backends.ws_backend(BACKEND, ns, replicas=2), namespace=ns)
    certs.apply_tls_secret(ca, "ws-cert", ns, WS_HOSTNAME)

    kubectl.apply([
        gw.params_configmap(
            "gw-params",
            ns,
            gw.infra_params_hcl(node_ports={
                "http": ports.WEBSOCKET,
                "https": ports.WEBSOCKET_TLS,
            }),
        ),
        gw.gateway(
            "ws-gw",
            ns,
            [
                gw.listener("http", 80, "HTTP"),
                gw.listener("https", 443, "HTTPS", tls_secret="ws-cert"),
            ],
            infra_params="gw-params",
        ),
        gw.http_route(
            "ws-route",
            ns,
            [gw.parent_ref("ws-gw")],
            rules=[
                {
                    "backendRefs": [
                        gw.backend_ref(BACKEND, backends.WS_BACKEND_PORT),
                    ],
                },
            ],
        ),
    ])

    kubectl.wait_condition("gateway", "ws-gw", ns, "Programmed", timeout=180)
    kubectl.wait_deployment_ready(BACKEND, ns)

    # The route also serves plain HTTP: /healthz reaches the backend
    # without upgrading, proving readiness end to end for each listener.
    net.wait_http_ok(ports.WEBSOCKET, path="/healthz")
    net.wait_http_ok(
        ports.WEBSOCKET_TLS,
        path="/healthz",
        scheme="https",
        host=WS_HOSTNAME,
    )

    return ns


def test_upgrade_and_echo(stack):
    """
    The handshake upgrades through the gateway and frames flow both ways
    (docs/spec/traffic.md Protocol handling).
    """

    with net.ws_connect(ports.WEBSOCKET) as conn:
        greeting = conn.recv(timeout=10)
        assert greeting.startswith("wsbin ")

        assert net.ws_echo_roundtrip(conn, "hello") == "hello"
        assert net.ws_echo_roundtrip(conn, "world") == "world"


def test_binary_frames(stack):
    """
    Binary frames are forwarded uninterpreted.
    """

    payload = bytes(range(32))

    with net.ws_connect(ports.WEBSOCKET) as conn:
        conn.recv(timeout=10)  # greeting

        conn.send(payload)
        assert conn.recv(timeout=10) == payload


def test_upgrade_over_https(stack, ca):
    """
    WebSocket upgrades work through TLS-terminating listeners (wss).
    """

    with net.ws_connect(
        ports.WEBSOCKET_TLS,
        scheme="wss",
        ca=ca,
        server_hostname=WS_HOSTNAME,
    ) as conn:
        greeting = conn.recv(timeout=10)
        assert greeting.startswith("wsbin ")

        assert net.ws_echo_roundtrip(conn, "secure") == "secure"


def test_tunnel_survives_reload(stack):
    """
    An established tunnel keeps flowing while a new generation is applied
    (docs/spec/traffic.md Connection lifecycle and hot reload).
    """

    ns = stack
    gateway = kubectl.get("gateway", "ws-gw", ns)
    gateway_uid = gateway["metadata"]["uid"]

    with net.ws_connect(ports.WEBSOCKET) as conn:
        conn.recv(timeout=10)  # greeting
        assert net.ws_echo_roundtrip(conn, "before-reload") == "before-reload"

        # Attach a second route: a new generation is compiled and applied.
        kubectl.apply(
            gw.http_route(
                "ws-route-extra",
                ns,
                [gw.parent_ref("ws-gw")],
                rules=[
                    {
                        "matches": [
                            {
                                "path": {
                                    "type": "PathPrefix",
                                    "value": "/extra",
                                },
                            },
                        ],
                        "backendRefs": [
                            gw.backend_ref(BACKEND, backends.WS_BACKEND_PORT),
                        ],
                    },
                ],
            ),
        )

        kubectl.wait_for(
            lambda: net.all_dataplane_pods_acked(gateway_uid) or None,
            timeout=120,
            desc="new generation applied by every data-plane pod",
        )

        # The held tunnel must still stream through the old objects.
        assert net.ws_echo_roundtrip(conn, "after-reload") == "after-reload"

    # New tunnels work against the new generation.
    with net.ws_connect(ports.WEBSOCKET) as conn:
        assert conn.recv(timeout=10).startswith("wsbin ")


def test_pods_reachable_across_connections(stack):
    """
    Upgrade connections balance across backend pods like plain requests
    (docs/spec/traffic.md Backend discovery and balancing).
    """

    pods = set()
    for _ in range(6):
        with net.ws_connect(ports.WEBSOCKET) as conn:
            greeting = conn.recv(timeout=10)
            pods.add(greeting.removeprefix("wsbin "))

    assert len(pods) == 2, f"expected both pods to serve tunnels, saw {pods}"
