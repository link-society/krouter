"""
TLS passthrough listeners and TLSRoute forwarding (docs/spec/traffic.md,
docs/spec/acceptance.md criterion 14).

A TLS listener in Passthrough mode routes on the SNI value of the
ClientHello and forwards the still-encrypted stream: the backend owns the
TLS session end to end, krouter never holds the certificate. Guarantees
match TCP forwarding.
"""

import ssl
import uuid

import pytest

from e2elib import backends, certs, gateway as gw, kubectl, net, ports

EXTERNAL_PORT = 8443
SNI_A = "a.tls.example.com"
SNI_B = "b.tls.example.com"
SNI_UNMATCHED = "nobody.tls.example.com"


@pytest.fixture(scope="module")
def stack(gateway_class, module_namespace):
    """
    Gateway with one TLS passthrough listener and two SNI-routed backends.
    """

    ns = module_namespace
    ca = certs.make_ca()

    certs.apply_tls_secret(ca, "echo-a-cert", ns, SNI_A)
    certs.apply_tls_secret(ca, "echo-b-cert", ns, SNI_B)

    kubectl.apply(
        backends.tls_echo_backend("echo-a", ns, "echo-a-cert", replicas=2),
        namespace=ns,
    )
    kubectl.apply(
        backends.tls_echo_backend("echo-b", ns, "echo-b-cert"),
        namespace=ns,
    )

    kubectl.apply([
        gw.params_configmap(
            "gw-params",
            ns,
            gw.infra_params_hcl(node_ports={"tls": ports.TLS_ROUTES}),
        ),
        gw.gateway(
            "tls-gw",
            ns,
            [gw.listener("tls", EXTERNAL_PORT, "TLS")],
            infra_params="gw-params",
        ),
        gw.tls_route(
            "route-a",
            ns,
            [gw.parent_ref("tls-gw")],
            hostnames=[SNI_A],
            backend_refs=[
                gw.backend_ref("echo-a", backends.TLS_BACKEND_PORT),
            ],
        ),
        gw.tls_route(
            "route-b",
            ns,
            [gw.parent_ref("tls-gw")],
            hostnames=[SNI_B],
            backend_refs=[
                gw.backend_ref("echo-b", backends.TLS_BACKEND_PORT),
            ],
        ),
    ])

    kubectl.wait_condition("gateway", "tls-gw", ns, "Programmed", timeout=180)
    kubectl.wait_deployment_ready("echo-a", ns)
    kubectl.wait_deployment_ready("echo-b", ns)
    net.wait_tls_ready(ports.TLS_ROUTES, SNI_A)
    net.wait_tls_ready(ports.TLS_ROUTES, SNI_B)

    return ns


def test_route_accepted_and_resolved(stack):
    """
    TLSRoute parents carry Accepted and ResolvedRefs (docs/spec/status.md).
    """

    for route in ("route-a", "route-b"):
        kubectl.wait_route_parent_condition(
            route,
            stack,
            "Accepted",
            kind="tlsroute",
        )
        kubectl.wait_route_parent_condition(
            route,
            stack,
            "ResolvedRefs",
            kind="tlsroute",
        )


def test_sni_selects_the_route(stack):
    """
    The SNI value selects the TLSRoute (docs/spec/traffic.md).
    """

    assert net.tls_greeting(ports.TLS_ROUTES, SNI_A).startswith("echo-a-")
    assert net.tls_greeting(ports.TLS_ROUTES, SNI_B).startswith("echo-b-")


def test_stream_encrypted_end_to_end(stack):
    """
    The backend terminates TLS: the handshake and echo complete through
    the proxy without interference (docs/spec/security.md).
    """

    with net.TlsStream(ports.TLS_ROUTES, SNI_A) as stream:
        stream.read_line()

        payload = f"ping-{uuid.uuid4()}"
        assert stream.echo(payload) == payload


def test_unmatched_sni_is_refused(stack):
    """
    A connection whose SNI matches no route is refused without a
    handshake (docs/spec/traffic.md, docs/spec/failure-modes.md).
    """

    with pytest.raises((OSError, ssl.SSLError)):
        net.tls_greeting(ports.TLS_ROUTES, SNI_UNMATCHED)


def test_connections_balanced_across_backends(stack):
    """
    The backend endpoint is selected per downstream connection
    (docs/spec/traffic.md).
    """

    kubectl.wait_for(
        lambda: len({net.tls_greeting(ports.TLS_ROUTES, SNI_A) for _ in range(6)}) == 2 or None,
        timeout=60,
        desc="both TLS backends serving",
    )

    seen = {net.tls_greeting(ports.TLS_ROUTES, SNI_A) for _ in range(12)}

    assert len(seen) == 2, f"expected both replicas to serve, saw {seen}"


def test_connection_survives_reload(stack):
    """
    Established passthrough connections keep their backend across
    configuration reloads (docs/spec/traffic.md, docs/spec/acceptance.md
    criterion 14).
    """

    gateway = kubectl.get("gateway", "tls-gw", stack)
    gateway_uid = gateway["metadata"]["uid"]

    with net.TlsStream(ports.TLS_ROUTES, SNI_A) as stream:
        stream.read_line()
        assert stream.echo("before-reload") == "before-reload"

        # Publish a new generation for the Gateway by changing a route.
        kubectl.apply(
            gw.tls_route(
                "route-a",
                stack,
                [gw.parent_ref("tls-gw")],
                hostnames=[SNI_A],
                backend_refs=[
                    gw.backend_ref("echo-a", backends.TLS_BACKEND_PORT, weight=7),
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
    assert net.tls_greeting(ports.TLS_ROUTES, SNI_A).startswith("echo-a-")
