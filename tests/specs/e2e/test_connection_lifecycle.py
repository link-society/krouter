"""
Connection lifecycle across reloads (docs/spec/traffic.md, docs/spec/security.md, docs/spec/performance.md, docs/spec/acceptance.md criterion 7).

Established connections and in-flight requests must survive route updates
and certificate rotations; only new connections/requests see the new
configuration.
"""

import time

import pytest

from e2elib import backends, certs, gateway as gw, kubectl, net, ports
from e2elib.backends import BACKEND_PORT

HOSTNAME = "lifecycle.example.com"


@pytest.fixture(scope="module")
def ca():
    return certs.make_ca()


@pytest.fixture(scope="module")
def stack(gateway_class, module_namespace, ca):
    ns = module_namespace
    certs.apply_tls_secret(ca, "lifecycle-cert", ns, HOSTNAME)
    kubectl.apply(backends.mockserver_backend("backend-a", ns))
    kubectl.apply(backends.mockserver_backend("backend-b", ns))

    kubectl.apply([
        gw.params_configmap(
            "lc-params",
            ns,
            gw.infra_params_hcl(
                node_ports={
                    "http": ports.CONN_LIFECYCLE,
                    "https": ports.CONN_LIFECYCLE_TLS,
                },
            ),
        ),
        gw.gateway(
            "lc-gw",
            ns,
            [
                gw.listener("http", 80, "HTTP"),
                gw.listener(
                    "https",
                    443,
                    "HTTPS",
                    hostname=HOSTNAME,
                    tls_secret="lifecycle-cert",
                ),
            ],
            infra_params="lc-params",
        ),
        _route(ns, "backend-a"),
    ])

    kubectl.wait_deployment_ready("backend-a", ns)
    kubectl.wait_deployment_ready("backend-b", ns)
    kubectl.wait_condition("gateway", "lc-gw", ns, "Programmed", timeout=180)
    net.wait_http_ok(ports.CONN_LIFECYCLE, host=HOSTNAME)
    net.wait_http_ok(ports.CONN_LIFECYCLE_TLS, host=HOSTNAME, scheme="https")

    yield ns

    kubectl.apply(_route(ns, "backend-a"))


def _route(ns: str, backend: str) -> dict:
    return gw.http_route(
        "lc-route",
        ns,
        [gw.parent_ref("lc-gw")],
        hostnames=[HOSTNAME],
        rules=[
            {"backendRefs": [
                gw.backend_ref(backend, BACKEND_PORT),
            ]},
        ],
    )


def _wait_switched(node_port: int, backend: str, scheme: str = "http"):
    def switched():
        data = net.request_json(node_port, host=HOSTNAME, scheme=scheme)

        return data["backend"] == backend or None

    kubectl.wait_for(switched, timeout=120, desc=f"route serving {backend}")


def test_keepalive_connection_survives_route_update(stack):
    """
    docs/spec/traffic.md: the same TCP connection keeps working across a reload, and
    new requests on it use the new routing table.
    """

    ns = stack
    conn = net.PersistentConnection(ports.CONN_LIFECYCLE, host=HOSTNAME)

    try:
        assert conn.get_json()["backend"] == "backend-a"

        kubectl.apply(_route(ns, "backend-b"))
        _wait_switched(ports.CONN_LIFECYCLE, "backend-b")

        # Same socket: no reconnect happened, and the new config is used.
        data = conn.get_json()
        assert data["backend"] == "backend-b", \
            "new requests on an existing connection must use the new routing table"

    finally:
        conn.close()


def test_in_flight_request_survives_route_update(stack):
    """
    docs/spec/traffic.md, docs/spec/acceptance.md criterion 7: a request already being served (delayed response) is
    not disturbed by a configuration reload happening mid-flight.
    """

    ns = stack
    conn = net.PersistentConnection(ports.CONN_LIFECYCLE, host=HOSTNAME)

    try:
        # /delayed answers after 15s; reload twice while it is in flight.
        conn.send_request("/delayed")
        time.sleep(1)
        kubectl.apply(_route(ns, "backend-b"))
        time.sleep(2)
        kubectl.apply(_route(ns, "backend-a"))

        status, body = conn.read_response()
        assert status == 200, "in-flight request must complete across reloads"
        assert b"delayed" in body

    finally:
        conn.close()


def test_tls_connection_survives_certificate_rotation(stack, ca):
    """
    docs/spec/security.md: a certificate update activates atomically without terminating
    connections established with the previous certificate.
    """

    ns = stack
    old_cert = net.get_server_certificate(ports.CONN_LIFECYCLE_TLS, sni=HOSTNAME)

    conn = net.PersistentTLSConnection(ports.CONN_LIFECYCLE_TLS, sni=HOSTNAME)

    try:
        assert conn.get_json()["backend"] in ("backend-a", "backend-b")

        # Rotate: issue a new certificate for the same hostname.
        certs.apply_tls_secret(ca, "lifecycle-cert", ns, HOSTNAME)

        def rotated():
            cert = net.get_server_certificate(ports.CONN_LIFECYCLE_TLS, sni=HOSTNAME)

            return cert.serial_number != old_cert.serial_number or None

        kubectl.wait_for(
            rotated,
            timeout=180,
            desc="new certificate served to new connections",
        )

        # The pre-rotation connection must still work.
        status, _ = conn.get()
        assert status == 200, \
            "connections using the previous certificate must not be terminated"

    finally:
        conn.close()


def test_no_dataplane_restarts_from_reloads(stack):
    """
    docs/spec/traffic.md: reloads happen in process — never through pod restarts.
    """

    restarts = kubectl.pod_restart_counts(kubectl.dataplane_pods())
    assert all(count == 0 for count in restarts.values()), \
        f"data-plane pods restarted during the suite: {restarts}"
