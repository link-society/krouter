"""
Client protocol coverage (spec §3, §12.1, §12.3, §20.2).

HTTP/1.1 and HTTP/2 must work through both HTTP and HTTPS listeners, with
TLS termination using the referenced certificate and regenerated
spoof-sensitive forwarding headers.
"""

import pytest

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from e2elib import backends, certs, gateway as gw, kubectl, net, ports
from e2elib.backends import BACKEND_PORT

HOSTNAME = "hello.example.com"


@pytest.fixture(scope="module")
def ca():
    return certs.make_ca()


@pytest.fixture(scope="module")
def stack(gateway_class, module_namespace, ca):
    """
    Gateway with one HTTP and one HTTPS listener routing to one backend.
    """

    ns = module_namespace
    certs.apply_tls_secret(ca, "hello-cert", ns, HOSTNAME)
    kubectl.apply(backends.mockserver_backend("echo", ns), namespace=ns)

    kubectl.apply([
        gw.params_configmap(
            "gw-params",
            ns,
            gw.infra_params_hcl(
                node_ports={
                    "http": ports.PROTOCOLS_HTTP,
                    "https": ports.PROTOCOLS_HTTPS,
                },
            ),
        ),
        gw.gateway(
            "proto-gw",
            ns,
            [
                gw.listener("http", 80, "HTTP"),
                gw.listener(
                    "https",
                    443,
                    "HTTPS",
                    hostname=HOSTNAME,
                    tls_secret="hello-cert",
                ),
            ],
            infra_params="gw-params",
        ),
        gw.http_route(
            "echo-route",
            ns,
            [gw.parent_ref("proto-gw")],
            hostnames=[HOSTNAME],
            rules=[
                {"backendRefs": [
                    gw.backend_ref("echo", BACKEND_PORT),
                ]},
            ],
        ),
    ])

    kubectl.wait_condition("gateway", "proto-gw", ns, "Programmed", timeout=180)
    kubectl.wait_deployment_ready("echo", ns)
    net.wait_http_ok(ports.PROTOCOLS_HTTP, host=HOSTNAME)
    net.wait_http_ok(ports.PROTOCOLS_HTTPS, host=HOSTNAME, scheme="https")

    return ns


def test_http1_over_http(stack):
    resp = net.request(ports.PROTOCOLS_HTTP, host=HOSTNAME)
    assert resp.status_code == 200
    assert resp.http_version == "HTTP/1.1"
    assert resp.json()["backend"] == "echo"


def test_http1_over_https(stack):
    resp = net.request(ports.PROTOCOLS_HTTPS, host=HOSTNAME, scheme="https")
    assert resp.status_code == 200
    assert resp.http_version == "HTTP/1.1"


def test_http2_over_https(stack):
    """
    HTTP/2 negotiated via ALPN on the TLS listener.
    """

    resp = net.request(
        ports.PROTOCOLS_HTTPS,
        host=HOSTNAME,
        scheme="https",
        http2=True,
    )
    assert resp.status_code == 200
    assert resp.http_version == "HTTP/2"


def test_http2_prior_knowledge_over_http(stack):
    """
    Cleartext HTTP/2 (prior knowledge) on the HTTP listener (spec §12.1).
    """

    resp = net.request(
        ports.PROTOCOLS_HTTP,
        host=HOSTNAME,
        http1=False,
        http2=True,
    )
    assert resp.status_code == 200
    assert resp.http_version == "HTTP/2"


def test_served_certificate_matches_listener_reference(stack, ca):
    """
    Spec §13: TLS terminates with the certificate referenced by the listener.
    """

    cert = net.get_server_certificate(ports.PROTOCOLS_HTTPS, sni=HOSTNAME)
    san = cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
    ).value
    assert HOSTNAME in san.get_values_for_type(x509.DNSName)


def test_unmatched_hostname_is_not_served(stack):
    """
    Spec §12.2: listener/route hostname isolation; unmatched host -> 404.
    """

    resp = net.request(ports.PROTOCOLS_HTTP, host="other.example.com")
    assert resp.status_code == 404


def test_forwarded_headers_are_regenerated(stack):
    """
    Spec §12.3: spoofed X-Forwarded-* values from the client must be
    replaced with values derived from the actual downstream connection.
    """

    ns = stack
    pod = kubectl.get("pods", namespace=ns, selector="app=echo")["items"][0]
    pod_name = pod["metadata"]["name"]
    backends.reset_recordings(pod_name, ns)

    resp = net.request(
        ports.PROTOCOLS_HTTP,
        path="/xff-probe",
        host=HOSTNAME,
        headers={
            "X-Forwarded-For": "1.2.3.4",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "spoofed.example.com",
        },
    )
    assert resp.status_code == 200

    recorded = backends.recorded_headers(pod_name, ns, path="/xff-probe")
    assert recorded, "backend did not record the probe request"

    headers = recorded[-1]

    xff = ",".join(headers.get("x-forwarded-for", []))
    assert "1.2.3.4" not in xff, "spoofed X-Forwarded-For must not pass through"

    assert headers.get("x-forwarded-proto") == ["http"], \
        "X-Forwarded-Proto must reflect the actual listener protocol"

    xfh = headers.get("x-forwarded-host", [])
    assert "spoofed.example.com" not in xfh, \
        "spoofed X-Forwarded-Host must not pass through"


def test_forwarded_proto_reflects_tls(stack):
    ns = stack
    pod = kubectl.get("pods", namespace=ns, selector="app=echo")["items"][0]
    pod_name = pod["metadata"]["name"]
    backends.reset_recordings(pod_name, ns)

    resp = net.request(
        ports.PROTOCOLS_HTTPS,
        path="/tls-probe",
        host=HOSTNAME,
        scheme="https",
    )
    assert resp.status_code == 200

    recorded = backends.recorded_headers(pod_name, ns, path="/tls-probe")
    assert recorded, "backend did not record the probe request"
    assert recorded[-1].get("x-forwarded-proto") == ["https"]
