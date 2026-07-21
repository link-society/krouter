"""
Cross-namespace attachment and references (docs/spec/traffic.md, docs/spec/security.md, docs/spec/acceptance.md criterion 3).

Covers listener allowedRoutes namespace selectors, cross-namespace backend
references gated by ReferenceGrant, and cross-namespace TLS certificate
references gated by ReferenceGrant.
"""

import pytest

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from e2elib import backends, certs, gateway as gw, kubectl, net, ports, unique_name
from e2elib.backends import BACKEND_PORT

HOSTNAME = "teams.example.com"
TLS_HOSTNAME = "secure.example.com"


@pytest.fixture(scope="module")
def ca():
    return certs.make_ca()


@pytest.fixture(scope="module")
def namespaces(cluster, gateway_class):
    """
    gw namespace + labelled app namespace + unlabelled namespace + backend
    namespace + secret namespace.
    """

    names = {
        "gw": unique_name("krouter-xns-gw"),
        "app": unique_name("krouter-xns-app"),
        "other": unique_name("krouter-xns-other"),
        "backend": unique_name("krouter-xns-backend"),
        "secrets": unique_name("krouter-xns-secrets"),
    }

    kubectl.create_namespace(names["gw"])
    kubectl.create_namespace(names["app"], labels={"team": "web"})
    kubectl.create_namespace(names["other"])
    kubectl.create_namespace(names["backend"])
    kubectl.create_namespace(names["secrets"])

    yield names

    for name in names.values():
        kubectl.delete_namespace(name)


@pytest.fixture(scope="module")
def stack(namespaces, ca):
    ns = namespaces
    certs.apply_tls_secret(ca, "xns-cert", ns["secrets"], TLS_HOSTNAME)
    kubectl.apply(backends.mockserver_backend("local-echo", ns["app"]))
    kubectl.apply(backends.mockserver_backend("remote-echo", ns["backend"]))

    kubectl.apply([
        gw.params_configmap(
            "gw-params",
            ns["gw"],
            gw.infra_params_hcl(
                node_ports={
                    "http": ports.CROSS_NAMESPACE,
                    "https": ports.CROSS_NAMESPACE_TLS,
                },
            ),
        ),
        gw.gateway(
            "xns-gw",
            ns["gw"],
            [
                gw.listener(
                    "http",
                    80,
                    "HTTP",
                    allowed_routes={
                        "namespaces": {
                            "from": "Selector",
                            "selector": {"matchLabels": {"team": "web"}},
                        },
                    },
                ),
                gw.listener(
                    "https",
                    443,
                    "HTTPS",
                    hostname=TLS_HOSTNAME,
                    tls_secret=(ns["secrets"], "xns-cert"),
                    allowed_routes={
                        "namespaces": {
                            "from": "Selector",
                            "selector": {"matchLabels": {"team": "web"}},
                        },
                    },
                ),
            ],
            infra_params="gw-params",
        ),
    ])

    kubectl.wait_deployment_ready("local-echo", ns["app"])
    kubectl.wait_deployment_ready("remote-echo", ns["backend"])

    return ns


def test_route_from_selected_namespace_is_accepted(stack):
    """
    docs/spec/acceptance.md criterion 3: allowedRoutes namespace selector admits labelled namespaces.
    """

    ns = stack
    kubectl.apply(gw.http_route(
        "allowed-route",
        ns["app"],
        [gw.parent_ref("xns-gw", namespace=ns["gw"], section_name="http")],
        hostnames=[HOSTNAME],
        rules=[
            {"backendRefs": [
                gw.backend_ref("local-echo", BACKEND_PORT),
            ]},
        ],
    ))

    kubectl.wait_route_parent_condition("allowed-route", ns["app"], "Accepted")
    net.wait_http_ok(ports.CROSS_NAMESPACE, host=HOSTNAME)

    data = net.request_json(ports.CROSS_NAMESPACE, host=HOSTNAME)
    assert data["backend"] == "local-echo"


def test_route_from_unselected_namespace_is_rejected(stack):
    """
    Routes from namespaces outside the selector must not attach.
    """

    ns = stack
    kubectl.apply(gw.http_route(
        "denied-route",
        ns["other"],
        [gw.parent_ref("xns-gw", namespace=ns["gw"], section_name="http")],
        hostnames=["denied.example.com"],
        rules=[
            {"backendRefs": [
                gw.backend_ref("local-echo", BACKEND_PORT, namespace=ns["app"]),
            ]},
        ],
    ))

    cond = kubectl.wait_route_parent_condition(
        "denied-route",
        ns["other"],
        "Accepted",
        status="False",
    )
    assert cond["reason"] == "NotAllowedByListeners"

    resp = net.request(ports.CROSS_NAMESPACE, host="denied.example.com")
    assert resp.status_code == 404, "unattached route must not receive traffic"


def test_cross_namespace_backend_requires_reference_grant(stack):
    """
    docs/spec/traffic.md: ReferenceGrant gates cross-namespace backends; without it
    ResolvedRefs=False/RefNotPermitted and the rule answers 500.
    """

    ns = stack
    kubectl.apply(gw.http_route(
        "xns-backend-route",
        ns["app"],
        [gw.parent_ref("xns-gw", namespace=ns["gw"], section_name="http")],
        hostnames=["backend.example.com"],
        rules=[
            {"backendRefs": [
                gw.backend_ref("remote-echo", BACKEND_PORT, namespace=ns["backend"]),
            ]},
        ],
    ))

    cond = kubectl.wait_route_parent_condition(
        "xns-backend-route",
        ns["app"],
        "ResolvedRefs",
        status="False",
    )
    assert cond["reason"] == "RefNotPermitted"

    def rejected():
        resp = net.request(ports.CROSS_NAMESPACE, host="backend.example.com")

        return resp if resp.status_code == 500 else None

    kubectl.wait_for(
        rejected,
        timeout=60,
        desc="500 for backend ref without ReferenceGrant",
    )

    # Granting access must flip ResolvedRefs and let traffic flow.
    kubectl.apply(gw.reference_grant(
        "allow-backend",
        ns["backend"],
        from_kind="HTTPRoute",
        from_namespace=ns["app"],
        to_kind="Service",
    ))
    kubectl.wait_route_parent_condition("xns-backend-route", ns["app"], "ResolvedRefs")

    def served():
        resp = net.request(ports.CROSS_NAMESPACE, host="backend.example.com")
        if resp.status_code != 200:
            return None

        return resp.json()["backend"] == "remote-echo" or None

    kubectl.wait_for(served, timeout=60, desc="traffic after ReferenceGrant")


def test_cross_namespace_certificate_requires_reference_grant(stack):
    """
    docs/spec/security.md: listener certificateRefs across namespaces obey ReferenceGrant.
    """

    ns = stack

    def listener_resolved(status: str):
        def check():
            obj = kubectl.get_or_none("gateway", "xns-gw", ns["gw"])
            if not obj:
                return None

            for listener_status in obj.get("status", {}).get("listeners", []):
                if listener_status["name"] != "https":
                    continue

                for cond in listener_status.get("conditions", []):
                    if cond["type"] == "ResolvedRefs" and cond["status"] == status:
                        return cond

            return None

        return check

    # Without a grant the listener must not resolve the secret reference.
    cond = kubectl.wait_for(
        listener_resolved("False"),
        timeout=120,
        desc="https listener ResolvedRefs=False without grant",
    )
    assert cond["reason"] == "RefNotPermitted"

    kubectl.apply(gw.reference_grant(
        "allow-cert",
        ns["secrets"],
        from_kind="Gateway",
        from_namespace=ns["gw"],
        to_kind="Secret",
        to_name="xns-cert",
    ))
    kubectl.wait_for(
        listener_resolved("True"),
        timeout=120,
        desc="https listener ResolvedRefs=True with grant",
    )

    # And the certificate must actually be served (docs/spec/security.md).
    def tls_served():
        try:
            cert = net.get_server_certificate(ports.CROSS_NAMESPACE_TLS, sni=TLS_HOSTNAME)

        except OSError:
            return None

        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        ).value

        return TLS_HOSTNAME in san.get_values_for_type(x509.DNSName) or None

    kubectl.wait_for(tls_served, timeout=120, desc="granted certificate served")
