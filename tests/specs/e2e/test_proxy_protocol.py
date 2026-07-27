"""
Proxy protocol listeners (docs/spec/traffic.md Proxy protocol,
docs/spec/acceptance.md criterion 27).

A listener named in `client_ip.proxy_protocol` requires a preamble on every
connection: the address it carries becomes the client, connections without
one are closed, and `LOCAL` preambles fall back to the peer so load
balancer health checks keep working.
"""

import pytest

from e2elib import backends, config, gateway as gw, kubectl, net, ports

BACKEND = "pp-backend"

# The peer krouter sees for a NodePort connection depends on the cluster's
# network path, so the suite trusts every peer and asserts on the preamble
# handling itself. Operators MUST NOT do this (docs/spec/security.md).
TRUSTED = ["0.0.0.0/0", "::/0"]

CLIENT = "203.0.113.9"
LOGGED_CLIENT = "198.51.100.77"


@pytest.fixture(scope="module")
def stack(gateway_class, module_namespace):
    """
    Gateway whose only listener requires a proxy protocol preamble.
    """

    ns = module_namespace
    kubectl.apply(backends.mockserver_backend(BACKEND, ns), namespace=ns)

    kubectl.apply([
        gw.params_configmap(
            "gw-params",
            ns,
            gw.infra_params_hcl(
                node_ports={"http": ports.PROXY_PROTOCOL},
                trusted_proxies=TRUSTED,
                proxy_protocol=["http"],
            ),
        ),
        gw.gateway(
            "pp-gw",
            ns,
            [gw.listener("http", 80, "HTTP")],
            infra_params="gw-params",
        ),
        gw.http_route(
            "probe-route",
            ns,
            [gw.parent_ref("pp-gw")],
            rules=[
                {
                    "matches": [
                        {"path": {"type": "PathPrefix", "value": "/probe"}},
                    ],
                    "backendRefs": [
                        gw.backend_ref(BACKEND, backends.BACKEND_PORT),
                    ],
                },
            ],
        ),
    ])

    kubectl.wait_condition("gateway", "pp-gw", ns, "Programmed", timeout=180)
    kubectl.wait_deployment_ready(BACKEND, ns)
    net.wait_raw_http_ok(
        ports.PROXY_PROTOCOL,
        path="/probe",
        preamble=net.proxy_v1(CLIENT),
    )

    return ns


@pytest.fixture
def backend_pod(stack):
    """
    The recording backend pod, with its request log cleared.
    """

    ns = stack
    pod = kubectl.get("pods", namespace=ns, selector=f"app={BACKEND}")["items"][0]
    name = pod["metadata"]["name"]
    backends.reset_recordings(name, ns)

    return name


def test_a_preamble_is_required(stack):
    """
    docs/spec/traffic.md: a connection that does not begin with a preamble
    is closed, without a response of any kind.
    """

    assert net.raw_http(ports.PROXY_PROTOCOL, path="/probe") == 0


def test_a_malformed_preamble_is_refused(stack):
    """
    docs/spec/traffic.md: a protocol violation closes the connection.
    """

    assert net.raw_http(
        ports.PROXY_PROTOCOL,
        path="/probe",
        preamble=b"PROXY TCP4 not-an-ip 10.0.0.1 1 2\r\n",
    ) == 0


def test_version_1_client_reaches_the_backend(stack, backend_pod):
    """
    docs/spec/traffic.md: the address the preamble carries replaces the
    peer, including in the chain backends receive.
    """

    ns = stack
    status = net.raw_http(
        ports.PROXY_PROTOCOL,
        path="/probe/v1",
        preamble=net.proxy_v1(CLIENT),
    )
    assert status == 200

    recorded = backends.recorded_headers(backend_pod, ns, path="/probe/v1")
    assert recorded, "backend did not record the probe request"

    chain = [
        entry.strip()
        for value in recorded[-1].get("x-forwarded-for", [])
        for entry in value.split(",")
    ]
    assert chain == [CLIENT], f"the preamble address must be the client, got {chain}"


def test_local_preamble_keeps_the_peer(stack, backend_pod):
    """
    docs/spec/traffic.md: `LOCAL` carries no client address, so the
    connection proceeds with the peer. Load balancer health checks use it.
    """

    ns = stack
    status = net.raw_http(
        ports.PROXY_PROTOCOL,
        path="/probe/local",
        preamble=net.proxy_v2_local(),
    )
    assert status == 200

    recorded = backends.recorded_headers(backend_pod, ns, path="/probe/local")
    assert recorded, "backend did not record the probe request"

    chain = recorded[-1].get("x-forwarded-for", [])
    assert CLIENT not in ",".join(chain), \
        f"LOCAL must not carry a client address, got {chain}"


def test_access_log_reports_the_preamble_address(stack):
    """
    docs/spec/observability.md: the access log reports the resolved client.
    """

    status = net.raw_http(
        ports.PROXY_PROTOCOL,
        path="/probe/logged",
        preamble=net.proxy_v1(LOGGED_CLIENT),
    )
    assert status == 200

    def logged():
        for pod in kubectl.dataplane_pods():
            logs = kubectl.pod_logs(
                pod["metadata"]["name"],
                config.SYSTEM_NAMESPACE,
                since="120s",
            )
            if f"client={LOGGED_CLIENT}" in logs:
                return True

        return None

    kubectl.wait_for(
        logged,
        timeout=60,
        desc=f"access log entry with client={LOGGED_CLIENT}",
    )


def wait_invalid_parameters(name: str, namespace: str, desc: str):
    """
    Wait for the Gateway to report InvalidParameters.
    """

    def check():
        obj = kubectl.get_or_none("gateway", name, namespace)
        if not obj:
            return None

        for cond in obj.get("status", {}).get("conditions", []):
            if cond.get("reason") == "InvalidParameters" and cond["status"] == "False":
                return cond

        return None

    kubectl.wait_for(check, timeout=120, desc=desc)


def test_proxy_protocol_without_trusted_proxies_is_invalid(gateway_class, namespace):
    """
    docs/spec/parameters.md: no peer would be allowed to send the preamble
    those listeners require.
    """

    ns = namespace
    kubectl.apply([
        gw.params_configmap(
            "no-trust",
            ns,
            gw.infra_params_hcl(proxy_protocol=["http"]),
        ),
        gw.gateway(
            "no-trust-gw",
            ns,
            [gw.listener("http", 80, "HTTP")],
            infra_params="no-trust",
        ),
    ])

    wait_invalid_parameters(
        "no-trust-gw",
        ns,
        "InvalidParameters on proxy protocol without trusted proxies",
    )


def test_unknown_listener_is_invalid(gateway_class, namespace):
    """
    docs/spec/parameters.md: every entry MUST name a listener the Gateway
    declares, so a typo cannot silently leave the listener unprotected.
    """

    ns = namespace
    kubectl.apply([
        gw.params_configmap(
            "bad-listener",
            ns,
            gw.infra_params_hcl(
                trusted_proxies=TRUSTED,
                proxy_protocol=["htpp"],
            ),
        ),
        gw.gateway(
            "bad-listener-gw",
            ns,
            [gw.listener("http", 80, "HTTP")],
            infra_params="bad-listener",
        ),
    ])

    wait_invalid_parameters(
        "bad-listener-gw",
        ns,
        "InvalidParameters on an unknown proxy protocol listener",
    )
