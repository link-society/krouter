"""
Trusted-proxy client IP resolution (docs/spec/traffic.md Forwarding
headers, docs/spec/acceptance.md criterion 26).

A Gateway whose `client_ip.trusted_proxies` parameter covers the peer
honors the `X-Forwarded-For` chain it presents: the resolved address
drives the access log and the `client_ip` rate limiting buckets, and the
chain reaches backends with the peer appended. The counterpart, an
untrusted peer whose spoofed values are discarded, is asserted by
test_protocols.py.
"""

import pytest

from e2elib import backends, config, gateway as gw, kubectl, net, ports

BACKEND = "cip-backend"

# The peer address krouter sees for a NodePort connection depends on the
# cluster's network path, so the suite trusts every peer and asserts on the
# resolution rules themselves. Operators MUST NOT do this
# (docs/spec/security.md Client IP trust).
TRUSTED = ["0.0.0.0/0", "::/0"]

CLIENT = "203.0.113.7"
OTHER_CLIENT = "203.0.113.8"
LOGGED_CLIENT = "198.51.100.42"


def ratelimit_hcl(requests: int, window: str) -> str:
    return (
        "version = 1\n"
        "\n"
        "rate_limit {\n"
        f"  requests = {requests}\n"
        f'  window   = "{window}"\n'
        '  key      = "client_ip"\n'
        "}\n"
    )


@pytest.fixture(scope="module")
def stack(gateway_class, module_namespace):
    """
    Gateway trusting every peer, with a backend recording what it receives.
    """

    ns = module_namespace
    kubectl.apply(backends.mockserver_backend(BACKEND, ns), namespace=ns)

    kubectl.apply([
        gw.params_configmap(
            "gw-params",
            ns,
            gw.infra_params_hcl(
                node_ports={"http": ports.CLIENT_IP},
                trusted_proxies=TRUSTED,
            ),
        ),
        gw.gateway(
            "cip-gw",
            ns,
            [gw.listener("http", 80, "HTTP")],
            infra_params="gw-params",
        ),
        gw.http_route(
            "probe-route",
            ns,
            [gw.parent_ref("cip-gw")],
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

    kubectl.wait_condition("gateway", "cip-gw", ns, "Programmed", timeout=180)
    kubectl.wait_deployment_ready(BACKEND, ns)
    net.wait_http_ok(ports.CLIENT_IP, path="/probe")

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


def test_trusted_chain_reaches_the_backend(stack, backend_pod):
    """
    docs/spec/traffic.md: a trusted peer's chain is preserved with the peer
    appended, instead of being regenerated from the connection.
    """

    ns = stack
    resp = net.request(
        ports.CLIENT_IP,
        path="/probe/chain",
        headers={"X-Forwarded-For": CLIENT},
    )
    assert resp.status_code == 200

    recorded = backends.recorded_headers(backend_pod, ns, path="/probe/chain")
    assert recorded, "backend did not record the probe request"

    chain = [
        entry.strip()
        for value in recorded[-1].get("x-forwarded-for", [])
        for entry in value.split(",")
    ]
    assert chain[0] == CLIENT, f"trusted chain must be preserved, got {chain}"
    assert len(chain) >= 2, f"the peer must be appended to the chain, got {chain}"
    assert chain[-1] != CLIENT, f"the peer must be appended to the chain, got {chain}"


def test_trusted_forwarded_host_and_proto_pass_through(stack, backend_pod):
    """
    docs/spec/traffic.md: values received from a trusted peer are passed
    through unchanged, the connection no longer describes the client.
    """

    ns = stack
    resp = net.request(
        ports.CLIENT_IP,
        path="/probe/passthrough",
        headers={
            "X-Forwarded-For": CLIENT,
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "front.example.com",
        },
    )
    assert resp.status_code == 200

    recorded = backends.recorded_headers(backend_pod, ns, path="/probe/passthrough")
    assert recorded, "backend did not record the probe request"

    headers = recorded[-1]
    assert headers.get("x-forwarded-proto") == ["https"], \
        f"trusted X-Forwarded-Proto must pass through, got {headers}"
    assert headers.get("x-forwarded-host") == ["front.example.com"], \
        f"trusted X-Forwarded-Host must pass through, got {headers}"


def test_resolved_client_ip_reaches_the_access_log(stack):
    """
    docs/spec/observability.md: the access log reports the resolved client
    IP, not the peer that carried the request.
    """

    resp = net.request(
        ports.CLIENT_IP,
        path="/probe/logged",
        headers={"X-Forwarded-For": LOGGED_CLIENT},
    )
    assert resp.status_code == 200

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


def test_rate_limit_buckets_by_resolved_client_ip(stack):
    """
    docs/spec/extensions.md: the `client_ip` key buckets by the resolved
    address, so one forwarded client cannot exhaust another's bucket.
    """

    ns = stack
    kubectl.apply([
        gw.extension_configmap(
            "cip-ratelimit",
            ns,
            ratelimit=ratelimit_hcl(requests=2, window="1h"),
        ),
        gw.http_route(
            "limited-route",
            ns,
            [gw.parent_ref("cip-gw")],
            rules=[
                {
                    "matches": [
                        {"path": {"type": "PathPrefix", "value": "/limited"}},
                    ],
                    "filters": [gw.extension_ref("cip-ratelimit")],
                    "backendRefs": [
                        gw.backend_ref(BACKEND, backends.BACKEND_PORT),
                    ],
                },
            ],
        ),
    ])
    kubectl.wait_route_parent_condition("limited-route", ns, "Accepted", timeout=60)
    kubectl.wait_route_parent_condition("limited-route", ns, "ResolvedRefs", timeout=60)
    net.wait_http_ok(ports.CLIENT_IP, path="/limited")

    statuses = [
        net.request(
            ports.CLIENT_IP,
            path="/limited",
            headers={"X-Forwarded-For": CLIENT},
        ).status_code
        for _ in range(3)
    ]
    assert statuses == [200, 200, 429], f"expected one bucket per client, got {statuses}"

    # A different forwarded client still has its own tokens; the readiness
    # probes above consumed the peer's bucket, not this one.
    other = net.request(
        ports.CLIENT_IP,
        path="/limited",
        headers={"X-Forwarded-For": OTHER_CLIENT},
    )
    assert other.status_code == 200, "buckets must be per resolved client IP"


def test_invalid_trusted_proxy_prefix_is_invalid_parameters(gateway_class, namespace):
    """
    docs/spec/parameters.md: a malformed prefix is an invalid parameter, so
    the Gateway never serves traffic with a half-applied trust list.
    """

    ns = namespace
    kubectl.apply([
        gw.params_configmap(
            "bad-trust",
            ns,
            gw.infra_params_hcl(trusted_proxies=["10.0.0.1"]),
        ),
        gw.gateway(
            "bad-trust-gw",
            ns,
            [gw.listener("http", 80, "HTTP")],
            infra_params="bad-trust",
        ),
    ])

    def has_invalid_parameters():
        obj = kubectl.get_or_none("gateway", "bad-trust-gw", ns)
        if not obj:
            return None

        for cond in obj.get("status", {}).get("conditions", []):
            if cond.get("reason") == "InvalidParameters" and cond["status"] == "False":
                return cond

        return None

    kubectl.wait_for(
        has_invalid_parameters,
        timeout=120,
        desc="InvalidParameters on a malformed trusted_proxies prefix",
    )
