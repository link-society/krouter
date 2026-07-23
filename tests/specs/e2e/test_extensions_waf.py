"""
ExtensionRef Coraza WAF (docs/spec/extensions.md,
docs/spec/acceptance.md criterion 25).

Route rules referencing extension ConfigMaps with `waf.hcl` inspect the
request phases before any byte reaches a backend: hostile requests are
denied with the interruption status, clean traffic passes, directive
fragments layer in filter order, WebSocket handshakes are inspected
before any hijack, and broken directives fail closed.
"""

import pytest

from e2elib import backends, gateway as gw, kubectl, net, ports

BACKEND = "waf-backend"
WS_BACKEND = "waf-ws-backend"
GRPC_BACKEND = "waf-grpc-backend"
GRPC_HOST = "waf-grpc.example.com"

XSS_QUERY = "?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"

CRS_HCL = """\
version = 1

waf {
  directives = <<-EOT
    Include @coraza.conf-recommended
    Include @crs-setup.conf.example
    Include @owasp_crs/*.conf
    SecRuleEngine On
  EOT
}
"""

# A standalone phase-1 rule fragment layered over the CRS base
# (docs/spec/extensions.md Web application firewall).
FRAGMENT_HCL = """\
version = 1

waf {
  directives = <<-EOT
    SecRule REQUEST_HEADERS:X-Attack "@streq yes" \\
      "id:911001,phase:1,deny,status:406,msg:'blocked by fragment'"
  EOT
}
"""

# Header-phase engine without the CRS, for gRPC and WebSocket cases.
HEADER_RULE_HCL = """\
version = 1

waf {
  directives = <<-EOT
    SecRuleEngine On
    SecRule REQUEST_HEADERS:X-Attack "@streq yes" \\
      "id:911002,phase:1,deny,status:403,msg:'hostile header'"
    SecRule ARGS_GET:q "@contains <script" \\
      "id:911003,phase:1,deny,status:403,msg:'hostile query'"
  EOT
}
"""

BROKEN_HCL = """\
version = 1

waf {
  directives = <<-EOT
    SecBogusDirective definitely-not-seclang
  EOT
}
"""


def waf_route(name, ns, path, config_names, backend=BACKEND,
              port=backends.BACKEND_PORT):
    return gw.http_route(
        name,
        ns,
        [gw.parent_ref("waf-gw")],
        rules=[
            {
                "matches": [
                    {"path": {"type": "PathPrefix", "value": path}},
                ],
                "filters": [gw.extension_ref(cm) for cm in config_names],
                "backendRefs": [gw.backend_ref(backend, port)],
            },
        ],
    )


@pytest.fixture(scope="module")
def stack(gateway_class, module_namespace):
    """
    Gateway with one HTTP listener; each test attaches its own route and
    WAF ConfigMaps under a unique path prefix.
    """

    ns = module_namespace
    kubectl.apply(backends.mockserver_backend(BACKEND, ns), namespace=ns)
    kubectl.apply(backends.ws_backend(WS_BACKEND, ns), namespace=ns)
    kubectl.apply(backends.grpc_greeter_backend(GRPC_BACKEND, ns), namespace=ns)

    kubectl.apply([
        gw.params_configmap(
            "gw-params",
            ns,
            gw.infra_params_hcl(node_ports={"http": ports.EXTENSIONS_WAF}),
        ),
        gw.gateway(
            "waf-gw",
            ns,
            [gw.listener("http", 80, "HTTP")],
            infra_params="gw-params",
        ),
        gw.http_route(
            "plain-route",
            ns,
            [gw.parent_ref("waf-gw")],
            rules=[
                {
                    "matches": [
                        {"path": {"type": "PathPrefix", "value": "/plain"}},
                    ],
                    "backendRefs": [
                        gw.backend_ref(BACKEND, backends.BACKEND_PORT),
                    ],
                },
            ],
        ),
    ])

    kubectl.wait_condition("gateway", "waf-gw", ns, "Programmed", timeout=180)
    kubectl.wait_deployment_ready(BACKEND, ns)
    kubectl.wait_deployment_ready(WS_BACKEND, ns)
    kubectl.wait_deployment_ready(GRPC_BACKEND, ns)
    net.wait_http_ok(ports.EXTENSIONS_WAF, path="/plain")

    return ns


def wait_route_ready(name, ns, path):
    kubectl.wait_route_parent_condition(name, ns, "Accepted", timeout=60)
    kubectl.wait_route_parent_condition(name, ns, "ResolvedRefs", timeout=60)
    net.wait_http_ok(ports.EXTENSIONS_WAF, path=path)


def test_crs_denies_hostile_and_passes_clean(stack):
    """
    The embedded Core Rule Set blocks a canonical XSS probe and leaves
    clean requests untouched (docs/spec/extensions.md).
    """

    ns = stack
    kubectl.apply([
        gw.extension_configmap("waf-crs", ns, waf=CRS_HCL),
        waf_route("crs-route", ns, "/crs", ["waf-crs"]),
    ])
    wait_route_ready("crs-route", ns, "/crs")

    hostile = net.request(ports.EXTENSIONS_WAF, path="/crs" + XSS_QUERY)
    assert hostile.status_code == 403

    clean = net.request(ports.EXTENSIONS_WAF, path="/crs")
    assert clean.status_code == 200
    assert clean.json()["backend"] == BACKEND


def test_fragments_layer_in_filter_order(stack):
    """
    A directive fragment layered over the CRS base adds its own rule with
    its own interruption status (docs/spec/extensions.md).
    """

    ns = stack
    kubectl.apply([
        gw.extension_configmap("waf-base", ns, waf=CRS_HCL),
        gw.extension_configmap("waf-fragment", ns, waf=FRAGMENT_HCL),
        waf_route("layered-route", ns, "/layered", ["waf-base", "waf-fragment"]),
    ])
    wait_route_ready("layered-route", ns, "/layered")

    # The fragment's rule interrupts with its own status...
    fragment_hit = net.request(
        ports.EXTENSIONS_WAF,
        path="/layered",
        headers={"X-Attack": "yes"},
    )
    assert fragment_hit.status_code == 406

    # ...the base CRS still blocks, and clean traffic still flows.
    assert net.request(
        ports.EXTENSIONS_WAF, path="/layered" + XSS_QUERY).status_code == 403
    assert net.request(
        ports.EXTENSIONS_WAF, path="/layered").status_code == 200


def test_grpc_headers_inspected(stack):
    """
    On gRPC routes the request-header phase is enforced; message payloads
    are not inspected (docs/spec/extensions.md).
    """

    ns = stack
    kubectl.apply([
        gw.extension_configmap("waf-grpc", ns, waf=HEADER_RULE_HCL),
        gw.grpc_route(
            "grpc-route",
            ns,
            [gw.parent_ref("waf-gw")],
            hostnames=[GRPC_HOST],
            rules=[
                {
                    "filters": [gw.extension_ref("waf-grpc")],
                    "backendRefs": [
                        gw.backend_ref(GRPC_BACKEND, backends.GRPC_BACKEND_PORT),
                    ],
                },
            ],
        ),
    ])
    kubectl.wait_route_parent_condition(
        "grpc-route", ns, "Accepted", kind="grpcroute", timeout=60)
    kubectl.wait_route_parent_condition(
        "grpc-route", ns, "ResolvedRefs", kind="grpcroute", timeout=60)

    def call(headers=None):
        return net.grpc_hello(
            ports.EXTENSIONS_WAF, GRPC_HOST, headers=headers)

    kubectl.wait_for(
        lambda: (call()[1].startswith("Hello") or None),
        timeout=60,
        desc="clean gRPC call served through the WAF route",
    )

    status, reply = call(headers={"x-attack": "yes"})
    assert not reply.startswith("Hello"), \
        f"hostile metadata must not reach the backend, got {reply!r}"


def test_websocket_handshake_denied_before_hijack(stack):
    """
    The WAF inspects the upgrade request before the connection is
    hijacked (docs/spec/extensions.md WebSocket and upgrade requests).
    """

    from websockets.exceptions import InvalidStatus

    ns = stack
    kubectl.apply([
        gw.extension_configmap("waf-ws", ns, waf=HEADER_RULE_HCL),
        waf_route("ws-route", ns, "/ws", ["waf-ws"],
                  backend=WS_BACKEND, port=backends.WS_BACKEND_PORT),
    ])
    kubectl.wait_route_parent_condition("ws-route", ns, "Accepted", timeout=60)
    kubectl.wait_route_parent_condition("ws-route", ns, "ResolvedRefs", timeout=60)
    net.wait_http_ok(ports.EXTENSIONS_WAF, path="/ws/healthz")

    # A hostile handshake is interrupted: no upgrade, no tunnel.
    with pytest.raises(InvalidStatus) as exc:
        net.ws_connect(
            ports.EXTENSIONS_WAF, path="/ws" + XSS_QUERY)

    assert exc.value.response.status_code == 403

    # A clean handshake upgrades and the tunnel echoes.
    with net.ws_connect(ports.EXTENSIONS_WAF, path="/ws") as conn:
        assert conn.recv(timeout=10).startswith("wsbin ")
        assert net.ws_echo_roundtrip(conn, "clean") == "clean"


def test_invalid_directives_fail_closed(stack):
    """
    Directives that fail to build resolve to InvalidExtensionRef and
    answer 500 (docs/spec/extensions.md Resolution and status).
    """

    ns = stack
    kubectl.apply([
        gw.extension_configmap("waf-broken", ns, waf=BROKEN_HCL),
        waf_route("broken-route", ns, "/broken", ["waf-broken"]),
    ])

    kubectl.wait_route_parent_condition(
        "broken-route",
        ns,
        "ResolvedRefs",
        status="False",
        reason="InvalidExtensionRef",
        timeout=60,
    )

    kubectl.wait_for(
        lambda: net.request(
            ports.EXTENSIONS_WAF, path="/broken",
        ).status_code == 500 or None,
        timeout=60,
        desc="fail-closed 500 for the broken WAF directives",
    )

    # Unrelated routes keep serving.
    assert net.request(ports.EXTENSIONS_WAF, path="/plain").status_code == 200
