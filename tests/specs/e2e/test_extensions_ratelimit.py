"""
ExtensionRef rate limiting (docs/spec/extensions.md,
docs/spec/acceptance.md criterion 24).

Route rules referencing extension ConfigMaps with `ratelimit.hcl` enforce
per-rule token buckets: exhaustion answers the configured status with
Retry-After, keys isolate buckets, partial documents merge in filter
order, broken references fail closed, and ConfigMap edits reload.
"""

import time

import pytest

from e2elib import backends, gateway as gw, kubectl, net, ports

BACKEND = "rl-backend"
WS_BACKEND = "rl-ws-backend"


def ratelimit_hcl(**attrs) -> str:
    """
    Render a ratelimit.hcl document from HCL attribute assignments.
    """

    lines = ["version = 1", "", "rate_limit {"]
    for key, value in attrs.items():
        rendered = f'"{value}"' if isinstance(value, str) else value
        lines.append(f"  {key} = {rendered}")

    lines.append("}")

    return "\n".join(lines) + "\n"


def route_with_extensions(name, ns, path, config_names, backend=BACKEND,
                          port=backends.BACKEND_PORT):
    return gw.http_route(
        name,
        ns,
        [gw.parent_ref("rl-gw")],
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
    extension ConfigMaps under a unique path prefix.
    """

    ns = module_namespace
    kubectl.apply(backends.mockserver_backend(BACKEND, ns), namespace=ns)
    kubectl.apply(backends.ws_backend(WS_BACKEND, ns), namespace=ns)

    kubectl.apply([
        gw.params_configmap(
            "gw-params",
            ns,
            gw.infra_params_hcl(node_ports={"http": ports.EXTENSIONS_RATELIMIT}),
        ),
        gw.gateway(
            "rl-gw",
            ns,
            [gw.listener("http", 80, "HTTP")],
            infra_params="gw-params",
        ),
        gw.http_route(
            "plain-route",
            ns,
            [gw.parent_ref("rl-gw")],
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

    kubectl.wait_condition("gateway", "rl-gw", ns, "Programmed", timeout=180)
    kubectl.wait_deployment_ready(BACKEND, ns)
    kubectl.wait_deployment_ready(WS_BACKEND, ns)
    net.wait_http_ok(ports.EXTENSIONS_RATELIMIT, path="/plain")

    return ns


def wait_route_ready(name, ns, path):
    """
    The route is accepted, resolved, and serving before assertions run.
    """

    kubectl.wait_route_parent_condition(name, ns, "Accepted", timeout=60)
    kubectl.wait_route_parent_condition(name, ns, "ResolvedRefs", timeout=60)
    net.wait_http_ok(ports.EXTENSIONS_RATELIMIT, path=path)


def test_exhaustion_answers_retry_after(stack):
    """
    An exhausted bucket rejects with 429 and Retry-After
    (docs/spec/extensions.md Rate limiting).
    """

    ns = stack
    kubectl.apply([
        gw.extension_configmap(
            "rl-exhaust",
            ns,
            ratelimit=ratelimit_hcl(requests=3, window="1h"),
        ),
        route_with_extensions("exhaust-route", ns, "/exhaust", ["rl-exhaust"]),
    ])
    wait_route_ready("exhaust-route", ns, "/exhaust")

    statuses = [
        net.request(ports.EXTENSIONS_RATELIMIT, path="/exhaust").status_code
        for _ in range(4)
    ]

    # wait_http_ok consumed one token: at least the last request is
    # rejected, and no rejection happens before exhaustion.
    assert statuses[-1] == 429, f"expected exhaustion, got {statuses}"
    assert statuses[0] == 200, f"expected initial capacity, got {statuses}"

    limited = net.request(ports.EXTENSIONS_RATELIMIT, path="/exhaust")
    assert limited.status_code == 429
    assert int(limited.headers["retry-after"]) >= 1


def test_bucket_refills(stack):
    """
    Tokens refill at requests/window and traffic recovers
    (docs/spec/extensions.md Rate limiting).
    """

    ns = stack
    kubectl.apply([
        gw.extension_configmap(
            "rl-refill",
            ns,
            ratelimit=ratelimit_hcl(requests=1, window="2s"),
        ),
        route_with_extensions("refill-route", ns, "/refill", ["rl-refill"]),
    ])
    wait_route_ready("refill-route", ns, "/refill")

    # Drain, observe the rejection, then recover after one window.
    net.request(ports.EXTENSIONS_RATELIMIT, path="/refill")
    limited = net.request(ports.EXTENSIONS_RATELIMIT, path="/refill")
    assert limited.status_code == 429

    time.sleep(3)

    recovered = net.request(ports.EXTENSIONS_RATELIMIT, path="/refill")
    assert recovered.status_code == 200


def test_header_keys_isolate_buckets(stack):
    """
    `key = "header:<Name>"` buckets per header value; requests without
    the header share one anonymous bucket
    (docs/spec/extensions.md Rate limiting).
    """

    ns = stack
    kubectl.apply([
        gw.extension_configmap(
            "rl-keys",
            ns,
            ratelimit=ratelimit_hcl(
                requests=1, window="1h", key="header:X-Api-Key"),
        ),
        route_with_extensions("keys-route", ns, "/keys", ["rl-keys"]),
    ])
    kubectl.wait_route_parent_condition("keys-route", ns, "Accepted", timeout=60)
    kubectl.wait_route_parent_condition("keys-route", ns, "ResolvedRefs", timeout=60)
    net.wait_http_ok(ports.EXTENSIONS_RATELIMIT, path="/keys",
                     headers={"X-Api-Key": "warmup"})

    def status(key: str | None) -> int:
        headers = {"X-Api-Key": key} if key else None
        return net.request(
            ports.EXTENSIONS_RATELIMIT, path="/keys", headers=headers,
        ).status_code

    assert status("alice") == 200
    assert status("alice") == 429

    # A different key holds a fresh bucket.
    assert status("bob") == 200
    assert status("bob") == 429

    # Requests without the header share the anonymous bucket.
    assert status(None) == 200
    assert status(None) == 429


def test_documents_merge_in_filter_order(stack):
    """
    A later partial document overrides the attributes it sets and
    inherits the rest (docs/spec/extensions.md Resolution and status).
    """

    ns = stack
    kubectl.apply([
        gw.extension_configmap(
            "rl-base",
            ns,
            ratelimit=ratelimit_hcl(requests=1, window="1h"),
        ),
        gw.extension_configmap(
            "rl-override",
            ns,
            ratelimit=ratelimit_hcl(status=418),
        ),
        route_with_extensions(
            "merge-route", ns, "/merge", ["rl-base", "rl-override"]),
    ])
    wait_route_ready("merge-route", ns, "/merge")

    net.request(ports.EXTENSIONS_RATELIMIT, path="/merge")

    # Limits come from the base document, the status from the override.
    limited = net.request(ports.EXTENSIONS_RATELIMIT, path="/merge")
    assert limited.status_code == 418
    assert int(limited.headers["retry-after"]) >= 1


def test_incomplete_merge_fails_closed(stack):
    """
    A merged configuration without `requests` and `window` resolves to
    InvalidExtensionRef and answers 500 (docs/spec/extensions.md).
    """

    ns = stack
    kubectl.apply([
        gw.extension_configmap(
            "rl-partial",
            ns,
            ratelimit=ratelimit_hcl(burst=5),
        ),
        route_with_extensions(
            "partial-route", ns, "/partial", ["rl-partial"]),
    ])

    kubectl.wait_route_parent_condition(
        "partial-route",
        ns,
        "ResolvedRefs",
        status="False",
        reason="InvalidExtensionRef",
        timeout=60,
    )

    kubectl.wait_for(
        lambda: net.request(
            ports.EXTENSIONS_RATELIMIT, path="/partial",
        ).status_code == 500 or None,
        timeout=60,
        desc="fail-closed 500 for the incomplete extension",
    )


def test_missing_configmap_fails_closed(stack):
    """
    A reference to an absent ConfigMap resolves to InvalidExtensionRef
    and answers 500 (docs/spec/extensions.md Resolution and status).
    """

    ns = stack
    kubectl.apply([
        route_with_extensions("ghost-route", ns, "/ghost", ["rl-ghost"]),
    ])

    kubectl.wait_route_parent_condition(
        "ghost-route",
        ns,
        "ResolvedRefs",
        status="False",
        reason="InvalidExtensionRef",
        timeout=60,
    )

    kubectl.wait_for(
        lambda: net.request(
            ports.EXTENSIONS_RATELIMIT, path="/ghost",
        ).status_code == 500 or None,
        timeout=60,
        desc="fail-closed 500 for the missing ConfigMap",
    )


def test_configmap_edit_reloads(stack):
    """
    Editing the extension ConfigMap produces a new generation; buckets
    reset and the new limits apply (docs/spec/extensions.md Configuration
    lifecycle).
    """

    ns = stack
    kubectl.apply([
        gw.extension_configmap(
            "rl-reload",
            ns,
            ratelimit=ratelimit_hcl(requests=1, window="1h"),
        ),
        route_with_extensions("reload-route", ns, "/reload", ["rl-reload"]),
    ])
    wait_route_ready("reload-route", ns, "/reload")

    net.request(ports.EXTENSIONS_RATELIMIT, path="/reload")
    assert net.request(
        ports.EXTENSIONS_RATELIMIT, path="/reload").status_code == 429

    # Raise the limit: a fresh generation applies with fresh buckets.
    kubectl.apply(
        gw.extension_configmap(
            "rl-reload",
            ns,
            ratelimit=ratelimit_hcl(requests=1000, window="1h"),
        ),
    )

    kubectl.wait_for(
        lambda: net.request(
            ports.EXTENSIONS_RATELIMIT, path="/reload",
        ).status_code == 200 or None,
        timeout=120,
        desc="raised limit applied after the ConfigMap edit",
    )


def test_websocket_handshake_limited(stack):
    """
    Rate limiting rejects WebSocket handshakes before any upgrade
    (docs/spec/extensions.md WebSocket and upgrade requests). The bucket
    key is a header so readiness polls cannot drain the tested bucket.
    """

    from websockets.exceptions import InvalidStatus

    ns = stack
    kubectl.apply([
        gw.extension_configmap(
            "rl-ws",
            ns,
            ratelimit=ratelimit_hcl(
                requests=1, window="1h", key="header:X-Ws-Client"),
        ),
        route_with_extensions(
            "ws-route", ns, "/ws", ["rl-ws"],
            backend=WS_BACKEND, port=backends.WS_BACKEND_PORT),
    ])
    kubectl.wait_route_parent_condition("ws-route", ns, "Accepted", timeout=60)
    kubectl.wait_route_parent_condition("ws-route", ns, "ResolvedRefs", timeout=60)
    net.wait_http_ok(ports.EXTENSIONS_RATELIMIT, path="/ws/healthz",
                     headers={"X-Ws-Client": "warmup"})

    # The client's one token opens the first tunnel...
    with net.ws_connect(
        ports.EXTENSIONS_RATELIMIT, path="/ws",
        headers={"X-Ws-Client": "one"},
    ) as conn:
        assert conn.recv(timeout=10).startswith("wsbin ")

        # ...and its next handshake is limited before any upgrade.
        with pytest.raises(InvalidStatus) as exc:
            net.ws_connect(
                ports.EXTENSIONS_RATELIMIT, path="/ws",
                headers={"X-Ws-Client": "one"},
            )

        assert exc.value.response.status_code == 429

        # The established tunnel is unaffected.
        assert net.ws_echo_roundtrip(conn, "still-open") == "still-open"

    # A different client holds a fresh bucket.
    with net.ws_connect(
        ports.EXTENSIONS_RATELIMIT, path="/ws",
        headers={"X-Ws-Client": "two"},
    ) as conn:
        assert conn.recv(timeout=10).startswith("wsbin ")
