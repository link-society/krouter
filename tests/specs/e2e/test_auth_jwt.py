"""
ExtensionRef bearer JWT authentication (docs/spec/authentication.md,
docs/spec/acceptance.md criterion 28).

Route rules referencing an `auth.hcl` Secret with a `provider "jwt"`
block validate `Authorization: Bearer` tokens against a JWKS document
served by a mock provider: valid tokens pass and inject the identity
headers, invalid or missing tokens are answered with the RFC 6750
challenge (the gRPC UNAUTHENTICATED status on GRPCRoute rules), claim
rules answer 403, and misplaced or empty configurations fail closed.
"""

import time

import pytest

from e2elib import auth, backends, gateway as gw, kubectl, net, ports

BACKEND = "jwt-backend"
GRPC_BACKEND = "jwt-grpc-backend"
GRPC_HOST = "jwt-grpc.example.com"
IDP = "jwt-idp"

ISSUER_PATH = "/idp"
JWKS_PATH = "/idp/jwks"
AUDIENCE = "my-api"
KID = "e2e-jwt"


def jwt_hcl(issuer: str, jwks_url: str, groups: list[str] | None = None) -> str:
    lines = [
        "version = 1",
        "",
        "auth {",
        '  provider "jwt" {',
        f'    issuer    = "{issuer}"',
        f'    audiences = ["{AUDIENCE}"]',
        f'    jwks_url  = "{jwks_url}"',
        "  }",
    ]

    if groups is not None:
        rendered = ", ".join(f'"{group}"' for group in groups)
        lines += [
            "",
            "  authorization {",
            "    require {",
            '      claim  = "groups"',
            f"      values = [{rendered}]",
            "    }",
            "  }",
        ]

    lines.append("}")

    return "\n".join(lines) + "\n"


@pytest.fixture(scope="module")
def signing_key():
    return auth.rsa_signing_key()


@pytest.fixture(scope="module")
def stack(gateway_class, module_namespace, signing_key):
    """
    Gateway with one HTTP listener, a mock provider pod serving the JWKS
    document, and a protected route referencing the `auth.hcl` Secret.
    """

    ns = module_namespace
    issuer = auth.svc_url(IDP, ns, ISSUER_PATH)

    kubectl.apply(backends.mockserver_backend(BACKEND, ns), namespace=ns)
    kubectl.apply(backends.grpc_greeter_backend(GRPC_BACKEND, ns), namespace=ns)
    kubectl.apply(backends.mockserver_backend(IDP, ns), namespace=ns)

    kubectl.apply([
        gw.params_configmap(
            "gw-params",
            ns,
            gw.infra_params_hcl(node_ports={"http": ports.AUTH_JWT}),
        ),
        gw.gateway(
            "jwt-gw",
            ns,
            [gw.listener("http", 80, "HTTP")],
            infra_params="gw-params",
        ),
        gw.extension_secret(
            "jwt-auth",
            ns,
            jwt_hcl(issuer, auth.svc_url(IDP, ns, JWKS_PATH)),
        ),
        gw.http_route(
            "plain-route",
            ns,
            [gw.parent_ref("jwt-gw")],
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
        gw.http_route(
            "api-route",
            ns,
            [gw.parent_ref("jwt-gw")],
            rules=[
                {
                    "matches": [
                        {"path": {"type": "PathPrefix", "value": "/api"}},
                    ],
                    "filters": [gw.extension_ref("jwt-auth", kind="Secret")],
                    "backendRefs": [
                        gw.backend_ref(BACKEND, backends.BACKEND_PORT),
                    ],
                },
            ],
        ),
    ])

    kubectl.wait_condition("gateway", "jwt-gw", ns, "Programmed", timeout=180)
    kubectl.wait_deployment_ready(BACKEND, ns)
    kubectl.wait_deployment_ready(GRPC_BACKEND, ns)
    kubectl.wait_deployment_ready(IDP, ns)

    idp_pod = kubectl.get("pods", namespace=ns, selector=f"app={IDP}")["items"][0]
    backends.put_expectations(
        idp_pod["metadata"]["name"],
        ns,
        [auth.json_expectation(JWKS_PATH, {"keys": [auth.jwk(signing_key, KID)]})],
    )

    kubectl.wait_route_parent_condition("api-route", ns, "Accepted", timeout=60)
    kubectl.wait_route_parent_condition("api-route", ns, "ResolvedRefs", timeout=60)
    net.wait_http_ok(ports.AUTH_JWT, path="/plain")

    # The JWKS is fetched lazily per data-plane pod: consecutive 200s
    # for a valid token prove every pod resolved it.
    token = auth.mint_jwt(signing_key, KID, claims(ns))
    net.wait_http_ok(
        ports.AUTH_JWT,
        path="/api",
        headers=auth.bearer(token),
        consecutive=8,
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


def issuer_of(ns: str) -> str:
    return auth.svc_url(IDP, ns, ISSUER_PATH)


def claims(ns: str, **overrides) -> dict:
    now = int(time.time())
    base = {
        "iss": issuer_of(ns),
        "aud": AUDIENCE,
        "sub": "alice",
        "email": "alice@example.com",
        "groups": ["platform-team"],
        "iat": now,
        "exp": now + 300,
    }
    base.update(overrides)

    return base


def test_missing_token_is_challenged(stack):
    """
    docs/spec/authentication.md Bearer JWT: no token on a jwt-only rule is
    answered 401 with the RFC 6750 challenge, never a redirect.
    """

    resp = net.request(
        ports.AUTH_JWT,
        path="/api",
        headers={"Accept": "text/html"},
    )
    assert resp.status_code == 401
    assert "bearer" in resp.headers.get("www-authenticate", "").lower()


def test_valid_token_passes_with_identity_headers(stack, signing_key, backend_pod):
    """
    docs/spec/authentication.md Identity headers: an accepted token
    forwards the request with X-Auth-Request-* populated from the claims.
    """

    ns = stack
    token = auth.mint_jwt(signing_key, KID, claims(ns))

    resp = net.request(ports.AUTH_JWT, path="/api", headers=auth.bearer(token))
    assert resp.status_code == 200
    assert resp.json()["backend"] == BACKEND

    recorded = backends.recorded_headers(backend_pod, ns, path="/api")
    assert recorded, "backend did not record the authenticated request"

    headers = recorded[-1]
    assert headers.get("x-auth-request-user") == ["alice"]
    assert headers.get("x-auth-request-email") == ["alice@example.com"]
    assert headers.get("x-auth-request-groups") == ["platform-team"]


@pytest.mark.parametrize(
    ("label", "mutate"),
    [
        ("expired", lambda ns: {"exp": int(time.time()) - 3600}),
        ("wrong-audience", lambda ns: {"aud": "someone-else"}),
        ("wrong-issuer", lambda ns: {"iss": "https://evil.example.com"}),
    ],
)
def test_invalid_claims_are_rejected(stack, signing_key, label, mutate):
    """
    docs/spec/authentication.md Bearer JWT: expiry, audience and issuer are
    validated; failures answer 401 with the Bearer challenge.
    """

    ns = stack
    token = auth.mint_jwt(signing_key, KID, claims(ns, **mutate(ns)))

    resp = net.request(ports.AUTH_JWT, path="/api", headers=auth.bearer(token))
    assert resp.status_code == 401, f"{label} token must be rejected"
    assert "bearer" in resp.headers.get("www-authenticate", "").lower()


def test_unsigned_and_symmetric_algorithms_are_rejected(stack):
    """
    docs/spec/authentication.md Bearer JWT: `none` and symmetric algorithms
    MUST be rejected whatever the claims say.
    """

    ns = stack

    unsigned = auth.mint_unsigned_jwt(claims(ns))
    resp = net.request(ports.AUTH_JWT, path="/api", headers=auth.bearer(unsigned))
    assert resp.status_code == 401

    symmetric = auth.mint_hs256_jwt(b"a" * 32, claims(ns))
    resp = net.request(ports.AUTH_JWT, path="/api", headers=auth.bearer(symmetric))
    assert resp.status_code == 401


def test_wrong_signing_key_is_rejected(stack):
    """
    docs/spec/authentication.md Bearer JWT: signatures are verified against
    the JWKS document, not merely parsed.
    """

    ns = stack
    imposter = auth.rsa_signing_key()
    token = auth.mint_jwt(imposter, KID, claims(ns))

    resp = net.request(ports.AUTH_JWT, path="/api", headers=auth.bearer(token))
    assert resp.status_code == 401


def test_claim_rules_answer_403_without_challenge_loop(stack, signing_key):
    """
    docs/spec/authentication.md Authorization: an authenticated principal
    failing the claim rules is answered 403, not challenged again.
    """

    ns = stack
    kubectl.apply([
        gw.extension_secret(
            "jwt-auth-admin",
            ns,
            jwt_hcl(
                issuer_of(ns),
                auth.svc_url(IDP, ns, JWKS_PATH),
                groups=["admins"],
            ),
        ),
        gw.http_route(
            "admin-route",
            ns,
            [gw.parent_ref("jwt-gw")],
            rules=[
                {
                    "matches": [
                        {"path": {"type": "PathPrefix", "value": "/admin"}},
                    ],
                    "filters": [gw.extension_ref("jwt-auth-admin", kind="Secret")],
                    "backendRefs": [
                        gw.backend_ref(BACKEND, backends.BACKEND_PORT),
                    ],
                },
            ],
        ),
    ])
    kubectl.wait_route_parent_condition("admin-route", ns, "ResolvedRefs", timeout=60)

    token = auth.mint_jwt(signing_key, KID, claims(ns))

    def check():
        resp = net.request(ports.AUTH_JWT, path="/admin", headers=auth.bearer(token))

        return resp if resp.status_code != 404 else None

    resp = kubectl.wait_for(check, timeout=60, desc="admin route serving")
    assert resp.status_code == 403
    assert "www-authenticate" not in resp.headers


def test_client_supplied_identity_headers_are_stripped(stack, signing_key, backend_pod):
    """
    docs/spec/authentication.md Identity headers: client-supplied
    X-Auth-Request-* headers never reach backends on auth-enabled rules.
    """

    ns = stack
    token = auth.mint_jwt(signing_key, KID, claims(ns))

    resp = net.request(
        ports.AUTH_JWT,
        path="/api",
        headers={
            **auth.bearer(token),
            "X-Auth-Request-User": "mallory",
            "X-Auth-Request-Groups": "admins",
        },
    )
    assert resp.status_code == 200

    recorded = backends.recorded_headers(backend_pod, ns, path="/api")
    headers = recorded[-1]
    assert headers.get("x-auth-request-user") == ["alice"]
    assert headers.get("x-auth-request-groups") == ["platform-team"]


def test_grpc_rule_enforces_bearer_tokens(stack, signing_key):
    """
    docs/spec/authentication.md Resolution and status: `jwt` is the one
    provider valid on GRPCRoute rules; missing tokens map to the gRPC
    UNAUTHENTICATED status, valid tokens reach the greeter.
    """

    ns = stack
    kubectl.apply(
        gw.grpc_route(
            "grpc-api",
            ns,
            [gw.parent_ref("jwt-gw")],
            hostnames=[GRPC_HOST],
            rules=[
                {
                    "filters": [gw.extension_ref("jwt-auth", kind="Secret")],
                    "backendRefs": [
                        gw.backend_ref(GRPC_BACKEND, backends.GRPC_BACKEND_PORT),
                    ],
                },
            ],
        ),
    )
    kubectl.wait_route_parent_condition(
        "grpc-api",
        ns,
        "ResolvedRefs",
        kind="grpcroute",
        timeout=60,
    )

    token = auth.mint_jwt(signing_key, KID, claims(ns))

    def check():
        status, reply = net.grpc_hello(
            ports.AUTH_JWT,
            GRPC_HOST,
            headers=auth.bearer(token),
        )

        return (status, reply) if reply.startswith("Hello") else None

    kubectl.wait_for(check, timeout=120, desc="authenticated gRPC greeting")

    status, _ = net.grpc_hello(ports.AUTH_JWT, GRPC_HOST)
    assert status == 16, f"expected UNAUTHENTICATED (16), got {status}"


def test_auth_hcl_in_a_configmap_fails_closed(stack):
    """
    docs/spec/extensions.md: `auth.hcl` in a ConfigMap is invalid because
    credentials MUST NOT live in ConfigMaps; the route resolves to
    InvalidExtensionRef and requests answer 500.
    """

    ns = stack
    kubectl.apply([
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "jwt-auth-misplaced", "namespace": ns},
            "data": {
                "auth.hcl": jwt_hcl(
                    issuer_of(ns),
                    auth.svc_url(IDP, ns, JWKS_PATH),
                ),
            },
        },
        gw.http_route(
            "misplaced-route",
            ns,
            [gw.parent_ref("jwt-gw")],
            rules=[
                {
                    "matches": [
                        {"path": {"type": "PathPrefix", "value": "/misplaced"}},
                    ],
                    "filters": [gw.extension_ref("jwt-auth-misplaced")],
                    "backendRefs": [
                        gw.backend_ref(BACKEND, backends.BACKEND_PORT),
                    ],
                },
            ],
        ),
    ])

    kubectl.wait_route_parent_condition(
        "misplaced-route",
        ns,
        "ResolvedRefs",
        status="False",
        reason="InvalidExtensionRef",
        timeout=60,
    )

    def check():
        resp = net.request(ports.AUTH_JWT, path="/misplaced")

        return resp if resp.status_code != 404 else None

    resp = kubectl.wait_for(check, timeout=60, desc="misplaced route fail-closed")
    assert resp.status_code == 500
