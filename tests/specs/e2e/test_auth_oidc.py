"""
ExtensionRef OIDC authentication (docs/spec/authentication.md,
docs/spec/acceptance.md criterion 28).

Route rules referencing an `auth.hcl` Secret with a `provider "oidc"`
block drive the authorization code flow against a mock provider: the
login page forwards the single interactive provider without a chooser,
`state`, `nonce` and PKCE ride the flow, the callback mints a stateless
session that survives reloads and pod replacement, expired tokens
refresh transparently, and logout clears the session.
"""

import secrets
import time

from urllib.parse import parse_qsl

import httpx
import pytest

from e2elib import auth, backends, config, gateway as gw, kubectl, net, ports

BACKEND = "oidc-backend"
IDP = "oidc-idp"

ISSUER_PATH = "/idp"
TOKEN_PATH = "/idp/token"
JWKS_PATH = "/idp/jwks"
CLIENT_ID = "krouter-e2e"
KID = "e2e-oidc"

PREFIX = "/.krouter/auth"

SESSION_SECRET = "0d0863385538e590686e05f2a1cbd77546a7ff27e3a4a08029283b5e82c02f6a"


def oidc_hcl(issuer: str) -> str:
    return f"""\
version = 1

auth {{
  session {{
    secret   = "{SESSION_SECRET}"
    lifetime = "12h"
  }}

  provider "oidc" {{
    issuer        = "{issuer}"
    client_id     = "{CLIENT_ID}"
    client_secret = "e2e-client-secret"
    scopes        = ["openid", "profile", "email"]
  }}
}}
"""


@pytest.fixture(scope="module")
def signing_key():
    return auth.rsa_signing_key()


@pytest.fixture(scope="module")
def stack(gateway_class, module_namespace, signing_key):
    """
    Gateway with one HTTP listener, a mock OIDC provider (discovery,
    JWKS and token endpoints), and a protected route under /app.
    """

    ns = module_namespace
    issuer = auth.svc_url(IDP, ns, ISSUER_PATH)

    kubectl.apply(backends.mockserver_backend(BACKEND, ns), namespace=ns)
    kubectl.apply(backends.mockserver_backend(IDP, ns), namespace=ns)

    kubectl.apply([
        gw.params_configmap(
            "gw-params",
            ns,
            gw.infra_params_hcl(node_ports={"http": ports.AUTH_OIDC}),
        ),
        gw.gateway(
            "oidc-gw",
            ns,
            [gw.listener("http", 80, "HTTP")],
            infra_params="gw-params",
        ),
        gw.extension_secret("oidc-auth", ns, oidc_hcl(issuer)),
        gw.http_route(
            "plain-route",
            ns,
            [gw.parent_ref("oidc-gw")],
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
            "app-route",
            ns,
            [gw.parent_ref("oidc-gw")],
            rules=[
                {
                    "matches": [
                        {"path": {"type": "PathPrefix", "value": "/app"}},
                    ],
                    "filters": [gw.extension_ref("oidc-auth", kind="Secret")],
                    "backendRefs": [
                        gw.backend_ref(BACKEND, backends.BACKEND_PORT),
                    ],
                },
            ],
        ),
    ])

    kubectl.wait_condition("gateway", "oidc-gw", ns, "Programmed", timeout=180)
    kubectl.wait_deployment_ready(BACKEND, ns)
    kubectl.wait_deployment_ready(IDP, ns)

    backends.put_expectations(
        idp_pod_name(ns),
        ns,
        [
            auth.oidc_discovery_expectation(issuer, ISSUER_PATH),
            auth.json_expectation(JWKS_PATH, {"keys": [auth.jwk(signing_key, KID)]}),
        ],
    )

    kubectl.wait_route_parent_condition("app-route", ns, "Accepted", timeout=60)
    kubectl.wait_route_parent_condition("app-route", ns, "ResolvedRefs", timeout=60)
    net.wait_http_ok(ports.AUTH_OIDC, path="/plain")

    def discovery_ready():
        """
        The data plane fetches the discovery document lazily; the first
        flow start can race Service endpoint propagation.
        """

        with auth.BrowserSession(ports.AUTH_OIDC) as browser:
            _, offsite, _ = browser.follow_offsite("/app")

            return offsite is not None or None

    kubectl.wait_for(
        discovery_ready,
        timeout=60,
        desc="oidc discovery reachable from the data plane",
    )

    return ns


def idp_pod_name(ns: str) -> str:
    pod = kubectl.get("pods", namespace=ns, selector=f"app={IDP}")["items"][0]

    return pod["metadata"]["name"]


def id_token_claims(ns: str, nonce: str, lifetime: int = 300, **overrides) -> dict:
    now = int(time.time())
    claims = {
        "iss": auth.svc_url(IDP, ns, ISSUER_PATH),
        "aud": CLIENT_ID,
        "sub": "alice",
        "email": "alice@example.com",
        "groups": ["platform-team"],
        "nonce": nonce,
        "iat": now,
        "exp": now + lifetime,
    }
    claims.update(overrides)

    return claims


def authorize_params(browser: auth.BrowserSession, path: str = "/app") -> tuple[dict, list[str]]:
    """
    Navigate unauthenticated to the provider and return the authorization
    request parameters with the visited local paths.
    """

    resp, offsite, visited = browser.follow_offsite(path)
    assert offsite is not None, (
        f"expected a redirect to the provider, settled on "
        f"{resp.status_code} at {visited}"
    )

    params = dict(parse_qsl(offsite.query.decode()))
    assert params.get("response_type") == "code"
    assert params.get("client_id") == CLIENT_ID

    return params, visited


def complete_login(
    ns: str,
    browser: auth.BrowserSession,
    signing_key,
    path: str = "/app",
    lifetime: int = 300,
    refresh_token: str | None = None,
) -> tuple[dict, list[str]]:
    """
    Play the provider for one authorization code flow: parse the
    authorization request, install the token expectation, and return
    through the callback to the protected path. Returns the
    authorization request parameters and the visited local paths.
    """

    params, visited = authorize_params(browser, path)

    code = secrets.token_urlsafe(12)
    id_token = auth.mint_jwt(
        signing_key,
        KID,
        id_token_claims(ns, params["nonce"], lifetime=lifetime),
    )

    tokens = {
        "token_type": "Bearer",
        "access_token": secrets.token_urlsafe(12),
        "id_token": id_token,
        "expires_in": lifetime,
    }
    if refresh_token is not None:
        tokens["refresh_token"] = refresh_token

    backends.put_expectations(
        idp_pod_name(ns),
        ns,
        [auth.token_expectation(TOKEN_PATH, {"code": code}, tokens)],
    )

    callback = httpx.URL(params["redirect_uri"])
    assert browser.is_local(callback), (
        f"redirect_uri must use the request's own authority: {callback}"
    )

    resp = browser.get(f"{callback.path}?code={code}&state={params['state']}")
    assert resp.status_code in (302, 303), (
        f"callback must redirect to the return URL, got {resp.status_code}: "
        f"{resp.text[:200]}"
    )

    resp = browser.get(resp.headers["location"])
    assert resp.status_code == 200, "post-login return must serve the app"

    return params, visited


def test_login_round_trip_mints_a_session(stack, signing_key):
    """
    docs/spec/authentication.md OpenID Connect: the code flow completes
    with state, nonce and PKCE, forwards through the login page without a
    chooser, and the session carries the identity to the backend.
    """

    ns = stack
    with auth.BrowserSession(ports.AUTH_OIDC) as browser:
        params, visited = complete_login(ns, browser, signing_key)

        # Single interactive provider: the login page is traversed, no
        # chooser is rendered (docs/spec/authentication.md Login page).
        assert any(path.startswith(f"{PREFIX}/login") for path in visited), (
            f"expected the login page in the redirect chain, got {visited}"
        )

        assert params.get("state"), "state MUST ride the authorization request"
        assert params.get("nonce"), "nonce MUST ride the authorization request"
        assert params.get("code_challenge"), "PKCE MUST ride the authorization request"
        assert params.get("code_challenge_method") == "S256"

        assert browser.cookie_names(), "the callback must set a session cookie"

        resp = browser.get("/app")
        assert resp.status_code == 200
        assert resp.json()["backend"] == BACKEND

        # The provider verified the PKCE exchange.
        forms = auth.recorded_forms(idp_pod_name(ns), ns, TOKEN_PATH)
        code_exchanges = [
            form for form in forms
            if form.get("grant_type") == "authorization_code"
        ]
        assert code_exchanges, "the token endpoint must see the code exchange"

        verifier = code_exchanges[-1].get("code_verifier", "")
        assert verifier, "the code exchange must carry the PKCE verifier"
        assert auth.s256(verifier) == params["code_challenge"], (
            "the verifier must match the challenge sent on the "
            "authorization request"
        )


def test_identity_headers_reach_the_backend(stack, signing_key):
    """
    docs/spec/authentication.md Identity headers: the session's claims are
    injected as X-Auth-Request-* on proxied requests.
    """

    ns = stack
    backend_pod = kubectl.get(
        "pods",
        namespace=ns,
        selector=f"app={BACKEND}",
    )["items"][0]["metadata"]["name"]

    with auth.BrowserSession(ports.AUTH_OIDC) as browser:
        complete_login(ns, browser, signing_key)

        backends.reset_recordings(backend_pod, ns)
        assert browser.get("/app").status_code == 200

        recorded = backends.recorded_headers(backend_pod, ns, path="/app")
        assert recorded, "backend did not record the authenticated request"

        headers = recorded[-1]
        assert headers.get("x-auth-request-user") == ["alice"]
        assert headers.get("x-auth-request-email") == ["alice@example.com"]
        assert headers.get("x-auth-request-groups") == ["platform-team"]


def test_non_navigation_requests_are_not_redirected(stack):
    """
    docs/spec/authentication.md Provider selection: only top-level browser
    navigations redirect; API calls fail fast with 401.
    """

    resp = net.request(
        ports.AUTH_OIDC,
        path="/app",
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 401


def test_session_survives_reload_and_pod_replacement(stack, signing_key):
    """
    docs/spec/authentication.md Stateless sessions: sessions are validated
    by key material, not generation identity, and no pod holds state.
    """

    ns = stack
    with auth.BrowserSession(ports.AUTH_OIDC) as browser:
        complete_login(ns, browser, signing_key)

        # Publish a new generation for the Gateway.
        gateway_uid = kubectl.get("gateway", "oidc-gw", ns)["metadata"]["uid"]
        kubectl.apply(
            gw.http_route(
                "reload-route",
                ns,
                [gw.parent_ref("oidc-gw")],
                rules=[
                    {
                        "matches": [
                            {"path": {"type": "PathPrefix", "value": "/reload"}},
                        ],
                        "backendRefs": [
                            gw.backend_ref(BACKEND, backends.BACKEND_PORT),
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

        assert browser.get("/app").status_code == 200, \
            "the session must survive a configuration reload"

        # Replace every data-plane pod: the cookie is the whole session.
        kubectl.kubectl(
            "-n", config.SYSTEM_NAMESPACE,
            "rollout", "restart",
            f"daemonset/{config.DATAPLANE_DAEMONSET}",
        )
        kubectl.wait_daemonset_ready(
            config.DATAPLANE_DAEMONSET,
            config.SYSTEM_NAMESPACE,
        )
        net.wait_http_ok(ports.AUTH_OIDC, path="/plain")

        assert browser.get("/app").status_code == 200, \
            "the session must survive data-plane pod replacement"


def test_tampered_cookies_are_no_session(stack, signing_key):
    """
    docs/spec/authentication.md Stateless sessions: a tampered cookie is
    treated as no session, never as an error.
    """

    ns = stack
    with auth.BrowserSession(ports.AUTH_OIDC) as browser:
        complete_login(ns, browser, signing_key)
        browser.tamper_cookies()

        resp = browser.get("/app")
        assert resp.status_code in (302, 303), (
            f"a tampered session must restart the login flow, "
            f"got {resp.status_code}"
        )


def test_expired_tokens_refresh_transparently(stack, signing_key):
    """
    docs/spec/authentication.md OpenID Connect: a granted refresh token is
    used transparently after token expiry, within the session lifetime.
    """

    ns = stack
    refresh_token = secrets.token_urlsafe(12)

    with auth.BrowserSession(ports.AUTH_OIDC) as browser:
        complete_login(
            ns,
            browser,
            signing_key,
            lifetime=5,
            refresh_token=refresh_token,
        )

        refreshed = auth.mint_jwt(
            signing_key,
            KID,
            id_token_claims(ns, nonce="", lifetime=300),
        )
        backends.put_expectations(
            idp_pod_name(ns),
            ns,
            [
                auth.token_expectation(
                    TOKEN_PATH,
                    {"grant_type": "refresh_token", "refresh_token": refresh_token},
                    {
                        "token_type": "Bearer",
                        "access_token": secrets.token_urlsafe(12),
                        "id_token": refreshed,
                        "expires_in": 300,
                    },
                ),
            ],
        )

        time.sleep(8)

        assert browser.get("/app").status_code == 200, \
            "an expired token with a refresh token must not re-authenticate"

        forms = auth.recorded_forms(idp_pod_name(ns), ns, TOKEN_PATH)
        assert any(
            form.get("grant_type") == "refresh_token" for form in forms
        ), "the provider must see the refresh grant"


def test_logout_clears_the_session(stack, signing_key):
    """
    docs/spec/authentication.md Logout and single logout: logout clears
    the session cookies and, without an end-session endpoint, redirects
    to /.
    """

    ns = stack
    with auth.BrowserSession(ports.AUTH_OIDC) as browser:
        complete_login(ns, browser, signing_key)
        assert browser.get("/app").status_code == 200

        resp = browser.get(f"{PREFIX}/logout")
        assert resp.status_code in (302, 303)

        resp, offsite, _ = browser.follow_offsite("/app")
        assert offsite is not None or resp.status_code != 200, \
            "after logout the session must be gone"
