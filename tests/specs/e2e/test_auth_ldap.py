"""
ExtensionRef LDAP authentication (docs/spec/authentication.md,
docs/spec/acceptance.md criterion 28).

Route rules referencing an `auth.hcl` Secret with a `provider "ldap"`
block authenticate against a GLAuth directory: API clients present HTTP
Basic credentials verified by search-then-bind, browsers log in through
the gateway-served credential form (never skipped for `ldap`), failed
binds re-challenge or re-render, group claims from `group_search` drive
authorization, and the form POST is protected against cross-site
submission.
"""

import base64

import pytest

from e2elib import auth, backends, gateway as gw, kubectl, net, ports

BACKEND = "ldap-backend"
DIRECTORY = "ldap-glauth"

PREFIX = "/.krouter/auth"
REALM = "krouter-e2e"

SESSION_SECRET = "cf83a4b90cd2f68c2ba18707445e2187e2f19b4c1325d9629b93546cd2f2911c"

ALICE_PASSWORD = "alice-password"
BOB_PASSWORD = "bob-password"

# sha256 of the passwords above and of the service account's bind secret;
# GLAuth stores hashes, the tests present the cleartext.
GLAUTH_CONFIG = """\
debug = true

[ldap]
  enabled = true
  listen = "0.0.0.0:3893"
  tls = false

[ldaps]
  enabled = false

[api]
  enabled = false

[behaviors]
  IgnoreCapabilities = false
  LimitFailedBinds = false

[backend]
  datastore = "config"
  baseDN = "dc=glauth,dc=com"

[[users]]
  name = "svc-krouter"
  uidnumber = 5000
  primarygroup = 5500
  passsha256 = "266739a274b3d2030954f1b943135d2116afe09e1a9f9d287d70bbd43ae94515"
    [[users.capabilities]]
    action = "search"
    object = "*"

[[users]]
  name = "alice"
  mail = "alice@example.com"
  uidnumber = 5001
  primarygroup = 5501
  passsha256 = "17a96502d336e4c18a43182a353d7f0a38414c6fc4daf678acae834a819cecee"

[[users]]
  name = "bob"
  mail = "bob@example.com"
  uidnumber = 5002
  primarygroup = 5502
  passsha256 = "df53c27a66157885ba143e34f25d6380e12168b0f7da4f0c46efa54cd9a083b7"

[[groups]]
  name = "svcaccts"
  gidnumber = 5500

[[groups]]
  name = "platform-team"
  gidnumber = 5501

[[groups]]
  name = "contractors"
  gidnumber = 5502
"""


def ldap_base_hcl(ns: str) -> str:
    """
    Platform-owned document: directory, service bind, session key
    (docs/spec/authentication.md Resolution and status).
    """

    url = f"ldap://{DIRECTORY}.{ns}.svc.cluster.local:{backends.GLAUTH_PORT}"

    return f"""\
version = 1

auth {{
  session {{
    secret   = "{SESSION_SECRET}"
    lifetime = "12h"
  }}

  provider "ldap" {{
    url           = "{url}"
    bind_dn       = "cn=svc-krouter,ou=svcaccts,dc=glauth,dc=com"
    bind_password = "svc-secret"
    user_base_dn  = "dc=glauth,dc=com"
    user_filter   = "(cn={{username}})"
    realm         = "{REALM}"

    attributes {{
      email = "mail"
    }}

    group_search {{
      base_dn   = "ou=groups,dc=glauth,dc=com"
      filter    = "(uniqueMember={{dn}})"
      attribute = "cn"
    }}
  }}
}}
"""


# Route-owned refinement: tightens access without repeating the provider
# (docs/spec/authentication.md Resolution and status).
ADMIN_TIGHTEN_HCL = """\
version = 1

auth {
  authorization {
    require {
      claim  = "groups"
      values = ["platform-team"]
    }
  }
}
"""


def basic(username: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()

    return {"Authorization": f"Basic {token}"}


@pytest.fixture(scope="module")
def stack(gateway_class, module_namespace):
    """
    Gateway with one HTTP listener, a GLAuth directory, an open
    authenticated route under /app, and a group-restricted route under
    /admin composed from two documents.
    """

    ns = module_namespace

    kubectl.apply(backends.mockserver_backend(BACKEND, ns), namespace=ns)
    kubectl.apply(backends.glauth_backend(DIRECTORY, ns, GLAUTH_CONFIG), namespace=ns)

    kubectl.apply([
        gw.params_configmap(
            "gw-params",
            ns,
            gw.infra_params_hcl(node_ports={"http": ports.AUTH_LDAP}),
        ),
        gw.gateway(
            "ldap-gw",
            ns,
            [gw.listener("http", 80, "HTTP")],
            infra_params="gw-params",
        ),
        gw.extension_secret("ldap-auth", ns, ldap_base_hcl(ns)),
        gw.extension_secret("ldap-admin-tighten", ns, ADMIN_TIGHTEN_HCL),
        gw.http_route(
            "plain-route",
            ns,
            [gw.parent_ref("ldap-gw")],
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
            [gw.parent_ref("ldap-gw")],
            rules=[
                {
                    "matches": [
                        {"path": {"type": "PathPrefix", "value": "/app"}},
                    ],
                    "filters": [gw.extension_ref("ldap-auth", kind="Secret")],
                    "backendRefs": [
                        gw.backend_ref(BACKEND, backends.BACKEND_PORT),
                    ],
                },
            ],
        ),
        gw.http_route(
            "admin-route",
            ns,
            [gw.parent_ref("ldap-gw")],
            rules=[
                {
                    "matches": [
                        {"path": {"type": "PathPrefix", "value": "/admin"}},
                    ],
                    "filters": [
                        gw.extension_ref("ldap-auth", kind="Secret"),
                        gw.extension_ref("ldap-admin-tighten", kind="Secret"),
                    ],
                    "backendRefs": [
                        gw.backend_ref(BACKEND, backends.BACKEND_PORT),
                    ],
                },
            ],
        ),
    ])

    kubectl.wait_condition("gateway", "ldap-gw", ns, "Programmed", timeout=180)
    kubectl.wait_deployment_ready(BACKEND, ns)
    kubectl.wait_deployment_ready(DIRECTORY, ns)

    kubectl.wait_route_parent_condition("app-route", ns, "Accepted", timeout=60)
    kubectl.wait_route_parent_condition("app-route", ns, "ResolvedRefs", timeout=60)
    kubectl.wait_route_parent_condition("admin-route", ns, "ResolvedRefs", timeout=60)
    net.wait_http_ok(ports.AUTH_LDAP, path="/plain")

    return ns


def test_basic_challenge_for_api_clients(stack):
    """
    docs/spec/authentication.md LDAP: non-browser requests without
    credentials are challenged with WWW-Authenticate: Basic and the
    configured realm.
    """

    resp = net.request(
        ports.AUTH_LDAP,
        path="/app",
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 401

    challenge = resp.headers.get("www-authenticate", "")
    assert challenge.lower().startswith("basic")
    assert REALM in challenge


def test_basic_credentials_authenticate(stack):
    """
    docs/spec/authentication.md LDAP: search-then-bind accepts presented
    Basic credentials and the identity reaches the backend.
    """

    ns = stack
    backend_pod = kubectl.get(
        "pods",
        namespace=ns,
        selector=f"app={BACKEND}",
    )["items"][0]["metadata"]["name"]
    backends.reset_recordings(backend_pod, ns)

    resp = net.request(
        ports.AUTH_LDAP,
        path="/app",
        headers=basic("alice", ALICE_PASSWORD),
    )
    assert resp.status_code == 200
    assert resp.json()["backend"] == BACKEND

    recorded = backends.recorded_headers(backend_pod, ns, path="/app")
    assert recorded, "backend did not record the authenticated request"

    headers = recorded[-1]
    assert headers.get("x-auth-request-user") == ["alice"]
    assert headers.get("x-auth-request-email") == ["alice@example.com"]
    assert headers.get("x-auth-request-groups") == ["platform-team"]


@pytest.mark.parametrize(
    ("username", "password"),
    [
        ("alice", "wrong-password"),
        ("nosuchuser", "whatever"),
    ],
)
def test_failed_binds_are_challenged_again(stack, username, password):
    """
    docs/spec/authentication.md LDAP: wrong passwords and unknown users
    answer the Basic challenge again, with no session.
    """

    resp = net.request(
        ports.AUTH_LDAP,
        path="/app",
        headers=basic(username, password),
    )
    assert resp.status_code == 401
    assert "basic" in resp.headers.get("www-authenticate", "").lower()
    assert "set-cookie" not in resp.headers


def test_login_form_flow(stack):
    """
    docs/spec/authentication.md Login page: browser navigations land on
    the credential form (never skipped for `ldap`); a successful POST
    mints the session and returns to the protected path.
    """

    with auth.BrowserSession(ports.AUTH_LDAP) as browser:
        resp, offsite, visited = browser.follow_offsite("/app")
        assert offsite is None, f"ldap must not redirect offsite, got {offsite}"
        assert resp.status_code == 200
        assert any(path.startswith(f"{PREFIX}/login") for path in visited), (
            f"expected the login page, visited {visited}"
        )

        action, data = auth.fill_login_form(resp.text, "alice", ALICE_PASSWORD)
        assert action.startswith(f"{PREFIX}/ldap/login"), (
            f"the form must POST to the provider's endpoint, got {action}"
        )

        resp = browser.post(action, data=data)
        assert resp.status_code in (302, 303), (
            f"a successful login must redirect, got {resp.status_code}"
        )
        assert browser.cookie_names(), "the login must set a session cookie"

        resp = browser.get(resp.headers["location"])
        assert resp.status_code == 200
        assert resp.json()["backend"] == BACKEND

        # The session stands on its own: no credentials on later requests.
        assert browser.get("/app").status_code == 200


def test_form_post_without_state_is_rejected(stack):
    """
    docs/spec/authentication.md Login page: the form POST requires the
    state cookie and the embedded anti-forgery token; a bare cross-site
    POST is rejected and mints nothing.
    """

    with auth.BrowserSession(ports.AUTH_LDAP) as browser:
        resp, _, _ = browser.follow_offsite("/app")
        action, data = auth.fill_login_form(resp.text, "alice", ALICE_PASSWORD)

    # Fresh client: same fields, no state cookie.
    with auth.BrowserSession(ports.AUTH_LDAP) as attacker:
        resp = attacker.post(action, data=data)
        assert 400 <= resp.status_code < 500, (
            f"a POST without the login state must be rejected, "
            f"got {resp.status_code}"
        )
        assert not attacker.cookie_names(), "no session may be minted"


def test_failed_form_bind_rerenders_generically(stack):
    """
    docs/spec/authentication.md Login page: a failed bind re-renders the
    form with a generic notice naming neither the reason nor the
    directory.
    """

    with auth.BrowserSession(ports.AUTH_LDAP) as browser:
        resp, _, _ = browser.follow_offsite("/app")
        action, data = auth.fill_login_form(resp.text, "alice", "wrong-password")

        resp = browser.post(action, data=data)
        assert resp.status_code in (200, 302, 303, 401), \
            f"unexpected status {resp.status_code}"

        if resp.status_code in (302, 303):
            resp = browser.get(resp.headers["location"])

        # The form is served again, with no directory internals leaked.
        auth.fill_login_form(resp.text, "alice", "retry")
        assert "glauth" not in resp.text.lower()
        assert "dc=glauth" not in resp.text

        assert browser.get("/app").status_code != 200, \
            "no session may exist after a failed bind"


def test_group_authorization_composes_from_documents(stack):
    """
    docs/spec/authentication.md Authorization and Resolution and status:
    the route document tightens the platform document; members pass,
    other authenticated principals get 403 with no challenge and no
    redirect.
    """

    member = net.request(
        ports.AUTH_LDAP,
        path="/admin",
        headers=basic("alice", ALICE_PASSWORD),
    )
    assert member.status_code == 200

    outsider = net.request(
        ports.AUTH_LDAP,
        path="/admin",
        headers={**basic("bob", BOB_PASSWORD), "Accept": "text/html"},
    )
    assert outsider.status_code == 403
    assert "www-authenticate" not in outsider.headers
    assert "location" not in outsider.headers

    # bob still reaches the untightened rule.
    open_route = net.request(
        ports.AUTH_LDAP,
        path="/app",
        headers=basic("bob", BOB_PASSWORD),
    )
    assert open_route.status_code == 200
