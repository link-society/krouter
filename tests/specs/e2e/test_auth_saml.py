"""
ExtensionRef SAML 2.0 authentication (docs/spec/authentication.md,
docs/spec/acceptance.md criterion 28).

Route rules referencing an `auth.hcl` Secret with a `provider "saml"`
block drive SP-initiated login against a mock IdP: signed AuthnRequests
leave over the HTTP-Redirect binding, signed assertions return through
the POST ACS and mint a stateless session, unsolicited assertions are
rejected, the SP metadata document reflects the serving host, and
front-channel single logout works in both directions.
"""

import base64

import httpx
import pytest

from lxml import etree

from e2elib import auth, backends, gateway as gw, kubectl, net, ports

BACKEND = "saml-backend"
IDP = "saml-idp"

IDP_ENTITY_ID = "urn:e2e:saml:idp"
SP_ENTITY_ID = "krouter-e2e-apps"
METADATA_PATH = "/idp/metadata"
SSO_PATH = "/idp/sso"
SLO_PATH = "/idp/slo"

PREFIX = "/.krouter/auth"
ACS_PATH = f"{PREFIX}/saml/acs"

SESSION_SECRET = "b7f5ac04c2f00ba54c4fd514e2c25c8b41b6b34924ee128a422bbf46e934b911"


def saml_hcl(ns: str, sp_key_pem: str, sp_cert_pem: str) -> str:
    key = "\n".join(f"    {line}" for line in sp_key_pem.strip().splitlines())
    cert = "\n".join(f"    {line}" for line in sp_cert_pem.strip().splitlines())

    return f"""\
version = 1

auth {{
  session {{
    secret   = "{SESSION_SECRET}"
    lifetime = "12h"
  }}

  provider "saml" {{
    entity_id        = "{SP_ENTITY_ID}"
    idp_metadata_url = "{auth.svc_url(IDP, ns, METADATA_PATH)}"

    sp_key = <<-EOT
{key}
    EOT

    sp_certificate = <<-EOT
{cert}
    EOT

    attributes {{
      email  = "mail"
      groups = "groups"
    }}
  }}
}}
"""


@pytest.fixture(scope="module")
def idp_material():
    """
    IdP signing key and certificate, published through the metadata.
    """

    return auth.self_signed_cert("saml-e2e-idp")


@pytest.fixture(scope="module")
def stack(gateway_class, module_namespace, idp_material):
    """
    Gateway with one HTTP listener, a mock IdP serving its metadata, and
    a protected route under /app.
    """

    ns = module_namespace
    idp_key, idp_cert = idp_material

    sp_key, sp_cert = auth.self_signed_cert("saml-e2e-sp")

    kubectl.apply(backends.mockserver_backend(BACKEND, ns), namespace=ns)
    kubectl.apply(backends.mockserver_backend(IDP, ns), namespace=ns)

    kubectl.apply([
        gw.params_configmap(
            "gw-params",
            ns,
            gw.infra_params_hcl(node_ports={"http": ports.AUTH_SAML}),
        ),
        gw.gateway(
            "saml-gw",
            ns,
            [gw.listener("http", 80, "HTTP")],
            infra_params="gw-params",
        ),
        gw.extension_secret(
            "saml-auth",
            ns,
            saml_hcl(ns, auth.key_pem(sp_key), sp_cert.decode()),
        ),
        gw.http_route(
            "plain-route",
            ns,
            [gw.parent_ref("saml-gw")],
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
            [gw.parent_ref("saml-gw")],
            rules=[
                {
                    "matches": [
                        {"path": {"type": "PathPrefix", "value": "/app"}},
                    ],
                    "filters": [gw.extension_ref("saml-auth", kind="Secret")],
                    "backendRefs": [
                        gw.backend_ref(BACKEND, backends.BACKEND_PORT),
                    ],
                },
            ],
        ),
    ])

    kubectl.wait_condition("gateway", "saml-gw", ns, "Programmed", timeout=180)
    kubectl.wait_deployment_ready(BACKEND, ns)
    kubectl.wait_deployment_ready(IDP, ns)

    idp_pod = kubectl.get("pods", namespace=ns, selector=f"app={IDP}")["items"][0]
    backends.put_expectations(
        idp_pod["metadata"]["name"],
        ns,
        [
            auth.xml_expectation(
                METADATA_PATH,
                auth.saml_idp_metadata(
                    IDP_ENTITY_ID,
                    auth.svc_url(IDP, ns, SSO_PATH),
                    auth.svc_url(IDP, ns, SLO_PATH),
                    idp_cert,
                ),
            ),
        ],
    )

    kubectl.wait_route_parent_condition("app-route", ns, "Accepted", timeout=60)
    kubectl.wait_route_parent_condition("app-route", ns, "ResolvedRefs", timeout=60)
    net.wait_http_ok(ports.AUTH_SAML, path="/plain")

    # The IdP metadata is fetched lazily: serving the SP metadata proves
    # the flow endpoints are ready end to end.
    net.wait_http_ok(ports.AUTH_SAML, path=f"{PREFIX}/saml/metadata")

    return ns


def start_login(browser: auth.BrowserSession) -> tuple[etree._Element, dict[str, str]]:
    """
    Navigate unauthenticated to the IdP and return the decoded
    AuthnRequest with the redirect binding parameters.
    """

    resp, offsite, visited = browser.follow_offsite("/app")
    assert offsite is not None, (
        f"expected a redirect to the IdP, settled on {resp.status_code} "
        f"at {visited}"
    )
    assert offsite.path == SSO_PATH, f"expected the IdP SSO endpoint, got {offsite}"

    request, params = auth.parse_redirect_binding(offsite)
    assert request.tag == f"{{{auth.NS_SAMLP}}}AuthnRequest"

    return request, params


def complete_login(
    ns: str,
    browser: auth.BrowserSession,
    idp_material,
    name_id: str = "alice",
) -> None:
    """
    Play the IdP for one SP-initiated flow: answer the AuthnRequest with
    a signed assertion POSTed to the ACS.
    """

    idp_key, idp_cert = idp_material
    request, params = start_login(browser)

    acs_url = request.get("AssertionConsumerServiceURL") or str(
        browser.client.base_url.join(ACS_PATH),
    )

    response = auth.mint_saml_response(
        idp_key,
        idp_cert,
        IDP_ENTITY_ID,
        in_response_to=request.get("ID"),
        acs_url=acs_url,
        audience=SP_ENTITY_ID,
        name_id=name_id,
        attributes={
            "mail": [f"{name_id}@example.com"],
            "groups": ["platform-team"],
        },
    )

    data = {"SAMLResponse": response}
    if params.get("RelayState"):
        data["RelayState"] = params["RelayState"]

    resp = browser.post(ACS_PATH, data=data)
    assert resp.status_code in (302, 303), (
        f"the ACS must redirect to the return URL, got {resp.status_code}: "
        f"{resp.text[:200]}"
    )

    resp = browser.get(resp.headers["location"])
    assert resp.status_code == 200, "post-login return must serve the app"


def test_login_through_the_post_acs(stack, idp_material):
    """
    docs/spec/authentication.md SAML 2.0: the SP-initiated flow signs its
    AuthnRequest, accepts the signed assertion on the POST ACS, and the
    session carries NameID and mapped attributes to the backend.
    """

    ns = stack
    backend_pod = kubectl.get(
        "pods",
        namespace=ns,
        selector=f"app={BACKEND}",
    )["items"][0]["metadata"]["name"]

    with auth.BrowserSession(ports.AUTH_SAML) as browser:
        request, params = start_login(browser)
        assert params.get("SigAlg") and params.get("Signature"), (
            "AuthnRequests MUST be signed with sp_key over the redirect "
            "binding"
        )

        complete_login(ns, browser, idp_material)
        assert browser.cookie_names(), "the ACS must set a session cookie"

        backends.reset_recordings(backend_pod, ns)
        resp = browser.get("/app")
        assert resp.status_code == 200
        assert resp.json()["backend"] == BACKEND

        recorded = backends.recorded_headers(backend_pod, ns, path="/app")
        assert recorded, "backend did not record the authenticated request"

        headers = recorded[-1]
        assert headers.get("x-auth-request-user") == ["alice"]
        assert headers.get("x-auth-request-email") == ["alice@example.com"]
        assert headers.get("x-auth-request-groups") == ["platform-team"]


def test_unsolicited_assertions_are_rejected(stack, idp_material):
    """
    docs/spec/authentication.md SAML 2.0: IdP-initiated responses MUST be
    rejected; InResponseTo MUST match the in-flight request ID.
    """

    ns = stack
    idp_key, idp_cert = idp_material

    with auth.BrowserSession(ports.AUTH_SAML) as browser:
        # No flow was started: there is no state cookie and no request ID.
        response = auth.mint_saml_response(
            idp_key,
            idp_cert,
            IDP_ENTITY_ID,
            in_response_to=auth.saml_id(),
            acs_url=str(browser.client.base_url.join(ACS_PATH)),
            audience=SP_ENTITY_ID,
            name_id="mallory",
            attributes={"mail": ["mallory@example.com"], "groups": []},
        )

        resp = browser.post(ACS_PATH, data={"SAMLResponse": response})
        assert 400 <= resp.status_code < 500, (
            f"an unsolicited assertion must be rejected, got {resp.status_code}"
        )

        resp, offsite, _ = browser.follow_offsite("/app")
        assert offsite is not None, "no session may exist after the rejection"


def test_sp_metadata_reflects_the_serving_host(stack):
    """
    docs/spec/authentication.md Reserved path prefix: the SP metadata
    document reflects the ACS and SLO URLs of the host it is fetched
    from.
    """

    with auth.BrowserSession(ports.AUTH_SAML) as browser:
        resp = browser.get(f"{PREFIX}/saml/metadata")
        assert resp.status_code == 200

        metadata = etree.fromstring(resp.content)
        assert metadata.get("entityID") == SP_ENTITY_ID

        acs = metadata.find(
            f"{{{auth.NS_MD}}}SPSSODescriptor"
            f"/{{{auth.NS_MD}}}AssertionConsumerService",
        )
        assert acs is not None, "the metadata must advertise the ACS"
        assert acs.get("Binding") == auth.BINDING_POST

        location = httpx.URL(acs.get("Location"))
        assert browser.is_local(location), (
            f"the ACS URL must use the serving host: {location}"
        )
        assert location.path == ACS_PATH


def test_rp_initiated_single_logout(stack, idp_material):
    """
    docs/spec/authentication.md Logout and single logout: logout redirects
    to the IdP SLO endpoint with a signed LogoutRequest built from the
    session's NameID.
    """

    ns = stack
    with auth.BrowserSession(ports.AUTH_SAML) as browser:
        complete_login(ns, browser, idp_material)
        assert browser.get("/app").status_code == 200

        resp, offsite, _ = browser.follow_offsite(f"{PREFIX}/logout")
        assert offsite is not None and offsite.path == SLO_PATH, (
            f"logout must reach the IdP SLO endpoint, got {offsite}"
        )

        request, params = auth.parse_redirect_binding(offsite)
        assert request.tag == f"{{{auth.NS_SAMLP}}}LogoutRequest"
        assert params.get("SigAlg") and params.get("Signature"), \
            "the LogoutRequest must be signed"

        name_id = request.find(f"{{{auth.NS_SAML}}}NameID")
        assert name_id is not None and name_id.text == "alice"

        resp, offsite, _ = browser.follow_offsite("/app")
        assert offsite is not None, "the session must be gone after logout"


def test_idp_initiated_single_logout(stack, idp_material):
    """
    docs/spec/authentication.md Logout and single logout: an IdP-initiated
    front-channel LogoutRequest clears the session and is answered with a
    LogoutResponse.
    """

    ns = stack
    idp_key, idp_cert = idp_material

    with auth.BrowserSession(ports.AUTH_SAML) as browser:
        complete_login(ns, browser, idp_material)

        logout_request = auth.mint_logout_request(
            idp_key,
            idp_cert,
            IDP_ENTITY_ID,
            destination=str(browser.client.base_url.join(f"{PREFIX}/saml/slo")),
            name_id="alice",
        )

        resp = browser.post(
            f"{PREFIX}/saml/slo",
            data={"SAMLRequest": logout_request},
        )
        assert resp.status_code in (200, 302, 303), (
            f"the SLO endpoint must answer the request, got {resp.status_code}"
        )

        # A LogoutResponse is returned over the requested binding.
        body_and_location = resp.text + resp.headers.get("location", "")
        assert "SAMLResponse" in body_and_location, \
            "the SLO endpoint must answer with a LogoutResponse"

        resp, offsite, _ = browser.follow_offsite("/app")
        assert offsite is not None, \
            "the session must be gone after IdP-initiated logout"
