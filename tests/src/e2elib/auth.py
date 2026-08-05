"""
Authentication test helpers (docs/spec/authentication.md).

Mock identity providers are MockServer pods: the fixtures install their
expectations (JWKS documents, OIDC discovery, token endpoints, SAML IdP
metadata) at runtime through the admin API (`backends.put_expectations`),
and the tests mint the signed material themselves with `cryptography`.
No real identity provider is involved: what reaches krouter is exactly
what the expectations serve.

Browser flows are driven by `BrowserSession`, a cookie-holding
pseudo-browser: gateway-local redirects are followed against the
NodePort, and the redirect leaving the gateway (the provider's URL) is
handed back to the test, which plays the provider itself.
"""

import base64
import json
import secrets
import zlib

import hashlib
import hmac

import datetime

from html.parser import HTMLParser
from urllib.parse import parse_qsl

import httpx

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from lxml import etree

from signxml import XMLSigner

from e2elib import backends, net


# ------------------------------------------------------------- encoding --

def b64url(data: bytes) -> str:
    """
    Base64url without padding (RFC 7515 section 2).
    """

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data: str) -> bytes:
    padded = data + "=" * (-len(data) % 4)

    return base64.urlsafe_b64decode(padded)


# ------------------------------------------------------------- key material --

def rsa_signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwk(key: rsa.RSAPrivateKey, kid: str) -> dict:
    """
    Public JWK (RFC 7517) for one RSA signing key.
    """

    numbers = key.public_key().public_numbers()

    def uint(value: int) -> str:
        return b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))

    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": uint(numbers.n),
        "e": uint(numbers.e),
    }


def key_pem(key: rsa.RSAPrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


# ------------------------------------------------------------------- jwt --

def mint_jwt(
    key: rsa.RSAPrivateKey,
    kid: str,
    claims: dict,
) -> str:
    """
    Compact RS256 JWT over the given claims (RFC 7519).
    """

    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    signing_input = _signing_input(header, claims)
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())

    return signing_input.decode() + "." + b64url(signature)


def mint_hs256_jwt(secret: bytes, claims: dict) -> str:
    """
    Symmetric HS256 JWT: providers MUST reject it
    (docs/spec/authentication.md Bearer JWT).
    """

    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = _signing_input(header, claims)
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()

    return signing_input.decode() + "." + b64url(signature)


def mint_unsigned_jwt(claims: dict) -> str:
    """
    `none`-algorithm JWT: providers MUST reject it
    (docs/spec/authentication.md Bearer JWT).
    """

    header = {"alg": "none", "typ": "JWT"}

    return _signing_input(header, claims).decode() + "."


def _signing_input(header: dict, claims: dict) -> bytes:
    encoded = (
        b64url(json.dumps(header, separators=(",", ":")).encode()),
        b64url(json.dumps(claims, separators=(",", ":")).encode()),
    )

    return ".".join(encoded).encode()


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------- mock IdP plumbing --

def svc_url(service: str, namespace: str, path: str = "", port: int = backends.MOCKSERVER_PORT) -> str:
    """
    In-cluster URL of a mock provider Service, as written into `auth.hcl`:
    providers are fetched by the data-plane pods, never by the test host.
    """

    return f"http://{service}.{namespace}.svc.cluster.local:{port}{path}"


def json_expectation(path: str, payload: dict, method: str = "GET") -> dict:
    """
    Static JSON MockServer expectation for one mock provider endpoint.
    """

    return {
        "priority": 50,
        "httpRequest": {"method": method, "path": path},
        "httpResponse": {
            "statusCode": 200,
            "headers": {"Content-Type": ["application/json"]},
            "body": {"type": "JSON", "json": payload},
        },
    }


# ---------------------------------------------------------------- oidc --

def oidc_discovery_expectation(issuer: str, issuer_path: str) -> dict:
    """
    OIDC discovery document expectation: endpoints live under the issuer
    path on the same mock provider pod.
    """

    return json_expectation(
        issuer_path + "/.well-known/openid-configuration",
        {
            "issuer": issuer,
            "authorization_endpoint": issuer + "/authorize",
            "token_endpoint": issuer + "/token",
            "jwks_uri": issuer + "/jwks",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "id_token_signing_alg_values_supported": ["RS256"],
        },
    )


def token_expectation(
    token_path: str,
    match: dict[str, str],
    tokens: dict,
) -> dict:
    """
    Token endpoint expectation answering one form-encoded POST whose
    parameters match, with the given token response.
    """

    return {
        "priority": 60,
        "httpRequest": {
            "method": "POST",
            "path": token_path,
            "body": {
                "type": "PARAMETERS",
                "parameters": {key: [value] for key, value in match.items()},
            },
        },
        "httpResponse": {
            "statusCode": 200,
            "headers": {"Content-Type": ["application/json"]},
            "body": {"type": "JSON", "json": tokens},
        },
    }


def recorded_forms(pod: str, namespace: str, path: str) -> list[dict[str, str]]:
    """
    Form-encoded request bodies recorded by a mock provider pod.
    """

    forms = []
    for request in backends.recorded_requests(pod, namespace, path=path):
        body = request.get("body", "")
        if isinstance(body, dict):
            if "parameters" in body:
                forms.append({
                    key: values[0]
                    for key, values in body["parameters"].items()
                })
                continue

            body = body.get("string", "")

        forms.append(dict(parse_qsl(body)))

    return forms


def s256(verifier: str) -> str:
    """
    PKCE S256 code challenge for one verifier (RFC 7636).
    """

    return b64url(hashlib.sha256(verifier.encode()).digest())


# ---------------------------------------------------------------- saml --

NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"

BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
NAMEID_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"


def self_signed_cert(common_name: str) -> tuple[rsa.RSAPrivateKey, bytes]:
    """
    RSA key and self-signed certificate PEM, for IdP metadata and SP
    key material.
    """

    key = rsa_signing_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )

    return key, cert.public_bytes(serialization.Encoding.PEM)


def cert_b64(cert_pem: bytes) -> str:
    """
    Certificate DER as base64, the X509Certificate element's content.
    """

    lines = [
        line for line in cert_pem.decode().splitlines()
        if line and not line.startswith("-----")
    ]

    return "".join(lines)


def saml_idp_metadata(
    entity_id: str,
    sso_url: str,
    slo_url: str,
    cert_pem: bytes,
) -> str:
    """
    IdP metadata document served by the mock provider
    (docs/spec/authentication.md SAML 2.0).
    """

    return f"""\
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="{NS_MD}" entityID="{entity_id}">
  <md:IDPSSODescriptor protocolSupportEnumeration="{NS_SAMLP}">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="{NS_DS}">
        <ds:X509Data>
          <ds:X509Certificate>{cert_b64(cert_pem)}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="{BINDING_REDIRECT}" Location="{slo_url}"/>
    <md:SingleSignOnService Binding="{BINDING_REDIRECT}" Location="{sso_url}"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
"""


def xml_expectation(path: str, xml: str) -> dict:
    """
    Static XML MockServer expectation (IdP metadata).
    """

    return {
        "priority": 50,
        "httpRequest": {"method": "GET", "path": path},
        "httpResponse": {
            "statusCode": 200,
            "headers": {"Content-Type": ["application/samlmetadata+xml"]},
            "body": {"type": "STRING", "string": xml},
        },
    }


def parse_redirect_binding(url: httpx.URL) -> tuple[etree._Element, dict[str, str]]:
    """
    Decode the SAML message of one HTTP-Redirect binding URL; returns the
    XML root and the query parameters.
    """

    params = dict(parse_qsl(url.query.decode()))
    message = params.get("SAMLRequest") or params.get("SAMLResponse")
    assert message, f"no SAML message on {url}"

    inflated = zlib.decompress(base64.b64decode(message), -15)

    return etree.fromstring(inflated), params


def _sign(element: etree._Element, key: rsa.RSAPrivateKey, cert_pem: bytes) -> etree._Element:
    """
    Enveloped XMLDSig over one SAML element, signature placed after the
    Issuer as the schema requires.
    """

    signer = XMLSigner(
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
    )
    signed = signer.sign(
        element,
        key=key_pem(key).encode(),
        cert=cert_pem.decode(),
        reference_uri="#" + element.get("ID"),
    )

    signature = signed.find(f"{{{NS_DS}}}Signature")
    if signature is not None:
        signed.remove(signature)
        signed.insert(1, signature)

    return signed


def _instant(offset_seconds: int = 0) -> str:
    at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        seconds=offset_seconds,
    )

    return at.strftime("%Y-%m-%dT%H:%M:%SZ")


def saml_id() -> str:
    return "_" + secrets.token_hex(16)


def mint_saml_response(
    idp_key: rsa.RSAPrivateKey,
    idp_cert: bytes,
    issuer: str,
    in_response_to: str,
    acs_url: str,
    audience: str,
    name_id: str,
    attributes: dict[str, list[str]],
    session_index: str | None = None,
) -> str:
    """
    Base64-encoded SAML Response with a signed assertion, ready for the
    HTTP-POST binding (docs/spec/authentication.md SAML 2.0).
    """

    session_index = session_index or saml_id()

    attribute_xml = "".join(
        f'<saml:Attribute Name="{name}">'
        + "".join(
            f"<saml:AttributeValue>{value}</saml:AttributeValue>"
            for value in values
        )
        + "</saml:Attribute>"
        for name, values in attributes.items()
    )

    assertion_xml = f"""\
<saml:Assertion xmlns:saml="{NS_SAML}" ID="{saml_id()}" Version="2.0" IssueInstant="{_instant()}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="{NAMEID_UNSPECIFIED}">{name_id}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData InResponseTo="{in_response_to}" Recipient="{acs_url}" NotOnOrAfter="{_instant(300)}"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="{_instant(-300)}" NotOnOrAfter="{_instant(300)}">
    <saml:AudienceRestriction>
      <saml:Audience>{audience}</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="{_instant()}" SessionIndex="{session_index}">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
  <saml:AttributeStatement>{attribute_xml}</saml:AttributeStatement>
</saml:Assertion>
"""

    assertion = _sign(etree.fromstring(assertion_xml.encode()), idp_key, idp_cert)

    response_xml = f"""\
<samlp:Response xmlns:samlp="{NS_SAMLP}" xmlns:saml="{NS_SAML}" ID="{saml_id()}"
    Version="2.0" IssueInstant="{_instant()}" Destination="{acs_url}"
    InResponseTo="{in_response_to}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="{STATUS_SUCCESS}"/>
  </samlp:Status>
</samlp:Response>
"""

    response = etree.fromstring(response_xml.encode())
    response.append(assertion)

    return base64.b64encode(etree.tostring(response)).decode()


def mint_logout_request(
    idp_key: rsa.RSAPrivateKey,
    idp_cert: bytes,
    issuer: str,
    destination: str,
    name_id: str,
    session_index: str | None = None,
) -> str:
    """
    Base64-encoded signed LogoutRequest for IdP-initiated front-channel
    SLO over the HTTP-POST binding.
    """

    session_xml = (
        f"<samlp:SessionIndex>{session_index}</samlp:SessionIndex>"
        if session_index
        else ""
    )

    request_xml = f"""\
<samlp:LogoutRequest xmlns:samlp="{NS_SAMLP}" xmlns:saml="{NS_SAML}"
    ID="{saml_id()}" Version="2.0" IssueInstant="{_instant()}"
    Destination="{destination}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <saml:NameID Format="{NAMEID_UNSPECIFIED}">{name_id}</saml:NameID>
  {session_xml}
</samlp:LogoutRequest>
"""

    signed = _sign(etree.fromstring(request_xml.encode()), idp_key, idp_cert)

    return base64.b64encode(etree.tostring(signed)).decode()


# --------------------------------------------------------------- browser --

class _FormParser(HTMLParser):
    """
    Collects the first form of the login page: action, method, and the
    inputs with their types and preset values.
    """

    def __init__(self):
        super().__init__()
        self.action: str | None = None
        self.fields: dict[str, str] = {}
        self.types: dict[str, str] = {}
        self._in_form = False
        self._done = False

    def handle_starttag(self, tag, attrs):
        if self._done:
            return

        attributes = dict(attrs)

        if tag == "form" and not self._in_form:
            self._in_form = True
            self.action = attributes.get("action")

            return

        if tag == "input" and self._in_form:
            name = attributes.get("name")
            if name:
                self.fields[name] = attributes.get("value", "")
                self.types[name] = attributes.get("type", "text")

    def handle_endtag(self, tag):
        if tag == "form" and self._in_form:
            self._in_form = False
            self._done = True


def fill_login_form(html: str, username: str, password: str) -> tuple[str, dict[str, str]]:
    """
    Fill the login page's credential form (docs/spec/authentication.md
    Login page) without assuming field names: the password input takes
    the password, the first text input takes the username, and hidden
    inputs (the anti-forgery token) keep their preset values.
    """

    parser = _FormParser()
    parser.feed(html)

    assert parser.action, "the login page must render a credential form"

    data = dict(parser.fields)
    username_set = False
    for name, field_type in parser.types.items():
        if field_type == "password":
            data[name] = password

        elif field_type in ("text", "email") and not username_set:
            data[name] = username
            username_set = True

    assert username_set, "the credential form must have a username input"
    assert any(t == "password" for t in parser.types.values()), \
        "the credential form must have a password input"

    return parser.action, data


class BrowserSession:
    """
    Cookie-holding pseudo-browser bound to one gateway NodePort.

    Redirects are never followed implicitly: `follow_offsite` walks
    gateway-local hops (the login page, flow starts, post-login returns)
    and stops at the first Location leaving the gateway, which is the
    provider URL the test then serves itself.
    """

    def __init__(self, node_port: int, worker: int = 1, timeout: float = 10):
        self._base = httpx.URL(net.base_url(node_port, "http", worker))
        self.client = httpx.Client(
            base_url=str(self._base),
            follow_redirects=False,
            timeout=timeout,
        )

    def get(
        self,
        path: str,
        browser: bool = True,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """
        GET as a top-level navigation (`Accept: text/html`) or as an API
        call (docs/spec/authentication.md Request path integration).
        """

        accept = "text/html" if browser else "application/json"

        return self.client.get(path, headers={"Accept": accept, **(headers or {})})

    def post(
        self,
        path: str,
        data: dict[str, str],
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        return self.client.post(
            path,
            data=data,
            headers={"Accept": "text/html", **(headers or {})},
        )

    def is_local(self, url: httpx.URL) -> bool:
        return not url.is_absolute_url or (
            url.host == self._base.host and url.port == self._base.port
        )

    def follow_offsite(
        self,
        path: str,
        max_hops: int = 5,
    ) -> tuple[httpx.Response, httpx.URL | None, list[str]]:
        """
        Navigate until a redirect leaves the gateway.

        Returns the last response, the offsite Location (None when the
        navigation settled locally), and the visited local paths.
        """

        visited = [path]
        resp = self.get(path)

        for _ in range(max_hops):
            if resp.status_code not in (301, 302, 303, 307):
                return resp, None, visited

            location = httpx.URL(resp.headers["location"])
            if not self.is_local(location):
                return resp, location, visited

            target = location.path
            if location.query:
                target += "?" + location.query.decode()

            visited.append(target)
            resp = self.get(target)

        raise AssertionError(f"redirect loop through {visited}")

    def tamper_cookies(self) -> None:
        """
        Corrupt every held cookie value: a tampered session MUST be
        treated as no session (docs/spec/authentication.md).
        """

        for cookie in list(self.client.cookies.jar):
            self.client.cookies.set(
                cookie.name,
                (cookie.value or "")[::-1],
                domain=cookie.domain,
                path=cookie.path,
            )

    def cookie_names(self) -> set[str]:
        return {cookie.name for cookie in self.client.cookies.jar}

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> "BrowserSession":
        return self

    def __exit__(self, *exc_info):
        self.close()
