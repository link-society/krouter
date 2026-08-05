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

import hashlib
import hmac

from urllib.parse import parse_qsl

import httpx

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

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


# --------------------------------------------------------------- browser --

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
