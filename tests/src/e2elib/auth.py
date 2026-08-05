"""
Authentication test helpers (docs/spec/authentication.md).

Mock identity providers are MockServer pods: the fixtures install their
expectations (JWKS documents, OIDC discovery, token endpoints, SAML IdP
metadata) at runtime through the admin API (`backends.put_expectations`),
and the tests mint the signed material themselves with `cryptography`.
No real identity provider is involved: what reaches krouter is exactly
what the expectations serve.
"""

import base64
import json

import hashlib
import hmac

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from e2elib import backends


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
