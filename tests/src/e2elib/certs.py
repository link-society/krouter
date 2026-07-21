"""
TLS material for HTTPS listener tests (docs/spec/security.md).

Certificates are issued in-test with trustme and pushed as standard
`kubernetes.io/tls` Secrets referenced by Gateway listeners.
"""

import trustme

from e2elib import kubectl


def make_ca() -> trustme.CA:
    return trustme.CA()


def issue(ca: trustme.CA, *hostnames: str) -> tuple[bytes, bytes]:
    """
    Issue a certificate; returns (cert_chain_pem, key_pem).
    """

    cert = ca.issue_cert(*hostnames)
    chain = b"".join(pem.bytes() for pem in cert.cert_chain_pems)
    key = cert.private_key_pem.bytes()

    return chain, key


def tls_secret(name: str, namespace: str, cert_pem: bytes, key_pem: bytes) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": name, "namespace": namespace},
        "type": "kubernetes.io/tls",
        "stringData": {
            "tls.crt": cert_pem.decode(),
            "tls.key": key_pem.decode(),
        },
    }


def apply_tls_secret(ca: trustme.CA, name: str, namespace: str, *hostnames: str) -> None:
    cert_pem, key_pem = issue(ca, *hostnames)
    kubectl.apply(tls_secret(name, namespace, cert_pem, key_pem))
