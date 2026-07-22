"""
HTTP helpers used to talk to Gateways through published NodePorts.
"""

import http.client
import json
import socket
import ssl
import threading
import time

import httpx

from cryptography import x509

from e2elib import config, kubectl, ports


def base_url(node_port: int, scheme: str = "http", worker: int = 1) -> str:
    return f"{scheme}://{config.TEST_HOST}:{ports.host_port(node_port, worker)}"


def request(
    node_port: int,
    path: str = "/",
    host: str | None = None,
    scheme: str = "http",
    http2: bool = False,
    worker: int = 1,
    headers: dict[str, str] | None = None,
    timeout: float = 10,
    http1: bool = True,
) -> httpx.Response:
    """
    Issue one request to a published NodePort.

    `host` sets both the Host/:authority header and, for TLS, the SNI value,
    which is how listener hostname matching (docs/spec/traffic.md) is exercised while
    connecting to 127.0.0.1.
    """

    url = base_url(node_port, scheme, worker) + path

    all_headers = dict(headers or {})
    if host:
        all_headers["Host"] = host

    extensions = {}
    if scheme == "https" and host:
        extensions["sni_hostname"] = host

    with httpx.Client(http1=http1, http2=http2, verify=False, timeout=timeout) as client:
        return client.get(url, headers=all_headers, extensions=extensions)


def request_json(node_port: int, **kwargs) -> dict:
    resp = request(node_port, **kwargs)
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text[:200]}"

    return resp.json()


def wait_http_ok(
    node_port: int,
    host: str | None = None,
    path: str = "/",
    scheme: str = "http",
    timeout: float = 120,
    worker: int = 1,
) -> httpx.Response:
    """
    Wait until the Gateway serves 200 for the request (traffic readiness).
    """

    def check():
        try:
            resp = request(node_port, path=path, host=host, scheme=scheme, worker=worker)

        except (httpx.HTTPError, OSError):
            return None

        return resp if resp.status_code == 200 else None

    return kubectl.wait_for(
        check,
        timeout=timeout,
        desc=f"HTTP 200 from {scheme}://…:{node_port}{path} (host={host})",
    )


def sample_backends(
    node_port: int,
    host: str | None = None,
    count: int = 20,
    path: str = "/",
    scheme: str = "http",
    worker: int = 1,
) -> list[str]:
    """
    Return the backend pod name serving each of `count` requests.
    """

    seen = []
    for _ in range(count):
        data = request_json(node_port, path=path, host=host, scheme=scheme, worker=worker)
        seen.append(data["pod"])

    return seen


# ------------------------------------------------------------ raw tcp --

class TcpStream:
    """
    One raw TCP connection to a published NodePort (docs/spec/traffic.md).

    The test echo backend greets with one line holding the serving pod name,
    then echoes every line it receives.
    """

    def __init__(self, node_port: int, worker: int = 1, timeout: float = 10):
        self.sock = socket.create_connection(
            (config.TEST_HOST, ports.host_port(node_port, worker)),
            timeout=timeout,
        )
        self.reader = self.sock.makefile("rb")

    def read_line(self) -> str:
        line = self.reader.readline()
        if not line:
            raise ConnectionError("connection closed by peer")

        return line.decode().strip()

    def echo(self, payload: str) -> str:
        """
        Send one line and return the line echoed back.
        """

        self.sock.sendall((payload + "\n").encode())

        return self.read_line()

    def close(self):
        try:
            self.reader.close()

        finally:
            self.sock.close()

    def __enter__(self) -> "TcpStream":
        return self

    def __exit__(self, *exc_info):
        self.close()


def tcp_greeting(node_port: int, worker: int = 1) -> str:
    """
    Connect once and return the greeted backend pod name.
    """

    with TcpStream(node_port, worker=worker) as stream:
        return stream.read_line()


def wait_tcp_ready(node_port: int, timeout: float = 120, worker: int = 1) -> str:
    """
    Wait until the TCP listener forwards to a greeting backend.
    """

    def check():
        try:
            return tcp_greeting(node_port, worker=worker) or None

        except OSError:
            return None

    return kubectl.wait_for(
        check,
        timeout=timeout,
        desc=f"TCP greeting from …:{node_port}",
    )


# --------------------------------------------------------- traffic probe --

def dataplane_readyz(pod: dict) -> dict:
    """
    Management readiness body of one data-plane pod (docs/spec/status.md).
    """

    name = pod["metadata"]["name"]
    port = kubectl.management_port(pod)

    with kubectl.port_forward(f"pod/{name}", port, config.SYSTEM_NAMESPACE) as local:
        with httpx.Client(timeout=10) as client:
            return client.get(f"http://127.0.0.1:{local}/readyz").json()


def all_dataplane_pods_acked(gateway_uid: str) -> bool:
    """
    True when every healthy data-plane pod reports desired == applied for
    the Gateway — the condition for Programmed=True (docs/spec/status.md).
    """

    pods = kubectl.dataplane_pods()
    if not pods:
        return False

    for pod in pods:
        entry = dataplane_readyz(pod).get("gateways", {}).get(gateway_uid)
        if not entry:
            return False

        if entry.get("appliedGeneration") != entry.get("desiredGeneration"):
            return False

        if entry.get("lastError"):
            return False

    return True


class TrafficSampler:
    """
    Continuously samples a Gateway from a background thread.

    Used to prove atomic activation (docs/spec/configuration.md, docs/spec/acceptance.md criterion 5): during a
    configuration change every response must keep succeeding, coming from
    either the old or the new configuration, never from a broken in-between
    state.
    """

    def __init__(
        self,
        node_port: int,
        host: str | None = None,
        path: str = "/",
        interval: float = 0.05,
        worker: int = 1,
    ):
        self.node_port = node_port
        self.host = host
        self.path = path
        self.interval = interval
        self.worker = worker
        self.results: list[tuple[int, str]] = []  # (status, backend pod)
        self.errors: list[str] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        url = base_url(self.node_port, worker=self.worker) + self.path
        headers = {"Host": self.host} if self.host else {}

        with httpx.Client(timeout=10) as client:
            while not self._stop.is_set():
                try:
                    resp = client.get(url, headers=headers)

                    pod = ""
                    if resp.status_code == 200:
                        try:
                            pod = resp.json().get("pod", "")

                        except ValueError:
                            pod = ""

                    self.results.append((resp.status_code, pod))

                except Exception as exc:
                    self.errors.append(repr(exc))

                time.sleep(self.interval)

    def __enter__(self) -> "TrafficSampler":
        self._thread.start()

        return self

    def __exit__(self, *exc_info):
        self._stop.set()
        self._thread.join(timeout=30)

    @property
    def statuses(self) -> list[int]:
        return [status for status, _ in self.results]

    @property
    def backends(self) -> list[str]:
        return [pod for _, pod in self.results if pod]


# ------------------------------------------------- persistent connections --

class PersistentConnection:
    """
    One plain-text keep-alive connection pinned to a single TCP socket.

    Used to prove that configuration reloads never disturb established
    connections (docs/spec/traffic.md, docs/spec/performance.md): if the proxy closes the socket, the next
    request raises instead of transparently reconnecting.
    """

    def __init__(self, node_port: int, host: str | None = None, worker: int = 1):
        self.host_header = host
        self.conn = http.client.HTTPConnection(
            config.TEST_HOST,
            ports.host_port(node_port, worker),
            timeout=30,
        )
        self.conn.connect()

    def get(self, path: str = "/") -> tuple[int, bytes]:
        headers = {"Host": self.host_header} if self.host_header else {}
        self.conn.request("GET", path, headers=headers)

        resp = self.conn.getresponse()
        body = resp.read()

        return resp.status, body

    def get_json(self, path: str = "/") -> dict:
        status, body = self.get(path)
        assert status == 200, f"expected 200 on persistent connection, got {status}"

        return json.loads(body)

    def send_request(self, path: str) -> None:
        """
        Send a request without reading the response.

        Combined with the backend's /delayed endpoint this keeps a request
        in flight while the test triggers a configuration reload
        (docs/spec/traffic.md, docs/spec/acceptance.md criterion 7). Call `read_response` to collect the result.
        """

        headers = {"Host": self.host_header} if self.host_header else {}
        self.conn.request("GET", path, headers=headers)

    def read_response(self) -> tuple[int, bytes]:
        resp = self.conn.getresponse()

        return resp.status, resp.read()

    def close(self):
        self.conn.close()


class PersistentTLSConnection(PersistentConnection):
    """
    Keep-alive TLS connection with explicit SNI, pinned to one socket.
    """

    def __init__(self, node_port: int, sni: str, worker: int = 1):
        self.host_header = sni

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        class _Conn(http.client.HTTPSConnection):
            def connect(inner):  # noqa: N805 - stdlib subclass idiom
                sock = socket.create_connection((inner.host, inner.port), inner.timeout)
                inner.sock = ctx.wrap_socket(sock, server_hostname=sni)

        self.conn = _Conn(
            config.TEST_HOST,
            ports.host_port(node_port, worker),
            timeout=30,
        )
        self.conn.connect()


def get_server_certificate(node_port: int, sni: str, worker: int = 1) -> x509.Certificate:
    """
    Fetch the certificate presented for `sni` (docs/spec/security.md activation checks).
    """

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection(
        (config.TEST_HOST, ports.host_port(node_port, worker)),
        timeout=10,
    ) as sock:
        with ctx.wrap_socket(sock, server_hostname=sni) as tls_sock:
            der = tls_sock.getpeercert(binary_form=True)

    return x509.load_der_x509_certificate(der)
