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
    headers: dict[str, str] | None = None,
    consecutive: int = 1,
) -> httpx.Response:
    """
    Wait until the Gateway serves 200 for the request (traffic readiness).

    `consecutive` requires that many 200s in a row: NodePorts balance over
    every data-plane pod, and lazily fetched provider material (JWKS, IdP
    metadata) is only proven ready per pod.
    """

    def check():
        resp = None
        for _ in range(consecutive):
            try:
                resp = request(
                    node_port,
                    path=path,
                    host=host,
                    scheme=scheme,
                    worker=worker,
                    headers=headers,
                )

            except (httpx.HTTPError, OSError):
                return None

            if resp.status_code != 200:
                return None

        return resp

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


# ------------------------------------------------------ proxy protocol --

def proxy_v1(
    source: str,
    source_port: int = 56324,
    destination: str = "10.0.0.1",
    destination_port: int = 443,
) -> bytes:
    """
    Version 1 preamble announcing `source` as the client
    (docs/spec/traffic.md Proxy protocol).
    """

    family = "TCP6" if ":" in source else "TCP4"

    return (
        f"PROXY {family} {source} {destination} "
        f"{source_port} {destination_port}\r\n"
    ).encode()


def proxy_v1_unknown() -> bytes:
    """
    Version 1 UNKNOWN preamble: no client address.
    """

    return b"PROXY UNKNOWN\r\n"


def proxy_v2_local() -> bytes:
    """
    Version 2 LOCAL preamble: no client address, what load balancer health
    checks send (docs/spec/traffic.md Proxy protocol).
    """

    return b"\r\n\r\n\x00\r\nQUIT\n" + bytes([0x20, 0x00, 0x00, 0x00])


def raw_http(
    node_port: int,
    path: str = "/",
    host: str | None = None,
    preamble: bytes = b"",
    worker: int = 1,
    timeout: float = 10,
) -> int:
    """
    Issue one HTTP/1.1 request on a raw socket, optionally prefixed with a
    PROXY protocol preamble, and return the response status.

    A gateway that closes the connection without answering, which is what a
    missing or refused preamble produces (docs/spec/traffic.md), returns 0:
    there is no status to report.
    """

    authority = host or config.TEST_HOST
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {authority}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()

    try:
        with socket.create_connection(
            (config.TEST_HOST, ports.host_port(node_port, worker)),
            timeout=timeout,
        ) as sock:
            sock.sendall(preamble + request)

            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break

                chunks.append(chunk)

    except (ConnectionError, socket.timeout):
        return 0

    response = b"".join(chunks)
    if not response.startswith(b"HTTP/"):
        return 0

    return int(response.split(b" ", 2)[1])


def wait_raw_http_ok(
    node_port: int,
    path: str = "/",
    host: str | None = None,
    preamble: bytes = b"",
    timeout: float = 120,
    worker: int = 1,
) -> int:
    """
    Wait until a raw request, preamble included, is served (traffic
    readiness on a proxy protocol listener).
    """

    def check():
        status = raw_http(
            node_port,
            path=path,
            host=host,
            preamble=preamble,
            worker=worker,
        )

        return status if status == 200 else None

    return kubectl.wait_for(
        check,
        timeout=timeout,
        desc=f"HTTP 200 from a raw request to …:{node_port}{path}",
    )


class UdpFlow:
    """
    One UDP flow (fixed source address) to a published NodePort
    (docs/spec/traffic.md).

    The test echo backend answers every datagram with the serving pod
    name, so exchanges double as identity probes.
    """

    def __init__(self, node_port: int, worker: int = 1, timeout: float = 5):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        self.addr = (config.TEST_HOST, ports.host_port(node_port, worker))

    def exchange(self, payload: str = "ping", attempts: int = 3) -> str:
        # UDP is best-effort: resend on timeout. Retries reuse the same
        # socket (same source address), so the flow identity is preserved.
        while True:
            attempts -= 1
            self.sock.sendto(payload.encode(), self.addr)

            try:
                data, _ = self.sock.recvfrom(4096)

            except TimeoutError:
                if attempts <= 0:
                    raise

                continue

            return data.decode().strip()

    def close(self):
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def udp_identity(node_port: int, worker: int = 1) -> str:
    """
    One fresh flow, one exchange: return the answering backend pod name.
    """

    with UdpFlow(node_port, worker=worker) as flow:
        return flow.exchange()


def wait_udp_ready(node_port: int, timeout: float = 120, worker: int = 1) -> str:
    """
    Wait until the UDP listener forwards to an answering backend.
    """

    def check():
        try:
            return udp_identity(node_port, worker=worker) or None

        except OSError:
            return None

    return kubectl.wait_for(
        check,
        timeout=timeout,
        desc=f"UDP reply from …:{node_port}",
    )


class TlsStream(TcpStream):
    """
    One TLS connection through a passthrough listener (docs/spec/traffic.md).

    The handshake is performed by the BACKEND: krouter only routes on the
    SNI value and forwards the still-encrypted stream. Verification is
    disabled because the test backends use self-issued certificates.
    """

    def __init__(self, node_port: int, sni: str, worker: int = 1, timeout: float = 10):
        raw = socket.create_connection(
            (config.TEST_HOST, ports.host_port(node_port, worker)),
            timeout=timeout,
        )

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        self.sock = context.wrap_socket(raw, server_hostname=sni)
        self.reader = self.sock.makefile("rb")


def tls_greeting(node_port: int, sni: str, worker: int = 1) -> str:
    """
    Connect once with the SNI value and return the greeted backend pod.
    """

    with TlsStream(node_port, sni, worker=worker) as stream:
        return stream.read_line()


def wait_tls_ready(node_port: int, sni: str, timeout: float = 120, worker: int = 1) -> str:
    """
    Wait until the TLS passthrough listener forwards the SNI to a backend.
    """

    def check():
        try:
            return tls_greeting(node_port, sni, worker=worker) or None

        except (OSError, ssl.SSLError):
            return None

    return kubectl.wait_for(
        check,
        timeout=timeout,
        desc=f"TLS greeting from …:{node_port} (sni={sni})",
    )


# ---------------------------------------------------------------- grpc --

def _grpc_frame(message: bytes) -> bytes:
    """
    gRPC length-prefixed message framing (uncompressed).
    """

    return b"\x00" + len(message).to_bytes(4, "big") + message


def _protobuf_string(field: int, value: str) -> bytes:
    """
    Encode one short protobuf string field (wire type 2, length < 128).
    """

    payload = value.encode()
    assert len(payload) < 128, "helper only encodes short strings"

    return bytes([field << 3 | 2, len(payload)]) + payload


def _protobuf_first_string(message: bytes) -> str:
    """
    Decode the first short protobuf string field of a message.
    """

    assert len(message) >= 2 and message[0] & 0x07 == 2, \
        f"expected a string field, got {message[:8]!r}"

    length = message[1]

    return message[2 : 2 + length].decode()


def grpc_hello(
    node_port: int,
    host: str,
    name: str = "krouter",
    path: str = "/helloworld.Greeter/SayHello",
    headers: dict[str, str] | None = None,
    worker: int = 1,
) -> tuple[int | None, str]:
    """
    One unary call to the hostname greeter through a published NodePort,
    speaking gRPC over cleartext HTTP/2 (docs/spec/traffic.md gRPC routing).

    Returns (grpc_status, reply). The status comes from the response
    HEADERS frame and is therefore only visible for trailers-only failure
    responses; successful replies return (None, "Hello <name> from <pod>").
    """

    url = base_url(node_port, "http", worker) + path

    all_headers = {
        "content-type": "application/grpc",
        "te": "trailers",
        "host": host,
        **(headers or {}),
    }

    body = _grpc_frame(_protobuf_string(1, name))

    with httpx.Client(http1=False, http2=True, timeout=10) as client:
        resp = client.post(url, content=body, headers=all_headers)

    status = resp.headers.get("grpc-status")
    grpc_status = int(status) if status is not None else None

    reply = ""
    if len(resp.content) > 5:
        reply = _protobuf_first_string(resp.content[5:])

    return grpc_status, reply


def wait_grpc_ready(
    node_port: int,
    host: str,
    timeout: float = 120,
    worker: int = 1,
) -> str:
    """
    Wait until the greeter answers through the Gateway.
    """

    def check():
        try:
            _, reply = grpc_hello(node_port, host, worker=worker)

        except (httpx.HTTPError, OSError):
            return None

        return reply if reply.startswith("Hello") else None

    return kubectl.wait_for(
        check,
        timeout=timeout,
        desc=f"gRPC greeting from …:{node_port} (host={host})",
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


# --------------------------------------------------------------- websocket --

def ws_connect(
    node_port: int,
    path: str = "/",
    scheme: str = "ws",
    ca=None,
    server_hostname: str | None = None,
    worker: int = 1,
    timeout: float = 10,
    headers: dict[str, str] | None = None,
):
    """
    Open one WebSocket connection through a published NodePort
    (docs/spec/traffic.md Protocol handling). Returns the connection from
    `websockets.sync.client.connect`; the caller owns closing it.

    For `wss`, pass the trustme CA and the certificate hostname: the TLS
    session verifies against the CA with that SNI while the URL targets
    the published loopback port.
    """

    from websockets.sync.client import connect

    url = f"{scheme}://{config.TEST_HOST}:{ports.host_port(node_port, worker)}{path}"

    kwargs: dict = {"open_timeout": timeout, "close_timeout": timeout}

    if headers:
        kwargs["additional_headers"] = headers

    if scheme == "wss":
        ctx = ssl.create_default_context()
        if ca is not None:
            ca.configure_trust(ctx)

        kwargs["ssl"] = ctx
        kwargs["server_hostname"] = server_hostname

    # A timed-out opening handshake is retried on a fresh connection:
    # nothing was exchanged yet, so no test semantics are involved.
    # Refusals (InvalidStatus and the like) propagate immediately.
    attempts = 3
    while True:
        attempts -= 1
        try:
            return connect(url, **kwargs)

        except TimeoutError:
            if attempts <= 0:
                raise


def ws_echo_roundtrip(conn, payload: str) -> str:
    """
    Send one text message and return the echoed reply.
    """

    conn.send(payload)

    return conn.recv(timeout=10)
