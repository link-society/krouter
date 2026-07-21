"""
MockServer-based test backend.

The suites deploy `mockserver/mockserver` pods as HTTPRoute backends. Because
the image is distroless and MockServer templates cannot read environment
variables, a busybox initContainer renders the expectation initializer JSON,
substituting the pod name (downward API) so every response identifies the
serving pod. That identity drives the round-robin (docs/spec/traffic.md), no-leakage
(docs/spec/acceptance.md criterion 4) and EndpointSlice readiness (docs/spec/acceptance.md criterion 8) assertions.

Endpoints configured through the initializer:

- GET /            -> 200 JSON {"pod": "<pod>", "backend": "<name>"}
- GET /ready       -> 200 (readiness probe target; overridden at runtime with
                      a 503 expectation to flip the pod unready without
                      terminating it, docs/spec/traffic.md, docs/spec/acceptance.md criterion 8)
- GET /delayed     -> 200 after a 15s server-side delay (in-flight requests
                      across reloads, docs/spec/traffic.md, docs/spec/acceptance.md criterion 7)

Runtime control goes through the MockServer API on the same port
(PUT /mockserver/expectation, PUT /mockserver/retrieve, ...) via
port-forwards to individual pods.
"""

import json

import httpx

from e2elib import kubectl

MOCKSERVER_IMAGE = "mockserver/mockserver:5.15.0"
MOCKSERVER_PORT = 1080

# Rendered by the initContainer: __POD_NAME__ is replaced with the pod name.
_INITIALIZER_TEMPLATE = json.dumps(
    [
        {
            "priority": 10,
            "httpRequest": {"method": "GET", "path": "/ready"},
            "httpResponse": {
                "statusCode": 200,
                "body": {
                    "type": "JSON",
                    "json": {"ready": True, "pod": "__POD_NAME__"},
                },
            },
        },
        {
            "priority": 10,
            "httpRequest": {"method": "GET", "path": "/delayed"},
            "httpResponse": {
                "statusCode": 200,
                "body": {
                    "type": "JSON",
                    "json": {"pod": "__POD_NAME__", "delayed": True},
                },
                "delay": {"timeUnit": "SECONDS", "value": 15},
            },
        },
        {
            "priority": 0,
            # Empty request matcher: matches every request not shadowed by a
            # higher-priority expectation.
            "httpRequest": {},
            "httpResponse": {
                "statusCode": 200,
                "body": {
                    "type": "JSON",
                    "json": {"pod": "__POD_NAME__", "backend": "__BACKEND_NAME__"},
                },
            },
        },
    ],
    indent=2,
)

_INIT_CONFIGMAP = "mockserver-initializer"


def mockserver_backend(name: str, namespace: str, replicas: int = 1) -> list[dict]:
    """
    ConfigMap + Deployment + Service for one MockServer backend.
    """

    labels = {"app": name}

    return [
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": f"{_INIT_CONFIGMAP}-{name}", "namespace": namespace},
            "data": {"initializer.template.json": _INITIALIZER_TEMPLATE},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": name, "namespace": namespace},
            "spec": {
                "replicas": replicas,
                "selector": {"matchLabels": labels},
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "initContainers": [
                            {
                                # Renders the initializer with this pod's identity.
                                "name": "render-initializer",
                                "image": "busybox:1.36",
                                "command": [
                                    "sh", "-c",
                                    "sed -e \"s/__POD_NAME__/${POD_NAME}/g\" "
                                    "-e \"s/__BACKEND_NAME__/${BACKEND_NAME}/g\" "
                                    "/template/initializer.template.json "
                                    "> /rendered/initializer.json",
                                ],
                                "env": [
                                    {"name": "BACKEND_NAME", "value": name},
                                    {
                                        "name": "POD_NAME",
                                        "valueFrom": {
                                            "fieldRef": {"fieldPath": "metadata.name"},
                                        },
                                    },
                                ],
                                "volumeMounts": [
                                    {"name": "template", "mountPath": "/template"},
                                    {"name": "rendered", "mountPath": "/rendered"},
                                ],
                            },
                        ],
                        "containers": [
                            {
                                "name": "mockserver",
                                "image": MOCKSERVER_IMAGE,
                                "ports": [{"containerPort": MOCKSERVER_PORT}],
                                "env": [
                                    {
                                        "name": "MOCKSERVER_SERVER_PORT",
                                        "value": str(MOCKSERVER_PORT),
                                    },
                                    {
                                        "name": "MOCKSERVER_INITIALIZATION_JSON_PATH",
                                        "value": "/rendered/initializer.json",
                                    },
                                    # JAVA_TOOL_OPTIONS is read by the JVM itself
                                    # (the distroless image has no shell). Keep the
                                    # heap small: many pods share a laptop-sized
                                    # kind cluster.
                                    {
                                        "name": "JAVA_TOOL_OPTIONS",
                                        "value": "-Xms64m -Xmx192m",
                                    },
                                ],
                                "volumeMounts": [
                                    {"name": "rendered", "mountPath": "/rendered"},
                                ],
                                "readinessProbe": {
                                    "httpGet": {"path": "/ready", "port": MOCKSERVER_PORT},
                                    "periodSeconds": 2,
                                    "failureThreshold": 2,
                                },
                            },
                        ],
                        "volumes": [
                            {
                                "name": "template",
                                "configMap": {"name": f"{_INIT_CONFIGMAP}-{name}"},
                            },
                            {"name": "rendered", "emptyDir": {}},
                        ],
                    },
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": name, "namespace": namespace},
            "spec": {
                "selector": labels,
                "ports": [
                    {
                        "name": "http",
                        "port": MOCKSERVER_PORT,
                        "targetPort": MOCKSERVER_PORT,
                    },
                ],
            },
        },
    ]


# Backwards-compatible alias used by the suites.
echo_backend = mockserver_backend
BACKEND_PORT = MOCKSERVER_PORT


# --------------------------------------------------- runtime pod control --

def _pod_api(
    pod: str,
    namespace: str,
    method: str,
    path: str,
    payload: dict | list | None = None,
) -> httpx.Response:
    with kubectl.port_forward(f"pod/{pod}", MOCKSERVER_PORT, namespace) as local_port:
        with httpx.Client(base_url=f"http://127.0.0.1:{local_port}", timeout=30) as client:
            return client.request(
                method,
                path,
                json=payload if payload is not None else None,
            )


def set_pod_ready(pod: str, namespace: str, ready: bool) -> None:
    """
    Flip the readiness probe target of one MockServer pod.

    A higher-priority expectation shadows the initializer's /ready rule, so
    the kubelet flips the pod's EndpointSlice `ready` condition while the
    process keeps running (docs/spec/traffic.md, docs/spec/acceptance.md criterion 8).
    """

    expectation = {
        "id": "ready-override",
        "priority": 100,
        "httpRequest": {"method": "GET", "path": "/ready"},
        "httpResponse": {
            "statusCode": 200 if ready else 503,
            "body": {"type": "JSON", "json": {"ready": ready}},
        },
    }

    resp = _pod_api(pod, namespace, "PUT", "/mockserver/expectation", expectation)
    assert resp.status_code in (200, 201), \
        f"failed to set readiness expectation on {pod}: {resp.status_code} {resp.text[:200]}"


def recorded_requests(pod: str, namespace: str, path: str = "/") -> list[dict]:
    """
    Requests recorded by one pod (docs/spec/traffic.md header assertions).
    """

    resp = _pod_api(
        pod,
        namespace,
        "PUT",
        "/mockserver/retrieve?type=REQUESTS&format=JSON",
        {"path": path},
    )
    assert resp.status_code == 200, \
        f"failed to retrieve requests from {pod}: {resp.status_code} {resp.text[:200]}"

    return resp.json()


def recorded_headers(pod: str, namespace: str, path: str = "/") -> list[dict[str, list[str]]]:
    """
    Lower-cased header maps of every recorded request for `path`.
    """

    result = []
    for req in recorded_requests(pod, namespace, path):
        headers = req.get("headers", {})
        result.append({k.lower(): v for k, v in headers.items()})

    return result


def reset_recordings(pod: str, namespace: str) -> None:
    resp = _pod_api(
        pod,
        namespace,
        "PUT",
        "/mockserver/clear?type=LOG",
        {"path": ".*"},
    )
    assert resp.status_code == 200, \
        f"failed to clear recordings on {pod}: {resp.status_code} {resp.text[:200]}"
