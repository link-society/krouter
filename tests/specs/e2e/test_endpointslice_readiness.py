"""
Backend discovery, balancing and readiness (spec §8.1, §11, §20.8).

EndpointSlice condition changes must alter backend selection without any pod
restart; round-robin distributes across ready endpoints; weights apply.
"""

from collections import Counter

import pytest

from e2elib import backends, gateway as gw, kubectl, net, ports
from e2elib.backends import BACKEND_PORT

HOSTNAME = "balance.example.com"


@pytest.fixture(scope="module")
def stack(gateway_class, module_namespace):
    ns = module_namespace
    kubectl.apply(backends.mockserver_backend("balanced", ns, replicas=2))
    kubectl.apply(backends.mockserver_backend("weight-heavy", ns))
    kubectl.apply(backends.mockserver_backend("weight-light", ns))

    kubectl.apply([
        gw.params_configmap(
            "eps-params",
            ns,
            gw.infra_params_hcl(node_ports={"http": ports.EPS_READINESS}),
        ),
        gw.gateway(
            "eps-gw",
            ns,
            [gw.listener("http", 80, "HTTP")],
            infra_params="eps-params",
        ),
        gw.http_route(
            "balanced-route",
            ns,
            [gw.parent_ref("eps-gw")],
            hostnames=[HOSTNAME],
            rules=[
                {"backendRefs": [
                    gw.backend_ref("balanced", BACKEND_PORT),
                ]},
            ],
        ),
        gw.http_route(
            "weighted-route",
            ns,
            [gw.parent_ref("eps-gw")],
            hostnames=["weighted.example.com"],
            rules=[
                {"backendRefs": [
                    gw.backend_ref("weight-heavy", BACKEND_PORT, weight=9),
                    gw.backend_ref("weight-light", BACKEND_PORT, weight=1),
                ]},
            ],
        ),
    ])

    for name in ("balanced", "weight-heavy", "weight-light"):
        kubectl.wait_deployment_ready(name, ns)

    kubectl.wait_condition("gateway", "eps-gw", ns, "Programmed", timeout=180)
    net.wait_http_ok(ports.EPS_READINESS, host=HOSTNAME)

    return ns


def _balanced_pods(ns: str) -> list[str]:
    return [
        pod["metadata"]["name"]
        for pod in kubectl.get("pods", namespace=ns, selector="app=balanced")["items"]
    ]


def _endpoint_ready(ns: str, pod_ip: str) -> bool | None:
    slices = kubectl.get(
        "endpointslices",
        namespace=ns,
        selector="kubernetes.io/service-name=balanced",
    )["items"]

    for slice_ in slices:
        for endpoint in slice_.get("endpoints", []):
            if pod_ip in endpoint.get("addresses", []):
                return endpoint.get("conditions", {}).get("ready")

    return None


def test_round_robin_across_ready_endpoints(stack):
    """
    Spec §8.1/§11: default round_robin spreads across ready endpoints.
    """

    seen = Counter(net.sample_backends(ports.EPS_READINESS, host=HOSTNAME, count=20))
    assert set(seen) == set(_balanced_pods(stack)), \
        f"round robin must reach every ready endpoint, got {dict(seen)}"
    assert min(seen.values()) >= 5, \
        f"distribution too skewed for round robin: {dict(seen)}"


def test_readiness_flip_changes_selection_without_restarts(stack):
    """
    Spec §11/§20.8: EndpointSlice `ready` transitions gate new traffic,
    with no krouter pod restart.
    """

    ns = stack
    dataplane_before = kubectl.pod_restart_counts(kubectl.dataplane_pods())

    pods = kubectl.get("pods", namespace=ns, selector="app=balanced")["items"]
    victim, survivor = pods[0], pods[1]
    victim_name = victim["metadata"]["name"]
    survivor_name = survivor["metadata"]["name"]

    # Flip the victim unready through its MockServer probe expectation.
    backends.set_pod_ready(victim_name, ns, ready=False)
    kubectl.wait_for(
        lambda: _endpoint_ready(ns, victim["status"]["podIP"]) is False,
        timeout=60,
        desc="EndpointSlice reporting the pod unready",
    )

    def only_survivor():
        seen = set(net.sample_backends(ports.EPS_READINESS, host=HOSTNAME, count=10))

        return seen == {survivor_name} or None

    kubectl.wait_for(
        only_survivor,
        timeout=60,
        desc="traffic excluding the unready endpoint",
    )

    # Flip it back: both endpoints must serve again.
    backends.set_pod_ready(victim_name, ns, ready=True)
    kubectl.wait_for(
        lambda: _endpoint_ready(ns, victim["status"]["podIP"]) is True,
        timeout=60,
        desc="EndpointSlice reporting the pod ready again",
    )

    def both_again():
        seen = set(net.sample_backends(ports.EPS_READINESS, host=HOSTNAME, count=20))

        return seen == {victim_name, survivor_name} or None

    kubectl.wait_for(both_again, timeout=60, desc="traffic reaching both endpoints")

    # The whole dance must not have restarted anything (spec §20.8).
    assert kubectl.pod_restart_counts(kubectl.dataplane_pods()) == dataplane_before, \
        "data-plane pods restarted during a readiness transition"


def test_backend_weights_are_applied(stack):
    """
    Spec §11: Gateway API backend weights shape selection (9:1).
    """

    seen = Counter(
        pod.rsplit("-", 2)[0]
        for pod in net.sample_backends(
            ports.EPS_READINESS,
            host="weighted.example.com",
            count=50,
        )
    )

    heavy, light = seen.get("weight-heavy", 0), seen.get("weight-light", 0)
    assert heavy + light == 50
    assert heavy >= 35, f"expected ~45/50 on the heavy backend, got {dict(seen)}"
    assert light >= 1, f"light backend must still receive traffic, got {dict(seen)}"


def test_no_ready_endpoints_yields_unavailable_response(stack):
    """
    Spec §18: no ready endpoints -> conformance-required unavailable
    response, while the connection itself is served.
    """

    ns = stack
    pods = kubectl.get("pods", namespace=ns, selector="app=balanced")["items"]

    for pod in pods:
        backends.set_pod_ready(pod["metadata"]["name"], ns, ready=False)

    try:
        def unavailable():
            resp = net.request(ports.EPS_READINESS, host=HOSTNAME)

            return resp.status_code in (500, 502, 503) or None

        kubectl.wait_for(
            unavailable,
            timeout=60,
            desc="unavailable response with no ready endpoints",
        )

    finally:
        for pod in pods:
            backends.set_pod_ready(pod["metadata"]["name"], ns, ready=True)

    def recovered():
        resp = net.request(ports.EPS_READINESS, host=HOSTNAME)

        return resp.status_code == 200 or None

    kubectl.wait_for(recovered, timeout=60, desc="recovery after readiness returns")
