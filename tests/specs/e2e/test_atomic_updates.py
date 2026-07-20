"""
Atomic configuration activation (spec §9.2, §10, §15.1, §20.5).

A Gateway update must activate atomically on every healthy data-plane pod:
while a route is switched between backends, traffic answers from the old or
the new configuration and never from a broken in-between state. Generations
are Gateway-scoped, so churning one Gateway must not disturb another.
"""

from __future__ import annotations

import time

import pytest

from e2elib import backends, gateway as gw, kubectl, net, ports
from e2elib.backends import BACKEND_PORT

HOSTNAME = "atomic.example.com"


def _route(ns: str, backend: str) -> dict:
    return gw.http_route(
        "switch-route",
        ns,
        [gw.parent_ref("atomic-gw")],
        hostnames=[HOSTNAME],
        rules=[
            {"backendRefs": [
                gw.backend_ref(backend, BACKEND_PORT),
            ]},
        ],
    )


@pytest.fixture(scope="module")
def stack(gateway_class, module_namespace):
    ns = module_namespace
    kubectl.apply(backends.mockserver_backend("backend-a", ns))
    kubectl.apply(backends.mockserver_backend("backend-b", ns))
    kubectl.apply(backends.mockserver_backend("backend-quiet", ns))

    kubectl.apply([
        gw.params_configmap(
            "atomic-params",
            ns,
            gw.infra_params_hcl(
                node_ports={"http": ports.ATOMIC_UPDATES_A},
            ),
        ),
        gw.gateway(
            "atomic-gw",
            ns,
            [gw.listener("http", 80, "HTTP")],
            infra_params="atomic-params",
        ),
        _route(ns, "backend-a"),

        # Independent Gateway used to verify generation scoping (spec §9.2).
        gw.params_configmap(
            "quiet-params",
            ns,
            gw.infra_params_hcl(
                node_ports={"http": ports.ATOMIC_UPDATES_B},
            ),
        ),
        gw.gateway(
            "quiet-gw",
            ns,
            [gw.listener("http", 80, "HTTP")],
            infra_params="quiet-params",
        ),
        gw.http_route(
            "quiet-route",
            ns,
            [gw.parent_ref("quiet-gw")],
            hostnames=[HOSTNAME],
            rules=[
                {"backendRefs": [
                    gw.backend_ref("backend-quiet", BACKEND_PORT),
                ]},
            ],
        ),
    ])

    for name in ("backend-a", "backend-b", "backend-quiet"):
        kubectl.wait_deployment_ready(name, ns)

    kubectl.wait_condition("gateway", "atomic-gw", ns, "Programmed", timeout=180)
    kubectl.wait_condition("gateway", "quiet-gw", ns, "Programmed", timeout=180)
    net.wait_http_ok(ports.ATOMIC_UPDATES_A, host=HOSTNAME)
    net.wait_http_ok(ports.ATOMIC_UPDATES_B, host=HOSTNAME)

    yield ns

    # Leave the module with the route pointing at backend-a again.
    kubectl.apply(_route(ns, "backend-a"))


def test_route_switch_is_atomic_and_lossless(stack):
    """Spec §20.5: the update activates atomically on every healthy pod."""
    ns = stack

    with net.TrafficSampler(ports.ATOMIC_UPDATES_A, host=HOSTNAME) as sampler:
        time.sleep(2)  # sample the old configuration
        kubectl.apply(_route(ns, "backend-b"))

        # Wait until the switch is observed, then keep sampling a little.
        kubectl.wait_for(
            lambda: any(pod.startswith("backend-b") for pod in sampler.backends),
            timeout=120,
            desc="traffic from backend-b after route update",
        )
        time.sleep(2)

    assert sampler.errors == [], f"connection errors during switchover: {sampler.errors[:5]}"
    bad = [s for s in sampler.statuses if s != 200]
    assert bad == [], f"non-200 responses during switchover: {bad[:10]}"

    served = {pod.rsplit("-", 2)[0] for pod in sampler.backends}
    assert served <= {"backend-a", "backend-b"}, \
        f"responses from unexpected backends: {served}"
    assert sampler.backends[-1].startswith("backend-b")

    # Convergence: every request eventually answers from the new config.
    def fully_switched():
        return all(
            pod.startswith("backend-b")
            for pod in net.sample_backends(
                ports.ATOMIC_UPDATES_A,
                host=HOSTNAME,
                count=10,
            )
        )

    kubectl.wait_for(fully_switched, timeout=60, desc="full convergence to backend-b")


def test_updating_one_gateway_does_not_disturb_another(stack):
    """
    Spec §9.2: generations are Gateway-scoped — churning atomic-gw must not
    reload or invalidate quiet-gw.
    """

    ns = stack

    with net.TrafficSampler(ports.ATOMIC_UPDATES_B, host=HOSTNAME) as sampler:
        for backend in ("backend-a", "backend-b", "backend-a", "backend-b"):
            kubectl.apply(_route(ns, backend))
            time.sleep(3)

    assert sampler.errors == [], \
        f"quiet gateway saw connection errors during churn: {sampler.errors[:5]}"
    bad = [s for s in sampler.statuses if s != 200]
    assert bad == [], f"quiet gateway saw non-200 responses: {bad[:10]}"
    served = {pod.rsplit("-", 2)[0] for pod in sampler.backends}
    assert served == {"backend-quiet"}, f"quiet gateway leaked to: {served}"


def test_every_dataplane_pod_acknowledges_the_generation(stack):
    """
    Spec §15.1: Programmed=True requires every healthy data-plane pod to
    report the desired generation as applied.
    """

    ns = stack
    gateway = kubectl.get("gateway", "atomic-gw", ns)
    uid = gateway["metadata"]["uid"]

    kubectl.wait_for(
        lambda: net.all_dataplane_pods_acked(uid),
        timeout=120,
        desc="all data-plane pods acknowledging the generation",
    )

    # The Programmed condition must reflect the acknowledged generation.
    gateway = kubectl.get("gateway", "atomic-gw", ns)
    cond = kubectl.find_condition(gateway, "Programmed")
    assert cond and cond["status"] == "True"
    assert cond["observedGeneration"] == gateway["metadata"]["generation"], \
        "Programmed must reference the current Gateway generation (spec §15)"
