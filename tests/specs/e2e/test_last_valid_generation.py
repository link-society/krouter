"""
Last-valid-generation behavior (docs/spec/configuration.md, docs/spec/failure-modes.md, docs/spec/acceptance.md criterion 6).

Two distinct failure modes are covered:

1. Invalid user configuration: a route referencing a missing backend is
   excluded from the next valid generation and reported through status,
   while previously accepted routes keep serving.

2. Data-plane load failure: the mutable manifest ConfigMap (the commit
   marker, docs/spec/configuration.md) is corrupted. Data-plane pods must keep serving the
   last valid generation, and the control plane must repair its generated
   state idempotently (docs/spec/failure-modes.md "generated resource manually deleted /
   recreate idempotently").
"""

import time

import pytest

from e2elib import backends, config, gateway as gw, kubectl, net, ports
from e2elib.backends import BACKEND_PORT

HOSTNAME = "lastvalid.example.com"


@pytest.fixture(scope="module")
def stack(gateway_class, module_namespace):
    ns = module_namespace
    kubectl.apply(backends.mockserver_backend("good-backend", ns))

    kubectl.apply([
        gw.params_configmap(
            "lv-params",
            ns,
            gw.infra_params_hcl(node_ports={"http": ports.LAST_VALID}),
        ),
        gw.gateway(
            "lv-gw",
            ns,
            [gw.listener("http", 80, "HTTP")],
            infra_params="lv-params",
        ),
        gw.http_route(
            "good-route",
            ns,
            [gw.parent_ref("lv-gw")],
            hostnames=[HOSTNAME],
            rules=[
                {"backendRefs": [
                    gw.backend_ref("good-backend", BACKEND_PORT),
                ]},
            ],
        ),
    ])

    kubectl.wait_deployment_ready("good-backend", ns)
    kubectl.wait_condition("gateway", "lv-gw", ns, "Programmed", timeout=180)
    net.wait_http_ok(ports.LAST_VALID, host=HOSTNAME)

    return ns


def test_invalid_route_is_excluded_not_served_stale(stack):
    """
    docs/spec/configuration.md: rejected routes get negative conditions and are excluded
    from the next valid generation; accepted routes keep serving.
    """

    ns = stack
    kubectl.apply(gw.http_route(
        "broken-route",
        ns,
        [gw.parent_ref("lv-gw")],
        hostnames=["broken.example.com"],
        rules=[
            {"backendRefs": [
                gw.backend_ref("no-such-service", BACKEND_PORT),
            ]},
        ],
    ))

    cond = kubectl.wait_route_parent_condition(
        "broken-route",
        ns,
        "ResolvedRefs",
        status="False",
    )
    assert cond["reason"] == "BackendNotFound"

    # Gateway API requires 500 for a rule whose backend cannot be resolved.
    def broken_answers_500():
        resp = net.request(ports.LAST_VALID, host="broken.example.com")

        return resp.status_code == 500 or None

    kubectl.wait_for(
        broken_answers_500,
        timeout=60,
        desc="500 for the rejected route",
    )

    # The healthy route is unaffected.
    data = net.request_json(ports.LAST_VALID, host=HOSTNAME)
    assert data["backend"] == "good-backend"

    kubectl.kubectl("delete", "httproute", "broken-route", "-n", ns, "--ignore-not-found")


def _gateway_configmaps(gateway_uid: str) -> list[dict]:
    """
    Generated ConfigMaps for a Gateway, discovered without relying on exact
    label keys (docs/spec/configuration.md only fixes their semantics, not their names):
    every generated object must carry the Gateway UID in its labels.
    """

    out = []
    for cm in kubectl.get("configmaps", namespace=config.SYSTEM_NAMESPACE)["items"]:
        labels = cm["metadata"].get("labels", {})
        if gateway_uid in labels.values():
            out.append(cm)

    return out


def test_corrupted_manifest_keeps_last_valid_generation_serving(stack):
    """
    docs/spec/configuration.md, docs/spec/failure-modes.md, docs/spec/acceptance.md criterion 6: a generation the data plane cannot load leaves the
    last valid generation serving; the control plane repairs generated state.
    """

    ns = stack
    gateway = kubectl.get("gateway", "lv-gw", ns)
    uid = gateway["metadata"]["uid"]

    generated = _gateway_configmaps(uid)
    assert generated, (
        "no generated ConfigMaps found for the Gateway in "
        f"{config.SYSTEM_NAMESPACE}; generated objects must be labelled with "
        "the Gateway UID (docs/spec/configuration.md)"
    )

    # The manifest/commit-marker is the mutable ConfigMap (docs/spec/configuration.md: all
    # per-generation objects are immutable).
    mutable = [cm for cm in generated if not cm.get("immutable", False)]
    assert mutable, "expected a mutable manifest ConfigMap (docs/spec/configuration.md)"

    manifest = mutable[0]["metadata"]["name"]

    with net.TrafficSampler(ports.LAST_VALID, host=HOSTNAME) as sampler:
        # Corrupt the commit marker so the desired generation cannot load.
        kubectl.kubectl(
            "patch", "configmap", manifest,
            "-n", config.SYSTEM_NAMESPACE,
            "--type", "merge",
            "-p", '{"data": {"krouter-test-corruption": "not a valid manifest"}}',
        )
        time.sleep(15)  # give the data plane time to observe the bad state

    # Traffic must never have been interrupted (last valid generation).
    assert sampler.errors == [], \
        f"traffic interrupted after manifest corruption: {sampler.errors[:5]}"

    bad = [s for s in sampler.statuses if s != 200]
    assert bad == [], f"non-200 responses after manifest corruption: {bad[:10]}"

    # Idempotent reconciliation must converge back to a fully acknowledged
    # generation (repaired manifest), and readiness must have stayed true.
    kubectl.wait_for(
        lambda: net.all_dataplane_pods_acked(uid),
        timeout=180,
        desc="data plane converging back to an acked generation",
    )

    data = net.request_json(ports.LAST_VALID, host=HOSTNAME)
    assert data["backend"] == "good-backend"
