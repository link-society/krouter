"""
Gateway API status and conditions (spec §3, §5, §8, §15, §18, §20.9).

The control plane is the sole status writer and must publish accurate
conditions, reasons and observedGeneration values for every owned resource —
and must leave foreign resources alone.
"""

import time

import pytest

from e2elib import backends, certs, config, gateway as gw, kubectl, net, ports, unique_name
from e2elib.backends import BACKEND_PORT

HOSTNAME = "status.example.com"


@pytest.fixture(scope="module")
def stack(gateway_class, module_namespace):
    ns = module_namespace
    kubectl.apply(backends.mockserver_backend("echo", ns))

    kubectl.apply([
        gw.params_configmap(
            "st-params",
            ns,
            gw.infra_params_hcl(node_ports={"http": ports.STATUS}),
        ),
        gw.gateway(
            "status-gw",
            ns,
            [gw.listener("http", 80, "HTTP")],
            infra_params="st-params",
        ),
        gw.http_route(
            "status-route",
            ns,
            [gw.parent_ref("status-gw")],
            hostnames=[HOSTNAME],
            rules=[
                {"backendRefs": [
                    gw.backend_ref("echo", BACKEND_PORT),
                ]},
            ],
        ),
    ])

    kubectl.wait_deployment_ready("echo", ns)
    kubectl.wait_condition("gateway", "status-gw", ns, "Programmed", timeout=180)
    kubectl.wait_route_parent_condition("status-route", ns, "Accepted")

    return ns


def test_gatewayclass_accepted_and_supported_version(gateway_class):
    """
    Spec §3/§15: GatewayClass Accepted and SupportedVersion published
    against the installed CRD bundle version.
    """

    obj = kubectl.get("gatewayclass", gateway_class)

    accepted = kubectl.find_condition(obj, "Accepted")
    assert accepted and accepted["status"] == "True"
    assert accepted["observedGeneration"] == obj["metadata"]["generation"]

    supported = kubectl.find_condition(obj, "SupportedVersion")
    assert supported is not None, "SupportedVersion condition must be published"
    assert supported["status"] == "True", \
        "v1.5.1 Standard CRDs are installed; SupportedVersion must be True"


def test_foreign_gatewayclass_is_ignored(cluster, cluster_scoped_cleanup):
    """
    Spec §5: only classes matching KROUTER_CONTROLLER_NAME are reconciled.
    """

    name = unique_name("foreign-class")
    cluster_scoped_cleanup(
        gw.gateway_class(name, controller_name="example.com/other-controller"),
    )
    kubectl.apply(gw.gateway_class(name, controller_name="example.com/other-controller"))

    time.sleep(10)  # give a misbehaving controller time to touch it

    obj = kubectl.get("gatewayclass", name)
    accepted = kubectl.find_condition(obj, "Accepted")

    # The CRD default (Unknown/Waiting) must still be in place.
    assert accepted is None or accepted["status"] == "Unknown", \
        "krouter must not reconcile GatewayClasses owned by other controllers"


def test_gateway_conditions_and_listener_status(stack):
    """
    Spec §15: Gateway Accepted/Programmed with correct observedGeneration,
    per-listener conditions and attachedRoutes counts.
    """

    obj = kubectl.get("gateway", "status-gw", stack)
    generation = obj["metadata"]["generation"]

    for cond_type in ("Accepted", "Programmed"):
        cond = kubectl.find_condition(obj, cond_type)
        assert cond and cond["status"] == "True", f"{cond_type} must be True"
        assert cond["observedGeneration"] == generation
        assert cond.get("reason"), "conditions must carry a reason"
        assert cond.get("lastTransitionTime"), "conditions must carry a timestamp"

    listeners = obj["status"].get("listeners", [])
    assert len(listeners) == 1

    http_listener = listeners[0]
    assert http_listener["name"] == "http"
    assert http_listener["attachedRoutes"] == 1

    kinds = {k["kind"] for k in http_listener.get("supportedKinds", [])}
    assert "HTTPRoute" in kinds

    for cond_type in ("Accepted", "Programmed", "ResolvedRefs"):
        cond = [c for c in http_listener["conditions"] if c["type"] == cond_type]
        assert cond and cond[0]["status"] == "True", \
            f"listener condition {cond_type} must be True"

    addresses = obj["status"].get("addresses", [])
    assert addresses, "a programmed Gateway must publish addresses (spec §15)"


def test_route_parent_status(stack):
    """
    Spec §15: parents[] entry with our controllerName and required conditions.
    """

    route = kubectl.get("httproute", "status-route", stack)
    parents = kubectl.route_parent_status(route)
    assert len(parents) == 1, "exactly one parents[] entry for the single parentRef"

    parent = parents[0]
    assert parent["controllerName"] == config.CONTROLLER_NAME
    assert parent["parentRef"]["name"] == "status-gw"

    for cond_type in ("Accepted", "ResolvedRefs"):
        cond = [c for c in parent["conditions"] if c["type"] == cond_type]
        assert cond and cond[0]["status"] == "True"
        assert cond[0]["observedGeneration"] == route["metadata"]["generation"]


def test_invalid_infrastructure_parameters(gateway_class, namespace):
    """
    Spec §8: missing or invalid parameter ConfigMaps produce the
    InvalidParameters reason and never crash the controller.
    """

    ns = namespace
    kubectl.apply(gw.gateway(
        "bad-params-gw",
        ns,
        [gw.listener("http", 80, "HTTP")],
        infra_params="does-not-exist",
    ))

    def has_invalid_parameters():
        obj = kubectl.get_or_none("gateway", "bad-params-gw", ns)
        if not obj:
            return None

        for cond in obj.get("status", {}).get("conditions", []):
            if cond.get("reason") == "InvalidParameters" and cond["status"] == "False":
                return cond

        return None

    kubectl.wait_for(
        has_invalid_parameters,
        timeout=120,
        desc="InvalidParameters on missing parameters ConfigMap",
    )

    # Unknown fields must be rejected too (spec §8: reject unknown fields).
    kubectl.apply(gw.params_configmap("bad-hcl", ns, 'version = 1\nbogus_field = "boom"\n'))
    kubectl.apply(gw.gateway(
        "bad-hcl-gw",
        ns,
        [gw.listener("http", 80, "HTTP")],
        infra_params="bad-hcl",
    ))

    def hcl_rejected():
        obj = kubectl.get_or_none("gateway", "bad-hcl-gw", ns)
        if not obj:
            return None

        for cond in obj.get("status", {}).get("conditions", []):
            if cond.get("reason") == "InvalidParameters" and cond["status"] == "False":
                return cond

        return None

    kubectl.wait_for(
        hcl_rejected,
        timeout=120,
        desc="InvalidParameters on unknown HCL field",
    )

    # The control plane must still be alive and reconciling.
    kubectl.wait_deployment_ready(
        config.CONTROLPLANE_DEPLOYMENT,
        config.SYSTEM_NAMESPACE,
        timeout=30,
    )


def test_missing_tls_secret_sets_resolved_refs_false(gateway_class, namespace):
    """
    Spec §18: missing TLS material -> ResolvedRefs=False, safe behavior,
    and recovery once the secret appears.
    """

    ns = namespace
    kubectl.apply(gw.gateway(
        "tls-gw",
        ns,
        [
            gw.listener(
                "https",
                443,
                "HTTPS",
                hostname="tls.example.com",
                tls_secret="missing-cert",
            ),
        ],
    ))

    def listener_ref_failed():
        obj = kubectl.get_or_none("gateway", "tls-gw", ns)
        if not obj:
            return None

        for listener_status in obj.get("status", {}).get("listeners", []):
            for cond in listener_status.get("conditions", []):
                if (
                    cond["type"] == "ResolvedRefs"
                    and cond["status"] == "False"
                    and cond["reason"] == "InvalidCertificateRef"
                ):
                    return cond

        return None

    kubectl.wait_for(
        listener_ref_failed,
        timeout=120,
        desc="ResolvedRefs=False for the missing certificate",
    )

    # Recovery: create the secret, the listener must resolve.
    certs.apply_tls_secret(certs.make_ca(), "missing-cert", ns, "tls.example.com")

    def listener_ref_ok():
        obj = kubectl.get_or_none("gateway", "tls-gw", ns)
        if not obj:
            return None

        for listener_status in obj.get("status", {}).get("listeners", []):
            for cond in listener_status.get("conditions", []):
                if cond["type"] == "ResolvedRefs" and cond["status"] == "True":
                    return cond

        return None

    kubectl.wait_for(
        listener_ref_ok,
        timeout=120,
        desc="ResolvedRefs=True after the secret is created",
    )
