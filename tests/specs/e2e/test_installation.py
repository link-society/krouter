"""
Installation contract tests (docs/spec/deployment.md, docs/spec/security.md, docs/spec/observability.md, docs/spec/acceptance.md criterion 12).

The installation must consist of the standard manifest only: one namespace,
one single-replica control-plane Deployment, one shared data-plane DaemonSet,
one image, no krouter CRDs.
"""

import httpx
import pytest

from e2elib import config, kubectl


@pytest.fixture(scope="module")
def controlplane_pods(cluster) -> list[dict]:
    pods = kubectl.get(
        "pods",
        namespace=config.SYSTEM_NAMESPACE,
        selector="app.kubernetes.io/name=krouter,app.kubernetes.io/component=controlplane",
    )["items"]

    if not pods:
        pods = [
            pod for pod in kubectl.get("pods", namespace=config.SYSTEM_NAMESPACE)["items"]
            if pod["metadata"]["name"].startswith(config.CONTROLPLANE_DEPLOYMENT)
        ]

    assert pods, "no control-plane pods found"

    return pods


@pytest.fixture(scope="module")
def dataplane_pods(cluster) -> list[dict]:
    pods = kubectl.dataplane_pods()
    assert pods, "no data-plane pods found"

    return pods


def test_singleton_controlplane_deployment(cluster):
    """
    docs/spec/deployment.md, docs/spec/architecture.md: single-replica Deployment, no leader election needed.
    """

    deploy = kubectl.get(
        "deployment",
        config.CONTROLPLANE_DEPLOYMENT,
        config.SYSTEM_NAMESPACE,
    )
    assert deploy["spec"]["replicas"] == 1
    assert deploy["status"].get("readyReplicas") == 1


def test_shared_dataplane_daemonset(cluster):
    """
    docs/spec/deployment.md, docs/spec/architecture.md: one shared DaemonSet serving every Gateway.
    """

    ds = kubectl.get("daemonset", config.DATAPLANE_DAEMONSET, config.SYSTEM_NAMESPACE)
    desired = ds["status"]["desiredNumberScheduled"]
    assert desired >= 2, "expected the DaemonSet on every worker node"
    assert ds["status"].get("numberReady") == desired


def test_no_krouter_crds(cluster):
    """
    docs/spec/overview.md: krouter defines no custom resources.
    """

    crds = kubectl.get("crd")["items"]
    offenders = [
        crd["metadata"]["name"] for crd in crds
        if "krouter" in crd["metadata"]["name"]
        or "krouter" in crd["spec"]["group"]
    ]
    assert offenders == [], f"krouter must not install CRDs, found: {offenders}"


def test_single_image_mode_selected_by_env(controlplane_pods, dataplane_pods):
    """
    docs/spec/overview.md.8, docs/spec/deployment.md: one image for both roles, selected via KROUTER_MODE.
    """

    cp_images = {c["image"] for pod in controlplane_pods for c in pod["spec"]["containers"]}
    dp_images = {c["image"] for pod in dataplane_pods for c in pod["spec"]["containers"]}
    assert cp_images == dp_images, "control plane and data plane must share one image"

    for pod in controlplane_pods:
        assert kubectl.container_env(pod, "KROUTER_MODE") == "controlplane"

    for pod in dataplane_pods:
        assert kubectl.container_env(pod, "KROUTER_MODE") == "dataplane"


def test_security_context(controlplane_pods, dataplane_pods):
    """
    docs/spec/security.md: non-root, read-only rootfs, no privilege escalation, dropped
    capabilities, default seccomp profile.
    """

    for pod in controlplane_pods + dataplane_pods:
        name = pod["metadata"]["name"]
        pod_sc = pod["spec"].get("securityContext", {})

        for container in pod["spec"]["containers"]:
            sc = container.get("securityContext", {})

            run_as_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
            assert run_as_non_root is True, f"{name}: must run as non-root"

            assert sc.get("readOnlyRootFilesystem") is True, \
                f"{name}: must use a read-only root filesystem"
            assert sc.get("allowPrivilegeEscalation") is False, \
                f"{name}: must disallow privilege escalation"
            assert sc.get("capabilities", {}).get("drop") == ["ALL"], \
                f"{name}: must drop all capabilities"

            seccomp = sc.get("seccompProfile") or pod_sc.get("seccompProfile") or {}
            assert seccomp.get("type") == "RuntimeDefault", \
                f"{name}: must use the default seccomp profile"


def test_management_endpoints(controlplane_pods, dataplane_pods):
    """
    docs/spec/observability.md: /livez, /readyz and /metrics on the management port.
    """

    for pod in controlplane_pods + dataplane_pods:
        name = pod["metadata"]["name"]
        port = kubectl.management_port(pod)

        with kubectl.port_forward(f"pod/{name}", port, config.SYSTEM_NAMESPACE) as local:
            with httpx.Client(base_url=f"http://127.0.0.1:{local}", timeout=10) as client:
                for path in ("/livez", "/readyz", "/metrics"):
                    resp = client.get(path)
                    assert resp.status_code == 200, \
                        f"{name}: GET {path} returned {resp.status_code}"


def test_dataplane_readiness_reports_generations(dataplane_pods):
    """
    docs/spec/status.md, docs/spec/observability.md: the data-plane readiness body carries per-Gateway
    desired/applied generation acknowledgement.
    """

    for pod in dataplane_pods:
        name = pod["metadata"]["name"]
        port = kubectl.management_port(pod)

        with kubectl.port_forward(f"pod/{name}", port, config.SYSTEM_NAMESPACE) as local:
            with httpx.Client(base_url=f"http://127.0.0.1:{local}", timeout=10) as client:
                body = client.get("/readyz").json()

        assert body.get("ready") is True, f"{name}: readiness body must report ready"
        assert isinstance(body.get("gateways"), dict), \
            f"{name}: readiness body must expose the per-gateway map"


def test_dataplane_uses_internal_ports_not_host_ports(dataplane_pods):
    """
    docs/spec/architecture.md: dynamically allocated internal ports, no host ports.
    """

    for pod in dataplane_pods:
        for container in pod["spec"]["containers"]:
            for port in container.get("ports", []):
                assert "hostPort" not in port, \
                    f"{pod['metadata']['name']}: data plane must not use host ports"
