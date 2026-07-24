"""
Session fixtures for the krouter e2e suite.

The suite is black-box: it requires a kind cluster created by
`task k8s:up` with krouter deployed by `task k8s:deploy`, then drives the
installation exclusively through the Kubernetes API and published NodePorts.
"""

import logging

import pytest

from e2elib import config, gateway as gw, kubectl, unique_name

log = logging.getLogger("e2e")


@pytest.fixture(scope="session", autouse=True)
def cluster():
    """
    Fail fast with actionable messages when preconditions are missing.
    """

    try:
        kubectl.kubectl("get", "nodes", timeout=20)

    except Exception as exc:
        pytest.fail(
            f"cluster {config.KUBE_CONTEXT!r} is not reachable "
            f"(run `task k8s:up k8s:deploy`): {exc}"
        )

    crd = kubectl.get_or_none("crd", "gatewayclasses.gateway.networking.k8s.io")
    if crd is None:
        pytest.fail(
            "Gateway API CRDs are not installed "
            "(run `task k8s:crds:install`)"
        )

    try:
        kubectl.wait_deployment_ready(
            config.CONTROLPLANE_DEPLOYMENT,
            config.SYSTEM_NAMESPACE,
        )
        kubectl.wait_daemonset_ready(
            config.DATAPLANE_DAEMONSET,
            config.SYSTEM_NAMESPACE,
        )

    except Exception as exc:
        pytest.fail(f"krouter is not deployed and ready (run `task k8s:deploy`): {exc}")


@pytest.fixture(scope="session")
def gateway_class(cluster) -> str:
    """
    Canonical GatewayClass reconciled by the installation (left in place).
    """

    kubectl.apply(gw.gateway_class(config.GATEWAY_CLASS))
    kubectl.wait_condition(
        "gatewayclass",
        config.GATEWAY_CLASS,
        None,
        "Accepted",
        timeout=60,
    )

    return config.GATEWAY_CLASS


@pytest.fixture
def make_namespace(request):
    """
    Factory creating uniquely-named namespaces, deleted on teardown.
    """

    created: list[str] = []

    def factory(prefix: str = "krouter-test", labels: dict[str, str] | None = None) -> str:
        name = unique_name(prefix)
        kubectl.create_namespace(name, labels)
        created.append(name)
        return name

    yield factory

    for name in created:
        try:
            kubectl.delete_namespace(name)

        except Exception as exc:  # teardown must not mask test results
            log.warning("failed to delete namespace %s: %s", name, exc)


@pytest.fixture
def namespace(make_namespace) -> str:
    return make_namespace()


@pytest.fixture(scope="module")
def module_namespace(cluster):
    """
    One namespace shared by every test of a module, deleted on teardown.
    """

    name = unique_name("krouter-test")
    kubectl.create_namespace(name)

    yield name

    try:
        kubectl.delete_namespace(name)

    except Exception as exc:
        log.warning("failed to delete namespace %s: %s", name, exc)


@pytest.fixture
def cluster_scoped_cleanup():
    """
    Track cluster-scoped objects (e.g. extra GatewayClasses) for teardown.
    """

    objs: list[dict] = []

    def track(obj: dict) -> dict:
        objs.append(obj)
        return obj

    yield track

    for obj in reversed(objs):
        try:
            kubectl.delete(obj, wait=False)

        except Exception as exc:
            log.warning("failed to delete %s: %s", obj["metadata"]["name"], exc)
