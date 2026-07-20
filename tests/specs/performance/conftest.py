"""
Session fixtures for the performance gate (reuses the e2e preconditions).
"""

import logging

import pytest

from e2elib import config, gateway as gw, kubectl, unique_name

log = logging.getLogger("performance")


@pytest.fixture(scope="session", autouse=True)
def cluster():
    try:
        kubectl.kubectl("get", "nodes", timeout=20)

    except Exception as exc:
        pytest.fail(
            f"cluster {config.KUBE_CONTEXT!r} is not reachable "
            f"(run `task k8s:up k8s:deploy`): {exc}"
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
    kubectl.apply(gw.gateway_class(config.GATEWAY_CLASS))
    kubectl.wait_condition(
        "gatewayclass",
        config.GATEWAY_CLASS,
        None,
        "Accepted",
        timeout=60,
    )

    return config.GATEWAY_CLASS


@pytest.fixture(scope="module")
def module_namespace(cluster):
    name = unique_name("krouter-perf")
    kubectl.create_namespace(name)

    yield name

    try:
        kubectl.delete_namespace(name)

    except Exception as exc:
        log.warning("failed to delete namespace %s: %s", name, exc)
