"""
Installation contract shared by every test suite.

These values mirror what the static installation manifest (docs/spec/deployment.md) is
expected to provide. They are overridable through environment variables so
the suite can target a differently-configured installation (docs/spec/deployment.md).
"""

import os

# kind cluster / kubectl context.
KIND_CLUSTER = os.environ.get("KROUTER_TEST_KIND_CLUSTER", "krouter-e2e")
KUBE_CONTEXT = os.environ.get("KROUTER_TEST_KUBE_CONTEXT", f"kind-{KIND_CLUSTER}")

# Host address where kind extraPortMappings publish worker NodePorts.
TEST_HOST = os.environ.get("KROUTER_TEST_HOST", "127.0.0.1")

# Installation contract (docs/spec/deployment.md).
SYSTEM_NAMESPACE = os.environ.get("KROUTER_SYSTEM_NAMESPACE", "krouter-system")
CONTROLLER_NAME = os.environ.get("KROUTER_CONTROLLER_NAME", "link-society.com/krouter")
CONTROLPLANE_DEPLOYMENT = "krouter-controlplane"
DATAPLANE_DAEMONSET = "krouter-dataplane"
DATAPLANE_LABEL_SELECTOR = os.environ.get(
    "KROUTER_TEST_DATAPLANE_SELECTOR",
    "app.kubernetes.io/name=krouter,app.kubernetes.io/component=dataplane",
)

# Canonical GatewayClass reconciled by the installation under test.
GATEWAY_CLASS = os.environ.get("KROUTER_TEST_GATEWAY_CLASS", "krouter")

# Management port (docs/spec/deployment.md KROUTER_MANAGEMENT_PORT). Tests first read the
# value from the pod spec env; this is only the fallback.
MANAGEMENT_PORT = int(os.environ.get("KROUTER_MANAGEMENT_PORT", "9090"))

# Internal listener port range (docs/spec/deployment.md): must not overlap the NodePort range.
INTERNAL_PORT_MIN = int(os.environ.get("KROUTER_INTERNAL_PORT_MIN", "10000"))
INTERNAL_PORT_MAX = int(os.environ.get("KROUTER_INTERNAL_PORT_MAX", "29999"))

# kind worker node names -> host port offset for published NodePorts
# (see tests/config/kind/cluster.yaml).
WORKER_HOST_PORT_OFFSETS = {
    f"{KIND_CLUSTER}-worker": 0,
    f"{KIND_CLUSTER}-worker2": 1000,
}
