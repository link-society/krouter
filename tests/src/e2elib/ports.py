"""
Static NodePort assignments for the test suites.

Every NodePort used by a test is requested deterministically through Gateway
infrastructure parameters (spec §8.2) and must be published by
tests/config/kind/cluster.yaml. Keeping the registry central prevents port
collisions between test modules sharing the session cluster.

Published window: 30080-30095 and 30443-30445.
"""

from e2elib import config

# e2e suite
PROTOCOLS_HTTP = 30080
MULTI_GW_A = 30081
MULTI_GW_B = 30082
CROSS_NAMESPACE = 30083
ATOMIC_UPDATES_A = 30084
ATOMIC_UPDATES_B = 30085
CONN_LIFECYCLE = 30086
EPS_READINESS = 30087
STATUS = 30088

# performance / benchmark suites
PERFORMANCE = 30089
BENCH_KROUTER = 30090
BENCH_NGINX = 30091
BENCH_TRAEFIK = 30092

# spares: 30093-30095
LAST_VALID = 30093

# TLS listeners
PROTOCOLS_HTTPS = 30443
CONN_LIFECYCLE_TLS = 30444
CROSS_NAMESPACE_TLS = 30445


def host_port(node_port: int, worker: int = 1) -> int:
    """
    Host port publishing `node_port` for the given kind worker (1-based).
    """

    offsets = sorted(config.WORKER_HOST_PORT_OFFSETS.values())

    return node_port + offsets[worker - 1]
