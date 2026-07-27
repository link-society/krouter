"""
Static NodePort assignments for the test suites.

Every NodePort used by a test is requested deterministically through Gateway
infrastructure parameters (docs/spec/parameters.md) and must be published by
tests/config/kind/cluster.yaml. Keeping the registry central prevents port
collisions between test modules sharing the session cluster.

Published window: 30080-30105 and 30443-30446.
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

LAST_VALID = 30093
TCP_ROUTES = 30094
TLS_ROUTES = 30095
GRPC_ROUTES = 30096
UDP_ROUTES = 30097  # published as UDP by the kind cluster config

# demo topology (tests/config/mocks/manifest.yml): 30098 (http), 30099 (tcp),
# 30100 (tls) — held while the demo is deployed, do not reuse in tests

WEBSOCKET = 30101
EXTENSIONS_RATELIMIT = 30102
EXTENSIONS_WAF = 30103
GOTESTWAF = 30104  # standing WAF target (tests/config/waf/manifest.yml)
CLIENT_IP = 30105

# TLS listeners
PROTOCOLS_HTTPS = 30443
CONN_LIFECYCLE_TLS = 30444
CROSS_NAMESPACE_TLS = 30445
WEBSOCKET_TLS = 30446


def host_port(node_port: int, worker: int = 1) -> int:
    """
    Host port publishing `node_port` for the given kind worker (1-based).
    """

    offsets = sorted(config.WORKER_HOST_PORT_OFFSETS.values())

    return node_port + offsets[worker - 1]
