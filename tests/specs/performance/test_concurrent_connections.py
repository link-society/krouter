"""
The 10,000 concurrent-connection release gate (docs/spec/performance.md, docs/spec/acceptance.md criterion 10).

Each data-plane pod must sustain 10,000 simultaneous established downstream
connections, preserve them across configuration reloads, produce no
proxy-generated disconnects or errors, and survive without restarts.

Run with `task tests:performance`. The load generator runs on the kind docker
network and targets one worker's NodePort directly, so all connections land
on a single data-plane pod (externalTrafficPolicy: Local).
"""

import json
import logging
import re
import subprocess
import threading
import time

from pathlib import Path

import pytest

from e2elib import backends, config, gateway as gw, kubectl, loadgen, net, ports
from e2elib.backends import BACKEND_PORT

log = logging.getLogger("performance")

HOSTNAME = "perf.example.com"
CONNECTIONS = 10_000
HOLD_DURATION_S = 180
RELOAD_AT_S = 60  # reload mid-hold (docs/spec/performance.md: preserved across reloads)

# One request per connection per interval keeps every connection observably
# alive (several requests before and after the reload) while bounding the
# aggregate rate at ~333 req/s: the gate is about held connections, and the
# 4-vCPU CI runner saturates near 1,000 req/s, turning scheduler latency
# into spurious timeouts.
REQUEST_INTERVAL_S = 30


def _route(ns: str, marker: str) -> dict:
    """
    Route variant used to force a new configuration generation mid-run.
    """

    return gw.http_route(
        "perf-route",
        ns,
        [gw.parent_ref("perf-gw")],
        hostnames=[HOSTNAME],
        rules=[
            {
                "filters": [
                    {
                        "type": "RequestHeaderModifier",
                        "requestHeaderModifier": {
                            "set": [
                                {"name": "X-Perf-Generation", "value": marker},
                            ],
                        },
                    },
                ],
                "backendRefs": [
                    gw.backend_ref("perf-backend", BACKEND_PORT),
                ],
            },
        ],
    )


@pytest.fixture(scope="module")
def stack(gateway_class, module_namespace):
    ns = module_namespace
    kubectl.apply(backends.mockserver_backend("perf-backend", ns, replicas=2))

    kubectl.apply([
        gw.params_configmap(
            "perf-params",
            ns,
            gw.infra_params_hcl(node_ports={"http": ports.PERFORMANCE}),
        ),
        gw.gateway(
            "perf-gw",
            ns,
            [gw.listener("http", 80, "HTTP")],
            infra_params="perf-params",
        ),
        _route(ns, "initial"),
    ])

    kubectl.wait_deployment_ready("perf-backend", ns)
    kubectl.wait_condition("gateway", "perf-gw", ns, "Programmed", timeout=180)
    net.wait_http_ok(ports.PERFORMANCE, host=HOSTNAME)

    return ns


@pytest.mark.performance
@pytest.mark.timeout(1800)
def test_10k_concurrent_connections_survive_reload(stack):
    ns = stack
    worker = f"{config.KIND_CLUSTER}-worker"
    node_ip = loadgen.node_internal_ip(worker)
    url = f"http://{node_ip}:{ports.PERFORMANCE}/"

    restarts_before = kubectl.pod_restart_counts(kubectl.dataplane_pods())

    # Record every packet on the NodePort for the whole hold into a pcap
    # (headers only) inside a netshoot container sharing the node's netns:
    # kindest/node has no tcpdump, and FIN-only captures kept hiding
    # whatever precedes a teardown. The pcap lands in the results
    # directory, which CI uploads as an artifact.
    capture_name = f"krouter-perf-capture-{int(time.time())}"
    capture_dir = (Path(__file__).parents[2] / "results" / "performance").resolve()
    capture_dir.mkdir(parents=True, exist_ok=True)
    tcpdump = subprocess.Popen(
        [
            "docker", "run", "--rm",
            "--name", capture_name,
            "--network", f"container:{worker}",
            "-v", f"{capture_dir}:/cap",
            "nicolaka/netshoot:v0.14",
            "timeout", str(HOLD_DURATION_S + 120),
            "tcpdump", "-n", "--immediate-mode",
            "-i", "any", "-s", "128",
            "-Z", "root",
            "-w", "/cap/hold.pcap",
            f"port {ports.PERFORMANCE}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    proc = loadgen.start(
        mode="hold",
        url=url,
        host=HOSTNAME,
        connections=CONNECTIONS,
        duration=f"{HOLD_DURATION_S}s",
        interval=f"{REQUEST_INTERVAL_S}s",
        ramp=500,
    )

    # Publish a new configuration generation while connections are held.
    def reload_config():
        log.info("applying route update while %d connections are held", CONNECTIONS)
        kubectl.apply(_route(ns, "reloaded"))

    timer = threading.Timer(RELOAD_AT_S, reload_config)
    timer.start()

    try:
        result = loadgen.wait(proc, timeout=HOLD_DURATION_S + 600)

    finally:
        timer.cancel()
        # docker stop delivers SIGTERM so tcpdump flushes the pcap; the
        # container removes itself (--rm) and the client process exits.
        subprocess.run(
            ["docker", "stop", capture_name],
            capture_output=True,
            text=True,
        )

        try:
            tcpdump.communicate(timeout=15)

        except subprocess.TimeoutExpired:
            tcpdump.kill()
            tcpdump.communicate()

    log.info(
        "loadgen report: established=%s requests=%s errors=%s disconnects=%s "
        "transport_churn=%s close_demanded=%s p99=%.1fms max=%.1fms",
        result["established"],
        result["requests"],
        result["request_errors"],
        result["disconnects"],
        result["transport_churn"],
        result["close_demanded"],
        result["latency"]["p99_ms"],
        result["latency"]["max_ms"],
    )

    # Diagnostics for any disconnect: when they happen (clustered at the
    # reload vs. scattered) and what the data plane logged, so a failure
    # is attributable from the captured output alone.
    drops = [cell for cell in result["timeline"] if cell.get("disconnects")]
    if drops:
        log.warning(
            "disconnect timeline (reload at t=%ds): %s",
            RELOAD_AT_S,
            json.dumps(drops),
        )

        # Conntrack evidence, straight from the target node: liberal window
        # tracking must be active (tests/config/kind/cluster.yaml) and the
        # stats counters say whether packets were marked invalid or lost
        # races (nonzero invalid/insert_failed/drop indicts conntrack).
        for cmd in (
            "sysctl net.netfilter.nf_conntrack_tcp_be_liberal net.netfilter.nf_conntrack_count net.netfilter.nf_conntrack_max",
            "conntrack -S",
        ):
            probe = subprocess.run(
                ["docker", "exec", worker, "sh", "-c", cmd],
                capture_output=True,
                text=True,
            )
            log.warning(
                "%s @ %s:\n%s%s",
                cmd,
                worker,
                probe.stdout.strip(),
                probe.stderr.strip(),
            )

        # Full per-flow history of every dropped connection, extracted from
        # the pcap: data, ACKs and teardown, not just FIN/RST. The old local
        # port from the reconnect event is the join key.
        for event in result.get("reconnects", []):
            old = event.get("old") or ""
            old_port = old.rsplit(":", 1)[-1]
            if not old_port.isdigit():
                continue

            flow = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "-v", f"{capture_dir}:/cap",
                    "nicolaka/netshoot:v0.14",
                    "tcpdump", "-n", "-tttt", "-r", "/cap/hold.pcap",
                    f"tcp port {old_port}",
                ],
                capture_output=True,
                text=True,
            )
            tail = "\n".join(flow.stdout.splitlines()[-40:])
            log.warning(
                "dead flow %s (reconnected at t=%.1fs), last packets:\n%s%s",
                old,
                event["at_s"],
                tail,
                flow.stderr.strip(),
            )

        for pod in kubectl.dataplane_pods():
            name = pod["metadata"]["name"]
            lines = kubectl.pod_logs(
                name,
                config.SYSTEM_NAMESPACE,
                since=f"{HOLD_DURATION_S + 120}s",
            ).splitlines()
            suspicious = [
                line for line in lines
                if re.search(r"panic|error|refused|reset|EOF", line, re.IGNORECASE)
            ]
            if suspicious:
                log.warning(
                    "dataplane pod %s suspicious log lines (last %d of %d):\n%s",
                    name,
                    len(suspicious[-50:]),
                    len(suspicious),
                    "\n".join(suspicious[-50:]),
                )

    # Release gate (docs/spec/performance.md, docs/spec/acceptance.md criterion 10) — all hard requirements.
    assert result["established"] == CONNECTIONS, (
        f"only {result['established']}/{CONNECTIONS} connections established "
        f"({result['connect_errors']} connect errors)"
    )
    assert result["disconnects"] == 0, (
        f"{result['disconnects']} proxy-generated disconnects during the hold "
        "(connections must survive configuration reloads)"
    )
    assert result["request_errors"] == 0, \
        f"{result['request_errors']} request errors during the hold"
    assert result["non_2xx"] == 0, \
        f"{result['non_2xx']} non-2xx responses during the hold"

    # No data-plane pod may have restarted or become unready.
    assert kubectl.pod_restart_counts(kubectl.dataplane_pods()) == restarts_before, \
        "data-plane pods restarted during the concurrency test"
    kubectl.wait_daemonset_ready(
        config.DATAPLANE_DAEMONSET,
        config.SYSTEM_NAMESPACE,
        timeout=60,
    )

    # Bounded memory (docs/spec/performance.md) is informational here: metrics-server is not
    # part of the kind setup, so sustained-growth analysis belongs to the
    # benchmark harness. Verify the pods are still serving.
    time.sleep(10)
    data = net.request_json(ports.PERFORMANCE, host=HOSTNAME)
    assert data["backend"] == "perf-backend"
