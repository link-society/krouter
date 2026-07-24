"""
Driver for the Go load generator (tests/src/loadgen).

The generator runs inside a golang container attached to the kind docker
network, so it reaches worker NodePorts directly (no host docker-proxy in the
path — required for 10,000 real concurrent connections and honest latency).
"""

import json
import logging
import subprocess

from pathlib import Path

from e2elib import kubectl

log = logging.getLogger("e2elib.loadgen")

GOLANG_IMAGE = "golang:1.26"
REPO_ROOT = Path(__file__).resolve().parents[3]


def node_internal_ip(node_name: str) -> str:
    node = kubectl.get("node", node_name)
    for addr in node["status"]["addresses"]:
        if addr["type"] == "InternalIP":
            return addr["address"]

    raise AssertionError(f"no InternalIP for node {node_name}")


def start(
    mode: str,
    url: str,
    connections: int,
    duration: str,
    host: str | None = None,
    interval: str = "5s",
    insecure: bool = False,
    ramp: int = 500,
) -> subprocess.Popen:
    """
    Start loadgen in a container on the kind network; returns the process.
    """

    args = [
        "docker", "run", "--rm",
        "--network", "kind",
        "--ulimit", "nofile=131072:131072",
        "-v", f"{REPO_ROOT}:/work", "-w", "/work",
        "-v", "krouter-go-mod:/go/pkg/mod",
        "-v", "krouter-go-cache:/root/.cache/go-build",
        GOLANG_IMAGE,
        "go", "run", "./tests/src/loadgen",
        "-mode", mode,
        "-url", url,
        "-connections", str(connections),
        "-duration", duration,
        "-interval", interval,
        "-ramp", str(ramp),
    ]

    if host:
        args += ["-host", host]

    if insecure:
        args += ["-insecure"]

    log.info("starting loadgen: %s", " ".join(args))

    return subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def wait(proc: subprocess.Popen, timeout: int) -> dict:
    """
    Wait for loadgen and parse its JSON report from stdout.
    """

    stdout, stderr = proc.communicate(timeout=timeout)
    if proc.returncode != 0:
        raise AssertionError(
            f"loadgen exited with {proc.returncode}\nstderr: {stderr[-2000:]}"
        )

    for line in stderr.splitlines():
        if "close-demanding" in line:
            log.warning("%s", line)

    try:
        return json.loads(stdout)

    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"loadgen produced invalid JSON: {exc}\n"
            f"stdout: {stdout[:2000]}\nstderr: {stderr[-2000:]}"
        ) from exc


def run(
    mode: str,
    url: str,
    connections: int,
    duration: str,
    timeout: int = 900,
    **kwargs,
) -> dict:
    return wait(start(mode, url, connections, duration, **kwargs), timeout=timeout)
