#!/usr/bin/env python3
"""
Comparative benchmark runner: krouter vs NGINX Gateway Fabric vs Traefik
(docs/spec/performance.md, docs/spec/acceptance.md criterion 11).

Usage (via task):

    task tests:bench -- krouter
    task tests:bench:all        # krouter nginx traefik
    python run.py nginx --install   # also run the pinned install commands

Per implementation and scenario it reports successful requests per second,
p50/p95/p99 latency, error and disconnect rate, CPU and memory of the proxy
pods, and errors observed in the reload window. Configuration and manifests
live in tests/config/benchmark/; results are written to
tests/results/benchmark/ and printed as a comparison table.
"""

import argparse
import datetime
import json
import statistics
import subprocess
import sys
import threading
import time

from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parents[2]
CONFIG_DIR = TESTS_DIR / "config" / "benchmark"
RESULTS_DIR = TESTS_DIR / "results" / "benchmark"
sys.path.insert(0, str(TESTS_DIR / "src"))

import yaml  # noqa: E402

from e2elib import config, kubectl, loadgen  # noqa: E402


def sh(command: str, check: bool = True) -> subprocess.CompletedProcess:
    print(f"+ {command}")

    return subprocess.run(command, shell=True, check=check, text=True, capture_output=False)


def retry(fn, timeout: float, interval: float = 5, desc: str = "step"):
    deadline = time.monotonic() + timeout

    while True:
        try:
            return fn()

        except Exception as exc:
            if time.monotonic() >= deadline:
                raise RuntimeError(f"{desc} did not succeed within {timeout}s") from exc

            print(f"  ({desc} not ready: {exc}; retrying)")
            time.sleep(interval)


class TopSampler:
    """
    Samples `kubectl top pods` for the proxy pods during a run.

    Requires metrics-server; when unavailable, CPU/memory are reported null.
    """

    def __init__(self, namespace: str, selector: str):
        self.namespace = namespace
        self.selector = selector
        self.cpu_m: list[int] = []
        self.mem_mi: list[int] = []
        self.available = self._probe()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _probe(self) -> bool:
        res = kubectl.kubectl(
            "top", "pods",
            "-n", self.namespace,
            "-l", self.selector,
            "--no-headers",
            check=False,
        )

        return res.returncode == 0

    def _sample(self):
        res = kubectl.kubectl(
            "top", "pods",
            "-n", self.namespace,
            "-l", self.selector,
            "--no-headers",
            check=False,
        )
        if res.returncode != 0:
            return

        cpu = mem = 0
        for line in res.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 3:
                cpu += int(parts[1].rstrip("m") or 0)
                mem += int(parts[2].rstrip("Mi") or 0)

        self.cpu_m.append(cpu)
        self.mem_mi.append(mem)

    def _run(self):
        while not self._stop.is_set():
            self._sample()
            self._stop.wait(5)

    def __enter__(self):
        if self.available:
            self._thread.start()
        else:
            print("  (metrics-server unavailable: CPU/memory not collected)")

        return self

    def __exit__(self, *exc_info):
        self._stop.set()

        if self.available:
            self._thread.join(timeout=10)

    def summary(self) -> dict:
        if not self.cpu_m:
            return {
                "cpu_milli_mean": None,
                "cpu_milli_peak": None,
                "memory_mi_mean": None,
                "memory_mi_peak": None,
            }

        return {
            "cpu_milli_mean": round(statistics.mean(self.cpu_m)),
            "cpu_milli_peak": max(self.cpu_m),
            "memory_mi_mean": round(statistics.mean(self.mem_mi)),
            "memory_mi_peak": max(self.mem_mi),
        }


def deploy(name: str, impl: dict, install: bool, hostname: str):
    if install and impl["install"]:
        for command in impl["install"]:
            sh(command)

    ns = impl["namespace"]
    kubectl.create_namespace(ns)
    kubectl.kubectl("apply", "-n", ns, "-f", str(CONFIG_DIR / "manifests/backend.yaml"))

    for manifest in impl["manifests"]:
        kubectl.kubectl("apply", "-n", ns, "-f", str(CONFIG_DIR / manifest))

    kubectl.kubectl("apply", "-n", ns, "-f", str(CONFIG_DIR / "manifests/route.yaml"))

    for command in impl["expose"]:
        retry(lambda c=command: sh(c), timeout=180, desc=f"expose {name}")

    kubectl.wait_deployment_ready("bench-backend", ns, timeout=180)

    # Traffic readiness through the published host port.
    def probe():
        import httpx

        resp = httpx.get(
            f"http://{config.TEST_HOST}:{impl['node_port']}/",
            headers={"Host": hostname},
            timeout=5,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"status {resp.status_code}")

    retry(probe, timeout=300, desc=f"{name} gateway serving")


def measure(name: str, impl: dict, scenario_name: str, scenario: dict, hostname: str) -> dict:
    ns = impl["namespace"]
    worker = f"{config.KIND_CLUSTER}-worker"
    url = f"http://{loadgen.node_internal_ip(worker)}:{impl['node_port']}/"

    print(f"[{name}] warmup {scenario['warmup_seconds']}s")
    loadgen.run(
        "load",
        url,
        connections=scenario["connections"],
        duration=f"{scenario['warmup_seconds']}s",
        host=hostname,
        timeout=scenario["warmup_seconds"] + 300,
    )

    print(
        f"[{name}] measuring {scenario['duration_seconds']}s "
        f"with {scenario['connections']} connections"
    )
    reload_at = scenario["reload_at_seconds"]

    def apply_reload():
        print(f"[{name}] applying route reload at T+{reload_at}s")
        kubectl.kubectl("apply", "-n", ns, "-f", str(CONFIG_DIR / "manifests/route-reload.yaml"))

    proc = loadgen.start(
        "load",
        url,
        connections=scenario["connections"],
        duration=f"{scenario['duration_seconds']}s",
        host=hostname,
    )
    timer = threading.Timer(reload_at, apply_reload)
    timer.start()

    try:
        with TopSampler(
            impl["proxy_pods"]["namespace"],
            impl["proxy_pods"]["selector"],
        ) as top:
            result = loadgen.wait(proc, timeout=scenario["duration_seconds"] + 600)

    finally:
        timer.cancel()
        # Restore the original route for repeatability.
        kubectl.kubectl("apply", "-n", ns, "-f", str(CONFIG_DIR / "manifests/route.yaml"))

    reload_window = [
        cell for cell in result["timeline"]
        if reload_at <= cell["second"] < reload_at + 10
    ]

    return {
        "implementation": name,
        "scenario": scenario_name,
        "requests_per_sec": round(result["requests_per_sec"], 1),
        "latency_ms": result["latency"],
        "requests": result["requests"],
        "request_errors": result["request_errors"],
        "non_2xx": result["non_2xx"],
        "disconnects": result["disconnects"],
        "reload_window_errors": sum(cell["errors"] for cell in reload_window),
        "resources": top.summary(),
    }


def print_table(rows: list[dict]):
    columns = [
        ("impl", lambda r: r["implementation"]),
        ("rps", lambda r: r["requests_per_sec"]),
        ("p50ms", lambda r: round(r["latency_ms"]["p50_ms"], 1)),
        ("p95ms", lambda r: round(r["latency_ms"]["p95_ms"], 1)),
        ("p99ms", lambda r: round(r["latency_ms"]["p99_ms"], 1)),
        ("errors", lambda r: r["request_errors"] + r["non_2xx"]),
        ("disconnects", lambda r: r["disconnects"]),
        ("reload_errs", lambda r: r["reload_window_errors"]),
        ("cpu(m)", lambda r: r["resources"]["cpu_milli_peak"]),
        ("mem(Mi)", lambda r: r["resources"]["memory_mi_peak"]),
    ]
    widths = [
        max(len(header), *(len(str(get(r))) for r in rows))
        for header, get in columns
    ]

    print()
    print("  ".join(header.ljust(width) for (header, _), width in zip(columns, widths)))

    for row in rows:
        print("  ".join(str(get(row)).ljust(width) for (_, get), width in zip(columns, widths)))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "implementations",
        nargs="+",
        choices=["krouter", "nginx", "traefik"],
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="run the pinned install commands for nginx/traefik",
    )
    parser.add_argument(
        "--scenario",
        default=None,
        help="scenario name from config.yaml (default: all)",
    )
    args = parser.parse_args()

    cfg = yaml.safe_load((CONFIG_DIR / "config.yaml").read_text())
    hostname = cfg["hostname"]

    scenarios = cfg["scenarios"]
    if args.scenario:
        scenarios = {args.scenario: scenarios[args.scenario]}

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    rows = []
    for name in args.implementations:
        impl = cfg["implementations"][name]
        deploy(name, impl, install=args.install, hostname=hostname)

        for scenario_name, scenario in scenarios.items():
            row = measure(name, impl, scenario_name, scenario, hostname)
            rows.append(row)

            out = RESULTS_DIR / f"{stamp}-{name}-{scenario_name}.json"
            out.write_text(json.dumps(row, indent=2) + "\n")
            print(f"[{name}] wrote {out}")

    print_table(rows)

    return 0


if __name__ == "__main__":
    sys.exit(main())
