"""
Thin kubectl wrapper used by the black-box suites.
"""

import json
import logging
import re
import subprocess
import time

from contextlib import contextmanager

import yaml

from e2elib import config

log = logging.getLogger("e2elib.kubectl")


class KubectlError(RuntimeError):
    pass


class TimeoutExpired(AssertionError):
    pass


def kubectl(
    *args: str,
    input: str | None = None,
    check: bool = True,
    timeout: int = 120,
) -> subprocess.CompletedProcess:
    cmd = ["kubectl", "--context", config.KUBE_CONTEXT, *args]
    res = subprocess.run(cmd, input=input, capture_output=True, text=True, timeout=timeout)

    if check and res.returncode != 0:
        raise KubectlError(
            f"command failed: {' '.join(cmd)}\n"
            f"stdout: {res.stdout}\nstderr: {res.stderr}"
        )

    return res


def to_yaml(objs: dict | list[dict]) -> str:
    if isinstance(objs, dict):
        objs = [objs]

    return yaml.safe_dump_all(objs)


def apply(objs: dict | list[dict] | str, namespace: str | None = None) -> None:
    manifest = objs if isinstance(objs, str) else to_yaml(objs)

    args = ["apply", "-f", "-"]
    if namespace:
        args += ["-n", namespace]

    kubectl(*args, input=manifest)


def delete(
    objs: dict | list[dict] | str,
    namespace: str | None = None,
    wait: bool = True,
) -> None:
    manifest = objs if isinstance(objs, str) else to_yaml(objs)

    args = ["delete", "-f", "-", "--ignore-not-found"]
    if not wait:
        args.append("--wait=false")

    if namespace:
        args += ["-n", namespace]

    kubectl(*args, input=manifest)


def get(
    kind: str,
    name: str | None = None,
    namespace: str | None = None,
    selector: str | None = None,
) -> dict:
    """
    Return the object (with name) or the List object (without name).
    """

    args = ["get", kind]
    if name:
        args.append(name)

    if namespace:
        args += ["-n", namespace]

    if selector:
        args += ["-l", selector]

    args += ["-o", "json"]

    return json.loads(kubectl(*args).stdout)


def get_or_none(kind: str, name: str, namespace: str | None = None) -> dict | None:
    args = ["get", kind, name, "-o", "json", "--ignore-not-found"]
    if namespace:
        args += ["-n", namespace]

    out = kubectl(*args).stdout.strip()

    return json.loads(out) if out else None


def create_namespace(name: str, labels: dict[str, str] | None = None) -> dict:
    ns = {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": name,
            "labels": {"krouter-test": "true", **(labels or {})},
        },
    }
    apply(ns)

    return ns


def delete_namespace(name: str) -> None:
    kubectl("delete", "namespace", name, "--ignore-not-found", "--wait=false")


# --------------------------------------------------------------- waiting --

def wait_for(fn, timeout: float = 120, interval: float = 2, desc: str = "condition"):
    """
    Poll `fn` until it returns a truthy value; raise TimeoutExpired otherwise.
    """

    deadline = time.monotonic() + timeout
    last_exc = None

    while time.monotonic() < deadline:
        try:
            value = fn()
            if value:
                return value

            last_exc = None

        except Exception as exc:  # tolerate transient kubectl/HTTP errors while polling
            last_exc = exc

        time.sleep(interval)

    detail = f" (last error: {last_exc})" if last_exc else ""
    raise TimeoutExpired(f"timed out after {timeout}s waiting for {desc}{detail}")


def find_condition(obj: dict, cond_type: str) -> dict | None:
    for cond in obj.get("status", {}).get("conditions", []):
        if cond.get("type") == cond_type:
            return cond

    return None


def wait_condition(
    kind: str,
    name: str,
    namespace: str | None,
    cond_type: str,
    status: str = "True",
    timeout: float = 120,
) -> dict:
    """
    Wait until status.conditions contains (type, status) and return the condition.
    """

    def check():
        obj = get_or_none(kind, name, namespace)
        if not obj:
            return None

        cond = find_condition(obj, cond_type)
        if cond and cond.get("status") == status:
            return cond

        return None

    return wait_for(
        check,
        timeout=timeout,
        desc=f"{kind}/{name} condition {cond_type}={status}",
    )


def wait_deployment_ready(name: str, namespace: str, timeout: int = 180) -> None:
    kubectl(
        "-n", namespace,
        "rollout", "status", f"deployment/{name}",
        f"--timeout={timeout}s",
        timeout=timeout + 30,
    )


def wait_daemonset_ready(name: str, namespace: str, timeout: int = 180) -> None:
    kubectl(
        "-n", namespace,
        "rollout", "status", f"daemonset/{name}",
        f"--timeout={timeout}s",
        timeout=timeout + 30,
    )


# --------------------------------------------------------------- routing --

def route_parent_status(route: dict, controller_name: str = config.CONTROLLER_NAME) -> list[dict]:
    """
    status.parents[] entries written by our controller (spec §15).
    """

    return [
        parent for parent in route.get("status", {}).get("parents", [])
        if parent.get("controllerName") == controller_name
    ]


def wait_route_parent_condition(
    name: str,
    namespace: str,
    cond_type: str,
    status: str = "True",
    timeout: float = 120,
) -> dict:
    def check():
        route = get_or_none("httproute", name, namespace)
        if not route:
            return None

        for parent in route_parent_status(route):
            for cond in parent.get("conditions", []):
                if cond.get("type") == cond_type and cond.get("status") == status:
                    return cond

        return None

    return wait_for(
        check,
        timeout=timeout,
        desc=f"httproute/{namespace}/{name} parent condition {cond_type}={status}",
    )


# ------------------------------------------------------------------ pods --

def dataplane_pods() -> list[dict]:
    pods = get(
        "pods",
        namespace=config.SYSTEM_NAMESPACE,
        selector=config.DATAPLANE_LABEL_SELECTOR,
    )["items"]

    if not pods:
        # Fall back to DaemonSet ownership if the label contract changes.
        pods = [
            pod for pod in get("pods", namespace=config.SYSTEM_NAMESPACE)["items"]
            if any(
                ref.get("kind") == "DaemonSet" and ref.get("name") == config.DATAPLANE_DAEMONSET
                for ref in pod["metadata"].get("ownerReferences", [])
            )
        ]

    return pods


def pod_restart_counts(pods: list[dict]) -> dict[str, int]:
    return {
        pod["metadata"]["name"]: sum(
            cs.get("restartCount", 0)
            for cs in pod.get("status", {}).get("containerStatuses", [])
        )
        for pod in pods
    }


def container_env(pod: dict, name: str) -> str | None:
    for container in pod["spec"]["containers"]:
        for env in container.get("env", []):
            if env.get("name") == name and "value" in env:
                return env["value"]

    return None


def management_port(pod: dict) -> int:
    value = container_env(pod, "KROUTER_MANAGEMENT_PORT")

    return int(value) if value else config.MANAGEMENT_PORT


@contextmanager
def port_forward(target: str, remote_port: int, namespace: str):
    """
    `kubectl port-forward` on a random local port; yields the local port.
    """

    cmd = [
        "kubectl", "--context", config.KUBE_CONTEXT, "-n", namespace,
        "port-forward", target, f"0:{remote_port}",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    try:
        line = proc.stdout.readline()
        match = re.search(r"Forwarding from 127\.0\.0\.1:(\d+)", line or "")
        if not match:
            proc.terminate()
            rest = proc.stdout.read() or ""
            raise KubectlError(f"port-forward {target} failed: {line!r} {rest!r}")

        yield int(match.group(1))

    finally:
        proc.terminate()
        proc.wait(timeout=10)
