"""Live metrics for every connected cluster (powers the dashboard charts).

Every ``METRICS_INTERVAL_SECONDS`` the :class:`MetricsSampler` takes one cheap,
read-only sample of each registered cluster and stores it in SQLite
(``cluster_samples``):

    pods_total / pods_ready / pods_unhealthy   from the pod list
    restarts_total                             sum of container restart counts
    warning_events                             Kubernetes ``Warning`` events in the last minute
    log_lines / error_lines                    lines logged since the previous sample, and how many
                                               look like errors (counts only: log TEXT is never stored)

The latest per-Deployment view (ready / desired replicas, image) is kept as a
snapshot on the cluster row. Only calls the existing Role already allows are
used: list pods, list events, list deployments and read pod logs. CPU and memory
are NOT sampled: they need metrics-server, which a default kind cluster lacks.

The sampler never raises into its loop. A failing cluster is marked
``unreachable`` / ``forbidden`` / ``not_configured`` and retried on the next cycle.
"""

from __future__ import annotations

import logging
import math
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from kubernetes.client.exceptions import ApiException

from backend import config, db, detector, kube

logger = logging.getLogger(__name__)

#: At most this many pods have their logs read per sample (keeps a big cluster cheap).
MAX_LOG_PODS = 25
LOG_REQUEST_TIMEOUT_SECONDS = 3
API_REQUEST_TIMEOUT_SECONDS = 5
MAX_CONCURRENT_CLUSTERS = 4

#: Lines that count as "errors" for the error-rate chart.
ERROR_PATTERN = re.compile(r"\b(error|exception|traceback|fatal|panic|critical|failed|refused)\b", re.IGNORECASE)

SERIES_KEYS = ("pods_ready", "pods_total", "unhealthy", "restarts", "log_rate", "error_rate", "warnings")


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def classify_logs(text: Any) -> Tuple[int, int]:
    """Return ``(lines, error_lines)`` for a block of log text. Non-text input counts as nothing."""
    if not isinstance(text, str) or not text:
        return 0, 0
    lines = [line for line in text.splitlines() if line.strip()]
    return len(lines), sum(1 for line in lines if ERROR_PATTERN.search(line))


def _pod_ready(pod: Any) -> bool:
    for condition in getattr(getattr(pod, "status", None), "conditions", None) or []:
        if getattr(condition, "type", None) == "Ready":
            return getattr(condition, "status", None) == "True"
    return False


def _restarts(pod: Any) -> int:
    total = 0
    for status in getattr(getattr(pod, "status", None), "container_statuses", None) or []:
        total += int(getattr(status, "restart_count", 0) or 0)
    return total


def _event_time(event: Any) -> Optional[datetime]:
    for name in ("last_timestamp", "event_time", "first_timestamp"):
        value = getattr(event, name, None)
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    metadata = getattr(event, "metadata", None)
    value = getattr(metadata, "creation_timestamp", None)
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return None


def _workload_status(desired: int, ready: int, problem: Optional[str]) -> str:
    if desired == 0:
        return "ScaledToZero"
    if problem:
        return "Degraded"
    if ready >= desired:
        return "Healthy"
    return "Progressing" if ready > 0 else "Unavailable"


def _owner_deployment(pod: Any, deployment_names: List[str]) -> Optional[str]:
    """Best-effort Deployment of a pod from its ReplicaSet owner name (``<deployment>-<hash>``)."""
    for ref in getattr(getattr(pod, "metadata", None), "owner_references", None) or []:
        if getattr(ref, "kind", None) != "ReplicaSet":
            continue
        rs_name = getattr(ref, "name", "") or ""
        # longest match first so "shop-api-v2" wins over "shop-api"
        for name in sorted(deployment_names, key=len, reverse=True):
            if rs_name.startswith(name + "-"):
                return name
    return None


# ---------------------------------------------------------------------------
# One sample of one cluster (talks to whatever cluster kube.use_cluster selected)
# ---------------------------------------------------------------------------


def sample_current_cluster(interval_seconds: float) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Take one sample using the clients of the active cluster.

    Returns ``(sample, snapshot)``.

    Raises:
        kube.KubeConfigError: no usable configuration for the cluster.
        ApiException / Exception: the cluster refused or could not be reached
            (the caller turns this into a connection state).
    """
    settings = config.get_settings()
    core_api = kube.core_v1()
    apps_api = kube.apps_v1()
    now = datetime.now(timezone.utc)
    since_seconds = max(2, int(math.ceil(interval_seconds)) + 1)

    pods_total = pods_ready = pods_unhealthy = restarts = warnings = log_lines = error_lines = 0
    workloads: List[Dict[str, Any]] = []
    loggable: List[Tuple[str, str, str]] = []

    for namespace in settings.namespace_allowlist:
        pods = core_api.list_namespaced_pod(namespace, _request_timeout=API_REQUEST_TIMEOUT_SECONDS).items or []
        deployments = apps_api.list_namespaced_deployment(
            namespace, _request_timeout=API_REQUEST_TIMEOUT_SECONDS
        ).items or []
        names = [d.metadata.name for d in deployments]
        problems_by_deployment: Dict[str, set] = {}
        restarts_by_deployment: Dict[str, int] = {}

        for pod in pods:
            if getattr(pod.metadata, "deletion_timestamp", None) is not None:
                continue
            phase = getattr(pod.status, "phase", None)
            if phase == "Succeeded":
                continue
            pods_total += 1
            ready = _pod_ready(pod)
            pods_ready += 1 if ready else 0
            pod_restarts = _restarts(pod)
            restarts += pod_restarts
            problems = detector.pod_problems(pod, settings.unhealthy_pod_grace_seconds, now)
            if problems:
                pods_unhealthy += 1
            owner = _owner_deployment(pod, names)
            if owner:
                restarts_by_deployment[owner] = restarts_by_deployment.get(owner, 0) + pod_restarts
                if problems:
                    problems_by_deployment.setdefault(owner, set()).update(problems)
            if phase == "Running":
                for container in getattr(pod.spec, "containers", None) or []:
                    loggable.append((namespace, pod.metadata.name, container.name))

        for deployment in deployments:
            desired = int(deployment.spec.replicas if deployment.spec.replicas is not None else 1)
            ready_replicas = int(getattr(deployment.status, "ready_replicas", 0) or 0)
            containers = getattr(getattr(deployment.spec.template, "spec", None), "containers", None) or []
            problems = problems_by_deployment.get(deployment.metadata.name)
            reason = detector.strongest_reason(problems) if problems else None
            workloads.append({
                "name": deployment.metadata.name,
                "namespace": namespace,
                "desired": desired,
                "ready": ready_replicas,
                "image": containers[0].image if containers else None,
                "restarts": restarts_by_deployment.get(deployment.metadata.name, 0),
                "problem": reason,
                "status": _workload_status(desired, ready_replicas, reason),
            })

        try:
            events = core_api.list_namespaced_event(namespace, _request_timeout=API_REQUEST_TIMEOUT_SECONDS).items or []
            for event in events:
                if getattr(event, "type", None) != "Warning":
                    continue
                when = _event_time(event)
                if when is not None and (now - when).total_seconds() <= 60:
                    warnings += 1
        except Exception:  # noqa: BLE001 - events are optional context; pods/deployments decide the state
            logger.debug("Could not list events in %s", namespace, exc_info=True)

    for namespace, pod_name, container in loggable[:MAX_LOG_PODS]:
        try:
            text = core_api.read_namespaced_pod_log(
                pod_name, namespace, container=container, since_seconds=since_seconds, tail_lines=500,
                _request_timeout=LOG_REQUEST_TIMEOUT_SECONDS,
            )
        except Exception:  # noqa: BLE001 - a pod may be restarting; skip its logs this time
            continue
        lines, errors = classify_logs(text)
        log_lines += lines
        error_lines += errors

    workloads.sort(key=lambda w: (w["status"] == "Healthy", w["name"]))
    sample = {
        "pods_total": pods_total, "pods_ready": pods_ready, "pods_unhealthy": pods_unhealthy,
        "restarts_total": restarts, "warning_events": warnings,
        "log_lines": log_lines, "error_lines": error_lines, "interval_seconds": float(interval_seconds),
    }
    snapshot = {
        "workloads": workloads[:50],
        "namespaces": list(settings.namespace_allowlist),
        "log_pods_sampled": min(len(loggable), MAX_LOG_PODS),
        "log_pods_total": len(loggable),
    }
    return sample, snapshot


def _state_for_error(exc: BaseException) -> Tuple[str, str]:
    """Map a sampling failure to a dashboard connection state and a short detail."""
    if isinstance(exc, kube.KubeConfigError):
        return "not_configured", str(exc)[:200]
    if isinstance(exc, ApiException):
        if exc.status in (401, 403):
            return "forbidden", f"HTTP {exc.status} {exc.reason}"
        return "error", f"HTTP {exc.status} {exc.reason}"
    return "unreachable", f"{type(exc).__name__}: {str(exc)[:160]}"


def probe_context(context: Optional[str], timeout: int = 4) -> Tuple[str, str]:
    """Check that a kubeconfig context answers for the first allow-listed namespace.

    Returns ``(state, detail)`` with state ``connected`` / ``forbidden`` / ``unreachable`` / ...
    """
    namespace = config.get_settings().namespace_allowlist[0]
    try:
        with kube.use_cluster(context):
            kube.core_v1().list_namespaced_pod(namespace, limit=1, _request_timeout=timeout)
        return "connected", f"Listed pods in namespace {namespace!r}"
    except Exception as exc:  # noqa: BLE001
        return _state_for_error(exc)


# ---------------------------------------------------------------------------
# View helpers for the API
# ---------------------------------------------------------------------------


def _rate_per_minute(count: int, interval: float) -> float:
    return round(count * 60.0 / interval, 2) if interval and interval > 0 else 0.0


def build_series(samples: List[Dict[str, Any]]) -> Dict[str, List[Any]]:
    """Turn stored samples into chart series (rates are per minute)."""
    series: Dict[str, List[Any]] = {"ts": [s["ts"] for s in samples]}
    series["pods_ready"] = [s["pods_ready"] for s in samples]
    series["pods_total"] = [s["pods_total"] for s in samples]
    series["unhealthy"] = [s["pods_unhealthy"] for s in samples]
    series["restarts"] = [s["restarts_total"] for s in samples]
    series["warnings"] = [s["warning_events"] for s in samples]
    series["log_rate"] = [_rate_per_minute(s["log_lines"], s["interval_seconds"]) for s in samples]
    series["error_rate"] = [_rate_per_minute(s["error_lines"], s["interval_seconds"]) for s in samples]
    return series


def cluster_view(cluster: Dict[str, Any], samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Assemble the dashboard payload for one cluster."""
    series = build_series(samples)
    latest = None
    if samples:
        last = samples[-1]
        latest = {
            "pods_total": last["pods_total"], "pods_ready": last["pods_ready"], "pods_unhealthy": last["pods_unhealthy"],
            "restarts_total": last["restarts_total"], "warning_events": last["warning_events"],
            "log_rate": series["log_rate"][-1], "error_rate": series["error_rate"][-1],
        }
    snapshot = cluster.get("snapshot") or {}
    open_incidents = cluster.get("open_incidents", 0)
    if cluster["is_default"]:
        blocked = "The built-in cluster cannot be deleted"
    elif open_incidents:
        blocked = "Resolve the open incident before deleting this cluster"
    else:
        blocked = None
    return {
        "id": cluster["id"], "name": cluster["name"], "context": cluster["context"],
        "is_default": cluster["is_default"], "state": cluster["state"], "state_detail": cluster["state_detail"],
        "created_at": cluster["created_at"], "last_sample_at": cluster["last_sample_at"],
        "open_incidents": open_incidents, "total_incidents": cluster.get("total_incidents", 0),
        "can_delete": blocked is None, "delete_blocked_reason": blocked,
        "latest": latest, "series": series,
        "workloads": snapshot.get("workloads", []), "namespaces": snapshot.get("namespaces", []),
    }


# ---------------------------------------------------------------------------
# Background loop
# ---------------------------------------------------------------------------


class MetricsSampler:
    """Sample every registered cluster on a fixed interval, in a background thread."""

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._last_run: Dict[int, float] = {}
        self._interval = float(config.get_settings().metrics_interval_seconds)
        self._last_cycle_at: Optional[str] = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        with self._lock:
            if self.running:
                return
            self._stop.clear()
            self._interval = float(config.get_settings().metrics_interval_seconds)
            self._thread = threading.Thread(target=self._run, name="metrics-sampler", daemon=True)
            self._thread.start()

    def stop(self, timeout: float = 10.0) -> bool:
        self._stop.set()
        self._wake.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)
            return not thread.is_alive()
        return True

    def wake(self) -> None:
        """Sample now instead of waiting for the next interval (used after connecting a cluster)."""
        self._wake.set()

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {"running": self.running, "interval_seconds": self._interval, "last_cycle_at": self._last_cycle_at}

    def _run(self) -> None:
        logger.info("Metrics sampler started (interval %.0fs)", self._interval)
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:  # noqa: BLE001
                logger.exception("Metrics cycle failed; retrying on the next interval")
            self._wake.wait(self._interval)
            self._wake.clear()
        logger.info("Metrics sampler stopped")

    def run_once(self) -> int:
        """Sample every cluster once. Returns how many were sampled successfully."""
        clusters = db.list_clusters()
        with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_CLUSTERS, thread_name_prefix="sample") as pool:
            results = list(pool.map(self._sample_cluster, clusters))
        with self._lock:
            self._last_cycle_at = db.utc_now_iso()
        return sum(1 for ok in results if ok)

    def _sample_cluster(self, cluster: Dict[str, Any]) -> bool:
        cluster_id = cluster["id"]
        now = time.monotonic()
        previous = self._last_run.get(cluster_id)
        elapsed = now - previous if previous is not None else self._interval
        interval = min(max(elapsed, 1.0), 300.0)
        try:
            with kube.use_cluster(cluster["context"]):
                sample, snapshot = sample_current_cluster(interval)
        except Exception as exc:  # noqa: BLE001 - one cluster must never stop the others
            state, detail = _state_for_error(exc)
            logger.debug("Sampling cluster %s failed: %s", cluster["name"], detail, exc_info=True)
            try:
                db.set_cluster_state(cluster_id, state, detail)
            except Exception:  # noqa: BLE001
                logger.exception("Could not record state of cluster %s", cluster_id)
            return False
        self._last_run[cluster_id] = now
        try:
            db.set_cluster_state(cluster_id, "connected", None)
            db.record_sample(cluster_id, sample, snapshot)
        except Exception:  # noqa: BLE001
            logger.exception("Could not store a sample for cluster %s", cluster_id)
            return False
        return True
