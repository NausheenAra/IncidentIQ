"""Detect unhealthy Deployments by inspecting pods through the Kubernetes API.

``check_cluster()`` is called by the detector loop (Stage 5) every
``DETECTOR_INTERVAL_SECONDS``. It returns ONE issue per affected Deployment::

    {"service": "shop-api", "namespace": "default", "reason": "CrashLoopBackOff"}

Conditions that make a pod "unhealthy" (strongest first, which is also the
priority used to pick a single ``reason`` for the Deployment):

    OOMKilled         last (or current) container termination reason is OOMKilled
    CrashLoopBackOff  container waiting reason
    ImagePullBackOff  container waiting reason
    ErrImagePull      container waiting reason
    HighRestartCount  container restart count >= 3
    NotReady          pod has been unready for longer than UNHEALTHY_POD_GRACE_SECONDS

Ownership is resolved properly: Pod -> ReplicaSet (owner reference) ->
Deployment (owner reference of the ReplicaSet). Pods that do not belong to a
Deployment (bare pods, Jobs, StatefulSets) are ignored.

Two deliberate refinements so that a service that has already recovered is not
flagged forever by stale history:
    * Pods that are being deleted (``deletionTimestamp`` set) are ignored; during
      a rollback the failing pods are terminating.
    * ``OOMKilled`` and "restart count >= 3" are history, because Kubernetes keeps
      them until the container restarts again. They only count while the
      container is NOT ready, or if the last termination was recent
      (``RECENT_TERMINATION_SECONDS``).

``check_cluster`` never raises: configuration errors and API errors are logged and
the affected namespace is retried on the next poll.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from kubernetes.client.exceptions import ApiException

from backend import config, kube

logger = logging.getLogger(__name__)

#: Restart count at or above which a container is considered to be crash-looping.
RESTART_COUNT_THRESHOLD = 3

#: A past termination (OOMKilled / restarts) only counts for a container that is
#: currently ready if it happened within this many seconds.
RECENT_TERMINATION_SECONDS = 600

WAITING_REASONS = ("CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull")

#: Strongest first. The first reason found among a Deployment's pods is reported.
REASON_PRIORITY: Tuple[str, ...] = (
    "OOMKilled",
    "CrashLoopBackOff",
    "ImagePullBackOff",
    "ErrImagePull",
    "HighRestartCount",
    "NotReady",
)


# ---------------------------------------------------------------------------
# Pure helpers (no Kubernetes calls; easy to unit test)
# ---------------------------------------------------------------------------


def _as_utc(value: Optional[datetime]) -> Optional[datetime]:
    """Return a timezone-aware UTC datetime (naive values are assumed UTC)."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _terminated_recently(terminated: Any, now: datetime) -> bool:
    """True if a terminated state finished within the recent window (or has no time)."""
    finished = _as_utc(getattr(terminated, "finished_at", None))
    if finished is None:
        return True  # unknown time: be conservative and treat as recent
    return (now - finished).total_seconds() <= RECENT_TERMINATION_SECONDS


def _container_problems(status: Any, now: datetime) -> Set[str]:
    """Return the problem reasons for one container status."""
    problems: Set[str] = set()
    state = getattr(status, "state", None)
    last_state = getattr(status, "last_state", None)
    ready = bool(getattr(status, "ready", False))

    waiting = getattr(state, "waiting", None)
    if waiting is not None and getattr(waiting, "reason", None) in WAITING_REASONS:
        problems.add(waiting.reason)

    # OOMKilled: either the container is terminated right now, or its previous
    # incarnation was OOM killed (kept in last_state until the next restart).
    for terminated in (getattr(state, "terminated", None), getattr(last_state, "terminated", None)):
        if terminated is not None and getattr(terminated, "reason", None) == "OOMKilled":
            if not ready or _terminated_recently(terminated, now):
                problems.add("OOMKilled")

    restarts = getattr(status, "restart_count", 0) or 0
    if restarts >= RESTART_COUNT_THRESHOLD:
        last_terminated = getattr(last_state, "terminated", None)
        if not ready or last_terminated is None or _terminated_recently(last_terminated, now):
            problems.add("HighRestartCount")
    return problems


def _pod_unready_seconds(pod: Any, now: datetime) -> Optional[float]:
    """Return how long a pod has been unready, or ``None`` if it is ready/unknown."""
    status = getattr(pod, "status", None)
    if status is None or getattr(status, "phase", None) not in ("Running", "Pending"):
        return None
    ready_condition = None
    for condition in getattr(status, "conditions", None) or []:
        if getattr(condition, "type", None) == "Ready":
            ready_condition = condition
            break
    if ready_condition is not None and ready_condition.status == "True":
        return None
    since = _as_utc(getattr(ready_condition, "last_transition_time", None)) if ready_condition else None
    if since is None:
        since = _as_utc(getattr(pod.metadata, "creation_timestamp", None))
    if since is None:
        return None
    return max((now - since).total_seconds(), 0.0)


def pod_problems(pod: Any, grace_seconds: int, now: Optional[datetime] = None) -> Set[str]:
    """Return the set of problem reasons for a pod (empty set = healthy).

    Pods that are terminating or have completed (Succeeded) are never problems.
    """
    now = now or datetime.now(timezone.utc)
    if getattr(pod.metadata, "deletion_timestamp", None) is not None:
        return set()
    status = getattr(pod, "status", None)
    if status is None or getattr(status, "phase", None) == "Succeeded":
        return set()

    problems: Set[str] = set()
    container_statuses = list(getattr(status, "container_statuses", None) or [])
    container_statuses += list(getattr(status, "init_container_statuses", None) or [])
    for container_status in container_statuses:
        problems |= _container_problems(container_status, now)

    unready_for = _pod_unready_seconds(pod, now)
    if unready_for is not None and unready_for > grace_seconds:
        problems.add("NotReady")
    return problems


def strongest_reason(reasons: Set[str]) -> str:
    """Pick the highest-priority reason from a non-empty set."""
    for reason in REASON_PRIORITY:
        if reason in reasons:
            return reason
    return sorted(reasons)[0]  # unreachable with known reasons; stays deterministic


# ---------------------------------------------------------------------------
# Ownership resolution
# ---------------------------------------------------------------------------


def _controller_ref(owner_references: Any, kind: str) -> Optional[Any]:
    """Return the controlling owner reference of ``kind`` (or any of that kind)."""
    matches = [ref for ref in (owner_references or []) if getattr(ref, "kind", None) == kind]
    for ref in matches:
        if getattr(ref, "controller", False):
            return ref
    return matches[0] if matches else None


class _OwnerResolver:
    """Resolve Pod -> ReplicaSet -> Deployment, caching ReplicaSet lookups per poll."""

    def __init__(self, apps_api: Any) -> None:
        self._apps = apps_api
        self._cache: Dict[Tuple[str, str], Optional[str]] = {}

    def deployment_for(self, pod: Any) -> Optional[str]:
        """Return the owning Deployment name, or ``None`` if there is none.

        Raises:
            ApiException: transient API failure (the caller skips the pod this poll).
        """
        rs_ref = _controller_ref(pod.metadata.owner_references, "ReplicaSet")
        if rs_ref is None:
            return None
        key = (pod.metadata.namespace, rs_ref.name)
        if key in self._cache:
            return self._cache[key]
        try:
            replica_set = self._apps.read_namespaced_replica_set(
                rs_ref.name, pod.metadata.namespace, _request_timeout=kube.REQUEST_TIMEOUT_SECONDS
            )
        except ApiException as exc:
            if exc.status == 404:  # ReplicaSet already gone: nothing to attribute
                self._cache[key] = None
                return None
            raise
        deploy_ref = _controller_ref(replica_set.metadata.owner_references, "Deployment")
        name = deploy_ref.name if deploy_ref is not None else None
        self._cache[key] = name
        return name


# ---------------------------------------------------------------------------
# Public contract
# ---------------------------------------------------------------------------


def check_cluster() -> List[Dict[str, str]]:
    """Return one issue per unhealthy Deployment in the allow-listed namespaces.

    Never raises. On configuration or API errors it logs and returns whatever
    could be determined (possibly an empty list); the next poll retries.
    """
    settings = config.get_settings()
    try:
        core_api = kube.core_v1()
        apps_api = kube.apps_v1()
    except kube.KubeConfigError:
        return []  # already logged by kube.ensure_configured()
    except Exception:  # noqa: BLE001
        logger.exception("Unexpected error creating Kubernetes clients")
        return []

    now = datetime.now(timezone.utc)
    resolver = _OwnerResolver(apps_api)
    found: Dict[Tuple[str, str], Set[str]] = {}
    affected_pods: Dict[Tuple[str, str], List[str]] = {}

    for namespace in settings.namespace_allowlist:
        try:
            pods = core_api.list_namespaced_pod(
                namespace, _request_timeout=kube.REQUEST_TIMEOUT_SECONDS
            ).items
        except ApiException as exc:
            logger.warning("Cannot list pods in namespace %s: HTTP %s %s", namespace, exc.status, exc.reason)
            continue
        except Exception as exc:  # noqa: BLE001 - connection errors, timeouts, ...
            logger.warning("Cannot list pods in namespace %s: %s", namespace, exc)
            continue

        for pod in pods:
            try:
                problems = pod_problems(pod, settings.unhealthy_pod_grace_seconds, now)
                if not problems:
                    continue
                deployment = resolver.deployment_for(pod)
            except ApiException as exc:
                logger.warning(
                    "Skipping pod %s/%s this poll: ownership lookup failed (HTTP %s %s)",
                    namespace, pod.metadata.name, exc.status, exc.reason,
                )
                continue
            except Exception as exc:  # noqa: BLE001
                logger.warning("Skipping pod %s/%s this poll: %s", namespace, pod.metadata.name, exc)
                continue
            if deployment is None:
                logger.debug("Ignoring unhealthy pod %s/%s: not owned by a Deployment", namespace, pod.metadata.name)
                continue
            key = (namespace, deployment)
            found.setdefault(key, set()).update(problems)
            affected_pods.setdefault(key, []).append(pod.metadata.name)

    issues = [
        {"service": service, "namespace": namespace, "reason": strongest_reason(reasons)}
        for (namespace, service), reasons in sorted(found.items())
    ]
    for issue in issues:
        logger.info(
            "Unhealthy deployment %s/%s: %s (pods: %s)",
            issue["namespace"], issue["service"], issue["reason"],
            ", ".join(sorted(affected_pods[(issue["namespace"], issue["service"])])),
        )
    return issues
