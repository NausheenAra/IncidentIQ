"""Collect diagnostic evidence for one Deployment.

``collect_evidence(namespace, service)`` returns a JSON-serialisable dict with
EXACTLY these top-level keys::

    logs             list of {pod, container, source, lines, error}
    events           list of recent events for the Deployment, its ReplicaSets and pods
    pods             list of pod/container states
    last_deploy_time ISO 8601 UTC string, or None if it cannot be established
    rollout_history  ReplicaSets of the Deployment, newest revision first

Each part is collected independently: a failure in one (missing pod, RBAC
denial, API outage) is logged and leaves that part empty/None but never stops
the others. Log requests record their own failure in the entry's ``error`` field.

Evidence is later sent to an LLM, so:
    * Configured secrets (API keys) are redacted from log lines.
    * Log lines and event messages are length-limited.
    * Environment variable NAMES of the pod template are included, never values.

``last_deploy_time`` is the time the Deployment was last CHANGED, never "now".
It is derived (in order of preference) from:
    1. ``metadata.managedFields``: the newest write that touched the object
       itself rather than its status subresource (``kubectl set image``,
       ``apply``, ``rollout undo`` and ``rollout restart`` all show up here);
    2. the ``Progressing`` condition's ``lastUpdateTime``;
    3. the creation time of the ReplicaSet for the current revision.
A rollback re-uses an OLD ReplicaSet, so ReplicaSet creation time alone would be
wrong - that is why it is only the last resort.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from kubernetes.client.exceptions import ApiException

from backend import config, kube

logger = logging.getLogger(__name__)

LOG_TAIL_LINES = 50
MAX_LOG_LINE_CHARS = 500
MAX_EVENT_MESSAGE_CHARS = 500
MAX_EVENTS = 30
MAX_PODS_WITH_LOGS = 6
MAX_ROLLOUT_HISTORY = 10

REVISION_ANNOTATION = "deployment.kubernetes.io/revision"
CHANGE_CAUSE_ANNOTATION = "kubernetes.io/change-cause"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _iso(value: Optional[datetime]) -> Optional[str]:
    """Format a datetime as an ISO 8601 UTC string (``None`` stays ``None``)."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def _truncate(text: Optional[str], limit: int) -> str:
    """Return ``text`` limited to ``limit`` characters."""
    text = text or ""
    return text if len(text) <= limit else text[: limit - 12] + " [truncated]"


def _redact(text: str, secrets: List[str]) -> str:
    """Replace configured secret values with ``***``."""
    for secret in secrets:
        if secret in text:
            text = text.replace(secret, "***")
    return text


def _describe_error(exc: Exception) -> str:
    """Short, safe description of a failure for the evidence record."""
    if isinstance(exc, ApiException):
        return f"HTTP {exc.status} {exc.reason}"
    return f"{type(exc).__name__}: {exc}"[:200]


def _owned_by(obj: Any, kind: str, name: Optional[str] = None, uid: Optional[str] = None) -> bool:
    """True if ``obj`` has an owner reference of ``kind`` matching name or uid."""
    for ref in getattr(obj.metadata, "owner_references", None) or []:
        if getattr(ref, "kind", None) != kind:
            continue
        if uid is not None and getattr(ref, "uid", None) == uid:
            return True
        if uid is None and name is not None and getattr(ref, "name", None) == name:
            return True
    return False


def _revision(obj: Any) -> Optional[int]:
    """Return the Deployment revision number stored in an object's annotations."""
    raw = (getattr(obj.metadata, "annotations", None) or {}).get(REVISION_ANNOTATION)
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _selector_string(deployment: Any) -> Optional[str]:
    """Build a label selector string from the Deployment's matchLabels."""
    selector = getattr(deployment.spec, "selector", None)
    match_labels = getattr(selector, "match_labels", None) or {}
    if not match_labels:
        return None
    return ",".join(f"{key}={value}" for key, value in sorted(match_labels.items()))


# ---------------------------------------------------------------------------
# Part collectors (each may raise; the public function isolates failures)
# ---------------------------------------------------------------------------


def _read_deployment(apps_api: Any, namespace: str, service: str) -> Any:
    return apps_api.read_namespaced_deployment(
        service, namespace, _request_timeout=kube.REQUEST_TIMEOUT_SECONDS
    )


def _list_replica_sets(apps_api: Any, namespace: str, deployment: Any) -> List[Any]:
    """ReplicaSets controlled by this Deployment (matched by owner UID)."""
    selector = _selector_string(deployment)
    kwargs: Dict[str, Any] = {"_request_timeout": kube.REQUEST_TIMEOUT_SECONDS}
    if selector:
        kwargs["label_selector"] = selector
    items = apps_api.list_namespaced_replica_set(namespace, **kwargs).items
    uid = getattr(deployment.metadata, "uid", None)
    return [
        rs for rs in items
        if _owned_by(rs, "Deployment", name=deployment.metadata.name, uid=uid)
    ]


def _list_pods(
    core_api: Any, namespace: str, deployment: Any, replica_sets: Optional[List[Any]]
) -> List[Any]:
    """Pods of the Deployment: label match, then confirmed through ReplicaSet ownership."""
    selector = _selector_string(deployment)
    kwargs: Dict[str, Any] = {"_request_timeout": kube.REQUEST_TIMEOUT_SECONDS}
    if selector:
        kwargs["label_selector"] = selector
    pods = core_api.list_namespaced_pod(namespace, **kwargs).items
    if replica_sets is None:
        return pods  # ReplicaSets unavailable: label selector is the best we have
    rs_names = {rs.metadata.name for rs in replica_sets}
    return [
        pod for pod in pods
        if any(
            getattr(ref, "kind", None) == "ReplicaSet" and getattr(ref, "name", None) in rs_names
            for ref in (pod.metadata.owner_references or [])
        )
    ]


def _container_state(status: Any) -> Tuple[str, Optional[str], Optional[str], Optional[int]]:
    """Return (state, waiting_reason, terminated_reason, exit_code) for a container."""
    state = getattr(status, "state", None)
    if getattr(state, "running", None) is not None:
        return "running", None, None, None
    waiting = getattr(state, "waiting", None)
    if waiting is not None:
        return "waiting", getattr(waiting, "reason", None), None, None
    terminated = getattr(state, "terminated", None)
    if terminated is not None:
        return "terminated", None, getattr(terminated, "reason", None), getattr(terminated, "exit_code", None)
    return "unknown", None, None, None


def _pod_summary(pod: Any) -> Dict[str, Any]:
    """Summarise one pod and its containers."""
    status = pod.status
    statuses = {cs.name: cs for cs in (getattr(status, "container_statuses", None) or [])}
    ready_pod = any(
        getattr(c, "type", None) == "Ready" and c.status == "True"
        for c in (getattr(status, "conditions", None) or [])
    )
    containers: List[Dict[str, Any]] = []
    for spec in pod.spec.containers or []:
        cs = statuses.get(spec.name)
        entry: Dict[str, Any] = {
            "name": spec.name,
            "image": spec.image,
            "ready": bool(cs.ready) if cs is not None else False,
            "state": "unknown",
            "waiting_reason": None,
            "terminated_reason": None,
            "restart_count": 0,
            "last_termination_reason": None,
            "last_exit_code": None,
        }
        if cs is not None:
            state, waiting_reason, terminated_reason, _ = _container_state(cs)
            last = getattr(getattr(cs, "last_state", None), "terminated", None)
            entry.update(
                state=state,
                waiting_reason=waiting_reason,
                terminated_reason=terminated_reason,
                restart_count=cs.restart_count or 0,
                last_termination_reason=getattr(last, "reason", None),
                last_exit_code=getattr(last, "exit_code", None),
            )
        containers.append(entry)
    return {
        "name": pod.metadata.name,
        "phase": getattr(status, "phase", None),
        "ready": ready_pod,
        "created": _iso(getattr(pod.metadata, "creation_timestamp", None)),
        "terminating": getattr(pod.metadata, "deletion_timestamp", None) is not None,
        "containers": containers,
    }


def _pod_priority(summary: Dict[str, Any]) -> Tuple[int, str]:
    """Sort key so unhealthy, non-terminating pods get their logs collected first."""
    unhealthy = (not summary["ready"]) or any(c["restart_count"] for c in summary["containers"])
    return (0 if unhealthy and not summary["terminating"] else 1, summary["name"])


def _fetch_logs_for_container(
    core_api: Any, namespace: str, pod_name: str, container: Dict[str, Any], secrets: List[str]
) -> Dict[str, Any]:
    """Fetch the last lines of one container: previous run first if it crashed."""
    entry: Dict[str, Any] = {
        "pod": pod_name, "container": container["name"],
        "source": "none", "lines": [], "error": None,
    }
    crashed = bool(container["restart_count"]) or container["last_termination_reason"] is not None
    attempts = [True, False] if crashed else [False]
    last_error: Optional[str] = None
    for previous in attempts:
        try:
            text = core_api.read_namespaced_pod_log(
                pod_name, namespace, container=container["name"],
                tail_lines=LOG_TAIL_LINES, previous=previous,
                _request_timeout=kube.REQUEST_TIMEOUT_SECONDS,
            )
        except Exception as exc:  # noqa: BLE001 - one failed request must not stop collection
            last_error = _describe_error(exc)
            continue
        lines = [
            _truncate(_redact(line, secrets), MAX_LOG_LINE_CHARS)
            for line in (text or "").splitlines()[-LOG_TAIL_LINES:]
        ]
        entry.update(source="previous" if previous else "current", lines=lines)
        if lines:
            entry["error"] = None
            return entry
        # Empty output: remember it and try the next source (e.g. previous was empty).
        last_error = None
    entry["error"] = last_error
    return entry


def _collect_logs(core_api: Any, namespace: str, pod_summaries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    secrets = config.get_settings().secrets_to_redact()
    ordered = sorted(pod_summaries, key=_pod_priority)[:MAX_PODS_WITH_LOGS]
    logs: List[Dict[str, Any]] = []
    for pod in ordered:
        for container in pod["containers"]:
            try:
                logs.append(_fetch_logs_for_container(core_api, namespace, pod["name"], container, secrets))
            except Exception as exc:  # noqa: BLE001 - defensive: never lose the other pods
                logger.warning("Log collection failed for %s/%s: %s", namespace, pod["name"], exc)
                logs.append({
                    "pod": pod["name"], "container": container["name"],
                    "source": "none", "lines": [], "error": _describe_error(exc),
                })
    return logs


def _event_time(event: Any) -> Optional[datetime]:
    for attribute in ("last_timestamp", "event_time", "first_timestamp"):
        value = getattr(event, attribute, None)
        if value is not None:
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    created = getattr(event.metadata, "creation_timestamp", None)
    if created is not None:
        return created if created.tzinfo else created.replace(tzinfo=timezone.utc)
    return None


def _collect_events(
    core_api: Any, namespace: str, service: str, replica_set_names: List[str], pod_names: List[str]
) -> List[Dict[str, Any]]:
    """Recent events involving the Deployment, its ReplicaSets or its pods."""
    wanted = {("Deployment", service)}
    wanted |= {("ReplicaSet", name) for name in replica_set_names}
    wanted |= {("Pod", name) for name in pod_names}
    items = core_api.list_namespaced_event(
        namespace, limit=500, _request_timeout=kube.REQUEST_TIMEOUT_SECONDS
    ).items
    epoch = datetime.min.replace(tzinfo=timezone.utc)
    relevant = [
        e for e in items
        if (getattr(e.involved_object, "kind", None), getattr(e.involved_object, "name", None)) in wanted
    ]
    relevant.sort(key=lambda e: _event_time(e) or epoch)
    events: List[Dict[str, Any]] = []
    for event in relevant[-MAX_EVENTS:]:
        events.append({
            "type": event.type,
            "reason": event.reason,
            "message": _truncate(event.message, MAX_EVENT_MESSAGE_CHARS),
            "involved_object": f"{event.involved_object.kind}/{event.involved_object.name}",
            "count": getattr(event, "count", None),
            "timestamp": _iso(_event_time(event)),
        })
    return events


def _last_deploy_time(deployment: Any, replica_sets: Optional[List[Any]]) -> Optional[str]:
    """Establish when the Deployment was last changed (see module docstring)."""
    # 1. Newest write to the object itself (not the status subresource).
    times = [
        entry.time
        for entry in (getattr(deployment.metadata, "managed_fields", None) or [])
        if getattr(entry, "time", None) is not None
        and not getattr(entry, "subresource", None)
        and getattr(entry, "operation", None) in ("Update", "Apply")
    ]
    if times:
        return _iso(max(t if t.tzinfo else t.replace(tzinfo=timezone.utc) for t in times))
    # 2. Progressing condition.
    for condition in getattr(deployment.status, "conditions", None) or []:
        if getattr(condition, "type", None) == "Progressing" and getattr(condition, "last_update_time", None):
            return _iso(condition.last_update_time)
    # 3. ReplicaSet of the current revision (may be old after a rollback).
    current = _revision(deployment)
    for rs in replica_sets or []:
        if current is not None and _revision(rs) == current and rs.metadata.creation_timestamp:
            return _iso(rs.metadata.creation_timestamp)
    return None


def _rollout_history(deployment: Any, replica_sets: List[Any]) -> List[Dict[str, Any]]:
    """Describe the Deployment's ReplicaSets, newest revision first."""
    current = _revision(deployment)
    history: List[Dict[str, Any]] = []
    for rs in replica_sets:
        template_spec = getattr(getattr(rs.spec, "template", None), "spec", None)
        containers = []
        for container in getattr(template_spec, "containers", None) or []:
            resources = getattr(container, "resources", None)
            containers.append({
                "name": container.name,
                "image": container.image,
                "env_var_names": sorted(e.name for e in (container.env or [])),  # names only, never values
                "resource_requests": dict(getattr(resources, "requests", None) or {}),
                "resource_limits": dict(getattr(resources, "limits", None) or {}),
            })
        revision = _revision(rs)
        status = rs.status
        history.append({
            "name": rs.metadata.name,
            "revision": revision,
            "is_current": current is not None and revision == current,
            "images": [c["image"] for c in containers],
            "created": _iso(rs.metadata.creation_timestamp),
            "desired_replicas": getattr(rs.spec, "replicas", None),
            "replicas": getattr(status, "replicas", None),
            "ready_replicas": getattr(status, "ready_replicas", None) or 0,
            "available_replicas": getattr(status, "available_replicas", None) or 0,
            "change_cause": (rs.metadata.annotations or {}).get(CHANGE_CAUSE_ANNOTATION),
            "pod_template": {"containers": containers},
        })
    history.sort(key=lambda h: (h["revision"] is None, -(h["revision"] or 0), h["name"]))
    return history[:MAX_ROLLOUT_HISTORY]


# ---------------------------------------------------------------------------
# Public contract
# ---------------------------------------------------------------------------


def collect_evidence(namespace: str, service: str) -> Dict[str, Any]:
    """Collect logs, events, pod states, last deploy time and rollout history.

    Never raises for Kubernetes problems. The returned dict always has exactly
    the five documented keys and is JSON-serialisable.
    """
    evidence: Dict[str, Any] = {
        "logs": [], "events": [], "pods": [], "last_deploy_time": None, "rollout_history": [],
    }
    try:
        core_api = kube.core_v1()
        apps_api = kube.apps_v1()
    except Exception as exc:  # noqa: BLE001 - includes KubeConfigError
        logger.warning("Evidence collection skipped for %s/%s: %s", namespace, service, exc)
        return evidence

    deployment: Any = None
    replica_sets: Optional[List[Any]] = None

    try:
        deployment = _read_deployment(apps_api, namespace, service)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Cannot read deployment %s/%s: %s", namespace, service, _describe_error(exc))

    if deployment is not None:
        try:
            replica_sets = _list_replica_sets(apps_api, namespace, deployment)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cannot list ReplicaSets for %s/%s: %s", namespace, service, _describe_error(exc))

        try:
            evidence["rollout_history"] = _rollout_history(deployment, replica_sets or [])
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cannot build rollout history for %s/%s: %s", namespace, service, exc)

        try:
            evidence["last_deploy_time"] = _last_deploy_time(deployment, replica_sets)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cannot determine last deploy time for %s/%s: %s", namespace, service, exc)

        try:
            pods = _list_pods(core_api, namespace, deployment, replica_sets)
            evidence["pods"] = [_pod_summary(pod) for pod in pods]
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cannot list pods for %s/%s: %s", namespace, service, _describe_error(exc))

    try:
        evidence["logs"] = _collect_logs(core_api, namespace, evidence["pods"])
    except Exception as exc:  # noqa: BLE001
        logger.warning("Cannot collect logs for %s/%s: %s", namespace, service, exc)

    try:
        evidence["events"] = _collect_events(
            core_api, namespace, service,
            [rs.metadata.name for rs in replica_sets or []],
            [pod["name"] for pod in evidence["pods"]],
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Cannot collect events for %s/%s: %s", namespace, service, _describe_error(exc))

    # Guarantee JSON-serialisability whatever the Kubernetes client returned.
    return json.loads(json.dumps(evidence, default=str))
