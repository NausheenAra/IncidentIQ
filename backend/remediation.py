"""Guarded remediation (rollback / restart / scale) and recovery verification.

Public contract::

    execute(action, namespace, service, *, incident_id=None, approved=False)
        -> {"success": bool, "detail": str}
    verify(namespace, service, timeout=None) -> bool
    verify_with_detail(namespace, service, timeout=None) -> (bool, str)

``incident_id`` and ``approved`` are optional keyword-only additions: callers that
use the three-argument form from the contract still work. Without ``incident_id``
the OPEN incident for the service/namespace is looked up.

Guardrails (all checked BEFORE the cluster is touched; refusals cost no attempt)
--------------------------------------------------------------------------------
1. Action allow-list: only ``rollback``, ``restart``, ``scale`` (exact match).
2. Namespace allow-list (``KUBERNETES_NAMESPACE_ALLOWLIST``).
3. ``service`` must be a valid Kubernetes object name (never reaches a shell).
4. Approval: when ``AUTO_REMEDIATE=false`` the caller must pass ``approved=True``
   (set only by the authenticated approve endpoint).
5. An open incident must exist for the service and must match the arguments.
6. Attempt limit: ``MAX_REMEDIATION_ATTEMPTS`` per incident, counted in the
   DATABASE (``incidents.remediation_attempts``), so it survives repeated calls
   and restarts of this Python process.
7. A second ``rollback`` for one incident is refused. A rollback creates a new
   revision, so rolling back again would redeploy the version just rolled back
   from (the bad one).

No arbitrary commands are ever run: ``kubectl`` mode uses a fixed argument list
(no shell), and python mode uses the Kubernetes API.

Recovery is NEVER assumed from a successful command; call ``verify`` and trust
only its result.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess  # nosec B404 - used with fixed argument lists, never shell=True
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from kubernetes import client
from kubernetes.client.exceptions import ApiException

from backend import config, db, kube

logger = logging.getLogger(__name__)

ALLOWED_ACTIONS = ("rollback", "restart", "scale")

KUBECTL_TIMEOUT_SECONDS = 60
MAX_KUBECTL_OUTPUT_CHARS = 300

RESTART_ANNOTATION = "kubectl.kubernetes.io/restartedAt"
REVISION_ANNOTATION = "deployment.kubernetes.io/revision"
POD_TEMPLATE_HASH_LABEL = "pod-template-hash"  # controller-managed; must not be copied

#: Kubernetes object names are DNS-1123 subdomains (max 253 characters).
_K8S_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")

# Indirection so tests can run verification without real waiting.
_sleep = time.sleep
_monotonic = time.monotonic

_serializer: Optional[client.ApiClient] = None


class RemediationError(Exception):
    """A remediation step failed; the message is safe to show to users."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _result(success: bool, detail: str) -> Dict[str, Any]:
    return {"success": success, "detail": detail}


def _refuse(detail: str) -> Dict[str, Any]:
    logger.warning("Remediation refused: %s", detail)
    return _result(False, f"Refused: {detail}")


def _is_valid_name(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 253 and bool(_K8S_NAME.match(value))


def _serialize(obj: Any) -> Any:
    """Convert a Kubernetes model to plain JSON-ready dicts (camelCase API names)."""
    global _serializer
    if _serializer is None:
        _serializer = client.ApiClient()
    return _serializer.sanitize_for_serialization(obj)


def _revision(obj: Any) -> Optional[int]:
    raw = (getattr(obj.metadata, "annotations", None) or {}).get(REVISION_ANNOTATION)
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _selector_string(deployment: Any) -> Optional[str]:
    match_labels = getattr(getattr(deployment.spec, "selector", None), "match_labels", None) or {}
    if not match_labels:
        return None
    return ",".join(f"{k}={v}" for k, v in sorted(match_labels.items()))


def _owned_replica_sets(apps_api: Any, namespace: str, deployment: Any) -> List[Any]:
    """ReplicaSets controlled by ``deployment`` (matched by owner UID)."""
    kwargs: Dict[str, Any] = {"_request_timeout": kube.REQUEST_TIMEOUT_SECONDS}
    selector = _selector_string(deployment)
    if selector:
        kwargs["label_selector"] = selector
    uid = getattr(deployment.metadata, "uid", None)
    owned = []
    for rs in apps_api.list_namespaced_replica_set(namespace, **kwargs).items:
        for ref in getattr(rs.metadata, "owner_references", None) or []:
            if getattr(ref, "kind", None) == "Deployment" and (
                ref.uid == uid if uid else ref.name == deployment.metadata.name
            ):
                owned.append(rs)
                break
    return owned


def _describe_api_error(exc: Exception) -> str:
    if isinstance(exc, ApiException):
        return f"Kubernetes API error: HTTP {exc.status} {exc.reason}"
    return f"{type(exc).__name__}: {exc}"[:200]


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------


def _rollback_kubectl(namespace: str, service: str) -> str:
    """Run ``kubectl rollout undo`` with a fixed argument list (no shell)."""
    kubectl = shutil.which("kubectl")
    if kubectl is None:
        raise RemediationError("kubectl executable not found on PATH (use ROLLBACK_MODE=python)")
    command = [kubectl]
    context = os.environ.get("KUBE_CONTEXT", "").strip()
    if context:
        command += ["--context", context]
    command += ["--namespace", namespace, "rollout", "undo", f"deployment/{service}"]
    try:
        completed = subprocess.run(  # nosec B603 - fixed argv, validated inputs, no shell
            command, capture_output=True, text=True, timeout=KUBECTL_TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise RemediationError(f"kubectl rollout undo timed out after {KUBECTL_TIMEOUT_SECONDS}s") from exc
    except OSError as exc:
        raise RemediationError(f"could not run kubectl: {exc}") from exc
    output = (completed.stdout or "").strip() or (completed.stderr or "").strip()
    output = output[:MAX_KUBECTL_OUTPUT_CHARS]
    if completed.returncode != 0:
        raise RemediationError(f"kubectl rollout undo failed (exit {completed.returncode}): {output}")
    return f"kubectl rollout undo: {output or 'ok'}"


def _rollback_python(namespace: str, service: str) -> str:
    """Restore the previous revision's pod template through the Kubernetes API.

    Equivalent to ``kubectl rollout undo``: the previous ReplicaSet is the one
    with the highest revision number BELOW the Deployment's current revision (the
    current, failing ReplicaSet is never selected). Its pod template replaces the
    Deployment's template, minus the controller-managed ``pod-template-hash``
    label.
    """
    apps_api = kube.apps_v1()
    deployment = apps_api.read_namespaced_deployment(
        service, namespace, _request_timeout=kube.REQUEST_TIMEOUT_SECONDS
    )
    revisions: List[Tuple[int, Any]] = []
    for rs in _owned_replica_sets(apps_api, namespace, deployment):
        revision = _revision(rs)
        if revision is not None:
            revisions.append((revision, rs))
    if not revisions:
        raise RemediationError("no ReplicaSet revisions found; nothing to roll back to")

    current = _revision(deployment)
    if current is None:
        current = max(revision for revision, _ in revisions)
    older = [(revision, rs) for revision, rs in revisions if revision < current]
    if not older:
        raise RemediationError(f"no revision older than the current revision {current}; nothing to roll back to")
    target_revision, target = max(older, key=lambda pair: pair[0])

    template = _serialize(target.spec.template)
    labels = (template.get("metadata") or {}).get("labels")
    if isinstance(labels, dict):
        labels.pop(POD_TEMPLATE_HASH_LABEL, None)

    operations: List[Dict[str, Any]] = []
    if (getattr(deployment.metadata, "annotations", None) or {}).get(REVISION_ANNOTATION) is not None:
        # Abort if someone changed the Deployment between our read and this patch.
        operations.append({
            "op": "test",
            "path": "/metadata/annotations/deployment.kubernetes.io~1revision",
            "value": str(current),
        })
    operations.append({"op": "replace", "path": "/spec/template", "value": template})
    apps_api.patch_namespaced_deployment(
        service, namespace, operations,
        _content_type="application/json-patch+json",
        _request_timeout=kube.REQUEST_TIMEOUT_SECONDS,
    )
    images = [c.image for c in (target.spec.template.spec.containers or [])]
    return (
        f"Rolled back {namespace}/{service} from revision {current} to revision "
        f"{target_revision} ({target.metadata.name}, image {', '.join(images)})"
    )


def _rollback(namespace: str, service: str) -> str:
    mode = config.get_settings().rollback_mode
    if mode == "kubectl":
        return _rollback_kubectl(namespace, service)
    return _rollback_python(namespace, service)


def _restart(namespace: str, service: str) -> str:
    """Trigger a rolling restart by stamping the pod template annotations."""
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    body = {"spec": {"template": {"metadata": {"annotations": {RESTART_ANNOTATION: stamp}}}}}
    kube.apps_v1().patch_namespaced_deployment(
        service, namespace, body,
        _content_type="application/merge-patch+json",
        _request_timeout=kube.REQUEST_TIMEOUT_SECONDS,
    )
    return f"Rolling restart of {namespace}/{service} requested at {stamp}"


def _scale(namespace: str, service: str) -> str:
    """Set the replica count to the configured target (``SCALE_TARGET_REPLICAS``)."""
    target = config.get_settings().scale_target_replicas
    if not isinstance(target, int) or isinstance(target, bool) or not 1 <= target <= 10:
        raise RemediationError(f"invalid scale target {target!r}; must be 1-10")
    apps_api = kube.apps_v1()
    deployment = apps_api.read_namespaced_deployment(
        service, namespace, _request_timeout=kube.REQUEST_TIMEOUT_SECONDS
    )
    current = getattr(deployment.spec, "replicas", None)
    if current == target:
        return f"{namespace}/{service} already has {target} replicas; no change made"
    apps_api.patch_namespaced_deployment(
        service, namespace, {"spec": {"replicas": target}},
        _content_type="application/merge-patch+json",
        _request_timeout=kube.REQUEST_TIMEOUT_SECONDS,
    )
    return f"Scaled {namespace}/{service} from {current} to {target} replicas"


_ACTIONS = {"rollback": _rollback, "restart": _restart, "scale": _scale}


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------


def execute(
    action: str,
    namespace: str,
    service: str,
    *,
    incident_id: Optional[int] = None,
    approved: bool = False,
) -> Dict[str, Any]:
    """Run one guarded remediation. Never raises; returns ``{"success", "detail"}``."""
    settings = config.get_settings()

    # 1-3: static validation
    if not isinstance(action, str) or action not in ALLOWED_ACTIONS:
        return _refuse(f"action must be one of {', '.join(ALLOWED_ACTIONS)}")
    if not isinstance(namespace, str) or not settings.is_namespace_allowed(namespace):
        return _refuse("namespace is not in the allow-list")
    if not _is_valid_name(service):
        return _refuse("service is not a valid Kubernetes name")

    # 4: approval
    if not settings.auto_remediate and not approved:
        return _refuse("approval required (AUTO_REMEDIATE=false); approve the incident first")

    # 5-7: incident, attempt limit, rollback repeat
    try:
        if incident_id is None:
            open_incident = db.find_open_incident(service, namespace)
            if open_incident is None:
                return _refuse(f"no open incident for {namespace}/{service}")
            incident_id = open_incident["id"]
        incident = db.get_incident(incident_id)
        if incident is None:
            return _refuse(f"incident {incident_id} does not exist")
        if incident["service"] != service or incident["namespace"] != namespace:
            return _refuse(f"incident {incident_id} does not belong to {namespace}/{service}")
        if incident["status"] in db.TERMINAL_STATUSES:
            return _refuse(f"incident {incident_id} is already {incident['status']}")
        used = incident.get("remediation_attempts", 0)
        if used >= settings.max_remediation_attempts:
            return _refuse(
                f"attempt limit reached ({used}/{settings.max_remediation_attempts}) for incident {incident_id}"
            )
        if action == "rollback" and used >= 1 and incident.get("action") == "rollback":
            return _refuse(
                "a rollback was already attempted for this incident; repeating it would redeploy the bad version"
            )
        attempt = db.increment_remediation_attempts(incident_id)
    except Exception as exc:  # noqa: BLE001 - database trouble must fail closed
        logger.exception("Could not check remediation guardrails")
        return _result(False, f"Refused: could not verify guardrails ({type(exc).__name__})")
    if attempt > settings.max_remediation_attempts:  # lost a race with a concurrent caller
        return _refuse(f"attempt limit reached ({settings.max_remediation_attempts}) for incident {incident_id}")

    logger.info("Executing %s on %s/%s (incident %s, attempt %s/%s)", action, namespace, service,
                incident_id, attempt, settings.max_remediation_attempts)
    try:
        detail = _ACTIONS[action](namespace, service)
    except RemediationError as exc:
        logger.warning("Remediation %s failed: %s", action, exc)
        return _result(False, f"{action} failed: {exc}")
    except kube.KubeConfigError as exc:
        return _result(False, f"{action} failed: Kubernetes is not reachable ({exc})")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Remediation %s failed: %s", action, _describe_api_error(exc))
        return _result(False, f"{action} failed: {_describe_api_error(exc)}")
    return _result(True, f"{detail} (attempt {attempt}/{settings.max_remediation_attempts})")


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


class _NonRecoverable(Exception):
    """Verification cannot succeed no matter how long we wait."""


def _check_recovered(namespace: str, service: str) -> Tuple[bool, str]:
    """One verification pass. Returns (recovered, human-readable reason)."""
    apps_api = kube.apps_v1()
    core_api = kube.core_v1()
    try:
        deployment = apps_api.read_namespaced_deployment(
            service, namespace, _request_timeout=kube.REQUEST_TIMEOUT_SECONDS
        )
    except ApiException as exc:
        if exc.status in (401, 403, 404):
            raise _NonRecoverable(f"cannot read deployment (HTTP {exc.status} {exc.reason})") from exc
        raise

    desired = deployment.spec.replicas if deployment.spec.replicas is not None else 1
    if desired < 1:
        return False, "deployment is scaled to 0 replicas"
    status = deployment.status
    generation = getattr(deployment.metadata, "generation", None)
    observed = getattr(status, "observed_generation", None)
    if generation is not None and observed is not None and observed < generation:
        return False, "deployment controller has not observed the latest spec yet"

    counts = {
        "replicas": getattr(status, "replicas", None) or 0,
        "updated": getattr(status, "updated_replicas", None) or 0,
        "ready": getattr(status, "ready_replicas", None) or 0,
        "available": getattr(status, "available_replicas", None) or 0,
    }
    if counts["updated"] < desired:
        return False, f"rollout in progress: {counts['updated']}/{desired} replicas updated"
    if counts["replicas"] > counts["updated"]:
        return False, f"old replicas still terminating ({counts['replicas'] - counts['updated']} left)"
    if counts["ready"] != desired or counts["available"] != desired:
        return False, f"{counts['ready']}/{desired} replicas ready, {counts['available']}/{desired} available"

    kwargs: Dict[str, Any] = {"_request_timeout": kube.REQUEST_TIMEOUT_SECONDS}
    selector = _selector_string(deployment)
    if selector:
        kwargs["label_selector"] = selector
    rs_names = {rs.metadata.name for rs in _owned_replica_sets(apps_api, namespace, deployment)}
    pods = [
        pod for pod in core_api.list_namespaced_pod(namespace, **kwargs).items
        if getattr(pod.metadata, "deletion_timestamp", None) is None
        and any(
            getattr(ref, "kind", None) == "ReplicaSet" and ref.name in rs_names
            for ref in (pod.metadata.owner_references or [])
        )
    ]
    if len(pods) != desired:
        return False, f"{len(pods)} pods found, expected {desired}"
    for pod in pods:
        ready_condition = any(
            getattr(c, "type", None) == "Ready" and c.status == "True"
            for c in (pod.status.conditions or [])
        )
        if pod.status.phase != "Running" or not ready_condition:
            return False, f"pod {pod.metadata.name} is {pod.status.phase} and not Ready"
    return True, f"{desired}/{desired} replicas updated, ready and available; all pods Running and Ready"


def verify_with_detail(
    namespace: str, service: str, timeout: Optional[float] = None
) -> Tuple[bool, str]:
    """Poll until the Deployment has fully recovered or ``timeout`` seconds pass.

    Returns ``(recovered, detail)``. ``recovered`` is True only when the rollout
    is complete and the expected number of pods are Running and Ready. Returns
    False on timeout or on a non-recoverable error (deployment missing, access
    denied, Kubernetes not configured).
    """
    settings = config.get_settings()
    if timeout is None:
        timeout = settings.verification_timeout_seconds
    interval = max(float(settings.verification_interval_seconds), 0.01)
    deadline = _monotonic() + max(float(timeout), 0.0)
    last = "not checked"
    while True:
        try:
            recovered, last = _check_recovered(namespace, service)
            if recovered:
                logger.info("Verification passed for %s/%s: %s", namespace, service, last)
                return True, last
        except _NonRecoverable as exc:
            logger.warning("Verification cannot succeed for %s/%s: %s", namespace, service, exc)
            return False, f"verification impossible: {exc}"
        except kube.KubeConfigError as exc:
            return False, f"verification impossible: Kubernetes is not reachable ({exc})"
        except Exception as exc:  # noqa: BLE001 - transient API/connection error: keep polling
            last = f"transient error: {_describe_api_error(exc)}"
            logger.debug("Verification poll error: %s", last)
        if _monotonic() >= deadline:
            logger.warning("Verification timed out for %s/%s: %s", namespace, service, last)
            return False, f"timed out after {timeout:g}s: {last}"
        _sleep(max(min(interval, deadline - _monotonic()), 0.0))


def verify(namespace: str, service: str, timeout: Optional[float] = None) -> bool:
    """Return True only when ``service`` has fully recovered (see ``verify_with_detail``)."""
    return verify_with_detail(namespace, service, timeout)[0]
