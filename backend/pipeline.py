"""Incident lifecycle: detection loop -> diagnosis -> guarded remediation -> verification.

Public contract::

    handle_incident(issue: dict) -> None          # one full incident lifecycle
    approve_incident(incident_id) -> dict         # authenticated approval of a waiting incident
    DetectorLoop                                  # background polling loop (start / stop / status)
    recover_interrupted_incidents() -> int        # call once at startup
    join_workers(timeout) -> bool                 # wait for background work (shutdown, tests)

Lifecycle (every step is written to the incident timeline)::

    DETECTED -> ANALYZING -> AWAITING_APPROVAL -> REMEDIATING -> VERIFYING -> RESOLVED
                         \\-> (AUTO_REMEDIATE=true skips the approval wait)     \\-> FAILED

Safety rules enforced here:

* RESOLVED is set only when ``remediation.verify_with_detail`` returns True. A
  successful remediation command alone never resolves an incident.
* A remediation refusal/failure or a failed verification always ends in FAILED.
* The pipeline makes exactly ONE remediation attempt per incident. The attempt
  counter, namespace and action allow-lists and approval check live in
  ``remediation.execute``; the pipeline never bypasses them.
* ``approved=True`` is passed to ``execute`` only from :func:`approve_incident`,
  which the API exposes behind API-key authentication.
* At most one incident is open per service and namespace, and a cooldown applies
  after an incident closes (RESOLVED or FAILED).
* ``incidents.action`` records the action actually attempted, which is what
  lets ``remediation.execute`` refuse a repeated rollback.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from backend import collector, config, db, detector, kube, rca, remediation

logger = logging.getLogger(__name__)

ALLOWED_ACTIONS = remediation.ALLOWED_ACTIONS

#: Upper bound on incident-processing threads started by the detector loop.
MAX_CONCURRENT_INCIDENTS = 4

#: Seconds to wait for the detector thread / background workers on shutdown.
DETECTOR_STOP_TIMEOUT_SECONDS = 15.0
WORKER_JOIN_TIMEOUT_SECONDS = 10.0

#: Statuses that mean "a worker was in the middle of this incident".
INTERRUPTIBLE_STATUSES = ("DETECTED", "ANALYZING", "REMEDIATING", "VERIFYING")

# Serialises "check for an open incident / cooldown, then create" across threads.
_creation_lock = threading.Lock()

# Background threads (incident processing and approvals), tracked for shutdown.
_workers_lock = threading.Lock()
_workers: Set[threading.Thread] = set()


class ApprovalError(Exception):
    """An approval request cannot be honoured.

    ``kind`` is ``"not_found"``, ``"conflict"`` (wrong state or already being
    processed) or ``"invalid"`` (the incident has nothing valid to approve). The
    API maps these to HTTP 404, 409 and 422.
    """

    def __init__(self, message: str, kind: str) -> None:
        super().__init__(message)
        self.kind = kind


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _empty_evidence() -> Dict[str, Any]:
    return {"logs": [], "events": [], "pods": [], "last_deploy_time": None, "rollout_history": []}


def _seconds_since(iso_timestamp: Optional[str]) -> Optional[float]:
    """Seconds elapsed since an ISO 8601 timestamp, or ``None`` if unparseable."""
    if not iso_timestamp:
        return None
    try:
        then = datetime.fromisoformat(iso_timestamp)
    except ValueError:
        return None
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - then).total_seconds()


def _spawn(name: str, target: Callable[[], None]) -> threading.Thread:
    """Run ``target`` in a tracked daemon thread; its exceptions are logged, never lost."""

    def runner() -> None:
        try:
            target()
        except Exception:  # noqa: BLE001 - a worker must never die silently
            logger.exception("Unhandled error in worker thread %s", name)
        finally:
            with _workers_lock:
                _workers.discard(threading.current_thread())

    thread = threading.Thread(target=runner, name=name, daemon=True)
    with _workers_lock:
        _workers.add(thread)
    thread.start()
    return thread


def join_workers(timeout: float = WORKER_JOIN_TIMEOUT_SECONDS) -> bool:
    """Wait for background workers to finish. Returns False if some are still running."""
    deadline = time.monotonic() + max(timeout, 0.0)
    while True:
        with _workers_lock:
            pending = [t for t in _workers if t.is_alive()]
        if not pending:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        pending[0].join(timeout=min(remaining, 0.1))


def _fail(incident_id: int, message: str) -> None:
    """Mark an incident FAILED and record why. Never raises."""
    try:
        db.update_incident(incident_id, status="FAILED")
        db.add_timeline(incident_id, "FAILED", message)
    except Exception:  # noqa: BLE001
        logger.exception("Could not record failure of incident %s", incident_id)
    logger.warning("Incident %s FAILED: %s", incident_id, message)


def _attempts(incident_id: int) -> int:
    incident = db.get_incident(incident_id)
    return int(incident["remediation_attempts"]) if incident else 0


# ---------------------------------------------------------------------------
# Duplicate prevention and cooldown
# ---------------------------------------------------------------------------


def skip_reason(service: str, namespace: str, cluster_id: Optional[int] = None) -> Optional[str]:
    """Return why a new incident must NOT be created now, or ``None`` if it may.

    Reasons: an incident is still open for the service, or the cooldown after
    the last closed (RESOLVED or FAILED) incident has not elapsed. ``cluster_id``
    scopes both checks to one cluster (the same service name may exist in several).
    """
    open_incident = db.find_open_incident(service, namespace, cluster_id)
    if open_incident is not None:
        return f"incident {open_incident['id']} is still open ({open_incident['status']})"
    cooldown = config.get_settings().incident_cooldown_seconds
    if cooldown > 0:
        elapsed = _seconds_since(db.get_last_closed_at(service, namespace, cluster_id))
        if elapsed is not None and elapsed < cooldown:
            return f"cooldown active ({cooldown - max(elapsed, 0):.0f}s remaining)"
    return None


def _validate_issue(issue: Any) -> Optional[Tuple[str, str, str]]:
    """Return ``(service, namespace, reason)`` for a well-formed issue, else ``None``."""
    if not isinstance(issue, dict):
        return None
    values = []
    for key in ("service", "namespace", "reason"):
        value = issue.get(key)
        if not isinstance(value, str) or not value.strip():
            return None
        values.append(value.strip())
    return values[0], values[1], values[2]


def _cluster_id_of(issue: Any) -> int:
    """The cluster an issue was detected in (the built-in cluster when unspecified)."""
    value = issue.get("cluster_id") if isinstance(issue, dict) else None
    if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
        return value
    return db.DEFAULT_CLUSTER_ID


def _context_of(cluster_id: int) -> Optional[str]:
    """kubeconfig context for a cluster id (``None`` = the built-in cluster)."""
    try:
        cluster = db.get_cluster(cluster_id)
    except Exception:  # noqa: BLE001
        logger.exception("Could not look up cluster %s", cluster_id)
        return None
    return cluster["context"] if cluster else None


def _create_incident_if_allowed(
    service: str, namespace: str, reason: str, cluster_id: int = db.DEFAULT_CLUSTER_ID
) -> Optional[int]:
    """Atomically check the open-incident and cooldown rules, then create the incident."""
    with _creation_lock:
        try:
            skip = skip_reason(service, namespace, cluster_id)
            if skip is not None:
                logger.info("Not creating an incident for %s/%s: %s", namespace, service, skip)
                return None
            return db.create_incident(service, namespace, reason, cluster_id)
        except Exception:  # noqa: BLE001 - fail closed: no incident rather than a duplicate
            logger.exception("Could not create an incident for %s/%s", namespace, service)
            return None


# ---------------------------------------------------------------------------
# Lifecycle steps
# ---------------------------------------------------------------------------


def _record_detection(incident_id: int, service: str, namespace: str, reason: str) -> None:
    """Attach a matching failure-injection timestamp (if any) and log DETECTED."""
    injected_at: Optional[str] = None
    try:
        injected_at = db.claim_injection(incident_id, config.get_settings().injection_max_age_seconds)
    except Exception:  # noqa: BLE001 - MTTD is optional; never block the incident
        logger.exception("Could not look up the failure injection for incident %s", incident_id)
    if injected_at:
        message = f"Detected {reason} on {namespace}/{service}. Matched the failure injection recorded at {injected_at}."
    else:
        message = f"Detected {reason} on {namespace}/{service}. No recent failure injection was recorded (MTTD unavailable)."
    db.add_timeline(incident_id, "DETECTED", message)


def _collect(incident_id: int, namespace: str, service: str) -> Dict[str, Any]:
    """Collect evidence; a collection failure degrades to empty evidence, never aborts."""
    try:
        evidence = collector.collect_evidence(namespace, service)
        if not isinstance(evidence, dict):
            raise TypeError("collector returned a non-dict value")
        return evidence
    except Exception as exc:  # noqa: BLE001
        logger.exception("Evidence collection failed for incident %s", incident_id)
        db.add_timeline(
            incident_id, "ANALYZING",
            f"Evidence collection failed ({type(exc).__name__}); continuing with empty evidence.",
        )
        return _empty_evidence()


def _diagnose(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Run RCA; if it misbehaves, use the deterministic fallback."""
    try:
        result = rca.analyze(evidence)
        if not isinstance(result, dict):
            raise TypeError("analyze() returned a non-dict value")
        return result
    except Exception as exc:  # noqa: BLE001 - analyze() should never raise, but we do not trust that
        logger.exception("RCA raised unexpectedly; using fallback analysis")
        reason = f"analysis raised {type(exc).__name__}"
    try:
        return rca.fallback_analysis(evidence, reason)
    except Exception:  # noqa: BLE001
        logger.exception("Fallback analysis failed; using the most conservative diagnosis")
        return {
            "probable_cause": f"Automated analysis was unavailable ({reason}).",
            "evidence": [],
            "confidence": 0.3,
            "recommended_action": "restart",
            "source": "fallback",
        }


def _evidence_summary(evidence: Dict[str, Any]) -> str:
    def count(key: str) -> int:
        value = evidence.get(key)
        return len(value) if isinstance(value, list) else 0

    return (
        f"Evidence collected: {count('pods')} pod(s), {count('logs')} log source(s), "
        f"{count('events')} event(s), {count('rollout_history')} ReplicaSet revision(s)."
    )


def _remediate_and_verify(
    incident_id: int, namespace: str, service: str, action: str, *, approved: bool, announce: str
) -> None:
    """Execute ONE remediation, verify recovery, and record RESOLVED or FAILED."""
    settings = config.get_settings()

    db.update_incident(incident_id, status="REMEDIATING")
    mode = f" (ROLLBACK_MODE={settings.rollback_mode})" if action == "rollback" else ""
    db.add_timeline(incident_id, "REMEDIATING", f"{announce} Executing '{action}'{mode}.")

    attempts_before = _attempts(incident_id)
    result = remediation.execute(action, namespace, service, incident_id=incident_id, approved=approved)
    success = bool(result.get("success"))
    detail = str(result.get("detail", ""))

    # Record the action ACTUALLY attempted (the rollback-repeat guard in
    # remediation.execute reads this). Refusals consume no attempt, so they are not recorded.
    if success or _attempts(incident_id) > attempts_before:
        db.update_incident(incident_id, action=action)

    if not success:
        _fail(incident_id, f"Remediation '{action}' did not succeed: {detail}")
        return
    db.add_timeline(incident_id, "REMEDIATING", f"Remediation succeeded: {detail}")

    db.update_incident(incident_id, status="VERIFYING")
    db.add_timeline(
        incident_id, "VERIFYING",
        f"Verifying recovery of {namespace}/{service} (timeout {settings.verification_timeout_seconds}s).",
    )
    recovered, verification = remediation.verify_with_detail(namespace, service)
    if not recovered:
        _fail(incident_id, f"Recovery verification failed: {verification}")
        return

    db.update_incident(incident_id, status="RESOLVED", resolved_at=db.utc_now_iso())
    db.add_timeline(incident_id, "RESOLVED", f"Recovery verified: {verification}")
    logger.info("Incident %s RESOLVED", incident_id)


def _run_lifecycle(incident_id: int, service: str, namespace: str, reason: str) -> None:
    settings = config.get_settings()
    _record_detection(incident_id, service, namespace, reason)

    db.update_incident(incident_id, status="ANALYZING")
    db.add_timeline(incident_id, "ANALYZING", "Collecting diagnostic evidence (logs, events, pods, rollout history).")
    evidence = _collect(incident_id, namespace, service)
    db.update_incident(incident_id, evidence_json=evidence)
    db.add_timeline(incident_id, "ANALYZING", _evidence_summary(evidence))

    diagnosis = _diagnose(evidence)
    db.update_incident(incident_id, rca_json=diagnosis)
    action = diagnosis.get("recommended_action")
    try:
        confidence = f"{float(diagnosis.get('confidence')):.2f}"
    except (TypeError, ValueError):
        confidence = "n/a"
    db.add_timeline(
        incident_id, "ANALYZING",
        f"Diagnosis ({diagnosis.get('source', 'unknown')}, confidence {confidence}): "
        f"{diagnosis.get('probable_cause', 'no cause given')} Recommended action: {action}.",
    )

    # A model/fallback answer is only a recommendation; refuse anything off the allow-list.
    if action not in ALLOWED_ACTIONS:
        _fail(incident_id, f"The diagnosis recommended an unsupported action ({action!r}); nothing was executed.")
        return

    if not settings.auto_remediate:
        db.update_incident(incident_id, status="AWAITING_APPROVAL")
        db.add_timeline(
            incident_id, "AWAITING_APPROVAL",
            f"Diagnosis saved. Recommended action '{action}' is waiting for approval "
            f"(AUTO_REMEDIATE=false). Approve with POST /api/incidents/{incident_id}/approve.",
        )
        return

    _remediate_and_verify(
        incident_id, namespace, service, action,
        approved=False, announce="AUTO_REMEDIATE=true: no approval wait.",
    )


# ---------------------------------------------------------------------------
# Public contract
# ---------------------------------------------------------------------------


def handle_incident(issue: Dict[str, Any]) -> None:
    """Run one incident through its full lifecycle. Never raises.

    ``issue`` is a detector result: ``{"service", "namespace", "reason"}``.
    Does nothing (and creates no incident) when the issue is malformed, the
    namespace is not allow-listed, an incident is already open for the service,
    or the cooldown after the previous incident has not elapsed.
    """
    parsed = _validate_issue(issue)
    if parsed is None:
        logger.warning("Ignoring malformed issue: %r", issue)
        return
    service, namespace, reason = parsed
    if not config.get_settings().is_namespace_allowed(namespace):
        logger.warning("Ignoring issue for namespace %r: not in the allow-list", namespace)
        return

    cluster_id = _cluster_id_of(issue)
    if db.get_cluster(cluster_id) is None:
        logger.warning("Ignoring issue for cluster %s: it is not connected (any more)", cluster_id)
        return

    incident_id = _create_incident_if_allowed(service, namespace, reason, cluster_id)
    if incident_id is None:
        return
    try:
        # Every Kubernetes call of this lifecycle (evidence, remediation, verification)
        # goes to the cluster the issue was detected in, never to another one.
        with kube.use_cluster(_context_of(cluster_id)):
            _run_lifecycle(incident_id, service, namespace, reason)
    except Exception as exc:  # noqa: BLE001 - keep the incident record, mark it failed
        logger.exception("Incident %s failed unexpectedly", incident_id)
        _fail(incident_id, f"Unexpected pipeline error ({type(exc).__name__}); see the backend logs.")


def approve_incident(incident_id: int, *, background: bool = True) -> Dict[str, Any]:
    """Approve a waiting incident and run its RECOMMENDED action.

    The caller (the authenticated API endpoint) has already verified the API key.
    Only the stored, validated recommendation is ever executed; nothing from the
    request influences the action. The status moves AWAITING_APPROVAL ->
    REMEDIATING with a compare-and-set, so concurrent approvals run it once.

    Args:
        incident_id: the incident to approve.
        background: run remediation + verification in a worker thread and return
            immediately (default). ``False`` runs inline (used by tests).

    Returns:
        ``{"id", "status": "REMEDIATING", "action", "approved": True}``

    Raises:
        ApprovalError: not found / wrong state / no valid recommendation.
    """
    incident = db.get_incident(incident_id)
    if incident is None:
        raise ApprovalError(f"Incident {incident_id} not found", "not_found")
    if incident["status"] != "AWAITING_APPROVAL":
        raise ApprovalError(
            f"Incident {incident_id} is {incident['status']}; only AWAITING_APPROVAL incidents can be approved",
            "conflict",
        )
    diagnosis = incident.get("rca")
    action = diagnosis.get("recommended_action") if isinstance(diagnosis, dict) else None
    if action not in ALLOWED_ACTIONS:
        raise ApprovalError(f"Incident {incident_id} has no valid recommended action to approve", "invalid")
    namespace, service = incident["namespace"], incident["service"]
    if not config.get_settings().is_namespace_allowed(namespace):
        raise ApprovalError(f"Namespace {namespace!r} is not in the allow-list", "invalid")

    if not db.transition_status(incident_id, "AWAITING_APPROVAL", "REMEDIATING"):
        raise ApprovalError(f"Incident {incident_id} was already approved or changed state", "conflict")

    context = _context_of(incident.get("cluster_id") or db.DEFAULT_CLUSTER_ID)

    def work() -> None:
        try:
            with kube.use_cluster(context):
                _remediate_and_verify(
                    incident_id, namespace, service, action,
                    approved=True, announce="Approved through the authenticated API.",
                )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Approved remediation for incident %s failed unexpectedly", incident_id)
            _fail(incident_id, f"Unexpected pipeline error ({type(exc).__name__}); see the backend logs.")

    if background:
        _spawn(f"approval-{incident_id}", work)
    else:
        work()
    return {"id": incident_id, "status": "REMEDIATING", "action": action, "approved": True}


def recover_interrupted_incidents() -> int:
    """Fail incidents whose worker was killed by a backend restart. Returns how many.

    Call once at startup, before the detector loop. An interrupted incident would
    otherwise stay open forever and block new incidents for its service.
    AWAITING_APPROVAL incidents are left alone: approval can still arrive.
    """
    count = 0
    for incident in db.list_incidents_with_status(INTERRUPTIBLE_STATUSES):
        _fail(
            incident["id"],
            "Processing was interrupted by a backend restart and the outcome is unknown. "
            "Check the workload with kubectl.",
        )
        count += 1
    if count:
        logger.warning("Marked %d interrupted incident(s) as FAILED", count)
    return count


# ---------------------------------------------------------------------------
# Detector loop
# ---------------------------------------------------------------------------


class DetectorLoop:
    """Poll the cluster and start at most one incident worker per service.

    Thread budget: one polling thread, plus at most one worker per
    (namespace, service) and at most :data:`MAX_CONCURRENT_INCIDENTS` workers
    overall, so repeated polls of a broken service cannot spawn unbounded threads.
    """

    def __init__(self, max_workers: int = MAX_CONCURRENT_INCIDENTS) -> None:
        self._max_workers = max_workers
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._active: Set[Tuple[int, str, str]] = set()
        self._interval = float(config.get_settings().detector_interval_seconds)
        self._last_poll_at: Optional[str] = None
        self._last_issue_count = 0

    # -- lifecycle ----------------------------------------------------------

    @property
    def running(self) -> bool:
        """True while the polling thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        """Start polling in a background thread. Calling it twice is harmless."""
        with self._lock:
            if self.running:
                return
            self._stop.clear()
            self._interval = float(config.get_settings().detector_interval_seconds)
            self._thread = threading.Thread(target=self._run, name="detector-loop", daemon=True)
            self._thread.start()

    def stop(self, timeout: float = DETECTOR_STOP_TIMEOUT_SECONDS) -> bool:
        """Ask the loop to stop and wait for it. Returns False if it did not stop in time."""
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)
            if thread.is_alive():
                logger.warning("Detector loop did not stop within %.0fs", timeout)
                return False
        return True

    def status(self) -> Dict[str, Any]:
        """Snapshot for the API status endpoint."""
        with self._lock:
            return {
                "running": self.running,
                "interval_seconds": self._interval,
                "last_poll_at": self._last_poll_at,
                "last_poll_issue_count": self._last_issue_count,
                "in_flight": sorted(
                    f"{ns}/{svc}" if cid == db.DEFAULT_CLUSTER_ID else f"cluster-{cid}:{ns}/{svc}"
                    for cid, ns, svc in self._active
                ),
            }

    # -- polling ------------------------------------------------------------

    def _run(self) -> None:
        logger.info("Detector loop started (interval %.0fs)", self._interval)
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:  # noqa: BLE001 - one bad poll must not end the loop
                logger.exception("Detector poll failed; retrying on the next interval")
            self._stop.wait(self._interval)
        logger.info("Detector loop stopped")

    def run_once(self) -> int:
        """Poll once and start workers for new incidents. Returns how many were started."""
        issues = self._poll_all_clusters()
        with self._lock:
            self._last_poll_at = db.utc_now_iso()
            self._last_issue_count = len(issues)
        started = 0
        for issue in issues:
            if self._stop.is_set():
                break
            if self._try_start(issue):
                started += 1
        return started

    def _poll_all_clusters(self) -> List[Dict[str, Any]]:
        """Run the detector against every connected cluster; tag each issue with its cluster id."""
        try:
            clusters = db.list_clusters()
        except Exception:  # noqa: BLE001 - fall back to the built-in cluster
            logger.exception("Could not list clusters; polling the built-in cluster only")
            clusters = [{"id": db.DEFAULT_CLUSTER_ID, "context": None}]
        issues: List[Dict[str, Any]] = []
        for cluster in clusters:
            if self._stop.is_set():
                break
            try:
                with kube.use_cluster(cluster["context"]):
                    found = detector.check_cluster()
            except Exception:  # noqa: BLE001 - check_cluster should never raise; do not trust that
                logger.exception("check_cluster() raised for cluster %s", cluster["id"])
                continue
            for issue in found or []:
                issues.append({**issue, "cluster_id": cluster["id"]} if isinstance(issue, dict) else issue)
        return issues

    def _try_start(self, issue: Any) -> bool:
        parsed = _validate_issue(issue)
        if parsed is None:
            logger.warning("Detector returned a malformed issue: %r", issue)
            return False
        service, namespace, _reason = parsed
        cluster_id = _cluster_id_of(issue)
        key = (cluster_id, namespace, service)
        with self._lock:
            if key in self._active:
                return False  # a worker is already handling this service
            if len(self._active) >= self._max_workers:
                logger.warning("Worker limit (%d) reached; %s/%s will be retried", self._max_workers, namespace, service)
                return False
            try:
                skip = skip_reason(service, namespace, cluster_id)
            except Exception:  # noqa: BLE001
                logger.exception("Could not check open incidents for %s/%s", namespace, service)
                return False
            if skip is not None:
                logger.debug("No new incident for %s/%s: %s", namespace, service, skip)
                return False
            self._active.add(key)

        def work() -> None:
            try:
                handle_incident(issue)
            finally:
                with self._lock:
                    self._active.discard(key)

        try:
            _spawn(f"incident-{namespace}-{service}", work)
        except Exception:  # noqa: BLE001 - e.g. cannot start a new thread; allow a retry next poll
            logger.exception("Could not start a worker for %s/%s", namespace, service)
            with self._lock:
                self._active.discard(key)
            return False
        return True
