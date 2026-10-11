"""Tests for backend/pipeline.py: lifecycle, guardrails, approval and the detector loop.

Kubernetes, Gemini and the remediation commands are replaced by the ``world``
fixture (see conftest.py); nothing here needs a cluster or network access.
"""

from __future__ import annotations

import threading
import time

import pytest

from backend import db, detector, pipeline, remediation
from conftest import set_settings

REAL_EXECUTE = remediation.execute  # captured before any test patches it

ISSUE = {"service": "shop-api", "namespace": "default", "reason": "CrashLoopBackOff"}


def wait_until(predicate, timeout=5.0, interval=0.01):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def collapsed_steps(incident):
    """Timeline steps with consecutive duplicates removed."""
    steps = []
    for entry in incident["timeline"]:
        if not steps or steps[-1] != entry["step"]:
            steps.append(entry["step"])
    return steps


def only_incident():
    incidents = db.list_incidents()
    assert len(incidents) == 1, incidents
    return db.get_incident(incidents[0]["id"])


@pytest.fixture(autouse=True)
def _finish_background_work():
    yield
    pipeline.join_workers(5)


@pytest.fixture()
def auto(monkeypatch):
    set_settings(monkeypatch, AUTO_REMEDIATE="true")


# ---------------------------------------------------------------------------
# Successful lifecycle
# ---------------------------------------------------------------------------


def test_auto_remediation_resolves_after_verification(world, auto):
    pipeline.handle_incident(ISSUE)

    incident = only_incident()
    assert incident["status"] == "RESOLVED"
    assert incident["resolved_at"] is not None
    assert incident["mttr_seconds"] is not None
    assert incident["action"] == "rollback"
    assert incident["remediation_attempts"] == 1
    assert incident["evidence"]["logs"][0]["lines"] == ["Exception: DB_URL missing"]
    assert incident["rca"]["recommended_action"] == "rollback"
    assert incident["rca"]["source"] == "llm"
    assert collapsed_steps(incident) == ["DETECTED", "ANALYZING", "REMEDIATING", "VERIFYING", "RESOLVED"]
    assert world.names() == ["collect", "analyze", "execute", "verify"]
    assert world.execute_kwargs == [{"incident_id": incident["id"], "approved": False}]


def test_timeline_messages_are_informative_and_timestamped(world, auto):
    pipeline.handle_incident(ISSUE)
    timeline = only_incident()["timeline"]
    text = " | ".join(entry["message"] for entry in timeline)
    assert "CrashLoopBackOff on default/shop-api" in text
    assert "DB_URL environment variable is missing" in text
    assert "ROLLBACK_MODE=python" in text
    assert "Recovery verified" in text
    stamps = [entry["timestamp"] for entry in timeline]
    assert stamps == sorted(stamps)


def test_resolved_is_set_only_after_verify_ran(world, auto, monkeypatch):
    seen = {}
    original_verify = world.verify

    def spying_verify(namespace, service, timeout=None):
        seen["status_during_verify"] = db.list_incidents()[0]["status"]
        return original_verify(namespace, service, timeout)

    monkeypatch.setattr(remediation, "verify_with_detail", spying_verify)
    pipeline.handle_incident(ISSUE)
    assert seen["status_during_verify"] == "VERIFYING"
    assert only_incident()["status"] == "RESOLVED"


# ---------------------------------------------------------------------------
# Failure paths
# ---------------------------------------------------------------------------


def test_failed_remediation_ends_in_failed_and_skips_verification(world, auto):
    world.execute_result = {"success": False, "detail": "rollback failed: no revision older than the current one"}
    pipeline.handle_incident(ISSUE)
    incident = only_incident()
    assert incident["status"] == "FAILED"
    assert incident["resolved_at"] is None and incident["mttr_seconds"] is None
    assert incident["action"] == "rollback"  # an attempt was consumed, so it is recorded
    assert "verify" not in world.names()
    assert collapsed_steps(incident)[-1] == "FAILED"
    assert "no revision older" in incident["timeline"][-1]["message"]


def test_refused_remediation_fails_without_recording_an_action(world, auto):
    world.execute_consumes_attempt = False
    world.execute_result = {"success": False, "detail": "Refused: namespace is not in the allow-list"}
    pipeline.handle_incident(ISSUE)
    incident = only_incident()
    assert incident["status"] == "FAILED"
    assert incident["action"] is None and incident["remediation_attempts"] == 0
    assert "Refused" in incident["timeline"][-1]["message"]


def test_failed_verification_ends_in_failed_not_resolved(world, auto):
    world.verify_result = (False, "timed out after 120s: 1/2 replicas ready")
    pipeline.handle_incident(ISSUE)
    incident = only_incident()
    assert incident["status"] == "FAILED"
    assert incident["resolved_at"] is None and incident["mttr_seconds"] is None
    assert incident["action"] == "rollback"
    assert "verification failed" in incident["timeline"][-1]["message"].lower()
    assert "1/2 replicas ready" in incident["timeline"][-1]["message"]
    assert "RESOLVED" not in collapsed_steps(incident)
    assert collapsed_steps(incident) == ["DETECTED", "ANALYZING", "REMEDIATING", "VERIFYING", "FAILED"]


def test_unexpected_exception_during_remediation_preserves_incident_as_failed(world, auto):
    world.execute_error = RuntimeError("boom with details that should stay in the logs")
    pipeline.handle_incident(ISSUE)
    incident = only_incident()
    assert incident["status"] == "FAILED"
    assert incident["evidence"] is not None and incident["rca"] is not None  # work so far is preserved
    last = incident["timeline"][-1]["message"]
    assert "RuntimeError" in last and "boom" not in last


def test_unsupported_recommended_action_is_never_executed(world, auto):
    world.diagnosis["recommended_action"] = "delete-everything"
    pipeline.handle_incident(ISSUE)
    incident = only_incident()
    assert incident["status"] == "FAILED"
    assert "execute" not in world.names()
    assert "unsupported action" in incident["timeline"][-1]["message"]


# ---------------------------------------------------------------------------
# Approval workflow
# ---------------------------------------------------------------------------


def test_default_mode_waits_for_approval_and_executes_nothing(world):
    pipeline.handle_incident(ISSUE)
    incident = only_incident()
    assert incident["status"] == "AWAITING_APPROVAL"
    assert incident["rca"]["recommended_action"] == "rollback"
    assert incident["evidence"] is not None
    assert incident["action"] is None and incident["remediation_attempts"] == 0
    assert world.names() == ["collect", "analyze"]
    assert collapsed_steps(incident) == ["DETECTED", "ANALYZING", "AWAITING_APPROVAL"]
    assert f"/api/incidents/{incident['id']}/approve" in incident["timeline"][-1]["message"]


def test_approval_runs_only_the_stored_recommendation_and_resolves(world):
    pipeline.handle_incident(ISSUE)
    incident_id = only_incident()["id"]

    result = pipeline.approve_incident(incident_id, background=False)

    assert result == {"id": incident_id, "status": "REMEDIATING", "action": "rollback", "approved": True}
    incident = db.get_incident(incident_id)
    assert incident["status"] == "RESOLVED" and incident["action"] == "rollback"
    assert world.execute_kwargs == [{"incident_id": incident_id, "approved": True}]
    assert world.names() == ["collect", "analyze", "execute", "verify"]
    assert collapsed_steps(incident) == ["DETECTED", "ANALYZING", "AWAITING_APPROVAL", "REMEDIATING", "VERIFYING", "RESOLVED"]


def test_approved_remediation_failure_ends_in_failed(world):
    pipeline.handle_incident(ISSUE)
    incident_id = only_incident()["id"]
    world.execute_result = {"success": False, "detail": "kubectl rollout undo failed (exit 1)"}
    pipeline.approve_incident(incident_id, background=False)
    assert db.get_incident(incident_id)["status"] == "FAILED"
    assert "verify" not in world.names()


def test_approved_failed_verification_ends_in_failed(world):
    pipeline.handle_incident(ISSUE)
    incident_id = only_incident()["id"]
    world.verify_result = (False, "timed out")
    pipeline.approve_incident(incident_id, background=False)
    incident = db.get_incident(incident_id)
    assert incident["status"] == "FAILED" and incident["resolved_at"] is None


def test_approve_unknown_incident_is_not_found(world):
    with pytest.raises(pipeline.ApprovalError) as exc:
        pipeline.approve_incident(12345, background=False)
    assert exc.value.kind == "not_found"


@pytest.mark.parametrize("status", ["DETECTED", "ANALYZING", "REMEDIATING", "VERIFYING", "RESOLVED", "FAILED"])
def test_approve_requires_awaiting_approval(world, status):
    incident_id = db.create_incident("shop-api", "default", "r")
    db.update_incident(incident_id, status=status, rca_json=world.diagnosis)
    with pytest.raises(pipeline.ApprovalError) as exc:
        pipeline.approve_incident(incident_id, background=False)
    assert exc.value.kind == "conflict"
    assert db.get_incident(incident_id)["status"] == status
    assert world.names() == []


@pytest.mark.parametrize("rca", [None, {}, {"recommended_action": "rm -rf /"}, {"recommended_action": None}, '"just a string"', "[1, 2]"])
def test_approve_without_a_valid_recommendation_is_rejected(world, rca):
    incident_id = db.create_incident("shop-api", "default", "r")
    db.update_incident(incident_id, status="AWAITING_APPROVAL", rca_json=rca)
    with pytest.raises(pipeline.ApprovalError) as exc:
        pipeline.approve_incident(incident_id, background=False)
    assert exc.value.kind == "invalid"
    assert db.get_incident(incident_id)["status"] == "AWAITING_APPROVAL"
    assert world.names() == []


def test_approve_refuses_namespace_outside_allow_list(world):
    incident_id = db.create_incident("shop-api", "kube-system", "r")
    db.update_incident(incident_id, status="AWAITING_APPROVAL", rca_json=world.diagnosis)
    with pytest.raises(pipeline.ApprovalError) as exc:
        pipeline.approve_incident(incident_id, background=False)
    assert exc.value.kind == "invalid"
    assert world.names() == []


def test_approve_in_background_returns_before_remediation_finishes(world):
    pipeline.handle_incident(ISSUE)
    incident_id = only_incident()["id"]
    world.execute_gate = threading.Event()

    result = pipeline.approve_incident(incident_id)  # background by default
    assert result["status"] == "REMEDIATING"
    assert wait_until(lambda: ("execute", "rollback", "default", "shop-api") in world.calls)
    assert db.get_incident(incident_id)["status"] == "REMEDIATING"  # still running

    world.execute_gate.set()
    assert pipeline.join_workers(10)
    assert db.get_incident(incident_id)["status"] == "RESOLVED"


def test_concurrent_approvals_execute_exactly_once(world):
    pipeline.handle_incident(ISSUE)
    incident_id = only_incident()["id"]
    world.execute_gate = threading.Event()
    outcomes, lock = [], threading.Lock()

    def approve():
        try:
            pipeline.approve_incident(incident_id)
            outcome = "ok"
        except pipeline.ApprovalError as exc:
            outcome = exc.kind
        with lock:
            outcomes.append(outcome)

    threads = [threading.Thread(target=approve) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    world.execute_gate.set()
    assert pipeline.join_workers(10)

    assert outcomes.count("ok") == 1
    assert outcomes.count("conflict") == 7
    assert world.names().count("execute") == 1
    assert db.get_incident(incident_id)["status"] == "RESOLVED"


# ---------------------------------------------------------------------------
# Degraded inputs: evidence and RCA problems
# ---------------------------------------------------------------------------


def test_evidence_collection_failure_does_not_stop_the_incident(world):
    world.collect_error = RuntimeError("API unreachable")
    pipeline.handle_incident(ISSUE)
    incident = only_incident()
    assert incident["status"] == "AWAITING_APPROVAL"
    assert incident["evidence"] == {"logs": [], "events": [], "pods": [], "last_deploy_time": None, "rollout_history": []}
    assert any("Evidence collection failed" in e["message"] for e in incident["timeline"])
    assert "analyze" in world.names()


def test_non_dict_evidence_is_treated_as_a_collection_failure(world):
    world.evidence = ["not", "a", "dict"]
    pipeline.handle_incident(ISSUE)
    incident = only_incident()
    assert incident["status"] == "AWAITING_APPROVAL"
    assert set(incident["evidence"]) == {"logs", "events", "pods", "last_deploy_time", "rollout_history"}


def test_fallback_diagnosis_from_rca_is_saved_and_used(world):
    world.diagnosis = {
        "probable_cause": "AI analysis unavailable (Gemini API key not configured). Rule-based assessment: ...",
        "evidence": [], "confidence": 0.4, "recommended_action": "rollback", "source": "fallback",
    }
    pipeline.handle_incident(ISSUE)
    incident = only_incident()
    assert incident["status"] == "AWAITING_APPROVAL"
    assert incident["rca"]["source"] == "fallback"
    assert "fallback" in " ".join(e["message"] for e in incident["timeline"])


def test_rca_raising_unexpectedly_uses_the_real_fallback(world):
    world.analyze_error = RuntimeError("SDK exploded")
    pipeline.handle_incident(ISSUE)
    incident = only_incident()
    assert incident["status"] == "AWAITING_APPROVAL"
    assert incident["rca"]["source"] == "fallback"
    assert incident["rca"]["recommended_action"] in ("rollback", "restart")
    assert "RuntimeError" in incident["rca"]["probable_cause"]


def test_rca_returning_garbage_uses_fallback(world, monkeypatch):
    monkeypatch.setattr(pipeline.rca, "analyze", lambda evidence: "not a dict")
    pipeline.handle_incident(ISSUE)
    assert only_incident()["rca"]["source"] == "fallback"


def test_rca_and_fallback_both_failing_still_yields_a_conservative_diagnosis(world, monkeypatch):
    world.analyze_error = RuntimeError("down")
    monkeypatch.setattr(pipeline.rca, "fallback_analysis", lambda *a, **k: (_ for _ in ()).throw(ValueError("also down")))
    pipeline.handle_incident(ISSUE)
    incident = only_incident()
    assert incident["status"] == "AWAITING_APPROVAL"
    assert incident["rca"]["recommended_action"] == "restart" and incident["rca"]["source"] == "fallback"


# ---------------------------------------------------------------------------
# Duplicate prevention, cooldown and input validation
# ---------------------------------------------------------------------------


def test_no_duplicate_incident_while_one_is_open(world):
    pipeline.handle_incident(ISSUE)
    pipeline.handle_incident(ISSUE)
    pipeline.handle_incident(ISSUE)
    assert len(db.list_incidents()) == 1
    assert world.names().count("collect") == 1


def test_concurrent_detections_create_exactly_one_incident(world):
    start = threading.Barrier(10)

    def detect():
        start.wait(timeout=10)
        pipeline.handle_incident(ISSUE)

    threads = [threading.Thread(target=detect) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert len(db.list_incidents()) == 1
    assert world.names().count("collect") == 1


def test_different_services_each_get_their_own_incident(world):
    pipeline.handle_incident(ISSUE)
    pipeline.handle_incident({**ISSUE, "service": "other-api"})
    assert {i["service"] for i in db.list_incidents()} == {"shop-api", "other-api"}


def test_cooldown_blocks_a_new_incident_after_resolution(world, auto):
    pipeline.handle_incident(ISSUE)
    assert only_incident()["status"] == "RESOLVED"
    pipeline.handle_incident(ISSUE)
    assert len(db.list_incidents()) == 1


def test_cooldown_also_applies_after_a_failed_incident(world, auto):
    world.verify_result = (False, "timed out")
    pipeline.handle_incident(ISSUE)
    assert only_incident()["status"] == "FAILED"
    pipeline.handle_incident(ISSUE)
    assert len(db.list_incidents()) == 1


def test_new_incident_is_allowed_once_the_cooldown_is_disabled(world, monkeypatch):
    set_settings(monkeypatch, AUTO_REMEDIATE="true", INCIDENT_COOLDOWN_SECONDS="0")
    pipeline.handle_incident(ISSUE)
    pipeline.handle_incident(ISSUE)
    assert len(db.list_incidents()) == 2


def test_issue_for_a_namespace_outside_the_allow_list_is_ignored(world):
    pipeline.handle_incident({**ISSUE, "namespace": "kube-system"})
    assert db.list_incidents() == [] and world.calls == []


@pytest.mark.parametrize(
    "issue",
    [None, "text", 5, [], {}, {"service": "s", "namespace": "default"}, {**ISSUE, "service": ""}, {**ISSUE, "reason": 5}, {**ISSUE, "namespace": "  "}],
)
def test_malformed_issues_are_ignored(world, issue):
    pipeline.handle_incident(issue)
    assert db.list_incidents() == [] and world.calls == []


def test_database_failure_when_creating_is_contained(world, monkeypatch):
    monkeypatch.setattr(pipeline.db, "create_incident", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("disk full")))
    pipeline.handle_incident(ISSUE)  # must not raise
    assert world.calls == []


# ---------------------------------------------------------------------------
# Failure-injection timestamps (MTTD)
# ---------------------------------------------------------------------------


def test_recorded_injection_gives_the_incident_an_mttd(world):
    injected = db.record_injection("shop-api", "default")
    time.sleep(0.05)
    pipeline.handle_incident(ISSUE)
    incident = only_incident()
    assert incident["injected_at"] == injected
    assert incident["mttd_seconds"] is not None and incident["mttd_seconds"] > 0
    assert "Matched the failure injection" in incident["timeline"][0]["message"]


def test_without_an_injection_mttd_is_unavailable_and_says_so(world):
    pipeline.handle_incident(ISSUE)
    incident = only_incident()
    assert incident["injected_at"] is None and incident["mttd_seconds"] is None
    assert "MTTD unavailable" in incident["timeline"][0]["message"]


def test_stale_injection_is_not_attached(world, monkeypatch):
    set_settings(monkeypatch, INJECTION_MAX_AGE_SECONDS="1")
    db.record_injection("shop-api", "default")
    time.sleep(1.2)
    pipeline.handle_incident(ISSUE)
    assert only_incident()["injected_at"] is None


# ---------------------------------------------------------------------------
# Startup recovery
# ---------------------------------------------------------------------------


def test_recover_interrupted_incidents_fails_only_the_in_flight_ones(temp_db):
    ids = {s: db.create_incident(f"svc-{s.lower()}", "default", "r") for s in
           ["DETECTED", "ANALYZING", "REMEDIATING", "VERIFYING", "AWAITING_APPROVAL", "RESOLVED", "FAILED"]}
    for status, incident_id in ids.items():
        if status != "DETECTED":
            db.update_incident(incident_id, status=status)

    assert pipeline.recover_interrupted_incidents() == 4

    final = {s: db.get_incident(i)["status"] for s, i in ids.items()}
    assert final == {"DETECTED": "FAILED", "ANALYZING": "FAILED", "REMEDIATING": "FAILED", "VERIFYING": "FAILED",
                     "AWAITING_APPROVAL": "AWAITING_APPROVAL", "RESOLVED": "RESOLVED", "FAILED": "FAILED"}
    assert "interrupted" in db.get_incident(ids["VERIFYING"])["timeline"][-1]["message"]
    assert pipeline.recover_interrupted_incidents() == 0  # idempotent


# ---------------------------------------------------------------------------
# Integration with the REAL remediation guardrails (cluster actions stubbed)
# ---------------------------------------------------------------------------


@pytest.fixture()
def real_guardrails(world, monkeypatch):
    """Use the real remediation.execute (guards + attempt counter); stub only the cluster action."""
    monkeypatch.setattr(remediation, "execute", REAL_EXECUTE)
    performed = []
    monkeypatch.setitem(remediation._ACTIONS, "rollback", lambda ns, svc: performed.append((ns, svc)) or "stub rollback done")
    return performed


def test_auto_mode_passes_the_real_guardrails_and_records_the_attempt(real_guardrails, world, auto):
    pipeline.handle_incident(ISSUE)
    incident = only_incident()
    assert incident["status"] == "RESOLVED"
    assert incident["remediation_attempts"] == 1 and incident["action"] == "rollback"
    assert real_guardrails == [("default", "shop-api")]


def test_default_mode_never_reaches_the_cluster_without_approval(real_guardrails, world):
    pipeline.handle_incident(ISSUE)
    assert only_incident()["status"] == "AWAITING_APPROVAL"
    assert real_guardrails == []


def test_approval_passes_the_real_guardrails(real_guardrails, world):
    pipeline.handle_incident(ISSUE)
    incident_id = only_incident()["id"]
    pipeline.approve_incident(incident_id, background=False)
    incident = db.get_incident(incident_id)
    assert incident["status"] == "RESOLVED" and incident["remediation_attempts"] == 1
    assert real_guardrails == [("default", "shop-api")]


def test_real_guardrails_refuse_unapproved_execution_even_if_the_pipeline_asked(real_guardrails, world):
    """Defence in depth: execute() itself refuses when AUTO_REMEDIATE=false and approved=False."""
    incident_id = db.create_incident("shop-api", "default", "r")
    result = REAL_EXECUTE("rollback", "default", "shop-api", incident_id=incident_id, approved=False)
    assert result["success"] is False and result["detail"].startswith("Refused")
    assert real_guardrails == []


# ---------------------------------------------------------------------------
# Detector loop
# ---------------------------------------------------------------------------


@pytest.fixture()
def fake_cluster(monkeypatch):
    """Control what the detector reports; record what the handler is asked to process."""

    class Cluster:
        issues = [dict(ISSUE)]
        handled = []
        gate = None
        checks = 0

    def check():
        Cluster.checks += 1
        if isinstance(Cluster.issues, Exception):
            raise Cluster.issues
        return list(Cluster.issues)

    def handler(issue):
        Cluster.handled.append(issue["service"])
        if Cluster.gate is not None:
            Cluster.gate.wait(timeout=10)

    Cluster.issues = [dict(ISSUE)]
    Cluster.handled = []
    Cluster.gate = None
    Cluster.checks = 0
    monkeypatch.setattr(detector, "check_cluster", check)
    monkeypatch.setattr(pipeline, "handle_incident", handler)
    return Cluster


def test_loop_starts_one_worker_for_an_unhealthy_service(temp_db, fake_cluster):
    loop = pipeline.DetectorLoop()
    assert loop.run_once() == 1
    assert pipeline.join_workers(5)
    assert fake_cluster.handled == ["shop-api"]


def test_repeated_polls_do_not_spawn_duplicate_workers_while_one_is_running(temp_db, fake_cluster):
    fake_cluster.gate = threading.Event()
    loop = pipeline.DetectorLoop()
    started = [loop.run_once() for _ in range(50)]
    assert sum(started) == 1
    assert wait_until(lambda: fake_cluster.handled == ["shop-api"])
    assert loop.status()["in_flight"] == ["default/shop-api"]
    fake_cluster.gate.set()
    assert pipeline.join_workers(5)
    assert loop.status()["in_flight"] == []
    assert fake_cluster.handled == ["shop-api"]


def test_loop_does_not_start_a_worker_when_an_incident_is_open(temp_db, fake_cluster):
    open_id = db.create_incident("shop-api", "default", "r")
    db.update_incident(open_id, status="AWAITING_APPROVAL")
    assert pipeline.DetectorLoop().run_once() == 0
    assert fake_cluster.handled == []


def test_loop_respects_the_cooldown_after_an_incident_closes(temp_db, fake_cluster, monkeypatch):
    closed = db.create_incident("shop-api", "default", "r")
    db.update_incident(closed, status="RESOLVED")
    assert pipeline.DetectorLoop().run_once() == 0

    set_settings(monkeypatch, INCIDENT_COOLDOWN_SECONDS="0")
    assert pipeline.DetectorLoop().run_once() == 1
    assert pipeline.join_workers(5)


def test_worker_count_is_capped(temp_db, fake_cluster):
    fake_cluster.gate = threading.Event()
    fake_cluster.issues = [{**ISSUE, "service": f"svc-{i}"} for i in range(5)]
    loop = pipeline.DetectorLoop(max_workers=2)
    assert loop.run_once() == 2
    assert wait_until(lambda: len(fake_cluster.handled) == 2)
    fake_cluster.gate.set()
    assert pipeline.join_workers(5)
    assert loop.run_once() >= 2  # the cap limits CONCURRENT workers, so slots are free again


def test_malformed_detector_output_is_ignored(temp_db, fake_cluster):
    fake_cluster.issues = [None, {"service": "x"}, "text", dict(ISSUE)]
    assert pipeline.DetectorLoop().run_once() == 1
    assert pipeline.join_workers(5)
    assert fake_cluster.handled == ["shop-api"]


def test_check_cluster_raising_does_not_break_run_once(temp_db, fake_cluster):
    fake_cluster.issues = RuntimeError("API down")
    loop = pipeline.DetectorLoop()
    assert loop.run_once() == 0
    assert loop.status()["last_poll_issue_count"] == 0


def test_loop_keeps_polling_after_errors_and_stops_cleanly(temp_db, fake_cluster, monkeypatch):
    set_settings(monkeypatch, DETECTOR_INTERVAL_SECONDS="1")
    fake_cluster.issues = RuntimeError("API down")
    loop = pipeline.DetectorLoop()
    loop.start()
    assert loop.running
    assert wait_until(lambda: fake_cluster.checks >= 2, timeout=6)  # kept going despite the error
    started = time.monotonic()
    assert loop.stop(timeout=5) is True
    assert time.monotonic() - started < 2
    assert not loop.running


def test_stop_wakes_a_loop_that_is_waiting_out_a_long_interval(temp_db, fake_cluster, monkeypatch):
    set_settings(monkeypatch, DETECTOR_INTERVAL_SECONDS="3600")
    loop = pipeline.DetectorLoop()
    loop.start()
    assert wait_until(lambda: fake_cluster.checks >= 1)
    started = time.monotonic()
    assert loop.stop(timeout=5) is True
    assert time.monotonic() - started < 2
    assert not loop.running


def test_start_twice_runs_one_thread_and_the_loop_can_restart(temp_db, fake_cluster, monkeypatch):
    set_settings(monkeypatch, DETECTOR_INTERVAL_SECONDS="3600")
    loop = pipeline.DetectorLoop()
    loop.start()
    first = loop._thread
    loop.start()
    assert loop._thread is first
    assert [t for t in threading.enumerate() if t.name == "detector-loop"] == [first]
    loop.stop(timeout=5)
    loop.start()
    assert loop.running and loop._thread is not first
    loop.stop(timeout=5)


def test_status_reports_the_last_poll(temp_db, fake_cluster):
    loop = pipeline.DetectorLoop()
    assert loop.status()["last_poll_at"] is None and loop.status()["running"] is False
    loop.run_once()
    pipeline.join_workers(5)
    status = loop.status()
    assert status["last_poll_at"] is not None and status["last_poll_issue_count"] == 1


def test_loop_and_real_pipeline_create_exactly_one_incident(world, monkeypatch):
    """End to end: the loop polls a persistently broken service repeatedly; one incident results."""
    monkeypatch.setattr(detector, "check_cluster", lambda: [dict(ISSUE)])
    loop = pipeline.DetectorLoop()
    for _ in range(5):
        loop.run_once()
        pipeline.join_workers(5)
    incident = only_incident()
    assert incident["status"] == "AWAITING_APPROVAL"
    assert world.names().count("collect") == 1
