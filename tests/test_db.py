"""Tests for backend/db.py. Each test uses a temporary SQLite file."""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import pytest

from backend import db


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value)


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


def test_init_db_creates_tables_and_indexes(temp_db):
    conn = temp_db._connect()
    try:
        tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        indexes = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    finally:
        conn.close()
    assert {"incidents", "timeline"} <= tables
    assert {"idx_incidents_status", "idx_incidents_service_ns", "idx_timeline_incident"} <= indexes


def test_init_db_is_idempotent_and_preserves_data(temp_db):
    incident_id = temp_db.create_incident("shop-api", "default", "CrashLoopBackOff")
    temp_db.init_db()
    temp_db.init_db()
    assert temp_db.get_incident(incident_id)["service"] == "shop-api"


def test_init_db_creates_missing_parent_directory(tmp_path, monkeypatch):
    from backend import config

    nested = tmp_path / "a" / "b" / "c.db"
    monkeypatch.setenv("DATABASE_PATH", str(nested))
    config.reset_settings()
    db.init_db()
    assert nested.exists()


def test_foreign_keys_are_enforced(temp_db):
    conn = temp_db._connect()
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO timeline (incident_id, step, message, timestamp) VALUES (999, 'X', 'y', 'z')"
            )
    finally:
        conn.close()


def test_check_constraint_rejects_invalid_status_at_sql_level(temp_db):
    incident_id = temp_db.create_incident("shop-api", "default", "x")
    conn = temp_db._connect()
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE incidents SET status = 'BOGUS' WHERE id = ?", (incident_id,))
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Create / read
# ---------------------------------------------------------------------------


def test_create_incident_defaults(temp_db):
    before = datetime.now(timezone.utc)
    incident_id = temp_db.create_incident("shop-api", "default", "CrashLoopBackOff")
    after = datetime.now(timezone.utc)

    assert isinstance(incident_id, int)
    incident = temp_db.get_incident(incident_id)
    assert incident["status"] == "DETECTED"
    assert incident["service"] == "shop-api"
    assert incident["namespace"] == "default"
    assert incident["reason"] == "CrashLoopBackOff"
    assert incident["resolved_at"] is None
    assert incident["injected_at"] is None
    assert incident["action"] is None
    assert incident["remediation_attempts"] == 0
    detected = _parse(incident["detected_at"])
    assert detected.utcoffset() == timedelta(0)
    assert before <= detected <= after


@pytest.mark.parametrize(
    "args",
    [("", "default", "r"), ("svc", "", "r"), ("svc", "default", "  "), (None, "default", "r"), ("svc", 5, "r")],
)
def test_create_incident_rejects_invalid_input(temp_db, args):
    with pytest.raises(ValueError):
        temp_db.create_incident(*args)


def test_create_incident_truncates_very_long_reason(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "x" * 5000)
    reason = temp_db.get_incident(incident_id)["reason"]
    assert len(reason) == db.MAX_REASON_LENGTH
    assert reason.endswith("[truncated]")


def test_sql_injection_text_is_stored_literally(temp_db):
    evil = "x'); DROP TABLE incidents; --"
    incident_id = temp_db.create_incident(evil, "default", evil)
    assert temp_db.get_incident(incident_id)["service"] == evil
    assert len(temp_db.list_incidents()) == 1


def test_list_incidents_newest_first(temp_db):
    ids = [temp_db.create_incident(f"svc-{i}", "default", "r") for i in range(3)]
    listed = temp_db.list_incidents()
    assert [i["id"] for i in listed] == list(reversed(ids))


def test_list_incidents_empty(temp_db):
    assert temp_db.list_incidents() == []


def test_list_incidents_omits_heavy_payloads(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    temp_db.update_incident(incident_id, evidence_json={"logs": ["a"]})
    summary = temp_db.list_incidents()[0]
    assert "evidence" not in summary and "rca" not in summary and "timeline" not in summary


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------


def test_update_status_and_action(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    temp_db.update_incident(incident_id, status="ANALYZING")
    assert temp_db.get_incident(incident_id)["status"] == "ANALYZING"
    temp_db.update_incident(incident_id, status="REMEDIATING", action="rollback")
    incident = temp_db.get_incident(incident_id)
    assert incident["status"] == "REMEDIATING"
    assert incident["action"] == "rollback"


@pytest.mark.parametrize("bad_status", ["bogus", "resolved", "", None, 5])
def test_update_rejects_invalid_status(temp_db, bad_status):
    incident_id = temp_db.create_incident("svc", "default", "r")
    with pytest.raises(ValueError):
        temp_db.update_incident(incident_id, status=bad_status)
    assert temp_db.get_incident(incident_id)["status"] == "DETECTED"


def test_update_rejects_unknown_fields(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    with pytest.raises(ValueError, match="Unknown"):
        temp_db.update_incident(incident_id, nonsense="x")
    with pytest.raises(ValueError, match="Unknown"):
        temp_db.update_incident(incident_id, id=99)
    with pytest.raises(ValueError, match="Unknown"):
        temp_db.update_incident(incident_id, detected_at="2026-01-01T00:00:00+00:00")
    with pytest.raises(ValueError, match="Unknown"):
        temp_db.update_incident(incident_id, status="ANALYZING", **{"status = 'RESOLVED' --": 1})


def test_update_with_no_fields_is_rejected(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    with pytest.raises(ValueError):
        temp_db.update_incident(incident_id)


def test_update_rejects_invalid_action(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    with pytest.raises(ValueError):
        temp_db.update_incident(incident_id, action="rm -rf /")
    temp_db.update_incident(incident_id, action="restart")
    temp_db.update_incident(incident_id, action=None)
    assert temp_db.get_incident(incident_id)["action"] is None


def test_failed_validation_does_not_partially_update(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    with pytest.raises(ValueError):
        temp_db.update_incident(incident_id, status="ANALYZING", action="bogus")
    assert temp_db.get_incident(incident_id)["status"] == "DETECTED"


def test_evidence_and_rca_round_trip(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    evidence = {"logs": {"pod-1": ["Exception: DB_URL missing"]}, "when": datetime(2026, 1, 1, tzinfo=timezone.utc)}
    rca = {"probable_cause": "DB_URL missing", "confidence": 0.9, "source": "llm"}
    temp_db.update_incident(incident_id, evidence_json=evidence, rca_json=rca)
    incident = temp_db.get_incident(incident_id)
    assert incident["evidence"]["logs"]["pod-1"] == ["Exception: DB_URL missing"]
    assert incident["evidence"]["when"]  # datetime was serialised, not rejected
    assert incident["rca"] == rca


def test_json_string_must_be_valid_json(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    temp_db.update_incident(incident_id, rca_json='{"a": 1}')
    assert temp_db.get_incident(incident_id)["rca"] == {"a": 1}
    with pytest.raises(ValueError):
        temp_db.update_incident(incident_id, rca_json="not json")


def test_unserialisable_evidence_is_rejected(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    with pytest.raises(ValueError):
        temp_db.update_incident(incident_id, evidence_json={1.5: object(), (1, 2): "tuple key"})


def test_corrupt_stored_json_returns_none(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    conn = temp_db._connect()
    try:
        conn.execute("UPDATE incidents SET evidence_json = '{broken' WHERE id = ?", (incident_id,))
        conn.commit()
    finally:
        conn.close()
    incident = temp_db.get_incident(incident_id)
    assert incident["evidence"] is None
    assert incident["id"] == incident_id


def test_resolved_without_timestamp_gets_one(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    temp_db.update_incident(incident_id, status="RESOLVED")
    incident = temp_db.get_incident(incident_id)
    assert incident["resolved_at"] is not None
    assert incident["mttr_seconds"] is not None


def test_failed_status_does_not_set_resolved_at(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    temp_db.update_incident(incident_id, status="FAILED")
    incident = temp_db.get_incident(incident_id)
    assert incident["resolved_at"] is None
    assert incident["mttr_seconds"] is None


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------


def test_normalize_timestamp_variants():
    assert db.normalize_timestamp("2026-10-09T12:00:00Z") == "2026-10-09T12:00:00.000000+00:00"
    assert db.normalize_timestamp("2026-10-09T12:00:00") == "2026-10-09T12:00:00.000000+00:00"
    assert db.normalize_timestamp("2026-10-09T17:30:00+05:30") == "2026-10-09T12:00:00.000000+00:00"
    assert db.normalize_timestamp(datetime(2026, 10, 9, 12, tzinfo=timezone.utc)).startswith("2026-10-09T12:00:00")


@pytest.mark.parametrize("bad", ["yesterday", "", 12345, None])
def test_normalize_timestamp_rejects_garbage(bad):
    with pytest.raises(ValueError):
        db.normalize_timestamp(bad)


def test_update_normalises_timestamps(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    temp_db.update_incident(incident_id, injected_at="2026-10-09T12:00:00Z")
    assert temp_db.get_incident(incident_id)["injected_at"] == "2026-10-09T12:00:00.000000+00:00"
    with pytest.raises(ValueError):
        temp_db.update_incident(incident_id, injected_at="not a time")


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


def test_timeline_entries_are_ordered_and_timestamped(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    steps = ["DETECTED", "ANALYZING", "REMEDIATING", "VERIFYING", "RESOLVED"]
    for step in steps:
        temp_db.add_timeline(incident_id, step, f"message for {step}")
    timeline = temp_db.get_incident(incident_id)["timeline"]
    assert [t["step"] for t in timeline] == steps
    assert timeline[0]["message"] == "message for DETECTED"
    stamps = [t["timestamp"] for t in timeline]
    assert stamps == sorted(stamps)
    assert all(_parse(s).utcoffset() == timedelta(0) for s in stamps)


def test_timeline_is_per_incident(temp_db):
    a = temp_db.create_incident("a", "default", "r")
    b = temp_db.create_incident("b", "default", "r")
    temp_db.add_timeline(a, "DETECTED", "a")
    temp_db.add_timeline(b, "DETECTED", "b")
    temp_db.add_timeline(b, "ANALYZING", "b2")
    assert len(temp_db.get_incident(a)["timeline"]) == 1
    assert len(temp_db.get_incident(b)["timeline"]) == 2


def test_timeline_rejects_invalid_input(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    with pytest.raises(ValueError):
        temp_db.add_timeline(incident_id, "", "msg")
    with pytest.raises(ValueError):
        temp_db.add_timeline(incident_id, "STEP", "   ")
    with pytest.raises(ValueError):
        temp_db.add_timeline(incident_id, "S" * 100, "msg")


def test_timeline_truncates_huge_message(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    temp_db.add_timeline(incident_id, "STEP", "m" * 10_000)
    message = temp_db.get_incident(incident_id)["timeline"][0]["message"]
    assert len(message) == db.MAX_MESSAGE_LENGTH


# ---------------------------------------------------------------------------
# Missing incidents
# ---------------------------------------------------------------------------


def test_get_missing_incident_returns_none(temp_db):
    assert temp_db.get_incident(12345) is None
    assert temp_db.get_incident(0) is None
    assert temp_db.get_incident(-1) is None


def test_update_and_timeline_on_missing_incident_raise_clear_error(temp_db):
    with pytest.raises(db.IncidentNotFoundError):
        temp_db.update_incident(999, status="ANALYZING")
    with pytest.raises(db.IncidentNotFoundError):
        temp_db.add_timeline(999, "STEP", "msg")
    with pytest.raises(db.IncidentNotFoundError):
        temp_db.increment_remediation_attempts(999)
    # IncidentNotFoundError is a LookupError so callers can catch it generically.
    assert issubclass(db.IncidentNotFoundError, LookupError)


@pytest.mark.parametrize("bad_id", ["1", 1.5, None, True])
def test_non_integer_ids_are_rejected(temp_db, bad_id):
    with pytest.raises(ValueError):
        temp_db.get_incident(bad_id)
    with pytest.raises(ValueError):
        temp_db.update_incident(bad_id, status="ANALYZING")
    with pytest.raises(ValueError):
        temp_db.add_timeline(bad_id, "S", "m")


# ---------------------------------------------------------------------------
# MTTD / MTTR / metrics
# ---------------------------------------------------------------------------


def test_mttd_and_mttr_calculation(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    detected = _parse(temp_db.get_incident(incident_id)["detected_at"])
    temp_db.update_incident(
        incident_id,
        injected_at=_iso(detected - timedelta(seconds=12.5)),
        resolved_at=_iso(detected + timedelta(seconds=45)),
        status="RESOLVED",
    )
    incident = temp_db.get_incident(incident_id)
    assert incident["mttd_seconds"] == 12.5
    assert incident["mttr_seconds"] == 45.0


def test_mttd_unavailable_without_injection(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    assert temp_db.get_incident(incident_id)["mttd_seconds"] is None


def test_mttr_unavailable_until_resolved(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    assert temp_db.get_incident(incident_id)["mttr_seconds"] is None
    temp_db.update_incident(incident_id, status="VERIFYING")
    assert temp_db.get_incident(incident_id)["mttr_seconds"] is None


def test_negative_mttd_is_treated_as_unavailable(temp_db):
    """An injection recorded AFTER detection (stale/clock skew) must not produce a negative MTTD."""
    incident_id = temp_db.create_incident("svc", "default", "r")
    detected = _parse(temp_db.get_incident(incident_id)["detected_at"])
    temp_db.update_incident(incident_id, injected_at=_iso(detected + timedelta(seconds=30)))
    assert temp_db.get_incident(incident_id)["mttd_seconds"] is None
    assert temp_db.get_metrics()["avg_mttd_seconds"] is None


def test_metrics_empty_database(temp_db):
    assert temp_db.get_metrics() == {
        "total": 0,
        "resolved": 0,
        "avg_mttd_seconds": None,
        "avg_mttr_seconds": None,
    }


def test_aggregate_metrics_exclude_unavailable_durations(temp_db):
    base = datetime.now(timezone.utc)

    # Incident A: resolved, MTTD 10s, MTTR 30s
    a = temp_db.create_incident("a", "default", "r")
    det_a = _parse(temp_db.get_incident(a)["detected_at"])
    temp_db.update_incident(
        a, injected_at=_iso(det_a - timedelta(seconds=10)), resolved_at=_iso(det_a + timedelta(seconds=30)), status="RESOLVED"
    )

    # Incident B: resolved, MTTD 20s, MTTR 60s
    b = temp_db.create_incident("b", "default", "r")
    det_b = _parse(temp_db.get_incident(b)["detected_at"])
    temp_db.update_incident(
        b, injected_at=_iso(det_b - timedelta(seconds=20)), resolved_at=_iso(det_b + timedelta(seconds=60)), status="RESOLVED"
    )

    # Incident C: resolved, no injection -> contributes to MTTR (90s) but not MTTD
    c = temp_db.create_incident("c", "default", "r")
    det_c = _parse(temp_db.get_incident(c)["detected_at"])
    temp_db.update_incident(c, resolved_at=_iso(det_c + timedelta(seconds=90)), status="RESOLVED")

    # Incident D: failed with injection (MTTD 40s) -> contributes to MTTD only, not resolved
    d = temp_db.create_incident("d", "default", "r")
    det_d = _parse(temp_db.get_incident(d)["detected_at"])
    temp_db.update_incident(d, injected_at=_iso(det_d - timedelta(seconds=40)), status="FAILED")

    # Incident E: still open, nothing available
    temp_db.create_incident("e", "default", "r")

    metrics = temp_db.get_metrics()
    assert metrics["total"] == 5
    assert metrics["resolved"] == 3
    assert metrics["avg_mttd_seconds"] == pytest.approx((10 + 20 + 40) / 3, abs=0.01)
    assert metrics["avg_mttr_seconds"] == pytest.approx((30 + 60 + 90) / 3, abs=0.01)
    assert base  # silence unused-variable linters


def test_metrics_agree_with_individual_incidents(temp_db):
    ids = []
    for i in range(3):
        incident_id = temp_db.create_incident(f"svc-{i}", "default", "r")
        detected = _parse(temp_db.get_incident(incident_id)["detected_at"])
        temp_db.update_incident(
            incident_id,
            injected_at=_iso(detected - timedelta(seconds=5 * (i + 1))),
            resolved_at=_iso(detected + timedelta(seconds=11 * (i + 1))),
            status="RESOLVED",
        )
        ids.append(incident_id)
    incidents = [temp_db.get_incident(i) for i in ids]
    metrics = temp_db.get_metrics()
    assert metrics["avg_mttd_seconds"] == pytest.approx(sum(i["mttd_seconds"] for i in incidents) / 3, abs=0.01)
    assert metrics["avg_mttr_seconds"] == pytest.approx(sum(i["mttr_seconds"] for i in incidents) / 3, abs=0.01)


# ---------------------------------------------------------------------------
# Helpers for later stages
# ---------------------------------------------------------------------------


def test_find_open_incident(temp_db):
    assert temp_db.find_open_incident("shop-api", "default") is None
    incident_id = temp_db.create_incident("shop-api", "default", "r")
    assert temp_db.find_open_incident("shop-api", "default")["id"] == incident_id
    assert temp_db.find_open_incident("shop-api", "other") is None
    assert temp_db.find_open_incident("other-svc", "default") is None
    for status in ("ANALYZING", "AWAITING_APPROVAL", "REMEDIATING", "VERIFYING"):
        temp_db.update_incident(incident_id, status=status)
        assert temp_db.find_open_incident("shop-api", "default") is not None
    temp_db.update_incident(incident_id, status="RESOLVED")
    assert temp_db.find_open_incident("shop-api", "default") is None
    failed = temp_db.create_incident("shop-api", "default", "r")
    temp_db.update_incident(failed, status="FAILED")
    assert temp_db.find_open_incident("shop-api", "default") is None


def test_get_last_closed_at(temp_db):
    assert temp_db.get_last_closed_at("shop-api", "default") is None
    open_id = temp_db.create_incident("shop-api", "default", "r")
    assert temp_db.get_last_closed_at("shop-api", "default") is None  # still open

    # A RESOLVED incident closed long ago.
    temp_db.update_incident(open_id, status="RESOLVED", resolved_at="2020-01-01T00:00:00Z")
    assert temp_db.get_last_closed_at("shop-api", "default") == "2020-01-01T00:00:00.000000+00:00"

    # A FAILED incident has no resolved_at, so its last timeline event is used,
    # and since it happened "now" it is the most recent closure.
    failed = temp_db.create_incident("shop-api", "default", "r")
    temp_db.add_timeline(failed, "FAILED", "verification failed")
    temp_db.update_incident(failed, status="FAILED")
    failed_stamp = temp_db.get_incident(failed)["timeline"][-1]["timestamp"]
    assert temp_db.get_last_closed_at("shop-api", "default") == failed_stamp
    assert temp_db.get_incident(failed)["resolved_at"] is None  # MTTR is not distorted

    # A RESOLVED incident closed later than everything else wins.
    later = temp_db.create_incident("shop-api", "default", "r")
    temp_db.update_incident(later, status="RESOLVED", resolved_at="2999-01-01T00:00:00Z")
    assert temp_db.get_last_closed_at("shop-api", "default") == "2999-01-01T00:00:00.000000+00:00"

    # Other services and namespaces are unaffected.
    assert temp_db.get_last_closed_at("other", "default") is None
    assert temp_db.get_last_closed_at("shop-api", "staging") is None


def test_increment_remediation_attempts_persists(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    assert temp_db.increment_remediation_attempts(incident_id) == 1
    assert temp_db.increment_remediation_attempts(incident_id) == 2
    assert temp_db.get_incident(incident_id)["remediation_attempts"] == 2
    other = temp_db.create_incident("other", "default", "r")
    assert temp_db.get_incident(other)["remediation_attempts"] == 0


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


def test_concurrent_writers_do_not_lose_data(temp_db):
    threads_count, per_thread = 8, 15
    errors = []
    created_ids = []
    ids_lock = threading.Lock()

    def worker(n: int) -> None:
        try:
            for i in range(per_thread):
                incident_id = temp_db.create_incident(f"svc-{n}-{i}", "default", "r")
                temp_db.add_timeline(incident_id, "DETECTED", "from thread")
                temp_db.increment_remediation_attempts(incident_id)
                temp_db.list_incidents()
                temp_db.get_metrics()
                with ids_lock:
                    created_ids.append(incident_id)
        except Exception as exc:  # pragma: no cover - only on failure
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(threads_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert errors == []
    assert len(set(created_ids)) == threads_count * per_thread
    assert len(temp_db.list_incidents()) == threads_count * per_thread
    sample = temp_db.get_incident(created_ids[0])
    assert len(sample["timeline"]) == 1 and sample["remediation_attempts"] == 1


def test_concurrent_attempt_increments_are_atomic(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    results = []
    lock = threading.Lock()

    def bump() -> None:
        value = temp_db.increment_remediation_attempts(incident_id)
        with lock:
            results.append(value)

    threads = [threading.Thread(target=bump) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert sorted(results) == list(range(1, 21))
