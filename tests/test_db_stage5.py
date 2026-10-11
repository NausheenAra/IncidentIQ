"""Tests for the Stage 5 additions to backend/db.py (injections, CAS transitions, status queries)."""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import pytest

from backend import db


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _set_injected(temp_db, service, namespace, seconds_before_now):
    """Insert an injection row dated ``seconds_before_now`` in the past; return its timestamp."""
    stamp = _iso(datetime.now(timezone.utc) - timedelta(seconds=seconds_before_now))
    conn = temp_db._connect()
    try:
        conn.execute("INSERT INTO injections (service, namespace, injected_at) VALUES (?, ?, ?)", (service, namespace, stamp))
        conn.commit()
    finally:
        conn.close()
    return stamp


# ---------------------------------------------------------------------------
# transition_status
# ---------------------------------------------------------------------------


def test_transition_status_succeeds_only_from_expected_state(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    temp_db.update_incident(incident_id, status="AWAITING_APPROVAL")
    assert temp_db.transition_status(incident_id, "AWAITING_APPROVAL", "REMEDIATING") is True
    assert temp_db.get_incident(incident_id)["status"] == "REMEDIATING"
    # Already moved on: the same transition must now fail and change nothing.
    assert temp_db.transition_status(incident_id, "AWAITING_APPROVAL", "REMEDIATING") is False
    assert temp_db.get_incident(incident_id)["status"] == "REMEDIATING"


def test_transition_status_on_missing_incident_returns_false(temp_db):
    assert temp_db.transition_status(999, "AWAITING_APPROVAL", "REMEDIATING") is False


@pytest.mark.parametrize("expected,new", [("BOGUS", "FAILED"), ("DETECTED", "BOGUS"), ("", "FAILED")])
def test_transition_status_validates_statuses(temp_db, expected, new):
    incident_id = temp_db.create_incident("svc", "default", "r")
    with pytest.raises(ValueError):
        temp_db.transition_status(incident_id, expected, new)


def test_transition_to_resolved_stamps_resolved_at(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    assert temp_db.transition_status(incident_id, "DETECTED", "RESOLVED")
    assert temp_db.get_incident(incident_id)["resolved_at"] is not None


def test_concurrent_transitions_have_exactly_one_winner(temp_db):
    incident_id = temp_db.create_incident("svc", "default", "r")
    temp_db.update_incident(incident_id, status="AWAITING_APPROVAL")
    results, lock = [], threading.Lock()

    def attempt():
        won = temp_db.transition_status(incident_id, "AWAITING_APPROVAL", "REMEDIATING")
        with lock:
            results.append(won)

    threads = [threading.Thread(target=attempt) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert results.count(True) == 1
    assert results.count(False) == 19


# ---------------------------------------------------------------------------
# list_incidents_with_status
# ---------------------------------------------------------------------------


def test_list_incidents_with_status_filters_and_orders_oldest_first(temp_db):
    a = temp_db.create_incident("a", "default", "r")
    b = temp_db.create_incident("b", "default", "r")
    c = temp_db.create_incident("c", "default", "r")
    temp_db.update_incident(b, status="VERIFYING")
    temp_db.update_incident(c, status="RESOLVED")
    found = temp_db.list_incidents_with_status(("DETECTED", "VERIFYING"))
    assert [i["id"] for i in found] == [a, b]
    assert temp_db.list_incidents_with_status(["FAILED"]) == []


def test_list_incidents_with_status_validates_input(temp_db):
    with pytest.raises(ValueError):
        temp_db.list_incidents_with_status([])
    with pytest.raises(ValueError):
        temp_db.list_incidents_with_status(["DETECTED", "nope"])


# ---------------------------------------------------------------------------
# record_injection / claim_injection
# ---------------------------------------------------------------------------


def test_record_injection_returns_utc_timestamp_and_persists(temp_db):
    before = datetime.now(timezone.utc)
    stamp = temp_db.record_injection("shop-api", "default")
    after = datetime.now(timezone.utc)
    assert before <= datetime.fromisoformat(stamp) <= after
    assert datetime.fromisoformat(stamp).utcoffset() == timedelta(0)


@pytest.mark.parametrize("args", [("", "default"), ("svc", ""), (None, "default"), ("svc", 5)])
def test_record_injection_validates_input(temp_db, args):
    with pytest.raises(ValueError):
        temp_db.record_injection(*args)


def test_claim_injection_attaches_timestamp_and_enables_mttd(temp_db):
    injected = temp_db.record_injection("shop-api", "default")
    incident_id = temp_db.create_incident("shop-api", "default", "CrashLoopBackOff")
    assert temp_db.claim_injection(incident_id, 600) == injected
    incident = temp_db.get_incident(incident_id)
    assert incident["injected_at"] == injected
    assert incident["mttd_seconds"] is not None and incident["mttd_seconds"] >= 0


def test_claim_injection_is_consumed_once(temp_db):
    temp_db.record_injection("shop-api", "default")
    first = temp_db.create_incident("shop-api", "default", "r")
    assert temp_db.claim_injection(first, 600) is not None
    temp_db.update_incident(first, status="RESOLVED")
    second = temp_db.create_incident("shop-api", "default", "r")
    assert temp_db.claim_injection(second, 600) is None
    assert temp_db.get_incident(second)["injected_at"] is None


def test_claim_injection_picks_newest_and_consumes_older(temp_db):
    older = _set_injected(temp_db, "shop-api", "default", 40)
    newer = _set_injected(temp_db, "shop-api", "default", 10)
    incident_id = temp_db.create_incident("shop-api", "default", "r")
    assert temp_db.claim_injection(incident_id, 600) == newer
    assert older != newer
    later = temp_db.create_incident("shop-api", "default", "r2")
    assert temp_db.claim_injection(later, 600) is None  # the older record was consumed too


def test_claim_injection_ignores_stale_injections_and_retires_them(temp_db):
    _set_injected(temp_db, "shop-api", "default", 3600)  # an hour old
    incident_id = temp_db.create_incident("shop-api", "default", "r")
    assert temp_db.claim_injection(incident_id, 600) is None
    assert temp_db.get_incident(incident_id)["mttd_seconds"] is None
    # The stale record is retired, so it cannot attach to a later incident either.
    later = temp_db.create_incident("shop-api", "default", "r")
    assert temp_db.claim_injection(later, 100_000) is None


def test_claim_injection_does_not_consume_injection_recorded_after_detection(temp_db):
    incident_id = temp_db.create_incident("shop-api", "default", "r")
    _set_injected(temp_db, "shop-api", "default", -30)  # 30 seconds in the FUTURE
    assert temp_db.claim_injection(incident_id, 600) is None
    # ... and it is still available for the next incident.
    conn = temp_db._connect()
    try:
        row = conn.execute("SELECT consumed_by_incident FROM injections").fetchone()
    finally:
        conn.close()
    assert row["consumed_by_incident"] is None


def test_claim_injection_matches_service_and_namespace_exactly(temp_db):
    temp_db.record_injection("other-api", "default")
    temp_db.record_injection("shop-api", "staging")
    incident_id = temp_db.create_incident("shop-api", "default", "r")
    assert temp_db.claim_injection(incident_id, 600) is None


def test_claim_injection_without_any_record_returns_none(temp_db):
    incident_id = temp_db.create_incident("shop-api", "default", "r")
    assert temp_db.claim_injection(incident_id, 600) is None


def test_claim_injection_on_missing_incident_raises(temp_db):
    with pytest.raises(db.IncidentNotFoundError):
        temp_db.claim_injection(999, 600)


def test_concurrent_claims_attach_an_injection_to_exactly_one_incident(temp_db):
    temp_db.record_injection("shop-api", "default")
    ids = [temp_db.create_incident("shop-api", "default", "r") for _ in range(6)]
    results, lock = [], threading.Lock()

    def claim(i):
        value = temp_db.claim_injection(i, 600)
        with lock:
            results.append(value)

    threads = [threading.Thread(target=claim, args=(i,)) for i in ids]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert len([r for r in results if r is not None]) == 1
