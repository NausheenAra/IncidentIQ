"""SQLite persistence for IncidentIQ incidents and their lifecycle timeline.

Concurrency model:
    * A NEW SQLite connection is opened for every public operation.
    * A process-wide re-entrant lock serialises all operations, so the
      detector thread, pipeline threads and API request threads can safely
      share the database inside the single backend process.

Timestamps:
    * Every timestamp is stored as an ISO 8601 UTC string with microseconds,
      e.g. ``2026-10-09T12:00:00.123456+00:00``. A fixed format means string
      comparison matches chronological comparison.

Metrics:
    * MTTD = ``detected_at - injected_at``  (needs an injection timestamp)
    * MTTR = ``resolved_at - detected_at``  (RESOLVED incidents only)
    * Unavailable or negative durations are ``None`` and are excluded from
      averages.

Storage note:
    When the backend runs in Kubernetes with an ``emptyDir`` volume, the
    database is NOT durable across pod replacement. See docs/architecture.md.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

from backend import config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_STATUSES = (
    "DETECTED",
    "ANALYZING",
    "AWAITING_APPROVAL",
    "REMEDIATING",
    "VERIFYING",
    "RESOLVED",
    "FAILED",
)
OPEN_STATUSES = ("DETECTED", "ANALYZING", "AWAITING_APPROVAL", "REMEDIATING", "VERIFYING")
TERMINAL_STATUSES = ("RESOLVED", "FAILED")

#: Remediation actions that may be recorded in ``incidents.action``.
VALID_ACTIONS = ("rollback", "restart", "scale")

#: Columns that :func:`update_incident` is allowed to change.
UPDATABLE_FIELDS = frozenset(
    {"reason", "status", "resolved_at", "injected_at", "evidence_json", "rca_json", "action"}
)
_TIMESTAMP_FIELDS = frozenset({"resolved_at", "injected_at"})
_JSON_FIELDS = frozenset({"evidence_json", "rca_json"})

MAX_SERVICE_LENGTH = 253
MAX_NAMESPACE_LENGTH = 63
MAX_REASON_LENGTH = 500
MAX_STEP_LENGTH = 64
MAX_MESSAGE_LENGTH = 2000

_LOCK = threading.RLock()


def _in_list(values: tuple) -> str:
    """Render a tuple of trusted constants as a quoted SQL list."""
    return ", ".join("'" + v + "'" for v in values)


_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS incidents (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    service              TEXT    NOT NULL,
    namespace            TEXT    NOT NULL,
    reason               TEXT    NOT NULL,
    status               TEXT    NOT NULL DEFAULT 'DETECTED'
                         CHECK (status IN ({_in_list(VALID_STATUSES)})),
    detected_at          TEXT    NOT NULL,
    resolved_at          TEXT,
    injected_at          TEXT,
    evidence_json        TEXT,
    rca_json             TEXT,
    action               TEXT
                         CHECK (action IS NULL OR action IN ({_in_list(VALID_ACTIONS)})),
    remediation_attempts INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS timeline (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL
                REFERENCES incidents(id) ON DELETE CASCADE,
    step        TEXT    NOT NULL,
    message     TEXT    NOT NULL,
    timestamp   TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_status       ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_service_ns   ON incidents(service, namespace, status);
CREATE INDEX IF NOT EXISTS idx_incidents_detected_at  ON incidents(detected_at);
CREATE INDEX IF NOT EXISTS idx_timeline_incident      ON timeline(incident_id, id);

CREATE TABLE IF NOT EXISTS injections (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    service              TEXT    NOT NULL,
    namespace            TEXT    NOT NULL,
    injected_at          TEXT    NOT NULL,
    consumed_by_incident INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    consumed_at          TEXT
);

CREATE INDEX IF NOT EXISTS idx_injections_lookup
    ON injections(service, namespace, consumed_by_incident, injected_at);
"""


class IncidentNotFoundError(LookupError):
    """Raised when an operation references an incident ID that does not exist."""

    def __init__(self, incident_id: Any) -> None:
        super().__init__(f"Incident {incident_id!r} not found")
        self.incident_id = incident_id


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------


def utc_now_iso() -> str:
    """Return the current UTC time as a normalised ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def normalize_timestamp(value: Any) -> str:
    """Normalise a datetime or ISO 8601 string to the stored UTC format.

    Naive values are assumed to already be UTC. A trailing ``Z`` is accepted.

    Raises:
        ValueError: if ``value`` is not a valid timestamp.
    """
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValueError(f"Invalid ISO 8601 timestamp: {value!r}") from exc
    else:
        raise ValueError(f"Timestamp must be a string or datetime, got {type(value).__name__}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _duration_seconds(start: Optional[str], end: Optional[str]) -> Optional[float]:
    """Return ``end - start`` in seconds, or ``None`` if unavailable or negative."""
    if not start or not end:
        return None
    try:
        delta = (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds()
    except (TypeError, ValueError):
        return None
    if delta < 0:
        return None
    return round(delta, 3)


# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------


def _db_path() -> str:
    """Return the configured database path."""
    return config.get_settings().database_path


def _connect() -> sqlite3.Connection:
    """Open a NEW connection with foreign keys enforced."""
    conn = sqlite3.connect(_db_path(), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def _session() -> Iterator[sqlite3.Connection]:
    """Yield a fresh connection under the process lock; commit or roll back; always close."""
    with _LOCK:
        conn = _connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _validate_id(incident_id: Any) -> int:
    """Return ``incident_id`` if it is a real integer (booleans are rejected)."""
    if isinstance(incident_id, bool) or not isinstance(incident_id, int):
        raise ValueError(f"Incident id must be an integer, got {incident_id!r}")
    return incident_id


def _require_text(name: str, value: Any, max_length: int, truncate: bool = False) -> str:
    """Return a stripped non-empty string, truncating or rejecting over-long input."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    text = value.strip()
    if len(text) > max_length:
        if not truncate:
            raise ValueError(f"{name} must be at most {max_length} characters")
        marker = " [truncated]"
        text = text[: max_length - len(marker)] + marker
    return text


def _to_json_text(name: str, value: Any) -> Optional[str]:
    """Serialise ``value`` for a JSON column. Strings must already be valid JSON."""
    if value is None:
        return None
    if isinstance(value, str):
        try:
            json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{name} string is not valid JSON") from exc
        return value
    try:
        return json.dumps(value, default=str, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} is not JSON serialisable: {exc}") from exc


def _from_json_text(text: Optional[str], incident_id: int, column: str) -> Any:
    """Deserialise a JSON column; corrupt data yields ``None`` instead of crashing."""
    if text is None:
        return None
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        logger.warning("Incident %s has invalid JSON in %s; returning None", incident_id, column)
        return None


def _prepare_field(name: str, value: Any) -> Any:
    """Validate and convert one field value for :func:`update_incident`."""
    if name == "status":
        if value not in VALID_STATUSES:
            raise ValueError(f"Invalid status {value!r}; expected one of {', '.join(VALID_STATUSES)}")
        return value
    if name == "action":
        if value is not None and value not in VALID_ACTIONS:
            raise ValueError(f"Invalid action {value!r}; expected one of {', '.join(VALID_ACTIONS)} or None")
        return value
    if name == "reason":
        return _require_text("reason", value, MAX_REASON_LENGTH, truncate=True)
    if name in _TIMESTAMP_FIELDS:
        return None if value is None else normalize_timestamp(value)
    if name in _JSON_FIELDS:
        return _to_json_text(name, value)
    raise ValueError(f"Unknown or non-updatable incident field: {name}")  # pragma: no cover


# ---------------------------------------------------------------------------
# Row conversion
# ---------------------------------------------------------------------------


def _summary(row: sqlite3.Row) -> Dict[str, Any]:
    """Convert an incident row to a lightweight dict (no evidence/RCA payloads)."""
    status = row["status"]
    return {
        "id": row["id"],
        "service": row["service"],
        "namespace": row["namespace"],
        "reason": row["reason"],
        "status": status,
        "detected_at": row["detected_at"],
        "resolved_at": row["resolved_at"],
        "injected_at": row["injected_at"],
        "action": row["action"],
        "remediation_attempts": row["remediation_attempts"],
        "mttd_seconds": _duration_seconds(row["injected_at"], row["detected_at"]),
        "mttr_seconds": (
            _duration_seconds(row["detected_at"], row["resolved_at"]) if status == "RESOLVED" else None
        ),
    }


_SUMMARY_COLUMNS = (
    "id, service, namespace, reason, status, detected_at, resolved_at, "
    "injected_at, action, remediation_attempts"
)


# ---------------------------------------------------------------------------
# Public contract
# ---------------------------------------------------------------------------


def init_db() -> None:
    """Create the database file, tables and indexes. Safe to call repeatedly."""
    path = os.path.abspath(_db_path())
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with _session() as conn:
        conn.executescript(_SCHEMA)
    logger.info("Database initialised at %s", path)


def create_incident(service: str, namespace: str, reason: str) -> int:
    """Insert a new incident with status DETECTED and return its ID."""
    service = _require_text("service", service, MAX_SERVICE_LENGTH)
    namespace = _require_text("namespace", namespace, MAX_NAMESPACE_LENGTH)
    reason = _require_text("reason", reason, MAX_REASON_LENGTH, truncate=True)
    with _session() as conn:
        cursor = conn.execute(
            "INSERT INTO incidents (service, namespace, reason, status, detected_at) "
            "VALUES (?, ?, ?, 'DETECTED', ?)",
            (service, namespace, reason, utc_now_iso()),
        )
        incident_id = int(cursor.lastrowid)
    logger.info("Created incident %s for %s/%s (%s)", incident_id, namespace, service, reason)
    return incident_id


def update_incident(incident_id: int, **fields: Any) -> None:
    """Update permitted fields of an incident.

    Permitted fields: ``reason, status, resolved_at, injected_at, evidence_json,
    rca_json, action``. ``evidence_json`` / ``rca_json`` accept Python objects
    (serialised for you) or an already-serialised JSON string.

    Moving an incident to RESOLVED without supplying ``resolved_at`` stamps the
    current UTC time, so a RESOLVED incident always has a resolution time.

    Raises:
        ValueError: unknown field, invalid status/action/timestamp/JSON, or no fields.
        IncidentNotFoundError: the incident does not exist.
    """
    _validate_id(incident_id)
    if not fields:
        raise ValueError("update_incident() requires at least one field")
    unknown = sorted(set(fields) - UPDATABLE_FIELDS)
    if unknown:
        raise ValueError(f"Unknown or non-updatable incident field(s): {', '.join(unknown)}")
    values = {name: _prepare_field(name, value) for name, value in fields.items()}

    with _session() as conn:
        row = conn.execute(
            "SELECT resolved_at FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        if row is None:
            raise IncidentNotFoundError(incident_id)
        if (
            values.get("status") == "RESOLVED"
            and "resolved_at" not in values
            and row["resolved_at"] is None
        ):
            values["resolved_at"] = utc_now_iso()
        # Column names come exclusively from the UPDATABLE_FIELDS allow-list
        # (validated above); all VALUES are bound parameters.
        assignments = ", ".join(f"{column} = ?" for column in values)
        conn.execute(  # nosec B608
            f"UPDATE incidents SET {assignments} WHERE id = ?",
            (*values.values(), incident_id),
        )


def add_timeline(incident_id: int, step: str, message: str) -> None:
    """Append a timeline event (UTC timestamp) to an incident.

    Raises:
        ValueError: invalid ``step`` or ``message``.
        IncidentNotFoundError: the incident does not exist.
    """
    _validate_id(incident_id)
    step = _require_text("step", step, MAX_STEP_LENGTH)
    message = _require_text("message", message, MAX_MESSAGE_LENGTH, truncate=True)
    with _session() as conn:
        if conn.execute("SELECT 1 FROM incidents WHERE id = ?", (incident_id,)).fetchone() is None:
            raise IncidentNotFoundError(incident_id)
        conn.execute(
            "INSERT INTO timeline (incident_id, step, message, timestamp) VALUES (?, ?, ?, ?)",
            (incident_id, step, message, utc_now_iso()),
        )


def list_incidents() -> List[Dict[str, Any]]:
    """Return incident summaries, newest first.

    Summaries omit the (large) evidence and RCA payloads; use
    :func:`get_incident` for those. Each summary includes ``mttd_seconds`` and
    ``mttr_seconds`` (``None`` when unavailable).
    """
    with _session() as conn:
        rows = conn.execute(
            f"SELECT {_SUMMARY_COLUMNS} FROM incidents ORDER BY detected_at DESC, id DESC"
        ).fetchall()
    return [_summary(row) for row in rows]


def get_incident(incident_id: int) -> Optional[Dict[str, Any]]:
    """Return one incident with parsed ``evidence``, ``rca`` and ordered ``timeline``.

    Returns ``None`` when the incident does not exist.
    """
    _validate_id(incident_id)
    with _session() as conn:
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if row is None:
            return None
        timeline_rows = conn.execute(
            "SELECT id, step, message, timestamp FROM timeline WHERE incident_id = ? ORDER BY id ASC",
            (incident_id,),
        ).fetchall()
    incident = _summary(row)
    incident["evidence"] = _from_json_text(row["evidence_json"], incident_id, "evidence_json")
    incident["rca"] = _from_json_text(row["rca_json"], incident_id, "rca_json")
    incident["timeline"] = [dict(t) for t in timeline_rows]
    return incident


def get_metrics() -> Dict[str, Any]:
    """Return aggregate metrics: total, resolved, avg_mttd_seconds, avg_mttr_seconds.

    Averages are ``None`` when no incident has the required timestamps.
    """
    with _session() as conn:
        rows = conn.execute(
            "SELECT status, detected_at, injected_at, resolved_at FROM incidents"
        ).fetchall()

    mttd_values: List[float] = []
    mttr_values: List[float] = []
    resolved = 0
    for row in rows:
        mttd = _duration_seconds(row["injected_at"], row["detected_at"])
        if mttd is not None:
            mttd_values.append(mttd)
        if row["status"] == "RESOLVED":
            resolved += 1
            mttr = _duration_seconds(row["detected_at"], row["resolved_at"])
            if mttr is not None:
                mttr_values.append(mttr)

    def _average(values: List[float]) -> Optional[float]:
        return round(sum(values) / len(values), 3) if values else None

    return {
        "total": len(rows),
        "resolved": resolved,
        "avg_mttd_seconds": _average(mttd_values),
        "avg_mttr_seconds": _average(mttr_values),
    }


# ---------------------------------------------------------------------------
# Helpers used by later stages (pipeline, remediation, detector)
# ---------------------------------------------------------------------------


def find_open_incident(service: str, namespace: str) -> Optional[Dict[str, Any]]:
    """Return the newest OPEN incident summary for a service/namespace, or ``None``."""
    placeholders = ", ".join("?" for _ in OPEN_STATUSES)
    with _session() as conn:
        row = conn.execute(  # nosec B608 - placeholders only, no user data in the SQL text
            f"SELECT {_SUMMARY_COLUMNS} FROM incidents "
            f"WHERE service = ? AND namespace = ? AND status IN ({placeholders}) "
            "ORDER BY id DESC LIMIT 1",
            (service, namespace, *OPEN_STATUSES),
        ).fetchone()
    return _summary(row) if row else None


def get_last_closed_at(service: str, namespace: str) -> Optional[str]:
    """Return when the latest RESOLVED or FAILED incident for a service ended.

    For RESOLVED incidents this is ``resolved_at``. FAILED incidents have no
    ``resolved_at`` (so MTTR is not distorted), so the time of their last
    timeline event is used. Used by the pipeline for cooldown decisions.
    """
    with _session() as conn:
        row = conn.execute(
            "SELECT MAX(COALESCE(i.resolved_at, "
            "    (SELECT MAX(t.timestamp) FROM timeline t WHERE t.incident_id = i.id), "
            "    i.detected_at)) AS closed_at "
            "FROM incidents i "
            "WHERE i.service = ? AND i.namespace = ? AND i.status IN ('RESOLVED', 'FAILED')",
            (service, namespace),
        ).fetchone()
    return row["closed_at"] if row else None


def increment_remediation_attempts(incident_id: int) -> int:
    """Atomically add one remediation attempt and return the new total.

    The counter lives in the database, so the attempt limit survives for the
    whole life of the incident regardless of how often callers are invoked.

    Raises:
        IncidentNotFoundError: the incident does not exist.
    """
    _validate_id(incident_id)
    with _session() as conn:
        cursor = conn.execute(
            "UPDATE incidents SET remediation_attempts = remediation_attempts + 1 WHERE id = ?",
            (incident_id,),
        )
        if cursor.rowcount == 0:
            raise IncidentNotFoundError(incident_id)
        row = conn.execute(
            "SELECT remediation_attempts FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        return int(row["remediation_attempts"])


# ---------------------------------------------------------------------------
# Stage 5 additions: status transitions, startup recovery, failure injections
# ---------------------------------------------------------------------------


def transition_status(incident_id: int, expected_status: str, new_status: str) -> bool:
    """Atomically change an incident's status only if it currently equals ``expected_status``.

    This is a compare-and-set, so two concurrent callers (for example two
    simultaneous approval requests) can never both succeed.

    Returns:
        ``True`` if this call performed the transition, ``False`` if the incident
        was not in ``expected_status`` or does not exist.

    Raises:
        ValueError: ``expected_status`` or ``new_status`` is not a valid status.
    """
    _validate_id(incident_id)
    for name, value in (("expected_status", expected_status), ("new_status", new_status)):
        if value not in VALID_STATUSES:
            raise ValueError(f"Invalid {name} {value!r}; expected one of {', '.join(VALID_STATUSES)}")
    with _session() as conn:
        cursor = conn.execute(
            "UPDATE incidents SET status = ? WHERE id = ? AND status = ?",
            (new_status, incident_id, expected_status),
        )
        changed = cursor.rowcount == 1
        if changed and new_status == "RESOLVED":
            conn.execute(
                "UPDATE incidents SET resolved_at = ? WHERE id = ? AND resolved_at IS NULL",
                (utc_now_iso(), incident_id),
            )
    return changed


def list_incidents_with_status(statuses: Any) -> List[Dict[str, Any]]:
    """Return incident summaries whose status is in ``statuses`` (oldest first).

    Raises:
        ValueError: ``statuses`` is empty or contains an invalid status.
    """
    wanted = tuple(statuses)
    if not wanted:
        raise ValueError("statuses must not be empty")
    for status in wanted:
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid status {status!r}; expected one of {', '.join(VALID_STATUSES)}")
    placeholders = ", ".join("?" for _ in wanted)
    with _session() as conn:
        rows = conn.execute(  # nosec B608 - placeholders only, values are bound
            f"SELECT {_SUMMARY_COLUMNS} FROM incidents WHERE status IN ({placeholders}) ORDER BY id ASC",
            wanted,
        ).fetchall()
    return [_summary(row) for row in rows]


def record_injection(service: str, namespace: str) -> str:
    """Record that a failure is being injected into ``namespace/service`` right now.

    Returns the normalised UTC injection timestamp. The record waits (unconsumed)
    until the detector creates an incident for the service, see
    :func:`claim_injection`.
    """
    service = _require_text("service", service, MAX_SERVICE_LENGTH)
    namespace = _require_text("namespace", namespace, MAX_NAMESPACE_LENGTH)
    injected_at = utc_now_iso()
    with _session() as conn:
        conn.execute(
            "INSERT INTO injections (service, namespace, injected_at) VALUES (?, ?, ?)",
            (service, namespace, injected_at),
        )
    logger.info("Recorded failure injection for %s/%s at %s", namespace, service, injected_at)
    return injected_at


def claim_injection(incident_id: int, max_age_seconds: float) -> Optional[str]:
    """Attach the most recent matching injection to a newly detected incident.

    An injection is eligible when it is unconsumed, belongs to the incident's
    service and namespace, was recorded BEFORE the incident was detected, and is
    no older than ``max_age_seconds`` at detection time. The newest eligible one
    wins. Every unconsumed injection recorded before detection is marked consumed
    by this incident, so a stale or superseded record can never be attached to a
    later, unrelated incident. Injections recorded after detection are left for
    the next incident.

    Returns:
        The claimed injection timestamp (also stored in ``incidents.injected_at``),
        or ``None`` when no eligible injection exists (MTTD is then unavailable).

    Raises:
        IncidentNotFoundError: the incident does not exist.
    """
    _validate_id(incident_id)
    with _session() as conn:
        incident = conn.execute(
            "SELECT service, namespace, detected_at FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        if incident is None:
            raise IncidentNotFoundError(incident_id)
        candidates = conn.execute(
            "SELECT id, injected_at FROM injections "
            "WHERE service = ? AND namespace = ? AND consumed_by_incident IS NULL AND injected_at <= ? "
            "ORDER BY injected_at DESC, id DESC",
            (incident["service"], incident["namespace"], incident["detected_at"]),
        ).fetchall()
        if not candidates:
            return None
        chosen: Optional[str] = None
        for candidate in candidates:  # newest first
            age = _duration_seconds(candidate["injected_at"], incident["detected_at"])
            if age is not None and age <= max_age_seconds:
                chosen = candidate["injected_at"]
                break
        now = utc_now_iso()
        conn.executemany(
            "UPDATE injections SET consumed_by_incident = ?, consumed_at = ? WHERE id = ?",
            [(incident_id, now, candidate["id"]) for candidate in candidates],
        )
        if chosen is not None:
            conn.execute("UPDATE incidents SET injected_at = ? WHERE id = ?", (chosen, incident_id))
    return chosen
