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

#: Cluster connection states shown on the dashboard.
CLUSTER_STATES = ("connecting", "connected", "forbidden", "unreachable", "not_configured", "error")

#: The built-in cluster (in-cluster config or KUBE_CONTEXT). Incidents recorded
#: before multi-cluster support belong to it, and it cannot be deleted.
DEFAULT_CLUSTER_ID = 1

#: Samples kept per cluster (about 30 minutes at the default 5 s interval).
SAMPLE_RETENTION = 360

MAX_CLUSTER_NAME_LENGTH = 63
MAX_CONTEXT_LENGTH = 253
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
    remediation_attempts INTEGER NOT NULL DEFAULT 0,
    cluster_id           INTEGER NOT NULL DEFAULT 1
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

CREATE TABLE IF NOT EXISTS clusters (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT    NOT NULL UNIQUE,
    context        TEXT,
    is_default     INTEGER NOT NULL DEFAULT 0,
    state          TEXT    NOT NULL DEFAULT 'connecting'
                   CHECK (state IN ({_in_list(CLUSTER_STATES)})),
    state_detail   TEXT,
    created_at     TEXT    NOT NULL,
    last_sample_at TEXT,
    snapshot_json  TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_clusters_context ON clusters(context) WHERE context IS NOT NULL;

CREATE TABLE IF NOT EXISTS cluster_samples (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id       INTEGER NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    ts               TEXT    NOT NULL,
    pods_total       INTEGER NOT NULL DEFAULT 0,
    pods_ready       INTEGER NOT NULL DEFAULT 0,
    pods_unhealthy   INTEGER NOT NULL DEFAULT 0,
    restarts_total   INTEGER NOT NULL DEFAULT 0,
    warning_events   INTEGER NOT NULL DEFAULT 0,
    log_lines        INTEGER NOT NULL DEFAULT 0,
    error_lines      INTEGER NOT NULL DEFAULT 0,
    interval_seconds REAL    NOT NULL DEFAULT 5
);

CREATE INDEX IF NOT EXISTS idx_samples_cluster_ts ON cluster_samples(cluster_id, id);
"""


class ClusterError(Exception):
    """A cluster operation cannot be honoured.

    ``kind`` is ``not_found``, ``conflict`` (duplicate name/context, or the
    cluster still has an open incident) or ``protected`` (the built-in cluster).
    """

    def __init__(self, message: str, kind: str) -> None:
        super().__init__(message)
        self.kind = kind


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
        "cluster_id": row["cluster_id"],
        "mttd_seconds": _duration_seconds(row["injected_at"], row["detected_at"]),
        "mttr_seconds": (
            _duration_seconds(row["detected_at"], row["resolved_at"]) if status == "RESOLVED" else None
        ),
    }


_SUMMARY_COLUMNS = (
    "id, service, namespace, reason, status, detected_at, resolved_at, "
    "injected_at, action, remediation_attempts, cluster_id"
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
        # Databases created before multi-cluster support lack incidents.cluster_id.
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(incidents)")}
        if "cluster_id" not in columns:
            conn.execute("ALTER TABLE incidents ADD COLUMN cluster_id INTEGER NOT NULL DEFAULT 1")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_cluster ON incidents(cluster_id, status)")
    ensure_default_cluster()
    logger.info("Database initialised at %s", path)


def create_incident(service: str, namespace: str, reason: str, cluster_id: int = DEFAULT_CLUSTER_ID) -> int:
    """Insert a new incident with status DETECTED and return its ID."""
    if isinstance(cluster_id, bool) or not isinstance(cluster_id, int) or cluster_id < 1:
        raise ValueError(f"cluster_id must be a positive integer, got {cluster_id!r}")
    service = _require_text("service", service, MAX_SERVICE_LENGTH)
    namespace = _require_text("namespace", namespace, MAX_NAMESPACE_LENGTH)
    reason = _require_text("reason", reason, MAX_REASON_LENGTH, truncate=True)
    with _session() as conn:
        cursor = conn.execute(
            "INSERT INTO incidents (service, namespace, reason, status, detected_at, cluster_id) "
            "VALUES (?, ?, ?, 'DETECTED', ?, ?)",
            (service, namespace, reason, utc_now_iso(), cluster_id),
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


def find_open_incident(service: str, namespace: str, cluster_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """Return the newest OPEN incident summary for a service/namespace, or ``None``.

    ``cluster_id=None`` looks across every cluster (the single-cluster behaviour).
    """
    placeholders = ", ".join("?" for _ in OPEN_STATUSES)
    cluster_sql = "" if cluster_id is None else " AND cluster_id = ?"
    params: tuple = (service, namespace, *OPEN_STATUSES) + (() if cluster_id is None else (cluster_id,))
    with _session() as conn:
        row = conn.execute(  # nosec B608 - placeholders only, no user data in the SQL text
            f"SELECT {_SUMMARY_COLUMNS} FROM incidents "
            f"WHERE service = ? AND namespace = ? AND status IN ({placeholders}){cluster_sql} "
            "ORDER BY id DESC LIMIT 1",
            params,
        ).fetchone()
    return _summary(row) if row else None


def get_last_closed_at(service: str, namespace: str, cluster_id: Optional[int] = None) -> Optional[str]:
    """Return when the latest RESOLVED or FAILED incident for a service ended.

    For RESOLVED incidents this is ``resolved_at``. FAILED incidents have no
    ``resolved_at`` (so MTTR is not distorted), so the time of their last
    timeline event is used. Used by the pipeline for cooldown decisions.
    """
    cluster_sql = "" if cluster_id is None else " AND i.cluster_id = ?"
    params: tuple = (service, namespace) + (() if cluster_id is None else (cluster_id,))
    with _session() as conn:
        row = conn.execute(  # nosec B608 - fixed SQL fragments, values are bound
            "SELECT MAX(COALESCE(i.resolved_at, "
            "    (SELECT MAX(t.timestamp) FROM timeline t WHERE t.incident_id = i.id), "
            "    i.detected_at)) AS closed_at "
            "FROM incidents i "
            f"WHERE i.service = ? AND i.namespace = ? AND i.status IN ('RESOLVED', 'FAILED'){cluster_sql}",
            params,
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


# ---------------------------------------------------------------------------
# Multi-cluster support: clusters, live samples, activity feed
# ---------------------------------------------------------------------------


def _cluster_row(row: sqlite3.Row) -> Dict[str, Any]:
    snapshot = None
    if row["snapshot_json"]:
        try:
            snapshot = json.loads(row["snapshot_json"])
        except ValueError:
            snapshot = None
    return {
        "id": row["id"],
        "name": row["name"],
        "context": row["context"],
        "is_default": bool(row["is_default"]),
        "state": row["state"],
        "state_detail": row["state_detail"],
        "created_at": row["created_at"],
        "last_sample_at": row["last_sample_at"],
        "snapshot": snapshot,
    }


def ensure_default_cluster() -> int:
    """Make sure the built-in cluster (id 1) exists; return its id. Safe to call repeatedly."""
    name = os.environ.get("KUBE_CONTEXT", "").strip() or "primary"
    with _session() as conn:
        row = conn.execute("SELECT id FROM clusters WHERE id = ?", (DEFAULT_CLUSTER_ID,)).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO clusters (id, name, context, is_default, state, created_at) "
                "VALUES (?, ?, NULL, 1, 'connecting', ?)",
                (DEFAULT_CLUSTER_ID, name[:MAX_CLUSTER_NAME_LENGTH], utc_now_iso()),
            )
    return DEFAULT_CLUSTER_ID


def create_cluster(name: str, context: str, state: str = "connected", state_detail: Optional[str] = None) -> int:
    """Register an additional cluster by kubeconfig context name. Returns its id.

    Only the context NAME is stored, never kubeconfig contents or credentials.

    Raises:
        ValueError: invalid name/context/state.
        ClusterError: ``conflict`` when the name or context is already registered.
    """
    name = _require_text("name", name, MAX_CLUSTER_NAME_LENGTH)
    context = _require_text("context", context, MAX_CONTEXT_LENGTH)
    if state not in CLUSTER_STATES:
        raise ValueError(f"Invalid cluster state {state!r}")
    with _session() as conn:
        if conn.execute("SELECT 1 FROM clusters WHERE context = ?", (context,)).fetchone():
            raise ClusterError(f"Context {context!r} is already connected", "conflict")
        if conn.execute("SELECT 1 FROM clusters WHERE name = ?", (name,)).fetchone():
            raise ClusterError(f"A cluster named {name!r} already exists", "conflict")
        cursor = conn.execute(
            "INSERT INTO clusters (name, context, is_default, state, state_detail, created_at) "
            "VALUES (?, ?, 0, ?, ?, ?)",
            (name, context, state, state_detail, utc_now_iso()),
        )
        cluster_id = int(cursor.lastrowid)
    logger.info("Connected cluster %s (%s) as id %s", name, context, cluster_id)
    return cluster_id


def list_clusters() -> List[Dict[str, Any]]:
    """Return every cluster (built-in first) with its latest snapshot and incident counts."""
    with _session() as conn:
        rows = conn.execute("SELECT * FROM clusters ORDER BY is_default DESC, id ASC").fetchall()
        open_marks = ", ".join("?" for _ in OPEN_STATUSES)
        open_rows = conn.execute(  # nosec B608 - placeholders only
            f"SELECT cluster_id, COUNT(*) AS n FROM incidents WHERE status IN ({open_marks}) GROUP BY cluster_id",
            OPEN_STATUSES,
        ).fetchall()
        total_rows = conn.execute("SELECT cluster_id, COUNT(*) AS n FROM incidents GROUP BY cluster_id").fetchall()
    open_by = {r["cluster_id"]: r["n"] for r in open_rows}
    total_by = {r["cluster_id"]: r["n"] for r in total_rows}
    result = []
    for row in rows:
        item = _cluster_row(row)
        item["open_incidents"] = open_by.get(row["id"], 0)
        item["total_incidents"] = total_by.get(row["id"], 0)
        result.append(item)
    return result


def get_cluster(cluster_id: int) -> Optional[Dict[str, Any]]:
    """Return one cluster, or ``None`` if it does not exist."""
    _validate_id(cluster_id)
    with _session() as conn:
        row = conn.execute("SELECT * FROM clusters WHERE id = ?", (cluster_id,)).fetchone()
    return _cluster_row(row) if row else None


def delete_cluster(cluster_id: int) -> Dict[str, Any]:
    """Disconnect a cluster and drop its samples. Incident history is kept.

    Raises:
        ClusterError: ``not_found``; ``protected`` for the built-in cluster;
            ``conflict`` while any of its incidents is still open (solve it first).
    """
    _validate_id(cluster_id)
    with _session() as conn:
        row = conn.execute("SELECT * FROM clusters WHERE id = ?", (cluster_id,)).fetchone()
        if row is None:
            raise ClusterError(f"Cluster {cluster_id} not found", "not_found")
        if row["is_default"]:
            raise ClusterError("The built-in cluster cannot be deleted", "protected")
        marks = ", ".join("?" for _ in OPEN_STATUSES)
        open_count = conn.execute(  # nosec B608 - placeholders only
            f"SELECT COUNT(*) AS n FROM incidents WHERE cluster_id = ? AND status IN ({marks})",
            (cluster_id, *OPEN_STATUSES),
        ).fetchone()["n"]
        if open_count:
            raise ClusterError(
                f"Cluster {row['name']!r} still has {open_count} open incident(s); resolve them before deleting it",
                "conflict",
            )
        conn.execute("DELETE FROM cluster_samples WHERE cluster_id = ?", (cluster_id,))
        conn.execute("DELETE FROM clusters WHERE id = ?", (cluster_id,))
    logger.info("Deleted cluster %s (%s)", cluster_id, row["name"])
    return _cluster_row(row)


def set_cluster_state(cluster_id: int, state: str, detail: Optional[str] = None) -> None:
    """Record the connection state of a cluster (no error if it was deleted meanwhile)."""
    if state not in CLUSTER_STATES:
        raise ValueError(f"Invalid cluster state {state!r}")
    with _session() as conn:
        conn.execute(
            "UPDATE clusters SET state = ?, state_detail = ? WHERE id = ?",
            (state, (detail or "")[:300] or None, cluster_id),
        )


def record_sample(cluster_id: int, sample: Dict[str, Any], snapshot: Optional[Dict[str, Any]] = None) -> None:
    """Store one metrics sample (and the latest workload snapshot) for a cluster.

    A sample for a cluster that was deleted while it was being taken is dropped.
    Old samples beyond :data:`SAMPLE_RETENTION` are pruned.
    """
    ts = utc_now_iso()
    with _session() as conn:
        if conn.execute("SELECT 1 FROM clusters WHERE id = ?", (cluster_id,)).fetchone() is None:
            return
        conn.execute(
            "INSERT INTO cluster_samples (cluster_id, ts, pods_total, pods_ready, pods_unhealthy, restarts_total, "
            "warning_events, log_lines, error_lines, interval_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                cluster_id, ts,
                int(sample.get("pods_total", 0)), int(sample.get("pods_ready", 0)), int(sample.get("pods_unhealthy", 0)),
                int(sample.get("restarts_total", 0)), int(sample.get("warning_events", 0)),
                int(sample.get("log_lines", 0)), int(sample.get("error_lines", 0)),
                float(sample.get("interval_seconds", 5)),
            ),
        )
        conn.execute(
            "UPDATE clusters SET last_sample_at = ?, snapshot_json = ? WHERE id = ?",
            (ts, json.dumps(snapshot, default=str) if snapshot is not None else None, cluster_id),
        )
        conn.execute(
            "DELETE FROM cluster_samples WHERE cluster_id = ? AND id NOT IN "
            "(SELECT id FROM cluster_samples WHERE cluster_id = ? ORDER BY id DESC LIMIT ?)",
            (cluster_id, cluster_id, SAMPLE_RETENTION),
        )


def get_samples(cluster_id: int, limit: int = 60) -> List[Dict[str, Any]]:
    """Return the newest ``limit`` samples of a cluster, oldest first."""
    limit = max(1, min(int(limit), SAMPLE_RETENTION))
    with _session() as conn:
        rows = conn.execute(
            "SELECT ts, pods_total, pods_ready, pods_unhealthy, restarts_total, warning_events, "
            "log_lines, error_lines, interval_seconds FROM cluster_samples "
            "WHERE cluster_id = ? ORDER BY id DESC LIMIT ?",
            (cluster_id, limit),
        ).fetchall()
    return [dict(r) for r in reversed(rows)]


def list_activity(limit: int = 40) -> List[Dict[str, Any]]:
    """Return the newest timeline entries across all incidents (for the live activity feed)."""
    limit = max(1, min(int(limit), 200))
    with _session() as conn:
        rows = conn.execute(
            "SELECT t.id, t.incident_id, t.step, t.message, t.timestamp, i.service, i.namespace, i.cluster_id "
            "FROM timeline t JOIN incidents i ON i.id = t.incident_id ORDER BY t.id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]
