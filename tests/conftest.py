"""Shared pytest fixtures.

Every test runs with an isolated environment: a temporary SQLite file, the
developer's real ``.env`` ignored, automatic remediation off, and no Gemini
key. No test needs a Kubernetes cluster or network access.
"""

from __future__ import annotations

import pytest

from backend import config, db


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path, monkeypatch):
    """Give each test its own configuration and database file."""
    # Never read the developer's real .env during tests.
    monkeypatch.setattr(config, "load_dotenv", lambda *args, **kwargs: False)
    for name, value in {
        "APP_ENV": "test",
        "API_KEY": "test-api-key-for-pytest",
        "DATABASE_PATH": str(tmp_path / "incidentiq-test.db"),
        "GEMINI_API_KEY": "",
        "KUBERNETES_NAMESPACE_ALLOWLIST": "default",
        "AUTO_REMEDIATE": "false",
        "ROLLBACK_MODE": "python",
        "MAX_REMEDIATION_ATTEMPTS": "2",
        "INCIDENT_COOLDOWN_SECONDS": "60",
    }.items():
        monkeypatch.setenv(name, value)
    config.reset_settings()
    yield
    config.reset_settings()


@pytest.fixture()
def temp_db(isolated_settings):
    """Initialise an empty temporary database and return the ``db`` module."""
    db.init_db()
    return db


# ---------------------------------------------------------------------------
# Shared by test_pipeline.py and test_api.py
# ---------------------------------------------------------------------------

from backend import collector, rca, remediation  # noqa: E402


def set_settings(monkeypatch, **env):
    """Set environment variables and reload the cached settings."""
    for name, value in env.items():
        monkeypatch.setenv(name, str(value))
    config.reset_settings()
    return config.get_settings()


class FakeWorld:
    """Controllable stand-ins for the collector, RCA and remediation modules.

    ``calls`` records the order of external operations so tests can assert, for
    example, that verification never ran after a failed remediation.
    """

    def __init__(self) -> None:
        self.calls = []
        self.evidence = {
            "logs": [{"pod": "shop-api-1", "container": "shop-api", "source": "previous",
                      "lines": ["Exception: DB_URL missing"], "error": None}],
            "events": [{"type": "Warning", "reason": "BackOff", "message": "Back-off restarting",
                        "involved_object": "Pod/shop-api-1", "count": 3, "timestamp": None}],
            "pods": [{"name": "shop-api-1", "phase": "Running", "ready": False, "created": None,
                      "terminating": False, "containers": []}],
            "last_deploy_time": "2026-10-09T10:00:00+00:00",
            "rollout_history": [{"name": "shop-api-abc", "revision": 2}],
        }
        self.diagnosis = {
            "probable_cause": "DB_URL environment variable is missing",
            "evidence": ["Exception: DB_URL missing"],
            "confidence": 0.9,
            "recommended_action": "rollback",
            "source": "llm",
        }
        self.execute_result = {"success": True, "detail": "Rolled back default/shop-api from revision 2 to revision 1"}
        self.verify_result = (True, "2/2 replicas updated, ready and available; all pods Running and Ready")
        self.collect_error = None
        self.analyze_error = None
        self.execute_error = None
        self.execute_consumes_attempt = True
        self.execute_kwargs = []
        self.execute_gate = None  # threading.Event: execute blocks until set

    def collect(self, namespace, service):
        self.calls.append(("collect", namespace, service))
        if self.collect_error:
            raise self.collect_error
        return self.evidence

    def analyze(self, evidence):
        self.calls.append(("analyze",))
        if self.analyze_error:
            raise self.analyze_error
        return dict(self.diagnosis)

    def execute(self, action, namespace, service, *, incident_id=None, approved=False):
        self.calls.append(("execute", action, namespace, service))
        self.execute_kwargs.append({"incident_id": incident_id, "approved": approved})
        if self.execute_gate is not None:
            self.execute_gate.wait(timeout=10)
        if self.execute_error:
            raise self.execute_error
        if self.execute_consumes_attempt and incident_id is not None:
            db.increment_remediation_attempts(incident_id)
        return dict(self.execute_result)

    def verify(self, namespace, service, timeout=None):
        self.calls.append(("verify", namespace, service))
        return self.verify_result

    def names(self):
        return [call[0] for call in self.calls]


@pytest.fixture()
def world(temp_db, monkeypatch):
    """Patch the external steps of the pipeline with a controllable :class:`FakeWorld`."""
    fake = FakeWorld()
    monkeypatch.setattr(collector, "collect_evidence", fake.collect)
    monkeypatch.setattr(rca, "analyze", fake.analyze)
    monkeypatch.setattr(remediation, "execute", fake.execute)
    monkeypatch.setattr(remediation, "verify_with_detail", fake.verify)
    return fake
