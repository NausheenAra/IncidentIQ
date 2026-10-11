"""Tests for backend/api.py using FastAPI's TestClient (no cluster, Gemini or network)."""

from __future__ import annotations

import logging
import time

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402
from kubernetes.client.exceptions import ApiException  # noqa: E402

from backend import config, db, detector, kube, pipeline  # noqa: E402
from backend.api import KubernetesProbe, create_app  # noqa: E402
from conftest import set_settings  # noqa: E402

KEY = "test-api-key-for-pytest"  # set by the autouse fixture in conftest.py
AUTH = {"X-API-Key": KEY}
ISSUE = {"service": "shop-api", "namespace": "default", "reason": "CrashLoopBackOff"}


def wait_until(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


@pytest.fixture()
def dashboard(tmp_path):
    folder = tmp_path / "dashboard"
    folder.mkdir()
    (folder / "index.html").write_text("<html><body>INDEX</body></html>", encoding="utf-8")
    (folder / "incident.html").write_text("<html><body>DETAIL</body></html>", encoding="utf-8")
    (folder / "app.js").write_text("console.log('hi');", encoding="utf-8")
    (folder / "style.css").write_text("body{}", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("TOP-SECRET", encoding="utf-8")
    return folder


@pytest.fixture()
def client(temp_db, dashboard):
    app = create_app(start_detector=False, dashboard_dir=dashboard, configure_logging=False)
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    pipeline.join_workers(5)


def open_incident(world):
    """Create an AWAITING_APPROVAL incident through the real pipeline."""
    pipeline.handle_incident(ISSUE)
    return db.list_incidents()[0]["id"]


# ---------------------------------------------------------------------------
# Read endpoints
# ---------------------------------------------------------------------------


def test_incident_list_starts_empty_and_is_newest_first(client):
    assert client.get("/api/incidents").json() == []
    first = db.create_incident("a", "default", "r")
    second = db.create_incident("b", "default", "r")
    listed = client.get("/api/incidents").json()
    assert [i["id"] for i in listed] == [second, first]
    assert {"id", "service", "namespace", "reason", "status", "detected_at", "mttd_seconds", "mttr_seconds"} <= set(listed[0])
    assert "evidence" not in listed[0]


def test_incident_detail_includes_evidence_rca_and_ordered_timeline(client, world):
    incident_id = open_incident(world)
    body = client.get(f"/api/incidents/{incident_id}").json()
    assert body["id"] == incident_id and body["status"] == "AWAITING_APPROVAL"
    assert body["evidence"]["logs"][0]["lines"] == ["Exception: DB_URL missing"]
    assert body["rca"]["recommended_action"] == "rollback"
    assert [t["step"] for t in body["timeline"]][0] == "DETECTED"
    assert body["timeline"][-1]["step"] == "AWAITING_APPROVAL"


def test_missing_incident_returns_404(client):
    response = client.get("/api/incidents/999")
    assert response.status_code == 404
    assert "999" in response.json()["detail"]


@pytest.mark.parametrize("bad_id", ["abc", "0", "-1", "1.5", "9" * 30])
def test_invalid_incident_ids_return_422_not_500(client, bad_id):
    assert client.get(f"/api/incidents/{bad_id}").status_code == 422
    assert client.post(f"/api/incidents/{bad_id}/approve", headers=AUTH).status_code == 422


def test_metrics_match_the_database_and_the_incident_record(client, world, monkeypatch):
    set_settings(monkeypatch, AUTO_REMEDIATE="true")
    assert client.get("/api/metrics").json() == {"total": 0, "resolved": 0, "avg_mttd_seconds": None, "avg_mttr_seconds": None}

    client.post("/api/injection", json={"service": "shop-api", "namespace": "default"}, headers=AUTH)
    time.sleep(0.05)
    pipeline.handle_incident(ISSUE)

    metrics = client.get("/api/metrics").json()
    incident = client.get("/api/incidents/1").json()
    assert metrics["total"] == 1 and metrics["resolved"] == 1
    assert metrics["avg_mttd_seconds"] == incident["mttd_seconds"] > 0
    assert metrics["avg_mttr_seconds"] == incident["mttr_seconds"] is not None
    assert metrics == db.get_metrics()


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok", "detector_running": False}


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("headers", [{}, {"X-API-Key": ""}, {"X-API-Key": "wrong-key"}, {"X-API-Key": KEY + "x"}, {"X-API-Key": KEY[:-1]},
                                     {"Authorization": f"Bearer {KEY}"}, {"x-api-key ": KEY}])
def test_approval_without_a_valid_key_is_rejected_and_does_nothing(client, world, headers):
    incident_id = open_incident(world)
    response = client.post(f"/api/incidents/{incident_id}/approve", headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "ApiKey"
    assert db.get_incident(incident_id)["status"] == "AWAITING_APPROVAL"
    assert "execute" not in world.names()


def test_key_in_the_query_string_is_not_accepted(client, world):
    incident_id = open_incident(world)
    assert client.post(f"/api/incidents/{incident_id}/approve?api_key={KEY}&X-API-Key={KEY}").status_code == 401


@pytest.mark.parametrize("headers", [{}, {"X-API-Key": "wrong-key"}])
def test_injection_without_a_valid_key_is_rejected_and_records_nothing(client, headers):
    response = client.post("/api/injection", json={"service": "shop-api", "namespace": "default"}, headers=headers)
    assert response.status_code == 401
    conn = db._connect()
    try:
        assert conn.execute("SELECT COUNT(*) FROM injections").fetchone()[0] == 0
    finally:
        conn.close()


def test_auth_is_checked_before_the_incident_lookup(client):
    """An unauthenticated caller must not learn which incident ids exist."""
    assert client.post("/api/incidents/424242/approve").status_code == 401
    assert client.post("/api/incidents/424242/approve", headers=AUTH).status_code == 404


def test_auth_is_checked_before_body_validation(client):
    assert client.post("/api/injection", json={"nonsense": True}).status_code == 401


def test_read_endpoints_need_no_key(client):
    for path in ("/api/incidents", "/api/metrics", "/api/status", "/healthz"):
        assert client.get(path).status_code == 200


def test_api_key_never_appears_in_responses_or_logs(client, world, caplog):
    incident_id = open_incident(world)
    wrong = "attacker-guess-SECRET-123"
    with caplog.at_level(logging.DEBUG):
        responses = [
            client.post(f"/api/incidents/{incident_id}/approve", headers={"X-API-Key": wrong}),
            client.post("/api/injection", json={"service": "x", "namespace": "default"}, headers={"X-API-Key": wrong}),
            client.post("/api/injection", json={"service": "x", "namespace": "default"}, headers=AUTH),
            client.get("/api/status"),
            client.get(f"/api/incidents/{incident_id}"),
        ]
    for response in responses:
        assert KEY not in response.text and wrong not in response.text
    assert KEY not in caplog.text and wrong not in caplog.text
    assert any("invalid API key" in record.getMessage() for record in caplog.records)


def test_validation_errors_do_not_echo_submitted_values(client):
    response = client.post(
        "/api/injection", json={"service": "SECRET-VALUE-XYZ", "namespace": "default"}, headers=AUTH
    )
    assert response.status_code == 422
    assert "SECRET-VALUE-XYZ" not in response.text
    assert response.json()["detail"][0]["loc"][-1] == "service"


# ---------------------------------------------------------------------------
# Approval workflow
# ---------------------------------------------------------------------------


def test_authenticated_approval_runs_the_recommended_action_and_resolves(client, world):
    incident_id = open_incident(world)

    response = client.post(f"/api/incidents/{incident_id}/approve", headers=AUTH)

    assert response.status_code == 202
    assert response.json() == {"id": incident_id, "status": "REMEDIATING", "action": "rollback", "approved": True}
    assert wait_until(lambda: db.get_incident(incident_id)["status"] in ("RESOLVED", "FAILED"))
    incident = client.get(f"/api/incidents/{incident_id}").json()
    assert incident["status"] == "RESOLVED"
    assert incident["action"] == "rollback" and incident["resolved_at"] is not None
    assert [t["step"] for t in incident["timeline"]][-3:] == ["REMEDIATING", "VERIFYING", "RESOLVED"]
    assert world.execute_kwargs == [{"incident_id": incident_id, "approved": True}]


def test_approval_cannot_choose_the_action(client, world):
    incident_id = open_incident(world)
    response = client.post(f"/api/incidents/{incident_id}/approve", headers=AUTH, json={"action": "scale", "namespace": "kube-system"})
    assert response.status_code == 202
    pipeline.join_workers(5)
    assert [c for c in world.calls if c[0] == "execute"] == [("execute", "rollback", "default", "shop-api")]


def test_failed_remediation_after_approval_is_reported_as_failed(client, world):
    incident_id = open_incident(world)
    world.verify_result = (False, "timed out after 120s: 1/2 replicas ready")
    assert client.post(f"/api/incidents/{incident_id}/approve", headers=AUTH).status_code == 202
    assert wait_until(lambda: db.get_incident(incident_id)["status"] in ("RESOLVED", "FAILED"))
    incident = client.get(f"/api/incidents/{incident_id}").json()
    assert incident["status"] == "FAILED" and incident["resolved_at"] is None


def test_approving_twice_returns_conflict(client, world):
    incident_id = open_incident(world)
    assert client.post(f"/api/incidents/{incident_id}/approve", headers=AUTH).status_code == 202
    pipeline.join_workers(5)
    second = client.post(f"/api/incidents/{incident_id}/approve", headers=AUTH)
    assert second.status_code == 409
    assert world.names().count("execute") == 1


def test_approving_a_missing_incident_returns_404(client):
    assert client.post("/api/incidents/777/approve", headers=AUTH).status_code == 404


@pytest.mark.parametrize("status", ["DETECTED", "ANALYZING", "REMEDIATING", "VERIFYING", "RESOLVED", "FAILED"])
def test_only_awaiting_incidents_can_be_approved(client, world, status):
    incident_id = db.create_incident("shop-api", "default", "r")
    db.update_incident(incident_id, status=status, rca_json=world.diagnosis)
    response = client.post(f"/api/incidents/{incident_id}/approve", headers=AUTH)
    assert response.status_code == 409 and status in response.json()["detail"]
    assert world.calls == []


def test_approval_without_a_valid_recommendation_returns_422(client, world):
    incident_id = db.create_incident("shop-api", "default", "r")
    db.update_incident(incident_id, status="AWAITING_APPROVAL", rca_json={"recommended_action": "format-disk"})
    assert client.post(f"/api/incidents/{incident_id}/approve", headers=AUTH).status_code == 422
    assert db.get_incident(incident_id)["status"] == "AWAITING_APPROVAL"


# ---------------------------------------------------------------------------
# Injection
# ---------------------------------------------------------------------------


def test_injection_records_the_time_and_the_next_incident_uses_it(client, world):
    # Exactly the request deploy_bad.sh sends:
    response = client.post("/api/injection", json={"service": "shop-api", "namespace": "default"}, headers=AUTH)
    assert response.status_code == 201
    body = response.json()
    assert body["service"] == "shop-api" and body["namespace"] == "default"
    assert body["injected_at"].endswith("+00:00")

    time.sleep(0.05)
    pipeline.handle_incident(ISSUE)  # the detector notices the failure afterwards

    incident = client.get("/api/incidents/1").json()
    assert incident["injected_at"] == body["injected_at"]
    assert incident["mttd_seconds"] is not None and incident["mttd_seconds"] > 0
    assert "Matched the failure injection" in incident["timeline"][0]["message"]


def test_injection_is_consumed_by_one_incident_only(client, world, monkeypatch):
    set_settings(monkeypatch, INCIDENT_COOLDOWN_SECONDS="0", AUTO_REMEDIATE="true")
    client.post("/api/injection", json={"service": "shop-api", "namespace": "default"}, headers=AUTH)
    pipeline.handle_incident(ISSUE)
    pipeline.handle_incident(ISSUE)
    incidents = client.get("/api/incidents").json()
    assert len(incidents) == 2
    with_injection = [i for i in incidents if i["injected_at"]]
    assert len(with_injection) == 1


def test_injection_for_a_namespace_outside_the_allow_list_is_forbidden(client):
    response = client.post("/api/injection", json={"service": "shop-api", "namespace": "kube-system"}, headers=AUTH)
    assert response.status_code == 403
    conn = db._connect()
    try:
        assert conn.execute("SELECT COUNT(*) FROM injections").fetchone()[0] == 0
    finally:
        conn.close()


@pytest.mark.parametrize(
    "payload",
    [
        {}, {"service": "shop-api"}, {"namespace": "default"},
        {"service": "", "namespace": "default"}, {"service": "shop-api", "namespace": ""},
        {"service": "Shop API", "namespace": "default"}, {"service": "../etc", "namespace": "default"},
        {"service": "shop-api; rm -rf /", "namespace": "default"}, {"service": "UPPER", "namespace": "default"},
        {"service": "shop-api", "namespace": "Default"}, {"service": "x" * 254, "namespace": "default"},
        {"service": 5, "namespace": "default"}, {"service": None, "namespace": "default"},
    ],
)
def test_injection_rejects_invalid_bodies(client, payload):
    assert client.post("/api/injection", json=payload, headers=AUTH).status_code == 422


def test_injection_rejects_non_json_bodies(client):
    assert client.post("/api/injection", content="service=shop-api", headers=AUTH).status_code == 422
    assert client.post("/api/injection", headers={**AUTH, "Content-Type": "application/json"}, content="{broken").status_code == 422


def test_injection_ignores_unknown_extra_fields(client):
    response = client.post("/api/injection", json={"service": "shop-api", "namespace": "default", "extra": 1}, headers=AUTH)
    assert response.status_code == 201


# ---------------------------------------------------------------------------
# Status and Kubernetes probe
# ---------------------------------------------------------------------------


class _Core:
    def __init__(self, error=None):
        self.error = error
        self.calls = 0

    def list_namespaced_pod(self, namespace, **kwargs):
        self.calls += 1
        if self.error:
            raise self.error
        return object()


@pytest.mark.parametrize(
    "error,state",
    [
        (None, "connected"),
        (kube.KubeConfigError("no kubeconfig"), "not_configured"),
        (ApiException(status=403, reason="Forbidden"), "forbidden"),
        (ApiException(status=401, reason="Unauthorized"), "forbidden"),
        (ApiException(status=500, reason="Server Error"), "error"),
        (ConnectionError("refused"), "unreachable"),
    ],
)
def test_kubernetes_probe_states(monkeypatch, error, state):
    core = _Core(error)
    monkeypatch.setattr(kube, "core_v1", lambda: (_ for _ in ()).throw(error) if isinstance(error, kube.KubeConfigError) else core)
    result = KubernetesProbe(ttl_seconds=0).get()
    assert result["state"] == state and result["checked_at"].endswith("+00:00")


def test_kubernetes_probe_is_cached(monkeypatch):
    core = _Core()
    monkeypatch.setattr(kube, "core_v1", lambda: core)
    probe = KubernetesProbe(ttl_seconds=60)
    probe.get(), probe.get(), probe.get()
    assert core.calls == 1
    KubernetesProbe(ttl_seconds=0).get()
    assert core.calls == 2


def test_status_endpoint_reports_modes_without_secrets(client, monkeypatch):
    monkeypatch.setattr(kube, "core_v1", lambda: _Core())
    body = client.get("/api/status").json()
    assert body["auto_remediate"] is False and body["rollback_mode"] == "python"
    assert body["namespaces"] == ["default"] and body["gemini_enabled"] is False
    assert body["kubernetes"]["state"] == "connected"
    assert body["detector"]["running"] is False
    assert KEY not in client.get("/api/status").text and "api_key" not in body


# ---------------------------------------------------------------------------
# Dashboard hosting and headers
# ---------------------------------------------------------------------------


def test_dashboard_pages_are_served_with_a_content_security_policy(client):
    index = client.get("/")
    assert index.status_code == 200 and "INDEX" in index.text
    assert "text/html" in index.headers["content-type"]
    assert "script-src 'self'" in index.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in index.headers["content-security-policy"]
    detail = client.get("/incidents/5")  # served even for ids that do not exist; the page shows the 404
    assert detail.status_code == 200 and "DETAIL" in detail.text


def test_static_assets_are_served(client):
    assert client.get("/static/app.js").text == "console.log('hi');"
    assert client.get("/static/style.css").status_code == 200


@pytest.mark.parametrize("path", ["/static/../secret.txt", "/static/%2e%2e/secret.txt", "/static/..%2fsecret.txt", "/static/missing.js"])
def test_static_path_traversal_is_blocked(client, path):
    response = client.get(path)
    assert response.status_code == 404 and "TOP-SECRET" not in response.text


def test_missing_dashboard_files_give_a_clear_404_instead_of_crashing(temp_db, tmp_path):
    app = create_app(start_detector=False, dashboard_dir=tmp_path / "nope", configure_logging=False)
    with TestClient(app) as c:
        assert c.get("/").status_code == 404 and "index.html" in c.get("/").json()["detail"]
        assert c.get("/incidents/1").status_code == 404
        assert c.get("/api/metrics").status_code == 200


def test_security_headers_and_no_store_on_api_responses(client):
    api = client.get("/api/metrics")
    assert api.headers["x-content-type-options"] == "nosniff"
    assert api.headers["x-frame-options"] == "DENY"
    assert api.headers["cache-control"] == "no-store"
    assert client.get("/").headers["x-content-type-options"] == "nosniff"


def test_interactive_docs_are_disabled_in_production(temp_db, monkeypatch):
    set_settings(monkeypatch, APP_ENV="production", API_KEY="p" * 40)
    app = create_app(start_detector=False, configure_logging=False)
    with TestClient(app) as c:
        assert c.get("/docs").status_code == 404 and c.get("/openapi.json").status_code == 404


def test_unhandled_errors_return_a_generic_500(client, monkeypatch):
    monkeypatch.setattr(db, "list_incidents", lambda: (_ for _ in ()).throw(RuntimeError("secret internal detail")))
    response = client.get("/api/incidents")
    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    assert "secret internal detail" not in response.text


# ---------------------------------------------------------------------------
# Application lifecycle
# ---------------------------------------------------------------------------


def test_startup_initialises_the_database_and_recovers_interrupted_incidents(tmp_path, monkeypatch):
    db.init_db()
    stuck = db.create_incident("shop-api", "default", "r")
    db.update_incident(stuck, status="VERIFYING")
    waiting = db.create_incident("other", "default", "r")
    db.update_incident(waiting, status="AWAITING_APPROVAL")

    with TestClient(create_app(start_detector=False, configure_logging=False)) as c:
        assert c.get("/api/incidents/%d" % stuck).json()["status"] == "FAILED"
        assert c.get("/api/incidents/%d" % waiting).json()["status"] == "AWAITING_APPROVAL"


def test_detector_loop_starts_with_the_app_and_stops_at_shutdown(temp_db, monkeypatch):
    set_settings(monkeypatch, DETECTOR_INTERVAL_SECONDS="3600")
    polls = []
    monkeypatch.setattr(detector, "check_cluster", lambda: polls.append(1) or [])
    app = create_app(start_detector=True, configure_logging=False)
    with TestClient(app) as c:
        assert wait_until(lambda: app.state.detector.running and polls)
        assert c.get("/api/status").json()["detector"]["running"] is True
        assert c.get("/healthz").json()["detector_running"] is True
        loop = app.state.detector
    assert not loop.running  # stopped promptly despite the one-hour interval


def test_detected_failure_flows_through_the_running_app(temp_db, world, monkeypatch):
    """Detector loop -> pipeline -> API, with an authenticated approval at the end.

    Mirrors the real order of events: the injection is recorded FIRST, the
    workload breaks afterwards, and only then does the detector see it.
    """
    set_settings(monkeypatch, DETECTOR_INTERVAL_SECONDS="1")
    cluster = {"broken": False}
    monkeypatch.setattr(detector, "check_cluster", lambda: [dict(ISSUE)] if cluster["broken"] else [])
    app = create_app(start_detector=True, configure_logging=False)
    with TestClient(app) as c:
        assert c.post("/api/injection", json={"service": "shop-api", "namespace": "default"}, headers=AUTH).status_code == 201
        time.sleep(0.05)
        cluster["broken"] = True
        assert wait_until(lambda: any(i["status"] == "AWAITING_APPROVAL" for i in c.get("/api/incidents").json()), timeout=8)
        time.sleep(2.2)  # let the loop poll the still-broken service a few more times
        incidents = c.get("/api/incidents").json()
        assert len(incidents) == 1  # polled repeatedly, still exactly one incident
        incident_id = incidents[0]["id"]
        assert c.post(f"/api/incidents/{incident_id}/approve", headers=AUTH).status_code == 202
        assert wait_until(lambda: c.get(f"/api/incidents/{incident_id}").json()["status"] == "RESOLVED", timeout=8)
        final = c.get(f"/api/incidents/{incident_id}").json()
        assert final["mttd_seconds"] is not None and final["mttd_seconds"] > 0
        assert final["mttr_seconds"] is not None
        assert c.get("/api/metrics").json()["resolved"] == 1


def test_module_level_app_exists_and_is_a_fastapi_instance():
    from fastapi import FastAPI

    from backend import api

    assert isinstance(api.app, FastAPI)
    assert config.get_settings().api_key  # settings load cleanly under the test environment
