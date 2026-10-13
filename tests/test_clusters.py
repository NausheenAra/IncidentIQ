"""Multi-cluster support: registry, live metrics sampling, API and per-cluster incidents.

No cluster, network or Gemini key is needed: Kubernetes is simulated with the
fakes in ``k8s_fakes.py`` and kubeconfig contexts are monkeypatched.
"""

from __future__ import annotations

import sqlite3
import time

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402
from kubernetes.client.exceptions import ApiException  # noqa: E402

import k8s_fakes as kf  # noqa: E402
from backend import config, db, kube, metrics, pipeline  # noqa: E402
from backend.api import create_app  # noqa: E402

KEY = "test-api-key-for-pytest"
AUTH = {"X-API-Key": KEY}
ISSUE = {"service": "shop-api", "namespace": "default", "reason": "CrashLoopBackOff"}


# ---------------------------------------------------------------------------
# Registry (db.py)
# ---------------------------------------------------------------------------


def test_init_creates_the_built_in_cluster(temp_db):
    clusters = db.list_clusters()
    assert [c["id"] for c in clusters] == [db.DEFAULT_CLUSTER_ID]
    assert clusters[0]["is_default"] is True and clusters[0]["context"] is None
    db.init_db()  # idempotent
    assert len(db.list_clusters()) == 1


def test_create_cluster_stores_only_the_context_name(temp_db):
    cid = db.create_cluster("staging", "kind-staging")
    cluster = db.get_cluster(cid)
    assert cluster["name"] == "staging" and cluster["context"] == "kind-staging"
    assert cluster["is_default"] is False


def test_duplicate_name_or_context_is_a_conflict(temp_db):
    db.create_cluster("staging", "kind-staging")
    with pytest.raises(db.ClusterError) as by_name:
        db.create_cluster("staging", "other")
    with pytest.raises(db.ClusterError) as by_context:
        db.create_cluster("other", "kind-staging")
    assert by_name.value.kind == "conflict" and by_context.value.kind == "conflict"


def test_built_in_cluster_cannot_be_deleted(temp_db):
    with pytest.raises(db.ClusterError) as exc:
        db.delete_cluster(db.DEFAULT_CLUSTER_ID)
    assert exc.value.kind == "protected"


def test_cluster_with_an_open_incident_cannot_be_deleted_until_it_is_solved(temp_db):
    cid = db.create_cluster("staging", "kind-staging")
    incident = db.create_incident("shop-api", "default", "CrashLoopBackOff", cid)
    with pytest.raises(db.ClusterError) as exc:
        db.delete_cluster(cid)
    assert exc.value.kind == "conflict"

    db.update_incident(incident, status="RESOLVED")
    removed = db.delete_cluster(cid)
    assert removed["name"] == "staging"
    assert db.get_cluster(cid) is None
    # history is kept, pointing at the removed cluster
    assert db.get_incident(incident)["cluster_id"] == cid


def test_failed_incident_also_unblocks_deletion(temp_db):
    cid = db.create_cluster("staging", "kind-staging")
    incident = db.create_incident("shop-api", "default", "OOMKilled", cid)
    db.update_incident(incident, status="FAILED")
    db.delete_cluster(cid)


def test_delete_unknown_cluster(temp_db):
    with pytest.raises(db.ClusterError) as exc:
        db.delete_cluster(999)
    assert exc.value.kind == "not_found"


def test_open_incident_and_cooldown_are_scoped_per_cluster(temp_db):
    other = db.create_cluster("staging", "kind-staging")
    db.create_incident("shop-api", "default", "CrashLoopBackOff", db.DEFAULT_CLUSTER_ID)
    assert db.find_open_incident("shop-api", "default", db.DEFAULT_CLUSTER_ID) is not None
    assert db.find_open_incident("shop-api", "default", other) is None
    assert db.find_open_incident("shop-api", "default") is not None  # no cluster filter = any


def test_old_databases_are_migrated(tmp_path, monkeypatch):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, service TEXT NOT NULL, namespace TEXT NOT NULL,"
        " reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'DETECTED', detected_at TEXT NOT NULL, resolved_at TEXT,"
        " injected_at TEXT, evidence_json TEXT, rca_json TEXT, action TEXT, remediation_attempts INTEGER NOT NULL DEFAULT 0);"
        "INSERT INTO incidents (service, namespace, reason, detected_at) VALUES ('shop-api','default','NotReady','2026-10-01T00:00:00+00:00');"
    )
    conn.commit()
    conn.close()
    monkeypatch.setenv("DATABASE_PATH", str(path))
    config.reset_settings()
    db.init_db()
    assert db.list_incidents()[0]["cluster_id"] == db.DEFAULT_CLUSTER_ID


def test_samples_are_stored_newest_last_and_pruned(temp_db, monkeypatch):
    monkeypatch.setattr(db, "SAMPLE_RETENTION", 5)
    for i in range(8):
        db.record_sample(db.DEFAULT_CLUSTER_ID, {"pods_total": i, "pods_ready": i}, {"workloads": []})
    samples = db.get_samples(db.DEFAULT_CLUSTER_ID, 60)
    assert [s["pods_total"] for s in samples] == [3, 4, 5, 6, 7]
    assert db.get_cluster(db.DEFAULT_CLUSTER_ID)["snapshot"] == {"workloads": []}


def test_sample_for_a_deleted_cluster_is_dropped(temp_db):
    db.record_sample(12345, {"pods_total": 1})  # must not raise
    assert db.get_samples(12345) == []


def test_activity_feed_spans_incidents(temp_db):
    a = db.create_incident("a", "default", "NotReady")
    b = db.create_incident("b", "default", "NotReady")
    db.add_timeline(a, "DETECTED", "first")
    db.add_timeline(b, "DETECTED", "second")
    feed = db.list_activity(10)
    assert [e["message"] for e in feed] == ["second", "first"]
    assert feed[0]["service"] == "b" and feed[0]["cluster_id"] == 1


# ---------------------------------------------------------------------------
# kube.py: per-cluster clients
# ---------------------------------------------------------------------------


def test_use_cluster_routes_clients_to_the_context(monkeypatch):
    kube.reset()
    built = []

    def fake_new_client(context=None, **_):
        built.append(context)
        return object()

    monkeypatch.setattr(kube.k8s_config, "new_client_from_config", fake_new_client)
    monkeypatch.setattr(kube.client, "CoreV1Api", lambda api_client=None: ("core", api_client))
    monkeypatch.setattr(kube.client, "AppsV1Api", lambda api_client=None: ("apps", api_client))
    assert kube.current_context() is None
    with kube.use_cluster("kind-staging"):
        assert kube.current_context() == "kind-staging"
        assert kube.core_v1()[0] == "core" and kube.apps_v1()[0] == "apps"
        kube.core_v1()  # cached
    assert built == ["kind-staging"]
    assert kube.current_context() is None


def test_unknown_context_raises_kube_config_error(monkeypatch):
    kube.reset()

    def boom(context=None, **_):
        raise RuntimeError("context not found")

    monkeypatch.setattr(kube.k8s_config, "new_client_from_config", boom)
    with kube.use_cluster("nope"), pytest.raises(kube.KubeConfigError):
        kube.core_v1()


def test_list_contexts_returns_names_only(monkeypatch):
    monkeypatch.setattr(
        kube.k8s_config, "list_kube_config_contexts",
        lambda: ([{"name": "a", "context": {"cluster": "c1", "user": "SECRET"}}, {"name": "b", "context": {}}], {"name": "b"}),
    )
    contexts = kube.list_contexts()
    assert [c["name"] for c in contexts] == ["a", "b"]
    assert contexts[1]["active"] is True
    assert "SECRET" not in repr(contexts)


def test_list_contexts_without_a_kubeconfig_is_empty(monkeypatch):
    def boom():
        raise RuntimeError("no kubeconfig")

    monkeypatch.setattr(kube.k8s_config, "list_kube_config_contexts", boom)
    assert kube.list_contexts() == []


# ---------------------------------------------------------------------------
# Metrics sampling
# ---------------------------------------------------------------------------


def test_classify_logs_counts_lines_and_errors():
    text = "GET /health 200\nERROR boom\n\nException: DB_URL missing\nall good\n"
    assert metrics.classify_logs(text) == (4, 2)
    assert metrics.classify_logs("") == (0, 0)
    assert metrics.classify_logs(None) == (0, 0)


@pytest.fixture()
def fake_cluster(monkeypatch):
    core, apps = kf.FakeCoreV1(), kf.FakeAppsV1()
    monkeypatch.setattr(kube, "core_v1", lambda: core)
    monkeypatch.setattr(kube, "apps_v1", lambda: apps)
    return core, apps


def test_sample_counts_pods_restarts_logs_and_workloads(temp_db, fake_cluster):
    core, apps = fake_cluster
    healthy = kf.make_pod("shop-api-abc-1", owner_rs="shop-api-abc", restarts=0)
    broken = kf.make_pod("shop-api-abc-2", owner_rs="shop-api-abc", ready=False, waiting="CrashLoopBackOff", restarts=5)
    core.pods["default"] = [healthy, broken]
    core.events = [kf.make_event("Pod", "shop-api-abc-2", when=kf.ago(10)), kf.make_event("Pod", "x", when=kf.ago(900))]
    core.logs[("shop-api-abc-1", False)] = "ok\nok\nERROR bad thing\n"
    core.logs[("shop-api-abc-2", False)] = "Traceback (most recent call last)\n"
    apps.deployments = [kf.make_deployment("shop-api", replicas=2, status={"ready_replicas": 1})]

    sample, snapshot = metrics.sample_current_cluster(5)
    assert sample["pods_total"] == 2 and sample["pods_ready"] == 1
    assert sample["restarts_total"] == 5
    assert sample["warning_events"] == 1  # the 15 minute old warning is outside the window
    assert sample["log_lines"] == 4 and sample["error_lines"] == 2
    workload = snapshot["workloads"][0]
    assert workload["name"] == "shop-api" and workload["ready"] == 1 and workload["desired"] == 2
    assert workload["restarts"] == 5 and workload["status"] == "Degraded"
    assert workload["problem"] == "CrashLoopBackOff"
    # since_seconds keeps each sample to the lines logged since the previous one
    assert all(call["since_seconds"] >= 2 for call in core.log_calls)


def test_sample_ignores_terminating_pods(temp_db, fake_cluster):
    core, _apps = fake_cluster
    core.pods["default"] = [kf.make_pod("a", deleting=True), kf.make_pod("b")]
    sample, _ = metrics.sample_current_cluster(5)
    assert sample["pods_total"] == 1


def test_sample_does_not_store_log_text(temp_db, fake_cluster):
    core, _apps = fake_cluster
    core.pods["default"] = [kf.make_pod("a")]
    core.logs[("a", False)] = "password=hunter2 ERROR\n"
    sample, snapshot = metrics.sample_current_cluster(5)
    assert "hunter2" not in repr(sample) and "hunter2" not in repr(snapshot)


def test_sampling_errors_map_to_connection_states(temp_db):
    assert metrics._state_for_error(kube.KubeConfigError("x"))[0] == "not_configured"
    assert metrics._state_for_error(ApiException(status=403, reason="Forbidden"))[0] == "forbidden"
    assert metrics._state_for_error(ApiException(status=500, reason="Boom"))[0] == "error"
    assert metrics._state_for_error(ConnectionError("down"))[0] == "unreachable"


def test_series_use_per_minute_rates():
    samples = [
        {"ts": "2026-10-13T10:00:00+00:00", "pods_total": 2, "pods_ready": 2, "pods_unhealthy": 0, "restarts_total": 0,
         "warning_events": 0, "log_lines": 10, "error_lines": 1, "interval_seconds": 5},
    ]
    series = metrics.build_series(samples)
    assert series["log_rate"] == [120.0] and series["error_rate"] == [12.0]


def test_cluster_view_flags_deletion_rules(temp_db):
    default = db.list_clusters()[0]
    assert metrics.cluster_view(default, [])["can_delete"] is False
    cid = db.create_cluster("staging", "kind-staging")
    db.create_incident("shop-api", "default", "NotReady", cid)
    sick = next(c for c in db.list_clusters() if c["id"] == cid)
    view = metrics.cluster_view(sick, [])
    assert view["can_delete"] is False and "Resolve" in view["delete_blocked_reason"]


def test_sampler_marks_state_and_isolates_failures(temp_db, monkeypatch):
    good = db.create_cluster("good", "ctx-good")
    bad = db.create_cluster("bad", "ctx-bad")

    def fake_sample(interval):
        if kube.current_context() == "ctx-bad":
            raise ApiException(status=403, reason="Forbidden")
        return {"pods_total": 3, "pods_ready": 3, "interval_seconds": interval}, {"workloads": []}

    monkeypatch.setattr(metrics, "sample_current_cluster", fake_sample)
    sampler = metrics.MetricsSampler()
    ok = sampler.run_once()
    assert db.get_cluster(good)["state"] == "connected"
    assert db.get_cluster(bad)["state"] == "forbidden"
    assert len(db.get_samples(good)) == 1 and db.get_samples(bad) == []
    assert ok >= 1


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(temp_db, tmp_path):
    folder = tmp_path / "dash"
    folder.mkdir()
    (folder / "index.html").write_text("<html></html>", encoding="utf-8")
    app = create_app(start_detector=False, dashboard_dir=folder, configure_logging=False)
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    pipeline.join_workers(5)


@pytest.fixture()
def contexts(monkeypatch):
    monkeypatch.setattr(kube, "list_contexts", lambda: [
        {"name": "kind-incidentiq", "cluster": "kind-incidentiq", "active": True},
        {"name": "kind-staging", "cluster": "kind-staging", "active": False},
    ])
    monkeypatch.setattr(metrics, "probe_context", lambda ctx, timeout=4: ("connected", "ok"))


def test_cluster_list_is_public_and_shaped_for_the_dashboard(client):
    db.record_sample(1, {"pods_total": 2, "pods_ready": 2, "log_lines": 6, "interval_seconds": 6}, {"workloads": [{"name": "shop-api"}]})
    body = client.get("/api/clusters").json()
    assert len(body) == 1
    cluster = body[0]
    assert cluster["is_default"] is True and cluster["can_delete"] is False
    assert cluster["latest"]["pods_total"] == 2 and cluster["latest"]["log_rate"] == 60.0
    assert set(metrics.SERIES_KEYS) <= set(cluster["series"])
    assert cluster["workloads"] == [{"name": "shop-api"}]
    assert "snapshot" not in cluster and "kubeconfig" not in str(cluster).lower()


def test_activity_endpoint(client):
    incident = db.create_incident("shop-api", "default", "NotReady")
    db.add_timeline(incident, "DETECTED", "hello")
    assert client.get("/api/activity?limit=5").json()[0]["message"] == "hello"
    assert client.get("/api/activity?limit=0").status_code == 422


def test_cluster_changes_require_the_api_key(client, contexts):
    assert client.get("/api/kube/contexts").status_code == 401
    assert client.post("/api/clusters", json={"name": "s", "context": "kind-staging"}).status_code == 401
    assert client.delete("/api/clusters/2").status_code == 401
    wrong = {"X-API-Key": "nope"}
    assert client.post("/api/clusters", json={"name": "s", "context": "kind-staging"}, headers=wrong).status_code == 401


def test_contexts_endpoint_marks_connected_ones(client, contexts):
    db.create_cluster("staging", "kind-staging")
    body = client.get("/api/kube/contexts", headers=AUTH).json()
    assert {c["name"]: c["connected"] for c in body} == {"kind-incidentiq": False, "kind-staging": True}


def test_connect_cluster_happy_path(client, contexts):
    response = client.post("/api/clusters", json={"name": "staging", "context": "kind-staging"}, headers=AUTH)
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "staging" and body["context"] == "kind-staging" and body["state"] == "connected"
    assert body["can_delete"] is True
    assert [c["name"] for c in client.get("/api/clusters").json()] == ["primary", "staging"]


def test_connect_rejects_unknown_context_and_duplicates(client, contexts):
    unknown = client.post("/api/clusters", json={"name": "x", "context": "does-not-exist"}, headers=AUTH)
    assert unknown.status_code == 400 and "not found" in unknown.json()["detail"]
    ok = client.post("/api/clusters", json={"name": "staging", "context": "kind-staging"}, headers=AUTH)
    assert ok.status_code == 201
    again = client.post("/api/clusters", json={"name": "other", "context": "kind-staging"}, headers=AUTH)
    assert again.status_code == 409


def test_connect_refuses_a_cluster_that_does_not_answer(client, contexts, monkeypatch):
    monkeypatch.setattr(metrics, "probe_context", lambda ctx, timeout=4: ("unreachable", "ConnectionError: refused"))
    response = client.post("/api/clusters", json={"name": "staging", "context": "kind-staging"}, headers=AUTH)
    assert response.status_code == 400 and "unreachable" in response.json()["detail"]
    assert len(db.list_clusters()) == 1  # nothing was registered


def test_connect_without_any_kubeconfig(client, monkeypatch):
    monkeypatch.setattr(kube, "list_contexts", lambda: [])
    response = client.post("/api/clusters", json={"name": "staging", "context": "kind-staging"}, headers=AUTH)
    assert response.status_code == 400 and "kubeconfig" in response.json()["detail"]


@pytest.mark.parametrize("body", [
    {"name": "", "context": "x"}, {"name": "<script>", "context": "x"}, {"name": "ok", "context": ""},
    {"name": "ok", "context": "bad\x00ctx"}, {"name": "ok"}, {"name": "a" * 64, "context": "x"},
])
def test_connect_validates_input(client, contexts, body):
    assert client.post("/api/clusters", json=body, headers=AUTH).status_code == 422


def test_delete_cluster_rules(client, contexts):
    client.post("/api/clusters", json={"name": "staging", "context": "kind-staging"}, headers=AUTH)
    cid = [c for c in db.list_clusters() if not c["is_default"]][0]["id"]

    assert client.delete(f"/api/clusters/{db.DEFAULT_CLUSTER_ID}", headers=AUTH).status_code == 403
    assert client.delete("/api/clusters/999", headers=AUTH).status_code == 404

    incident = db.create_incident("shop-api", "default", "CrashLoopBackOff", cid)
    blocked = client.delete(f"/api/clusters/{cid}", headers=AUTH)
    assert blocked.status_code == 409 and "open incident" in blocked.json()["detail"]
    assert db.get_cluster(cid) is not None

    db.update_incident(incident, status="RESOLVED")
    done = client.delete(f"/api/clusters/{cid}", headers=AUTH)
    assert done.status_code == 200 and done.json()["deleted"] is True
    assert db.get_cluster(cid) is None
    assert client.get(f"/api/incidents/{incident}").json()["cluster_id"] == cid  # history survives


def test_status_reports_the_metrics_sampler(client):
    assert "metrics" in client.get("/api/status").json()


# ---------------------------------------------------------------------------
# Per-cluster incident handling
# ---------------------------------------------------------------------------


def test_the_same_service_in_two_clusters_gets_two_incidents(world, monkeypatch):
    other = db.create_cluster("staging", "kind-staging")
    pipeline.handle_incident({**ISSUE, "cluster_id": db.DEFAULT_CLUSTER_ID})
    pipeline.handle_incident({**ISSUE, "cluster_id": other})
    pipeline.handle_incident({**ISSUE, "cluster_id": other})  # duplicate in the same cluster is still suppressed
    incidents = db.list_incidents()
    assert sorted(i["cluster_id"] for i in incidents) == [db.DEFAULT_CLUSTER_ID, other]


def test_lifecycle_runs_against_the_incidents_own_cluster(world, monkeypatch):
    other = db.create_cluster("staging", "kind-staging")
    seen = []
    original = world.collect

    def spy(namespace, service):
        seen.append(kube.current_context())
        return original(namespace, service)

    monkeypatch.setattr("backend.collector.collect_evidence", spy)
    pipeline.handle_incident({**ISSUE, "cluster_id": other})
    pipeline.handle_incident({**ISSUE, "cluster_id": db.DEFAULT_CLUSTER_ID})
    assert seen == ["kind-staging", None]


def test_approval_executes_against_the_incidents_own_cluster(world, monkeypatch):
    other = db.create_cluster("staging", "kind-staging")
    pipeline.handle_incident({**ISSUE, "cluster_id": other})
    incident_id = db.list_incidents()[0]["id"]
    contexts_seen = []
    original = world.execute

    def spy(*args, **kwargs):
        contexts_seen.append(kube.current_context())
        return original(*args, **kwargs)

    monkeypatch.setattr("backend.remediation.execute", spy)
    pipeline.approve_incident(incident_id, background=False)
    assert contexts_seen == ["kind-staging"]
    assert db.get_incident(incident_id)["status"] == "RESOLVED"


def test_issue_for_a_deleted_cluster_is_ignored(world):
    pipeline.handle_incident({**ISSUE, "cluster_id": 424242})
    assert db.list_incidents() == []


def test_detector_loop_polls_every_cluster_and_tags_issues(temp_db, monkeypatch):
    other = db.create_cluster("staging", "kind-staging")
    polled = []

    def fake_check():
        polled.append(kube.current_context())
        return [dict(ISSUE)]

    monkeypatch.setattr("backend.detector.check_cluster", fake_check)
    started = []
    monkeypatch.setattr(pipeline, "handle_incident", lambda issue: started.append(issue["cluster_id"]))
    loop = pipeline.DetectorLoop()
    assert loop.run_once() == 2
    deadline = time.monotonic() + 3
    while len(started) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    pipeline.join_workers(3)
    assert polled == [None, "kind-staging"]
    assert sorted(started) == [db.DEFAULT_CLUSTER_ID, other]
