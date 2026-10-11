"""Collector tests. The Kubernetes client is replaced by fakes; no cluster is used."""

from __future__ import annotations

import json

import pytest
from kubernetes import client

from backend import collector, config, kube
from k8s_fakes import (
    FakeAppsV1,
    FakeCoreV1,
    ago,
    api_error,
    make_deployment,
    make_event,
    make_pod,
    make_replica_set,
    managed_field,
)

EXPECTED_KEYS = {"logs", "events", "pods", "last_deploy_time", "rollout_history"}
TRACEBACK = ["Traceback (most recent call last):", '  File "main.py", line 1', "Exception: DB_URL missing"]


@pytest.fixture()
def cluster(monkeypatch):
    """A shop-api Deployment at revision 2 (crashing v2) with v1 as revision 1."""
    core, apps = FakeCoreV1(), FakeAppsV1()
    apps.deployment = make_deployment(
        managed_fields=[managed_field(ago(100)), managed_field(ago(20), manager="kube-controller-manager", subresource="status")]
    )
    apps.replica_sets["shop-api-v1"] = make_replica_set(
        "shop-api-v1", revision=1, image="shop-api:v1", created=ago(3600), replicas=0, ready_replicas=0
    )
    apps.replica_sets["shop-api-v2"] = make_replica_set(
        "shop-api-v2", revision=2, image="shop-api:v2", created=ago(100), replicas=1, ready_replicas=0,
        env=[client.V1EnvVar(name="LOG_FORMAT", value="super-secret-value")],
    )
    core.pods["default"] = [
        make_pod("shop-api-v2-aaa", owner_rs="shop-api-v2", ready=False, waiting="CrashLoopBackOff",
                 restarts=4, image="shop-api:v2", last_terminated=("Error", ago(10))),
        make_pod("unrelated-pod", owner_rs="other-rs", labels={"app": "shop-api"}),
    ]
    core.logs[("shop-api-v2-aaa", True)] = "\n".join(TRACEBACK)
    core.events = [
        make_event("Pod", "shop-api-v2-aaa", "BackOff", "Back-off restarting failed container", when=ago(30)),
        make_event("Deployment", "shop-api", "ScalingReplicaSet", "Scaled up replica set shop-api-v2 to 1", when=ago(100), type_="Normal"),
        make_event("Pod", "some-other-pod", "BackOff", "not ours", when=ago(10)),
    ]
    monkeypatch.setattr(kube, "core_v1", lambda: core)
    monkeypatch.setattr(kube, "apps_v1", lambda: apps)
    return core, apps


# --------------------------------------------------------------------------
# Shape
# --------------------------------------------------------------------------


def test_exact_top_level_keys_and_json_serialisable(cluster):
    evidence = collector.collect_evidence("default", "shop-api")
    assert set(evidence) == EXPECTED_KEYS
    assert json.loads(json.dumps(evidence)) == evidence


# --------------------------------------------------------------------------
# Logs
# --------------------------------------------------------------------------


def test_crashed_container_uses_previous_logs(cluster):
    core, _ = cluster
    logs = collector.collect_evidence("default", "shop-api")["logs"]
    entry = next(l for l in logs if l["pod"] == "shop-api-v2-aaa")
    assert entry["source"] == "previous"
    assert entry["lines"] == TRACEBACK
    assert entry["error"] is None
    assert core.log_calls[0]["previous"] is True
    assert core.log_calls[0]["tail_lines"] == 50


def test_previous_logs_unavailable_falls_back_to_current(cluster):
    core, _ = cluster
    del core.logs[("shop-api-v2-aaa", True)]
    core.logs[("shop-api-v2-aaa", False)] = "current line"
    entry = collector.collect_evidence("default", "shop-api")["logs"][0]
    assert entry["source"] == "current"
    assert entry["lines"] == ["current line"]
    assert [c["previous"] for c in core.log_calls] == [True, False]


def test_both_log_requests_failing_records_error_and_continues(cluster):
    core, _ = cluster
    del core.logs[("shop-api-v2-aaa", True)]
    evidence = collector.collect_evidence("default", "shop-api")
    entry = evidence["logs"][0]
    assert entry["lines"] == [] and "HTTP 400" in entry["error"]
    assert evidence["events"] and evidence["rollout_history"]  # other parts unaffected


def test_permission_error_on_logs_does_not_block_other_evidence(cluster):
    core, _ = cluster
    core.logs[("shop-api-v2-aaa", True)] = api_error(403, "Forbidden")
    core.logs[("shop-api-v2-aaa", False)] = api_error(403, "Forbidden")
    evidence = collector.collect_evidence("default", "shop-api")
    assert "HTTP 403" in evidence["logs"][0]["error"]
    assert evidence["pods"] and evidence["events"]


def test_healthy_pod_only_reads_current_logs(cluster):
    core, apps = cluster
    core.pods["default"] = [make_pod("shop-api-v1-bbb", owner_rs="shop-api-v1")]
    core.logs[("shop-api-v1-bbb", False)] = "ok"
    entry = collector.collect_evidence("default", "shop-api")["logs"][0]
    assert entry["source"] == "current"
    assert [c["previous"] for c in core.log_calls] == [False]


def test_log_lines_are_limited_to_50(cluster):
    core, _ = cluster
    core.logs[("shop-api-v2-aaa", True)] = "\n".join(f"line {i}" for i in range(80))
    lines = collector.collect_evidence("default", "shop-api")["logs"][0]["lines"]
    assert len(lines) == 50 and lines[-1] == "line 79"


def test_secrets_are_redacted_from_logs(cluster):
    core, _ = cluster
    core.logs[("shop-api-v2-aaa", True)] = "connecting with key test-api-key-for-pytest now"
    line = collector.collect_evidence("default", "shop-api")["logs"][0]["lines"][0]
    assert "test-api-key-for-pytest" not in line and "***" in line


def test_very_long_log_lines_are_truncated(cluster):
    core, _ = cluster
    core.logs[("shop-api-v2-aaa", True)] = "x" * 5000
    line = collector.collect_evidence("default", "shop-api")["logs"][0]["lines"][0]
    assert len(line) <= collector.MAX_LOG_LINE_CHARS


def test_unhealthy_pods_get_logs_first_and_count_is_capped(cluster):
    core, _ = cluster
    healthy = [make_pod(f"h{i}", owner_rs="shop-api-v1") for i in range(10)]
    core.pods["default"] = healthy + [core.pods["default"][0]]
    logs = collector.collect_evidence("default", "shop-api")["logs"]
    assert logs[0]["pod"] == "shop-api-v2-aaa"
    assert len({l["pod"] for l in logs}) == collector.MAX_PODS_WITH_LOGS


# --------------------------------------------------------------------------
# Pods
# --------------------------------------------------------------------------


def test_pod_states_include_required_fields_and_exclude_unrelated_pods(cluster):
    pods = collector.collect_evidence("default", "shop-api")["pods"]
    assert [p["name"] for p in pods] == ["shop-api-v2-aaa"]  # 'unrelated-pod' belongs to another RS
    pod = pods[0]
    assert pod["phase"] == "Running" and pod["ready"] is False
    container = pod["containers"][0]
    assert container["image"] == "shop-api:v2"
    assert container["state"] == "waiting"
    assert container["waiting_reason"] == "CrashLoopBackOff"
    assert container["restart_count"] == 4
    assert container["last_termination_reason"] == "Error"
    assert container["last_exit_code"] == 1


def test_oomkilled_reason_is_reported(cluster):
    core, _ = cluster
    core.pods["default"] = [make_pod("p", owner_rs="shop-api-v2", ready=False, waiting="CrashLoopBackOff",
                                     restarts=2, last_terminated=("OOMKilled", ago(5)))]
    container = collector.collect_evidence("default", "shop-api")["pods"][0]["containers"][0]
    assert container["last_termination_reason"] == "OOMKilled"


def test_terminating_pod_is_flagged(cluster):
    core, _ = cluster
    core.pods["default"] = [make_pod("p", owner_rs="shop-api-v2", deleting=True)]
    assert collector.collect_evidence("default", "shop-api")["pods"][0]["terminating"] is True


# --------------------------------------------------------------------------
# Events
# --------------------------------------------------------------------------


def test_events_filtered_to_service_and_sorted_oldest_first(cluster):
    events = collector.collect_evidence("default", "shop-api")["events"]
    assert [e["involved_object"] for e in events] == ["Deployment/shop-api", "Pod/shop-api-v2-aaa"]
    assert {"type", "reason", "message", "involved_object", "timestamp"} <= set(events[0])
    assert all("some-other-pod" not in e["involved_object"] for e in events)


def test_events_capped_to_most_recent(cluster):
    core, _ = cluster
    core.events = [make_event("Pod", "shop-api-v2-aaa", f"R{i}", when=ago(1000 - i)) for i in range(100)]
    events = collector.collect_evidence("default", "shop-api")["events"]
    assert len(events) == collector.MAX_EVENTS
    assert events[-1]["reason"] == "R99"


def test_event_failure_does_not_block_other_parts(cluster):
    core, _ = cluster
    core.events_error = api_error(403, "Forbidden")
    evidence = collector.collect_evidence("default", "shop-api")
    assert evidence["events"] == []
    assert evidence["logs"] and evidence["pods"] and evidence["rollout_history"]


# --------------------------------------------------------------------------
# last_deploy_time
# --------------------------------------------------------------------------


def test_last_deploy_time_uses_spec_write_not_status_write_or_now(cluster):
    value = collector.collect_evidence("default", "shop-api")["last_deploy_time"]
    # fixture: kubectl update 100s ago, controller STATUS update 20s ago (must be ignored)
    expected = collector._iso(ago(100))
    assert value == expected


def test_last_deploy_time_is_not_the_observation_time(cluster):
    from datetime import datetime, timezone

    value = collector.collect_evidence("default", "shop-api")["last_deploy_time"]
    parsed = datetime.fromisoformat(value)
    assert (datetime.now(timezone.utc) - parsed).total_seconds() > 60


def test_last_deploy_time_falls_back_to_progressing_condition(cluster):
    _, apps = cluster
    apps.deployment = make_deployment(managed_fields=None, progressing_update=ago(50))
    assert collector.collect_evidence("default", "shop-api")["last_deploy_time"] == collector._iso(ago(50))


def test_last_deploy_time_falls_back_to_current_revision_replicaset(cluster):
    _, apps = cluster
    apps.deployment = make_deployment(managed_fields=None, progressing_update=None, revision=2)
    assert collector.collect_evidence("default", "shop-api")["last_deploy_time"] == collector._iso(ago(100))


def test_last_deploy_time_none_when_unknowable(cluster):
    _, apps = cluster
    apps.deployment = make_deployment(managed_fields=None, progressing_update=None, revision=None)
    assert collector.collect_evidence("default", "shop-api")["last_deploy_time"] is None


# --------------------------------------------------------------------------
# Rollout history
# --------------------------------------------------------------------------


def test_rollout_history_newest_revision_first_with_template_info(cluster):
    history = collector.collect_evidence("default", "shop-api")["rollout_history"]
    assert [h["revision"] for h in history] == [2, 1]
    assert [h["images"] for h in history] == [["shop-api:v2"], ["shop-api:v1"]]
    assert history[0]["is_current"] is True and history[1]["is_current"] is False
    assert history[0]["ready_replicas"] == 0 and history[0]["desired_replicas"] == 1
    assert history[0]["created"] is not None
    container = history[0]["pod_template"]["containers"][0]
    assert container["resource_limits"] == {"memory": "128Mi"}


def test_rollout_history_never_contains_env_values(cluster):
    evidence = collector.collect_evidence("default", "shop-api")
    container = evidence["rollout_history"][0]["pod_template"]["containers"][0]
    assert container["env_var_names"] == ["LOG_FORMAT"]
    assert "super-secret-value" not in json.dumps(evidence)


def test_replicasets_of_other_deployments_are_excluded(cluster):
    _, apps = cluster
    apps.replica_sets["cart-rs"] = make_replica_set("cart-rs", deployment="cart", deployment_uid="other-uid", revision=7)
    history = collector.collect_evidence("default", "shop-api")["rollout_history"]
    assert "cart-rs" not in [h["name"] for h in history]


# --------------------------------------------------------------------------
# Failure isolation
# --------------------------------------------------------------------------


def test_missing_deployment_still_returns_all_keys(cluster):
    _, apps = cluster
    apps.deployment = None
    evidence = collector.collect_evidence("default", "shop-api")
    assert set(evidence) == EXPECTED_KEYS
    assert evidence["rollout_history"] == [] and evidence["pods"] == [] and evidence["last_deploy_time"] is None


def test_replicaset_listing_failure_falls_back_to_label_selector(cluster):
    _, apps = cluster
    apps.list_rs_error = api_error(403, "Forbidden")
    evidence = collector.collect_evidence("default", "shop-api")
    assert {p["name"] for p in evidence["pods"]} == {"shop-api-v2-aaa", "unrelated-pod"}
    assert evidence["rollout_history"] == []
    assert evidence["last_deploy_time"] is not None  # still known from managedFields


def test_kube_config_error_returns_empty_but_complete_evidence(monkeypatch):
    def boom():
        raise kube.KubeConfigError("no cluster")

    monkeypatch.setattr(kube, "core_v1", boom)
    evidence = collector.collect_evidence("default", "shop-api")
    assert set(evidence) == EXPECTED_KEYS
    assert evidence == {"logs": [], "events": [], "pods": [], "last_deploy_time": None, "rollout_history": []}
