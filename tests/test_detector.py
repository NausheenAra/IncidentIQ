"""Detector tests. The Kubernetes client is replaced by fakes; no cluster is used."""

from __future__ import annotations

import pytest

from backend import config, detector, kube
from k8s_fakes import (
    FakeAppsV1,
    FakeCoreV1,
    ago,
    api_error,
    make_pod,
    make_replica_set,
)


@pytest.fixture()
def cluster(monkeypatch):
    """Install fake core/apps clients and return them with a healthy default RS."""
    core, apps = FakeCoreV1(), FakeAppsV1()
    apps.replica_sets["shop-api-abc"] = make_replica_set("shop-api-abc", "shop-api")
    monkeypatch.setattr(kube, "core_v1", lambda: core)
    monkeypatch.setattr(kube, "apps_v1", lambda: apps)
    return core, apps


def issues_for(core, pods, namespace="default"):
    core.pods[namespace] = pods
    return detector.check_cluster()


# --------------------------------------------------------------------------
# Individual conditions
# --------------------------------------------------------------------------


def test_healthy_cluster_reports_nothing(cluster):
    core, _ = cluster
    assert issues_for(core, [make_pod("p1"), make_pod("p2")]) == []


def test_crashloopbackoff(cluster):
    core, _ = cluster
    pod = make_pod("p1", ready=False, waiting="CrashLoopBackOff", restarts=1)
    assert issues_for(core, [pod]) == [
        {"service": "shop-api", "namespace": "default", "reason": "CrashLoopBackOff"}
    ]


def test_imagepullbackoff(cluster):
    core, _ = cluster
    pod = make_pod("p1", phase="Pending", ready=False, waiting="ImagePullBackOff")
    assert issues_for(core, [pod])[0]["reason"] == "ImagePullBackOff"


def test_errimagepull(cluster):
    core, _ = cluster
    pod = make_pod("p1", phase="Pending", ready=False, waiting="ErrImagePull")
    assert issues_for(core, [pod])[0]["reason"] == "ErrImagePull"


def test_excessive_restart_count_while_not_ready(cluster):
    core, _ = cluster
    pod = make_pod("p1", ready=False, restarts=3, ready_since=ago(5))
    assert issues_for(core, [pod])[0]["reason"] == "HighRestartCount"


def test_restart_count_below_threshold_is_ignored(cluster):
    core, _ = cluster
    assert issues_for(core, [make_pod("p1", restarts=2)]) == []


def test_unready_longer_than_grace_period(cluster):
    core, _ = cluster
    pod = make_pod("p1", ready=False, ready_since=ago(120))
    assert issues_for(core, [pod]) == [
        {"service": "shop-api", "namespace": "default", "reason": "NotReady"}
    ]


def test_unready_within_grace_period_is_ignored(cluster):
    core, _ = cluster
    pod = make_pod("p1", ready=False, ready_since=ago(5))
    assert issues_for(core, [pod]) == []


def test_unready_uses_creation_time_when_no_ready_condition(cluster):
    core, _ = cluster
    pod = make_pod("p1", phase="Pending", ready=False, created=ago(200))
    pod.status.conditions = None
    assert issues_for(core, [pod])[0]["reason"] == "NotReady"


def test_oomkilled_in_last_state(cluster):
    core, _ = cluster
    pod = make_pod("p1", ready=False, waiting="CrashLoopBackOff", restarts=2,
                   last_terminated=("OOMKilled", ago(5)))
    assert issues_for(core, [pod])[0]["reason"] == "OOMKilled"  # outranks CrashLoopBackOff


def test_oomkilled_current_termination(cluster):
    core, _ = cluster
    pod = make_pod("p1", ready=False, terminated=("OOMKilled", ago(2)))
    assert issues_for(core, [pod])[0]["reason"] == "OOMKilled"


# --------------------------------------------------------------------------
# Stale history must not flag a recovered pod forever
# --------------------------------------------------------------------------


def test_old_oomkill_on_ready_container_is_ignored(cluster):
    core, _ = cluster
    pod = make_pod("p1", ready=True, restarts=1, last_terminated=("OOMKilled", ago(3600)))
    assert issues_for(core, [pod]) == []


def test_recent_oomkill_on_ready_container_is_reported(cluster):
    core, _ = cluster
    pod = make_pod("p1", ready=True, restarts=1, last_terminated=("OOMKilled", ago(30)))
    assert issues_for(core, [pod])[0]["reason"] == "OOMKilled"


def test_old_restarts_on_ready_container_are_ignored(cluster):
    core, _ = cluster
    pod = make_pod("p1", ready=True, restarts=5, last_terminated=("Error", ago(7200)))
    assert issues_for(core, [pod]) == []


def test_terminating_pods_are_ignored(cluster):
    core, _ = cluster
    pod = make_pod("p1", ready=False, waiting="CrashLoopBackOff", deleting=True)
    assert issues_for(core, [pod]) == []


def test_succeeded_pods_are_ignored(cluster):
    core, _ = cluster
    pod = make_pod("p1", phase="Succeeded", ready=False, ready_since=ago(999))
    assert issues_for(core, [pod]) == []


# --------------------------------------------------------------------------
# Ownership and grouping
# --------------------------------------------------------------------------


def test_deployment_resolved_through_replicaset_not_pod_name(cluster):
    """The pod name says 'frontend' but the owner chain says 'shop-api'."""
    core, apps = cluster
    apps.replica_sets["weird-rs"] = make_replica_set("weird-rs", "shop-api")
    pod = make_pod("frontend-xyz", owner_rs="weird-rs", ready=False, waiting="CrashLoopBackOff")
    assert issues_for(core, [pod])[0]["service"] == "shop-api"


def test_duplicate_pods_grouped_into_one_issue(cluster):
    core, _ = cluster
    pods = [
        make_pod("p1", ready=False, waiting="CrashLoopBackOff"),
        make_pod("p2", ready=False, waiting="CrashLoopBackOff"),
        make_pod("p3", ready=False, ready_since=ago(300)),  # a different, weaker problem
    ]
    result = issues_for(core, pods)
    assert result == [{"service": "shop-api", "namespace": "default", "reason": "CrashLoopBackOff"}]


def test_replicaset_lookups_are_cached_within_a_poll(cluster):
    core, apps = cluster
    pods = [make_pod(f"p{i}", ready=False, waiting="CrashLoopBackOff") for i in range(5)]
    issues_for(core, pods)
    assert apps.rs_reads == 1


def test_separate_deployments_get_separate_issues(cluster):
    core, apps = cluster
    apps.replica_sets["cart-rs"] = make_replica_set("cart-rs", "cart")
    pods = [
        make_pod("a", ready=False, waiting="CrashLoopBackOff"),
        make_pod("b", owner_rs="cart-rs", phase="Pending", ready=False, waiting="ErrImagePull"),
    ]
    result = issues_for(core, pods)
    assert result == [
        {"service": "cart", "namespace": "default", "reason": "ErrImagePull"},
        {"service": "shop-api", "namespace": "default", "reason": "CrashLoopBackOff"},
    ]


def test_pods_without_a_deployment_are_ignored(cluster):
    core, apps = cluster
    apps.replica_sets["orphan-rs"] = make_replica_set("orphan-rs", deployment=None)
    pods = [
        make_pod("bare", owner_rs=None, ready=False, waiting="CrashLoopBackOff"),
        make_pod("orphan", owner_rs="orphan-rs", ready=False, waiting="CrashLoopBackOff"),
    ]
    assert issues_for(core, pods) == []


def test_missing_replicaset_is_ignored_not_fatal(cluster):
    core, _ = cluster
    pod = make_pod("p1", owner_rs="gone-rs", ready=False, waiting="CrashLoopBackOff")
    assert issues_for(core, [pod]) == []


# --------------------------------------------------------------------------
# Namespaces
# --------------------------------------------------------------------------


def test_only_allow_listed_namespaces_are_inspected(cluster):
    core, _ = cluster
    core.pods["default"] = []
    core.pods["kube-system"] = [make_pod("bad", namespace="kube-system", ready=False, waiting="CrashLoopBackOff")]
    assert detector.check_cluster() == []


def test_multiple_namespaces(cluster, monkeypatch):
    core, apps = cluster
    monkeypatch.setenv("KUBERNETES_NAMESPACE_ALLOWLIST", "default,staging")
    config.reset_settings()
    apps.replica_sets["shop-api-abc"] = make_replica_set("shop-api-abc", "shop-api")
    core.pods["default"] = [make_pod("a", ready=False, waiting="CrashLoopBackOff")]
    core.pods["staging"] = [make_pod("b", namespace="staging", ready=False, waiting="ErrImagePull", phase="Pending")]
    namespaces = {i["namespace"]: i["reason"] for i in detector.check_cluster()}
    assert namespaces == {"default": "CrashLoopBackOff", "staging": "ErrImagePull"}


# --------------------------------------------------------------------------
# Errors never crash the loop
# --------------------------------------------------------------------------


def test_api_error_listing_pods_returns_empty(cluster):
    core, _ = cluster
    core.list_pods_errors["default"] = api_error(500)
    assert detector.check_cluster() == []


def test_one_namespace_failing_does_not_hide_another(cluster, monkeypatch):
    core, apps = cluster
    monkeypatch.setenv("KUBERNETES_NAMESPACE_ALLOWLIST", "broken,default")
    config.reset_settings()
    core.list_pods_errors["broken"] = api_error(503)
    core.pods["default"] = [make_pod("a", ready=False, waiting="CrashLoopBackOff")]
    assert [i["service"] for i in detector.check_cluster()] == ["shop-api"]


def test_connection_error_listing_pods_returns_empty(cluster):
    core, _ = cluster
    core.list_pods_errors["default"] = ConnectionError("cluster unreachable")
    assert detector.check_cluster() == []


def test_transient_replicaset_error_skips_pod_then_recovers(cluster):
    core, apps = cluster
    pod = make_pod("p1", ready=False, waiting="CrashLoopBackOff")
    apps.rs_errors["shop-api-abc"] = api_error(503)
    assert issues_for(core, [pod]) == []  # skipped this poll, no crash
    del apps.rs_errors["shop-api-abc"]
    assert detector.check_cluster()[0]["service"] == "shop-api"  # retried on next poll


def test_missing_kube_config_returns_empty(monkeypatch):
    def boom():
        raise kube.KubeConfigError("no cluster")

    monkeypatch.setattr(kube, "core_v1", boom)
    assert detector.check_cluster() == []


def test_unexpected_client_creation_error_returns_empty(monkeypatch):
    def boom():
        raise RuntimeError("surprise")

    monkeypatch.setattr(kube, "core_v1", boom)
    assert detector.check_cluster() == []


def test_issue_shape_has_exactly_three_keys(cluster):
    core, _ = cluster
    issue = issues_for(core, [make_pod("p1", ready=False, waiting="CrashLoopBackOff")])[0]
    assert set(issue) == {"service", "namespace", "reason"}
