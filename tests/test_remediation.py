"""Remediation tests. Kubernetes and subprocess are faked; no cluster is touched."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest
from kubernetes import client

from backend import config, db, kube, remediation
from k8s_fakes import (
    FakeAppsV1,
    FakeCoreV1,
    api_error,
    make_deployment,
    make_pod,
    make_replica_set,
    healthy_status,
)


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


def set_env(monkeypatch, **values):
    for key, value in values.items():
        monkeypatch.setenv(key, str(value))
    config.reset_settings()


@pytest.fixture()
def cluster(monkeypatch, temp_db):
    """Deployment at revision 2 (failing v2) with revision 1 (v1) available to roll back to."""
    core, apps = FakeCoreV1(), FakeAppsV1()
    apps.deployment = make_deployment(revision=2, replicas=2)
    apps.replica_sets["shop-api-v1"] = make_replica_set(
        "shop-api-v1", revision=1, image="shop-api:v1", replicas=0, ready_replicas=0)
    apps.replica_sets["shop-api-v2"] = make_replica_set(
        "shop-api-v2", revision=2, image="shop-api:v2", replicas=2, ready_replicas=0)
    monkeypatch.setattr(kube, "core_v1", lambda: core)
    monkeypatch.setattr(kube, "apps_v1", lambda: apps)
    return core, apps


@pytest.fixture()
def incident(temp_db):
    return temp_db.create_incident("shop-api", "default", "CrashLoopBackOff")


@pytest.fixture()
def auto(monkeypatch):
    """Automatic remediation enabled (no approval needed)."""
    set_env(monkeypatch, AUTO_REMEDIATE="true")


def run(action="restart", **kwargs):
    return remediation.execute(action, "default", "shop-api", **kwargs)


# --------------------------------------------------------------------------
# Action / namespace / name validation
# --------------------------------------------------------------------------


@pytest.mark.parametrize("action", ["delete", "Rollback", "RESTART", " restart", "restart;ls", "", None, 5, ["restart"]])
def test_unsupported_actions_are_rejected(cluster, incident, auto, action):
    _, apps = cluster
    result = remediation.execute(action, "default", "shop-api")
    assert result["success"] is False and result["detail"].startswith("Refused")
    assert apps.patches == []
    assert db.get_incident(incident)["remediation_attempts"] == 0


@pytest.mark.parametrize("action", ["rollback", "restart", "scale"])
def test_each_allowed_action_passes_validation(cluster, incident, auto, action):
    assert run(action)["success"] is True


@pytest.mark.parametrize("namespace", ["kube-system", "prod", "", None, "default ", "DEFAULT"])
def test_namespace_outside_allow_list_is_rejected(cluster, incident, auto, namespace):
    _, apps = cluster
    result = remediation.execute("restart", namespace, "shop-api")
    assert result["success"] is False and "allow-list" in result["detail"]
    assert apps.patches == []


@pytest.mark.parametrize("service", ["", "../etc", "a b", "UPPER", "x;rm -rf /", "$(id)", "a" * 254, None, "-lead", "trail-", "a\nb"])
def test_invalid_service_names_are_rejected(cluster, incident, auto, service):
    _, apps = cluster
    result = remediation.execute("restart", "default", service)
    assert result["success"] is False and "valid Kubernetes name" in result["detail"]
    assert apps.patches == []


def test_malicious_service_name_never_reaches_subprocess(cluster, incident, auto, monkeypatch):
    set_env(monkeypatch, ROLLBACK_MODE="kubectl")
    monkeypatch.setattr(remediation.subprocess, "run", lambda *a, **k: pytest.fail("subprocess must not run"))
    assert remediation.execute("rollback", "default", "shop-api; rm -rf /")["success"] is False


def test_result_has_exactly_success_and_detail(cluster, incident, auto):
    assert set(run()) == {"success", "detail"}


# --------------------------------------------------------------------------
# Approval workflow
# --------------------------------------------------------------------------


def test_approval_required_by_default(cluster, incident):
    _, apps = cluster
    result = run("restart")
    assert result["success"] is False and "approval required" in result["detail"]
    assert apps.patches == []
    assert db.get_incident(incident)["remediation_attempts"] == 0


def test_approved_flag_allows_execution_when_auto_remediate_is_off(cluster, incident):
    _, apps = cluster
    assert run("restart", approved=True)["success"] is True
    assert len(apps.patches) == 1


def test_auto_remediate_true_does_not_need_approval(cluster, incident, auto):
    assert run("restart")["success"] is True


def test_approved_does_not_bypass_namespace_allow_list(cluster, incident):
    assert remediation.execute("restart", "prod", "shop-api", approved=True)["success"] is False


# --------------------------------------------------------------------------
# Incident lookup
# --------------------------------------------------------------------------


def test_no_open_incident_is_refused(cluster, auto):
    result = run("restart")
    assert result["success"] is False and "no open incident" in result["detail"]


def test_incident_for_other_service_is_refused(cluster, auto, temp_db):
    other = temp_db.create_incident("cart", "default", "CrashLoopBackOff")
    result = run("restart", incident_id=other)
    assert result["success"] is False and "does not belong" in result["detail"]


def test_missing_incident_id_is_refused(cluster, auto):
    assert "does not exist" in run("restart", incident_id=9999)["detail"]


def test_closed_incident_is_refused(cluster, auto, incident, temp_db):
    temp_db.update_incident(incident, status="RESOLVED")
    assert "already RESOLVED" in run("restart", incident_id=incident)["detail"]


def test_explicit_incident_id_is_used(cluster, auto, incident):
    assert run("restart", incident_id=incident)["success"] is True
    assert db.get_incident(incident)["remediation_attempts"] == 1


# --------------------------------------------------------------------------
# Attempt limits (persistent)
# --------------------------------------------------------------------------


def test_third_attempt_is_refused_and_counter_is_persistent(cluster, incident, auto):
    _, apps = cluster
    assert run("restart")["success"] is True
    assert run("scale")["success"] is True
    third = run("restart")
    assert third["success"] is False and "attempt limit reached (2/2)" in third["detail"]
    assert len(apps.patches) == 1  # only the restart wrote; the scale was already at target (no-op)
    assert db.get_incident(incident)["remediation_attempts"] == 2


def test_limit_survives_settings_reload_and_repeated_calls(cluster, incident, auto, monkeypatch):
    """The counter is in SQLite, not in Python memory."""
    run("restart")
    run("restart")
    config.reset_settings()
    for _ in range(5):
        assert run("restart")["success"] is False
    assert db.get_incident(incident)["remediation_attempts"] == 2


def test_refusals_do_not_consume_attempts(cluster, incident):
    run("restart")  # refused: approval required
    run("delete")  # refused: bad action
    remediation.execute("restart", "prod", "shop-api")  # refused: namespace
    assert db.get_incident(incident)["remediation_attempts"] == 0


def test_failed_attempts_still_count(cluster, incident, auto):
    _, apps = cluster
    apps.patch_error = api_error(500)
    assert run("restart")["success"] is False
    assert db.get_incident(incident)["remediation_attempts"] == 1


def test_configured_limit_of_one(cluster, incident, auto, monkeypatch):
    set_env(monkeypatch, MAX_REMEDIATION_ATTEMPTS=1)
    assert run("restart")["success"] is True
    assert "attempt limit reached (1/1)" in run("restart")["detail"]


def test_each_incident_has_its_own_budget(cluster, auto, temp_db):
    first = temp_db.create_incident("shop-api", "default", "CrashLoopBackOff")
    run("restart", incident_id=first)
    run("restart", incident_id=first)
    temp_db.update_incident(first, status="FAILED")
    second = temp_db.create_incident("shop-api", "default", "CrashLoopBackOff")
    assert run("restart", incident_id=second)["success"] is True


def test_second_rollback_for_same_incident_is_refused(cluster, incident, auto, temp_db):
    """A second rollback would flip back to the version that was just rolled back from."""
    temp_db.update_incident(incident, action="rollback")
    assert run("rollback")["success"] is True  # first attempt: counter is 0
    result = run("rollback")
    assert result["success"] is False and "already attempted" in result["detail"]
    assert run("restart")["success"] is True  # other actions are still allowed


# --------------------------------------------------------------------------
# Rollback: python mode
# --------------------------------------------------------------------------


def patch_ops(apps):
    assert len(apps.patches) == 1
    return apps.patches[0]


def test_python_rollback_restores_previous_revision_template(cluster, incident, auto):
    _, apps = cluster
    result = run("rollback")
    assert result["success"] is True
    assert "revision 2 to revision 1" in result["detail"] and "shop-api:v1" in result["detail"]
    patch = patch_ops(apps)
    assert patch["_content_type"] == "application/json-patch+json"
    assert isinstance(patch["body"], list)
    replace = [op for op in patch["body"] if op["op"] == "replace"][0]
    assert replace["path"] == "/spec/template"
    assert replace["value"]["spec"]["containers"][0]["image"] == "shop-api:v1"


def test_python_rollback_never_selects_the_failing_replicaset(cluster, incident, auto):
    _, apps = cluster
    run("rollback")
    body = patch_ops(apps)["body"]
    template = [op for op in body if op["op"] == "replace"][0]["value"]
    assert template["spec"]["containers"][0]["image"] != "shop-api:v2"


def test_python_rollback_picks_newest_revision_below_current(cluster, incident, auto):
    """Revisions 1, 2, 3 with current=3 -> roll back to 2, not 1 and not 3."""
    _, apps = cluster
    apps.deployment = make_deployment(revision=3)
    apps.replica_sets["shop-api-v3"] = make_replica_set("shop-api-v3", revision=3, image="shop-api:v3")
    run("rollback")
    template = [op for op in patch_ops(apps)["body"] if op["op"] == "replace"][0]["value"]
    assert template["spec"]["containers"][0]["image"] == "shop-api:v2"


def test_python_rollback_strips_pod_template_hash_label(cluster, incident, auto):
    _, apps = cluster
    apps.replica_sets["shop-api-v1"].spec.template.metadata.labels["pod-template-hash"] = "abc123"
    run("rollback")
    template = [op for op in patch_ops(apps)["body"] if op["op"] == "replace"][0]["value"]
    labels = template["metadata"]["labels"]
    assert "pod-template-hash" not in labels and labels["app"] == "shop-api"


def test_python_rollback_template_is_plain_json_with_api_field_names(cluster, incident, auto):
    _, apps = cluster
    run("rollback")
    template = [op for op in patch_ops(apps)["body"] if op["op"] == "replace"][0]["value"]
    assert isinstance(template, dict)
    container = template["spec"]["containers"][0]
    assert "resources" in container and container["resources"]["limits"] == {"memory": "128Mi"}


def test_python_rollback_guards_against_concurrent_change(cluster, incident, auto):
    _, apps = cluster
    run("rollback")
    test_ops = [op for op in patch_ops(apps)["body"] if op["op"] == "test"]
    assert test_ops == [{"op": "test", "path": "/metadata/annotations/deployment.kubernetes.io~1revision", "value": "2"}]


def test_python_rollback_without_previous_revision_fails_cleanly(cluster, incident, auto):
    _, apps = cluster
    del apps.replica_sets["shop-api-v1"]
    result = run("rollback")
    assert result["success"] is False and "nothing to roll back to" in result["detail"]
    assert apps.patches == []


def test_python_rollback_ignores_replicasets_of_other_deployments(cluster, incident, auto):
    _, apps = cluster
    del apps.replica_sets["shop-api-v1"]
    apps.replica_sets["cart-rs"] = make_replica_set(
        "cart-rs", deployment="cart", deployment_uid="other-uid", revision=1, image="cart:v1")
    assert run("rollback")["success"] is False
    assert apps.patches == []


def test_python_rollback_patch_conflict_is_reported(cluster, incident, auto):
    _, apps = cluster
    apps.patch_error = api_error(422, "Unprocessable Entity")
    result = run("rollback")
    assert result["success"] is False and "HTTP 422" in result["detail"]


def test_python_rollback_deployment_missing(cluster, incident, auto):
    _, apps = cluster
    apps.deployment = None
    result = run("rollback")
    assert result["success"] is False and "HTTP 404" in result["detail"]


def test_python_rollback_never_runs_subprocess(cluster, incident, auto, monkeypatch):
    monkeypatch.setattr(remediation.subprocess, "run", lambda *a, **k: pytest.fail("python mode must not shell out"))
    assert run("rollback")["success"] is True


def test_kube_config_error_is_reported_not_raised(monkeypatch, incident, auto):
    def boom():
        raise kube.KubeConfigError("no cluster")

    monkeypatch.setattr(kube, "apps_v1", boom)
    result = run("restart")
    assert result["success"] is False and "not reachable" in result["detail"]


def test_unexpected_exception_is_reported_not_raised(cluster, incident, auto):
    _, apps = cluster
    apps.patch_error = RuntimeError("kaboom")
    result = run("restart")
    assert result["success"] is False and "RuntimeError" in result["detail"]


# --------------------------------------------------------------------------
# Rollback: kubectl mode
# --------------------------------------------------------------------------


@pytest.fixture()
def kubectl_mode(monkeypatch):
    set_env(monkeypatch, ROLLBACK_MODE="kubectl", AUTO_REMEDIATE="true")
    monkeypatch.delenv("KUBE_CONTEXT", raising=False)
    monkeypatch.setattr(remediation.shutil, "which", lambda name: "/usr/local/bin/kubectl")
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout="deployment.apps/shop-api rolled back\n", stderr="")

    monkeypatch.setattr(remediation.subprocess, "run", fake_run)
    return calls


def test_kubectl_rollback_uses_fixed_argument_list_without_shell(cluster, incident, kubectl_mode):
    result = run("rollback")
    assert result["success"] is True and "rolled back" in result["detail"]
    (command, kwargs), = kubectl_mode
    assert command == ["/usr/local/bin/kubectl", "--namespace", "default", "rollout", "undo", "deployment/shop-api"]
    assert isinstance(command, list)
    assert not kwargs.get("shell")
    assert kwargs["timeout"] == remediation.KUBECTL_TIMEOUT_SECONDS
    assert kwargs["capture_output"] is True


def test_kubectl_rollback_adds_context_when_configured(cluster, incident, kubectl_mode, monkeypatch):
    monkeypatch.setenv("KUBE_CONTEXT", "kind-incidentiq")
    run("rollback")
    assert kubectl_mode[0][0][1:3] == ["--context", "kind-incidentiq"]


def test_kubectl_nonzero_exit_is_a_failure(cluster, incident, kubectl_mode, monkeypatch):
    monkeypatch.setattr(
        remediation.subprocess, "run",
        lambda command, **kw: subprocess.CompletedProcess(command, 1, stdout="", stderr='error: no rollout history found'))
    result = run("rollback")
    assert result["success"] is False and "exit 1" in result["detail"] and "no rollout history" in result["detail"]


def test_kubectl_timeout_is_a_failure(cluster, incident, kubectl_mode, monkeypatch):
    def slow(command, **kw):
        raise subprocess.TimeoutExpired(command, kw["timeout"])

    monkeypatch.setattr(remediation.subprocess, "run", slow)
    result = run("rollback")
    assert result["success"] is False and "timed out" in result["detail"]


def test_kubectl_missing_is_a_failure(cluster, incident, kubectl_mode, monkeypatch):
    monkeypatch.setattr(remediation.shutil, "which", lambda name: None)
    result = run("rollback")
    assert result["success"] is False and "kubectl executable not found" in result["detail"]


def test_kubectl_os_error_is_a_failure(cluster, incident, kubectl_mode, monkeypatch):
    def broken(command, **kw):
        raise PermissionError("denied")

    monkeypatch.setattr(remediation.subprocess, "run", broken)
    assert run("rollback")["success"] is False


def test_kubectl_mode_only_used_for_rollback(cluster, incident, kubectl_mode):
    _, apps = cluster
    run("restart")
    assert kubectl_mode == [] and len(apps.patches) == 1


# --------------------------------------------------------------------------
# Restart and scale
# --------------------------------------------------------------------------


def test_restart_patches_template_annotation_only(cluster, incident, auto):
    _, apps = cluster
    assert run("restart")["success"] is True
    patch = patch_ops(apps)
    assert patch["_content_type"] == "application/merge-patch+json"
    annotations = patch["body"]["spec"]["template"]["metadata"]["annotations"]
    assert list(annotations) == ["kubectl.kubernetes.io/restartedAt"]
    assert set(patch["body"]["spec"]) == {"template"}
    assert annotations["kubectl.kubernetes.io/restartedAt"].endswith("+00:00")


def test_scale_patches_replicas_to_configured_target(cluster, incident, auto, monkeypatch):
    set_env(monkeypatch, SCALE_TARGET_REPLICAS=4)
    _, apps = cluster
    result = run("scale")
    assert result["success"] is True and "from 2 to 4" in result["detail"]
    assert patch_ops(apps)["body"] == {"spec": {"replicas": 4}}


def test_scale_is_a_noop_when_already_at_target(cluster, incident, auto):
    _, apps = cluster
    result = run("scale")  # default target 2, deployment has 2
    assert result["success"] is True and "no change" in result["detail"]
    assert apps.patches == []


def test_scale_patch_error_is_reported(cluster, incident, auto, monkeypatch):
    set_env(monkeypatch, SCALE_TARGET_REPLICAS=3)
    _, apps = cluster
    apps.patch_error = api_error(403, "Forbidden")
    result = run("scale")
    assert result["success"] is False and "HTTP 403" in result["detail"]


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------


class Clock:
    """Fake monotonic clock; sleeping advances it instantly."""

    def __init__(self):
        self.now = 0.0
        self.sleeps = []
        self.on_sleep = None

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds
        if self.on_sleep:
            self.on_sleep(len(self.sleeps))


@pytest.fixture()
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(remediation, "_monotonic", c.monotonic)
    monkeypatch.setattr(remediation, "_sleep", c.sleep)
    set_env(monkeypatch, VERIFICATION_INTERVAL_SECONDS=5, VERIFICATION_TIMEOUT_SECONDS=120)
    return c


def healthy_cluster(monkeypatch, replicas=2):
    core, apps = FakeCoreV1(), FakeAppsV1()
    apps.deployment = make_deployment(replicas=replicas, status=healthy_status(replicas), generation=1)
    apps.replica_sets["shop-api-abc"] = make_replica_set("shop-api-abc", replicas=replicas, ready_replicas=replicas)
    core.pods["default"] = [make_pod(f"shop-api-abc-{i}") for i in range(replicas)]
    monkeypatch.setattr(kube, "core_v1", lambda: core)
    monkeypatch.setattr(kube, "apps_v1", lambda: apps)
    return core, apps


def test_verify_succeeds_immediately_when_healthy(monkeypatch, clock):
    healthy_cluster(monkeypatch)
    assert remediation.verify("default", "shop-api") is True
    assert clock.sleeps == []


def test_verify_waits_for_rollout_to_complete(monkeypatch, clock):
    core, apps = healthy_cluster(monkeypatch)
    good_status = healthy_status()
    apps.deployment.status = client.V1DeploymentStatus(**{**good_status, "ready_replicas": 0, "available_replicas": 0})

    def heal(n):
        if n == 3:
            apps.deployment.status = client.V1DeploymentStatus(**good_status)

    clock.on_sleep = heal
    ok, detail = remediation.verify_with_detail("default", "shop-api")
    assert ok is True and len(clock.sleeps) == 3 and "Running and Ready" in detail


def test_verify_times_out_and_returns_false(monkeypatch, clock):
    _, apps = healthy_cluster(monkeypatch)
    apps.deployment.status = client.V1DeploymentStatus(**{**healthy_status(), "ready_replicas": 0, "available_replicas": 0})
    ok, detail = remediation.verify_with_detail("default", "shop-api", timeout=20)
    assert ok is False and "timed out after 20s" in detail and "0/2 replicas ready" in detail
    assert sum(clock.sleeps) == 20 and all(s <= 5 for s in clock.sleeps)


def test_verify_polls_every_configured_interval(monkeypatch, clock):
    _, apps = healthy_cluster(monkeypatch)
    apps.deployment.status = client.V1DeploymentStatus(**{**healthy_status(), "ready_replicas": 0, "available_replicas": 0})
    remediation.verify("default", "shop-api", timeout=15)
    assert clock.sleeps == [5, 5, 5]


def test_verify_uses_configured_default_timeout(monkeypatch, clock):
    set_env(monkeypatch, VERIFICATION_TIMEOUT_SECONDS=30, VERIFICATION_INTERVAL_SECONDS=5)
    _, apps = healthy_cluster(monkeypatch)
    apps.deployment.status = client.V1DeploymentStatus(**{**healthy_status(), "ready_replicas": 0, "available_replicas": 0})
    assert remediation.verify("default", "shop-api") is False
    assert sum(clock.sleeps) == 30


def test_verify_with_zero_timeout_still_checks_once(monkeypatch, clock):
    healthy_cluster(monkeypatch)
    assert remediation.verify("default", "shop-api", timeout=0) is True


@pytest.mark.parametrize("mutate,expected", [
    (lambda c, a: setattr(a.deployment.status, "replicas", 3), "old replicas still terminating"),
    (lambda c, a: setattr(a.deployment.status, "updated_replicas", 1), "rollout in progress"),
    (lambda c, a: setattr(a.deployment.status, "available_replicas", 1), "available"),
    (lambda c, a: setattr(a.deployment.status, "observed_generation", 0), "not observed the latest spec"),
    (lambda c, a: setattr(a.deployment.spec, "replicas", 0), "scaled to 0"),
])
def test_verify_rejects_incomplete_rollouts(monkeypatch, clock, mutate, expected):
    core, apps = healthy_cluster(monkeypatch)
    apps.deployment.metadata.generation = 1
    mutate(core, apps)
    ok, detail = remediation.verify_with_detail("default", "shop-api", timeout=0)
    assert ok is False and expected in detail


def test_verify_rejects_pod_that_is_not_ready_even_if_counts_look_fine(monkeypatch, clock):
    core, _ = healthy_cluster(monkeypatch)
    core.pods["default"][1] = make_pod("shop-api-abc-1", ready=False)
    ok, detail = remediation.verify_with_detail("default", "shop-api", timeout=0)
    assert ok is False and "shop-api-abc-1" in detail and "not Ready" in detail


def test_verify_rejects_pod_that_is_not_running(monkeypatch, clock):
    core, _ = healthy_cluster(monkeypatch)
    core.pods["default"][0] = make_pod("shop-api-abc-0", phase="Pending", ready=True)
    assert remediation.verify("default", "shop-api", timeout=0) is False


def test_verify_rejects_wrong_pod_count(monkeypatch, clock):
    core, _ = healthy_cluster(monkeypatch)
    core.pods["default"].pop()
    ok, detail = remediation.verify_with_detail("default", "shop-api", timeout=0)
    assert ok is False and "1 pods found, expected 2" in detail


def test_verify_ignores_terminating_pods(monkeypatch, clock):
    core, _ = healthy_cluster(monkeypatch)
    core.pods["default"].append(make_pod("old-bad", ready=False, deleting=True))
    assert remediation.verify("default", "shop-api", timeout=0) is True


def test_verify_ignores_pods_of_other_workloads(monkeypatch, clock):
    core, _ = healthy_cluster(monkeypatch)
    core.pods["default"].append(make_pod("cart-1", owner_rs="cart-rs", ready=False))
    assert remediation.verify("default", "shop-api", timeout=0) is True


def test_verify_missing_deployment_fails_fast_without_waiting(monkeypatch, clock):
    _, apps = healthy_cluster(monkeypatch)
    apps.deployment = None
    ok, detail = remediation.verify_with_detail("default", "shop-api")
    assert ok is False and "verification impossible" in detail and "404" in detail
    assert clock.sleeps == []


def test_verify_permission_denied_fails_fast(monkeypatch, clock):
    _, apps = healthy_cluster(monkeypatch)
    apps.deployment_error = api_error(403, "Forbidden")
    assert remediation.verify("default", "shop-api") is False
    assert clock.sleeps == []


def test_verify_survives_transient_errors_then_succeeds(monkeypatch, clock):
    _, apps = healthy_cluster(monkeypatch)
    apps.deployment_error = api_error(503, "Service Unavailable")

    def recover(n):
        if n == 2:
            apps.deployment_error = None

    clock.on_sleep = recover
    assert remediation.verify("default", "shop-api") is True
    assert len(clock.sleeps) == 2


def test_verify_persistent_transient_error_times_out(monkeypatch, clock):
    _, apps = healthy_cluster(monkeypatch)
    apps.deployment_error = ConnectionError("reset")
    ok, detail = remediation.verify_with_detail("default", "shop-api", timeout=10)
    assert ok is False and "timed out" in detail and "ConnectionError" in detail


def test_verify_kube_config_error_fails_fast(monkeypatch, clock):
    def boom():
        raise kube.KubeConfigError("no cluster")

    monkeypatch.setattr(kube, "apps_v1", boom)
    assert remediation.verify("default", "shop-api") is False
    assert clock.sleeps == []


def test_verify_returns_a_real_bool(monkeypatch, clock):
    healthy_cluster(monkeypatch)
    assert remediation.verify("default", "shop-api") is True
