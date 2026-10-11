"""Stage 7: static checks of the Kubernetes manifests, image and deploy script.

These need no cluster. They guard the properties that are easy to break by accident:
least-privilege RBAC, no committed secrets, a single backend replica, a ConfigMap that
the real configuration loader accepts, and consistent names/ports between files.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from backend import config

ROOT = Path(__file__).resolve().parent.parent
K8S = ROOT / "k8s"


def _docs(name: str) -> list[dict]:
    return [d for d in yaml.safe_load_all((K8S / name).read_text(encoding="utf-8")) if d]


def _by_kind(docs: list[dict], kind: str) -> list[dict]:
    return [d for d in docs if d.get("kind") == kind]


@pytest.fixture(scope="module")
def rbac() -> list[dict]:
    return _docs("rbac.yaml")


@pytest.fixture(scope="module")
def backend() -> list[dict]:
    return _docs("backend.yaml")


# --------------------------------------------------------------------------- RBAC


def test_rbac_is_namespaced_never_cluster_wide(rbac):
    kinds = {d["kind"] for d in rbac}
    assert kinds == {"Namespace", "ServiceAccount", "Role", "RoleBinding"}
    assert "ClusterRole" not in kinds and "ClusterRoleBinding" not in kinds


def test_role_grants_exactly_what_the_contracts_require(rbac):
    (role,) = _by_kind(rbac, "Role")
    granted = {(g, r): set(rule["verbs"]) for rule in role["rules"] for g in rule["apiGroups"] for r in rule["resources"]}
    assert granted == {
        ("", "pods"): {"get", "list"},
        ("", "pods/log"): {"get"},
        ("", "events"): {"get", "list"},
        ("apps", "replicasets"): {"get", "list"},
        ("apps", "deployments"): {"get", "list", "patch"},
    }


def test_role_has_no_wildcards_secrets_or_destructive_verbs(rbac):
    (role,) = _by_kind(rbac, "Role")
    for rule in role["rules"]:
        for field in ("apiGroups", "resources", "verbs"):
            assert "*" not in rule[field]
        assert "secrets" not in rule["resources"]
        assert not ({"create", "delete", "deletecollection", "update", "escalate", "bind", "impersonate"} & set(rule["verbs"]))
        # Only deployments may be modified at all.
        if "patch" in rule["verbs"]:
            assert rule["resources"] == ["deployments"]


def test_binding_connects_backend_service_account_to_the_role(rbac):
    (role,) = _by_kind(rbac, "Role")
    (binding,) = _by_kind(rbac, "RoleBinding")
    (account,) = _by_kind(rbac, "ServiceAccount")
    assert binding["roleRef"]["kind"] == "Role" and binding["roleRef"]["name"] == role["metadata"]["name"]
    assert binding["metadata"]["namespace"] == role["metadata"]["namespace"] == "default"
    (subject,) = binding["subjects"]
    assert subject == {"kind": "ServiceAccount", "name": account["metadata"]["name"], "namespace": account["metadata"]["namespace"]}


# ------------------------------------------------------------------------- backend


def test_backend_runs_as_a_single_recreated_replica(backend):
    (deployment,) = _by_kind(backend, "Deployment")
    assert deployment["spec"]["replicas"] == 1, "each pod runs its own detector and SQLite file"
    assert deployment["spec"]["strategy"]["type"] == "Recreate"


def test_backend_pod_is_hardened_but_can_reach_the_kubernetes_api(backend, rbac):
    (deployment,) = _by_kind(backend, "Deployment")
    pod = deployment["spec"]["template"]["spec"]
    (account,) = _by_kind(rbac, "ServiceAccount")
    assert pod["serviceAccountName"] == account["metadata"]["name"]
    assert pod["automountServiceAccountToken"] is True
    assert pod["securityContext"]["runAsNonRoot"] is True
    container = pod["containers"][0]
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
    assert container["resources"]["limits"]["memory"]
    mounts = {m["mountPath"] for m in container["volumeMounts"]}
    assert {"/data", "/tmp"} <= mounts, "read-only root needs writable /data (SQLite) and /tmp"


def test_probes_use_the_healthz_endpoint(backend):
    container = _by_kind(backend, "Deployment")[0]["spec"]["template"]["spec"]["containers"][0]
    assert container["readinessProbe"]["httpGet"]["path"] == "/healthz"
    assert container["livenessProbe"]["httpGet"]["path"] == "/healthz"


def test_all_resources_live_in_the_backend_namespace(backend, rbac):
    (namespace,) = _by_kind(rbac, "Namespace")
    for doc in backend:
        assert doc["metadata"]["namespace"] == namespace["metadata"]["name"]


def test_secrets_are_referenced_never_committed(backend):
    (deployment,) = _by_kind(backend, "Deployment")
    refs = deployment["spec"]["template"]["spec"]["containers"][0]["envFrom"]
    assert {"secretRef": {"name": "incidentiq-secrets"}} in refs
    assert not _by_kind(backend, "Secret"), "the Secret is created by scripts/deploy_backend.sh from .env"
    for path in list(K8S.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"^\s*(API_KEY|GEMINI_API_KEY)\s*:\s*\S+", text, flags=re.M), f"secret value in {path.name}"
        assert "AIza" not in text, f"looks like a Google API key in {path.name}"
    assert "incidentiq-secrets" in (ROOT / "scripts" / "deploy_backend.sh").read_text(encoding="utf-8")


def test_configmap_is_accepted_by_the_real_config_loader(backend):
    (configmap,) = _by_kind(backend, "ConfigMap")
    env = dict(configmap["data"])
    assert not {"API_KEY", "GEMINI_API_KEY"} & set(env), "secrets belong in the Secret, not the ConfigMap"
    env["API_KEY"] = "k" * 43  # what the Secret supplies
    settings = config.Settings.from_env(env)
    assert settings.is_production
    assert settings.auto_remediate is False, "the packaged default must require approval"
    assert settings.namespace_allowlist == ("default",) or list(settings.namespace_allowlist) == ["default"]
    assert settings.database_path.startswith("/data/")


def test_configmap_keys_are_all_known_settings(backend):
    (configmap,) = _by_kind(backend, "ConfigMap")
    documented = set(re.findall(r"^([A-Z_]+)=", (ROOT / ".env.example").read_text(encoding="utf-8"), flags=re.M))
    unknown = set(configmap["data"]) - documented
    assert not unknown, f"ConfigMap sets variables that .env.example does not document: {sorted(unknown)}"


def test_nodeport_matches_the_kind_port_mapping(backend):
    (service,) = _by_kind(backend, "Service")
    node_port = service["spec"]["ports"][0]["nodePort"]
    kind_config = yaml.safe_load((K8S / "kind-config.yaml").read_text(encoding="utf-8"))
    mapping = kind_config["nodes"][0]["extraPortMappings"][0]
    assert mapping["containerPort"] == node_port
    assert mapping["listenAddress"] == "127.0.0.1", "unauthenticated reads must not be exposed to the network"


# --------------------------------------------------------------------------- image


def test_dockerfile_matches_the_pod_spec():
    dockerfile = (ROOT / "backend.Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^USER 10001$", dockerfile, flags=re.M)
    assert "--workers" not in dockerfile, "the detector loop lives in the process; use exactly one worker"
    assert "COPY backend/" in dockerfile and "COPY dashboard/" in dockerfile
    assert ".env" not in re.sub(r"\.env\.example", "", dockerfile)
    ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8").split()
    assert ".env" in ignored and ".git" in ignored


def test_runtime_requirements_exclude_test_tools():
    runtime = (ROOT / "requirements-backend.txt").read_text(encoding="utf-8")
    assert "pytest" not in runtime and "httpx" not in runtime
    assert "-r requirements-backend.txt" in (ROOT / "requirements.txt").read_text(encoding="utf-8")
