"""Builders and fake API clients for detector/collector tests.

They create REAL ``kubernetes.client`` model objects (not loose mocks), so the
code under test sees the same attribute shapes it sees against a live cluster.
No cluster or network access is involved.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

from kubernetes import client
from kubernetes.client.exceptions import ApiException

NOW = datetime.now(timezone.utc)  # the code under test also uses the real clock


def ago(seconds: float) -> datetime:
    """A timestamp ``seconds`` before NOW."""
    return NOW - timedelta(seconds=seconds)


def api_error(status: int = 500, reason: str = "Internal Server Error") -> ApiException:
    return ApiException(status=status, reason=reason)


# ---------------------------------------------------------------------------
# Object builders
# ---------------------------------------------------------------------------


def owner(kind: str, name: str, uid: str = "uid-1", controller: bool = True) -> client.V1OwnerReference:
    return client.V1OwnerReference(
        api_version="apps/v1", kind=kind, name=name, uid=uid, controller=controller
    )


def make_pod(
    name: str = "shop-api-abc-1",
    namespace: str = "default",
    owner_rs: Optional[str] = "shop-api-abc",
    phase: str = "Running",
    ready: bool = True,
    ready_since: Optional[datetime] = None,
    waiting: Optional[str] = None,
    terminated: Optional[Tuple[str, Optional[datetime]]] = None,
    last_terminated: Optional[Tuple[str, Optional[datetime]]] = None,
    restarts: int = 0,
    image: str = "shop-api:v1",
    deleting: bool = False,
    created: Optional[datetime] = None,
    labels: Optional[Dict[str, str]] = None,
    container: str = "shop-api",
) -> client.V1Pod:
    """Build a pod. ``terminated``/``last_terminated`` are (reason, finished_at)."""
    state = client.V1ContainerState()
    if waiting:
        state = client.V1ContainerState(waiting=client.V1ContainerStateWaiting(reason=waiting))
    elif terminated:
        state = client.V1ContainerState(
            terminated=client.V1ContainerStateTerminated(
                exit_code=137, reason=terminated[0], finished_at=terminated[1]
            )
        )
    elif phase == "Running":
        state = client.V1ContainerState(running=client.V1ContainerStateRunning(started_at=ago(500)))
    last_state = client.V1ContainerState()
    if last_terminated:
        last_state = client.V1ContainerState(
            terminated=client.V1ContainerStateTerminated(
                exit_code=1, reason=last_terminated[0], finished_at=last_terminated[1]
            )
        )
    container_status = client.V1ContainerStatus(
        name=container, image=image, image_id="", ready=ready,
        restart_count=restarts, state=state, last_state=last_state,
    )
    condition = client.V1PodCondition(
        type="Ready",
        status="True" if ready else "False",
        last_transition_time=ready_since if ready_since is not None else ago(600),
    )
    owners = [owner("ReplicaSet", owner_rs)] if owner_rs else None
    return client.V1Pod(
        metadata=client.V1ObjectMeta(
            name=name, namespace=namespace, owner_references=owners,
            creation_timestamp=created or ago(900), labels=labels or {"app": "shop-api"},
            deletion_timestamp=ago(1) if deleting else None,
        ),
        spec=client.V1PodSpec(containers=[client.V1Container(name=container, image=image)]),
        status=client.V1PodStatus(
            phase=phase, conditions=[condition], container_statuses=[container_status]
        ),
    )


def make_replica_set(
    name: str = "shop-api-abc",
    deployment: Optional[str] = "shop-api",
    deployment_uid: str = "deploy-uid",
    namespace: str = "default",
    revision: Optional[int] = 1,
    image: str = "shop-api:v1",
    created: Optional[datetime] = None,
    replicas: int = 2,
    ready_replicas: int = 2,
    env: Optional[List[client.V1EnvVar]] = None,
    annotations: Optional[Dict[str, str]] = None,
) -> client.V1ReplicaSet:
    notes = dict(annotations or {})
    if revision is not None:
        notes["deployment.kubernetes.io/revision"] = str(revision)
    owners = [owner("Deployment", deployment, uid=deployment_uid)] if deployment else None
    template = client.V1PodTemplateSpec(
        metadata=client.V1ObjectMeta(labels={"app": "shop-api"}),
        spec=client.V1PodSpec(
            containers=[
                client.V1Container(
                    name="shop-api", image=image, env=env,
                    resources=client.V1ResourceRequirements(
                        requests={"memory": "64Mi"}, limits={"memory": "128Mi"}
                    ),
                )
            ]
        ),
    )
    return client.V1ReplicaSet(
        metadata=client.V1ObjectMeta(
            name=name, namespace=namespace, owner_references=owners,
            creation_timestamp=created or ago(3600), annotations=notes,
        ),
        spec=client.V1ReplicaSetSpec(
            replicas=replicas,
            selector=client.V1LabelSelector(match_labels={"app": "shop-api"}),
            template=template,
        ),
        status=client.V1ReplicaSetStatus(
            replicas=replicas, ready_replicas=ready_replicas, available_replicas=ready_replicas
        ),
    )


def make_deployment(
    name: str = "shop-api",
    namespace: str = "default",
    uid: str = "deploy-uid",
    revision: Optional[int] = 2,
    managed_fields: Optional[List[client.V1ManagedFieldsEntry]] = None,
    progressing_update: Optional[datetime] = None,
    replicas: int = 2,
    status: Optional[Dict[str, int]] = None,
    generation: Optional[int] = None,
) -> client.V1Deployment:
    conditions = None
    if progressing_update is not None:
        conditions = [
            client.V1DeploymentCondition(
                type="Progressing", status="True", last_update_time=progressing_update,
                reason="NewReplicaSetAvailable",
            )
        ]
    annotations = {"deployment.kubernetes.io/revision": str(revision)} if revision is not None else {}
    return client.V1Deployment(
        metadata=client.V1ObjectMeta(
            name=name, namespace=namespace, uid=uid, annotations=annotations,
            managed_fields=managed_fields, creation_timestamp=ago(7200), generation=generation,
        ),
        spec=client.V1DeploymentSpec(
            replicas=replicas,
            selector=client.V1LabelSelector(match_labels={"app": "shop-api"}),
            template=client.V1PodTemplateSpec(
                spec=client.V1PodSpec(containers=[client.V1Container(name="shop-api", image="shop-api:v1")])
            ),
        ),
        status=client.V1DeploymentStatus(conditions=conditions, **(status or {})),
    )


def healthy_status(replicas: int = 2) -> Dict[str, int]:
    """Deployment status counts of a fully rolled-out Deployment."""
    return {
        "replicas": replicas, "updated_replicas": replicas, "ready_replicas": replicas,
        "available_replicas": replicas, "observed_generation": 1,
    }


def managed_field(time: Optional[datetime], manager: str = "kubectl", operation: str = "Update",
                  subresource: Optional[str] = None) -> client.V1ManagedFieldsEntry:
    return client.V1ManagedFieldsEntry(
        manager=manager, operation=operation, time=time, subresource=subresource, api_version="apps/v1"
    )


def make_event(
    kind: str, name: str, reason: str = "BackOff", message: str = "Back-off restarting failed container",
    when: Optional[datetime] = None, type_: str = "Warning", namespace: str = "default", count: int = 1,
) -> client.CoreV1Event:
    return client.CoreV1Event(
        metadata=client.V1ObjectMeta(name=f"{name}.{reason}.{id(object())}", namespace=namespace),
        involved_object=client.V1ObjectReference(kind=kind, name=name, namespace=namespace),
        reason=reason, message=message, type=type_, last_timestamp=when or ago(60), count=count,
    )


# ---------------------------------------------------------------------------
# Fake API clients
# ---------------------------------------------------------------------------


class FakeCoreV1:
    """Stands in for ``CoreV1Api``. Set ``*_error`` attributes to simulate failures."""

    def __init__(self) -> None:
        self.pods: Dict[str, List[Any]] = {}
        self.events: List[Any] = []
        # (pod, previous) -> text or Exception
        self.logs: Dict[Tuple[str, bool], Any] = {}
        self.list_pods_errors: Dict[str, Exception] = {}
        self.events_error: Optional[Exception] = None
        self.log_calls: List[Dict[str, Any]] = []

    def list_namespaced_pod(self, namespace: str, **kwargs: Any) -> SimpleNamespace:
        if namespace in self.list_pods_errors:
            raise self.list_pods_errors[namespace]
        return SimpleNamespace(items=list(self.pods.get(namespace, [])))

    def list_namespaced_event(self, namespace: str, **kwargs: Any) -> SimpleNamespace:
        if self.events_error is not None:
            raise self.events_error
        return SimpleNamespace(items=list(self.events))

    def read_namespaced_pod_log(self, name: str, namespace: str, **kwargs: Any) -> str:
        self.log_calls.append({"name": name, "namespace": namespace, **kwargs})
        result = self.logs.get((name, bool(kwargs.get("previous"))))
        if result is None:
            raise api_error(400, "Bad Request")
        if isinstance(result, Exception):
            raise result
        return result


class FakeAppsV1:
    """Stands in for ``AppsV1Api``."""

    def __init__(self) -> None:
        self.replica_sets: Dict[str, Any] = {}
        self.deployment: Any = None
        self.rs_errors: Dict[str, Exception] = {}
        self.deployment_error: Optional[Exception] = None
        self.list_rs_error: Optional[Exception] = None
        self.rs_reads = 0
        self.deployments: List[Any] = []
        self.patches: List[Dict[str, Any]] = []
        self.patch_error: Optional[Exception] = None

    def read_namespaced_replica_set(self, name: str, namespace: str, **kwargs: Any) -> Any:
        self.rs_reads += 1
        if name in self.rs_errors:
            raise self.rs_errors[name]
        if name not in self.replica_sets:
            raise api_error(404, "Not Found")
        return self.replica_sets[name]

    def list_namespaced_replica_set(self, namespace: str, **kwargs: Any) -> SimpleNamespace:
        if self.list_rs_error is not None:
            raise self.list_rs_error
        return SimpleNamespace(items=list(self.replica_sets.values()))

    def list_namespaced_deployment(self, namespace: str, **kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(items=list(self.deployments))

    def read_namespaced_deployment(self, name: str, namespace: str, **kwargs: Any) -> Any:
        if self.deployment_error is not None:
            raise self.deployment_error
        if self.deployment is None:
            raise api_error(404, "Not Found")
        return self.deployment

    def patch_namespaced_deployment(self, name: str, namespace: str, body: Any, **kwargs: Any) -> Any:
        self.patches.append({"name": name, "namespace": namespace, "body": body, **kwargs})
        if self.patch_error is not None:
            raise self.patch_error
        return self.deployment
