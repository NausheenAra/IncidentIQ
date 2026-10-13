"""Shared Kubernetes client setup for the detector, collector and remediation.

Configuration order:
    1. ``load_incluster_config()``  - when running inside a pod.
    2. ``load_kube_config()``       - local development (your kubeconfig).

Safety: for local development you can pin the kubeconfig context with the
``KUBE_CONTEXT`` environment variable (the demo scripts use the same name), for
example ``KUBE_CONTEXT=kind-incidentiq``. The active context is logged once so it
is obvious which cluster IncidentIQ is talking to.

Failures never crash callers' loops: :func:`ensure_configured` raises
:class:`KubeConfigError`, which callers catch, log and retry on the next poll.
A failed configuration attempt is NOT cached, so starting the cluster later
fixes things without restarting the backend.
"""

from __future__ import annotations

import contextvars
import logging
import os
import threading
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional, Tuple

from kubernetes import client, config as k8s_config

logger = logging.getLogger(__name__)

#: Seconds to wait for any single Kubernetes API call.
REQUEST_TIMEOUT_SECONDS = 10

_lock = threading.Lock()
_configured = False
_core: Optional[client.CoreV1Api] = None
_apps: Optional[client.AppsV1Api] = None
_last_error: Optional[str] = None

#: kubeconfig context the CURRENT thread/task should talk to. ``None`` means the
#: default cluster (in-cluster config, or ``KUBE_CONTEXT``/the active context).
#: A ContextVar keeps concurrent incident workers for different clusters apart.
_active_context: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "incidentiq_kube_context", default=None
)
_context_clients: Dict[str, Tuple[client.CoreV1Api, client.AppsV1Api]] = {}


class KubeConfigError(RuntimeError):
    """Raised when no usable Kubernetes configuration can be loaded."""


def ensure_configured() -> None:
    """Load Kubernetes configuration once; raise :class:`KubeConfigError` on failure."""
    global _configured, _last_error
    with _lock:
        if _configured:
            return
        errors = []
        try:
            k8s_config.load_incluster_config()
            _configured = True
            _last_error = None
            logger.info("Loaded in-cluster Kubernetes configuration")
            return
        except Exception as exc:  # noqa: BLE001 - any failure means "not in a cluster"
            errors.append(f"in-cluster: {exc}")
        try:
            context = os.environ.get("KUBE_CONTEXT", "").strip() or None
            k8s_config.load_kube_config(context=context)
            _configured = True
            _last_error = None
            try:
                active = k8s_config.list_kube_config_contexts()[1]
                logger.info(
                    "Loaded kubeconfig; active context: %s",
                    context or active.get("name", "unknown"),
                )
            except Exception:  # noqa: BLE001 - logging nicety only
                logger.info("Loaded kubeconfig")
            return
        except Exception as exc:  # noqa: BLE001
            errors.append(f"kubeconfig: {exc}")
        message = "; ".join(errors)
        # Log loudly once per distinct error, quietly afterwards (polling every 10s).
        if message != _last_error:
            logger.warning("Kubernetes configuration unavailable (%s)", message)
        else:
            logger.debug("Kubernetes configuration still unavailable")
        _last_error = message
        raise KubeConfigError(message)


def _clients_for_context(context: str) -> Tuple[client.CoreV1Api, client.AppsV1Api]:
    """Build (and cache) API clients bound to one kubeconfig context.

    Uses ``new_client_from_config`` so the process-wide default configuration is
    never touched: two clusters can be used at the same time.
    """
    with _lock:
        cached = _context_clients.get(context)
    if cached is not None:
        return cached
    try:
        api_client = k8s_config.new_client_from_config(context=context)
    except Exception as exc:  # noqa: BLE001 - missing kubeconfig, unknown context, bad exec plugin ...
        raise KubeConfigError(f"context {context!r}: {exc}") from exc
    pair = (client.CoreV1Api(api_client), client.AppsV1Api(api_client))
    with _lock:
        _context_clients[context] = pair
    return pair


def forget_context(context: str) -> None:
    """Drop cached clients for a context (used when a cluster is deleted)."""
    with _lock:
        _context_clients.pop(context, None)


@contextmanager
def use_cluster(context: Optional[str]) -> Iterator[None]:
    """Route :func:`core_v1` / :func:`apps_v1` for this thread to ``context``.

    ``None`` selects the default cluster. Always restores the previous value.
    """
    token = _active_context.set(context)
    try:
        yield
    finally:
        _active_context.reset(token)


def current_context() -> Optional[str]:
    """The kubeconfig context selected by :func:`use_cluster` (``None`` = default)."""
    return _active_context.get()


def list_contexts() -> List[Dict[str, Any]]:
    """Return the kubeconfig contexts available on this machine (names only, never credentials).

    Returns an empty list when there is no kubeconfig (for example in a pod).
    """
    try:
        contexts, active = k8s_config.list_kube_config_contexts()
    except Exception:  # noqa: BLE001 - no kubeconfig file / unreadable
        return []
    active_name = (active or {}).get("name")
    return [
        {"name": c.get("name"), "cluster": (c.get("context") or {}).get("cluster"), "active": c.get("name") == active_name}
        for c in contexts or []
        if c.get("name")
    ]


def core_v1() -> client.CoreV1Api:
    """Return a CoreV1Api (pods, logs, events). Raises :class:`KubeConfigError`."""
    global _core
    context = _active_context.get()
    if context:
        return _clients_for_context(context)[0]
    ensure_configured()
    with _lock:
        if _core is None:
            _core = client.CoreV1Api()
        return _core


def apps_v1() -> client.AppsV1Api:
    """Return an AppsV1Api (deployments, replicasets). Raises :class:`KubeConfigError`."""
    global _apps
    context = _active_context.get()
    if context:
        return _clients_for_context(context)[1]
    ensure_configured()
    with _lock:
        if _apps is None:
            _apps = client.AppsV1Api()
        return _apps


def reset() -> None:
    """Forget cached configuration and clients (used by tests)."""
    global _configured, _core, _apps, _last_error
    with _lock:
        _configured = False
        _core = None
        _apps = None
        _last_error = None
        _context_clients.clear()
