"""Tests for Kubernetes configuration loading (no cluster needed)."""

from __future__ import annotations

import pytest

from backend import kube


@pytest.fixture(autouse=True)
def clean_kube():
    kube.reset()
    yield
    kube.reset()


def test_prefers_in_cluster_config(monkeypatch):
    calls = []
    monkeypatch.setattr(kube.k8s_config, "load_incluster_config", lambda: calls.append("incluster"))
    monkeypatch.setattr(kube.k8s_config, "load_kube_config", lambda **kw: calls.append("kubeconfig"))
    kube.ensure_configured()
    assert calls == ["incluster"]


def test_falls_back_to_kubeconfig_and_honours_kube_context(monkeypatch):
    seen = {}

    def no_cluster():
        raise kube.k8s_config.ConfigException("not in a pod")

    monkeypatch.setattr(kube.k8s_config, "load_incluster_config", no_cluster)
    monkeypatch.setattr(kube.k8s_config, "load_kube_config", lambda **kw: seen.update(kw))
    monkeypatch.setattr(kube.k8s_config, "list_kube_config_contexts", lambda: ([], {"name": "x"}))
    monkeypatch.setenv("KUBE_CONTEXT", "kind-incidentiq")
    kube.ensure_configured()
    assert seen == {"context": "kind-incidentiq"}


def test_failure_raises_and_is_retried_next_time(monkeypatch):
    attempts = []

    def fail(*args, **kwargs):
        attempts.append(1)
        raise kube.k8s_config.ConfigException("nope")

    monkeypatch.setattr(kube.k8s_config, "load_incluster_config", fail)
    monkeypatch.setattr(kube.k8s_config, "load_kube_config", fail)
    for _ in range(2):
        with pytest.raises(kube.KubeConfigError):
            kube.ensure_configured()
    assert len(attempts) == 4  # both loaders tried on both calls: nothing cached


def test_success_is_cached(monkeypatch):
    calls = []
    monkeypatch.setattr(kube.k8s_config, "load_incluster_config", lambda: calls.append(1))
    kube.ensure_configured()
    kube.ensure_configured()
    assert len(calls) == 1
