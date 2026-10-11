"""Tests for the shop-api demo application (app/main.py).

These tests need neither Docker nor Kubernetes. The v4 memory test uses a tiny
ceiling (a few MB) so it is safe to run on a developer machine.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

import main as shop  # noqa: E402  (import after sys.path change)


def test_v1_is_healthy() -> None:
    with TestClient(shop.create_app("v1")) as client:
        assert client.get("/").status_code == 200
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"


def test_v2_fails_startup_when_db_url_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DB_URL", raising=False)
    with pytest.raises(Exception, match="DB_URL missing"):
        with TestClient(shop.create_app("v2")):
            pass


def test_v2_starts_when_db_url_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DB_URL", "sqlite:///demo.db")
    with TestClient(shop.create_app("v2")) as client:
        assert client.get("/health").status_code == 200


def test_v3_root_ok_but_health_500() -> None:
    with TestClient(shop.create_app("v3")) as client:
        assert client.get("/").status_code == 200
        assert client.get("/health").status_code == 500


def test_v4_refuses_to_allocate_without_memory_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shop, "detect_memory_limit_bytes", lambda: None)
    monkeypatch.delenv("ALLOW_UNBOUNDED_MEMORY", raising=False)
    with TestClient(shop.create_app("v4")) as client:
        body = client.get("/health").json()
        assert body["allocation_enabled"] is False
        assert body["allocated_mb"] == 0


def test_memory_hog_allocates_up_to_ceiling() -> None:
    hog = shop.MemoryHog(
        step_mb=1,
        interval_seconds=0.05,
        max_mb=3,
        limit_bytes=128 * 1024 * 1024,
    )
    assert hog.start() is True
    deadline = time.time() + 5
    while hog.allocated_mb < 3 and time.time() < deadline:
        time.sleep(0.05)
    assert hog.allocated_mb == 3
    hog.stop()
    assert hog.allocated_mb == 0


def test_unsupported_version_rejected() -> None:
    with pytest.raises(ValueError):
        shop.create_app("v9")


def test_detect_memory_limit_parsing(tmp_path: Path) -> None:
    limited = tmp_path / "limited"
    limited.write_text("134217728\n")
    unlimited_v2 = tmp_path / "unlimited_v2"
    unlimited_v2.write_text("max\n")
    unlimited_v1 = tmp_path / "unlimited_v1"
    unlimited_v1.write_text("9223372036854771712\n")
    missing = str(tmp_path / "does-not-exist")

    assert shop.detect_memory_limit_bytes((str(limited),)) == 134217728
    assert shop.detect_memory_limit_bytes((str(unlimited_v2),)) is None
    assert shop.detect_memory_limit_bytes((str(unlimited_v1),)) is None
    assert shop.detect_memory_limit_bytes((missing,)) is None
