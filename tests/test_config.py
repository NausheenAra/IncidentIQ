"""Tests for backend/config.py (validation, safety defaults, secret handling)."""

from __future__ import annotations

import logging

import pytest

from backend import config
from backend.config import ConfigError, Settings

STRONG_KEY = "k" * 40


def make(**overrides: str) -> Settings:
    """Build Settings from an explicit mapping (never touches os.environ or .env)."""
    return Settings.from_env({"APP_ENV": "development", **overrides})


def test_defaults_match_specification():
    s = make()
    assert s.app_name == "IncidentIQ"
    assert s.app_env == "development"
    assert s.log_level == "INFO"
    assert s.api_host == "0.0.0.0"
    assert s.api_port == 8000
    assert s.database_path == "./data/incidentiq.db"
    assert s.gemini_model == "gemini-2.5-flash"
    assert s.namespace_allowlist == ("default",)
    assert s.detector_interval_seconds == 10
    assert s.unhealthy_pod_grace_seconds == 30
    assert s.rollback_mode == "python"
    assert s.max_remediation_attempts == 2
    assert s.verification_timeout_seconds == 120
    assert s.verification_interval_seconds == 5
    assert s.incident_cooldown_seconds == 60


def test_auto_remediation_is_disabled_by_default():
    assert make().auto_remediate is False


def test_development_generates_random_api_key():
    a, b = make(), make()
    assert a.api_key_generated and b.api_key_generated
    assert len(a.api_key) >= 32
    assert a.api_key != b.api_key


def test_configured_api_key_is_used_as_is():
    s = make(API_KEY="my-dev-key")
    assert s.api_key == "my-dev-key"
    assert s.api_key_generated is False


def test_production_requires_api_key():
    with pytest.raises(ConfigError, match="API_KEY"):
        Settings.from_env({"APP_ENV": "production"})


def test_production_rejects_short_api_key():
    with pytest.raises(ConfigError, match="at least"):
        Settings.from_env({"APP_ENV": "production", "API_KEY": "short"})


def test_production_accepts_strong_api_key():
    s = Settings.from_env({"APP_ENV": "production", "API_KEY": STRONG_KEY})
    assert s.is_production and s.api_key == STRONG_KEY


@pytest.mark.parametrize(
    "text,expected",
    [("true", True), ("TRUE", True), ("1", True), ("yes", True), ("on", True),
     ("false", False), ("0", False), ("No", False), ("off", False)],
)
def test_boolean_parsing(text, expected):
    assert make(AUTO_REMEDIATE=text).auto_remediate is expected


def test_invalid_boolean_is_rejected():
    with pytest.raises(ConfigError, match="AUTO_REMEDIATE"):
        make(AUTO_REMEDIATE="maybe")


@pytest.mark.parametrize(
    "name,value",
    [
        ("API_PORT", "abc"),
        ("API_PORT", "0"),
        ("API_PORT", "70000"),
        ("DETECTOR_INTERVAL_SECONDS", "0"),
        ("DETECTOR_INTERVAL_SECONDS", "-5"),
        ("UNHEALTHY_POD_GRACE_SECONDS", "-1"),
        ("MAX_REMEDIATION_ATTEMPTS", "0"),
        ("MAX_REMEDIATION_ATTEMPTS", "3"),
        ("SCALE_TARGET_REPLICAS", "0"),
        ("SCALE_TARGET_REPLICAS", "100"),
        ("VERIFICATION_TIMEOUT_SECONDS", "x"),
        ("INCIDENT_COOLDOWN_SECONDS", "-1"),
        ("GEMINI_TIMEOUT_SECONDS", "nan"),
        ("GEMINI_TIMEOUT_SECONDS", "0"),
        ("LOG_LEVEL", "LOUD"),
        ("APP_ENV", "staging"),
        ("ROLLBACK_MODE", "shell"),
    ],
)
def test_invalid_values_are_rejected(name, value):
    with pytest.raises(ConfigError, match=name):
        make(**{name: value})


def test_verification_interval_cannot_exceed_timeout():
    with pytest.raises(ConfigError, match="VERIFICATION_INTERVAL_SECONDS"):
        make(VERIFICATION_INTERVAL_SECONDS="60", VERIFICATION_TIMEOUT_SECONDS="30")


def test_blank_values_fall_back_to_defaults():
    s = make(API_PORT="  ", LOG_LEVEL="", AUTO_REMEDIATE="", GEMINI_MODEL=" ")
    assert s.api_port == 8000 and s.log_level == "INFO"
    assert s.auto_remediate is False and s.gemini_model == "gemini-2.5-flash"


def test_log_level_and_rollback_mode_are_case_insensitive():
    s = make(LOG_LEVEL="debug", ROLLBACK_MODE="KUBECTL")
    assert s.log_level == "DEBUG" and s.rollback_mode == "kubectl"


def test_namespace_allowlist_parsing():
    s = make(KUBERNETES_NAMESPACE_ALLOWLIST=" default , staging,default,,prod-1 ")
    assert s.namespace_allowlist == ("default", "staging", "prod-1")
    assert s.is_namespace_allowed("staging")
    assert not s.is_namespace_allowed("kube-system")
    assert not s.is_namespace_allowed("")


@pytest.mark.parametrize("bad", ["*", "default,*", "def*", "Has_Upper", "-lead", "trail-", "a b", "x" * 64, ",,,"])
def test_namespace_allowlist_rejects_wildcards_and_invalid_names(bad):
    with pytest.raises(ConfigError):
        make(KUBERNETES_NAMESPACE_ALLOWLIST=bad)


@pytest.mark.parametrize("bad", [":memory:", "file:test.db?mode=memory"])
def test_database_path_must_be_a_real_file(bad):
    with pytest.raises(ConfigError, match="DATABASE_PATH"):
        make(DATABASE_PATH=bad)


def test_missing_gemini_key_is_allowed_and_reported():
    s = make()
    assert s.gemini_api_key == "" and s.gemini_enabled is False
    assert make(GEMINI_API_KEY="abc123456").gemini_enabled is True


def test_secrets_are_not_in_repr_or_redacted_view():
    s = make(API_KEY="super-secret-api-key", GEMINI_API_KEY="super-secret-gemini-key")
    assert "super-secret" not in repr(s)
    assert "super-secret" not in str(s.redacted())
    assert s.redacted()["api_key"] == "***set***"


def test_settings_are_immutable():
    s = make()
    with pytest.raises(Exception):
        s.auto_remediate = True  # type: ignore[misc]


def test_get_settings_caches_and_reload_refreshes(monkeypatch):
    first = config.get_settings()
    assert config.get_settings() is first
    monkeypatch.setenv("LOG_LEVEL", "ERROR")
    assert config.get_settings().log_level == first.log_level  # cached
    assert config.reload_settings().log_level == "ERROR"


def test_logging_redacts_secrets(caplog_free=None):
    settings = make(API_KEY="super-secret-api-key", GEMINI_API_KEY="super-secret-gemini-key")
    config.setup_logging(settings)
    config.setup_logging(settings)  # idempotent: must not stack handlers

    root = logging.getLogger()
    ours = [h for h in root.handlers if getattr(h, "_incidentiq", False)]
    assert len(ours) == 1

    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record)

    capture = Capture()
    for f in ours[0].filters:
        capture.addFilter(f)
    root.addHandler(capture)
    try:
        logging.getLogger("test").error("leak? %s and super-secret-gemini-key", "super-secret-api-key")
    finally:
        root.removeHandler(capture)
        root.removeHandler(ours[0])

    assert records
    assert "super-secret" not in records[0].getMessage()
    assert "***" in records[0].getMessage()


def test_injection_max_age_default_and_override():
    assert make().injection_max_age_seconds == 600
    assert make(INJECTION_MAX_AGE_SECONDS="45").injection_max_age_seconds == 45


@pytest.mark.parametrize("value", ["0", "-5", "abc", "86401"])
def test_injection_max_age_rejects_invalid_values(value):
    with pytest.raises(ConfigError, match="INJECTION_MAX_AGE_SECONDS"):
        make(INJECTION_MAX_AGE_SECONDS=value)
