"""Centralised configuration for IncidentIQ.

All settings come from environment variables (optionally loaded from a
``.env`` file). Values are validated once, at load time, and exposed through
an immutable :class:`Settings` object.

Typical usage::

    from backend.config import get_settings
    settings = get_settings()
    print(settings.detector_interval_seconds)

Design notes:
    * Real environment variables always win over values in ``.env``.
    * Secrets (``api_key``, ``gemini_api_key``) are excluded from ``repr`` and
      are masked by the logging redaction filter installed by
      :func:`setup_logging`.
    * Automatic remediation is OFF unless explicitly enabled.
    * The namespace allow-list must be explicit; wildcards are rejected.
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

from dotenv import load_dotenv

logger = logging.getLogger(__name__)

VALID_APP_ENVS: Tuple[str, ...] = ("development", "test", "production")
VALID_ROLLBACK_MODES: Tuple[str, ...] = ("python", "kubectl")
VALID_LOG_LEVELS: Tuple[str, ...] = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

#: Minimum length of a configured API key when APP_ENV=production.
MIN_PRODUCTION_API_KEY_LENGTH = 32

#: Hard upper bound on remediation attempts per incident (project guardrail).
MAX_ALLOWED_REMEDIATION_ATTEMPTS = 2

#: Values that are never acceptable as a production API key.
_WEAK_API_KEYS = frozenset(
    {"changeme", "change-me", "password", "secret", "admin", "incidentiq", "test", "demo"}
)

#: Kubernetes namespace names are RFC 1123 labels (max 63 characters).
_NAMESPACE_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")

#: Secrets shorter than this are not redacted from logs (avoids mangling text).
_MIN_REDACTABLE_SECRET_LENGTH = 6


class ConfigError(ValueError):
    """Raised when the environment contains an invalid configuration."""


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


def _get_str(env: Mapping[str, str], name: str, default: str) -> str:
    """Return a stripped string setting, or ``default`` when unset/blank."""
    value = env.get(name)
    if value is None or not value.strip():
        return default
    return value.strip()


def _get_int(
    env: Mapping[str, str], name: str, default: int, minimum: int, maximum: int
) -> int:
    """Return an integer setting constrained to ``[minimum, maximum]``."""
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}, got {value}")
    return value


def _get_float(
    env: Mapping[str, str], name: str, default: float, minimum: float, maximum: float
) -> float:
    """Return a float setting constrained to ``[minimum, maximum]``."""
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc
    if value != value or not minimum <= value <= maximum:  # NaN check + range
        raise ConfigError(f"{name} must be between {minimum} and {maximum}, got {raw!r}")
    return value


def _get_bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    """Return a boolean setting (true/false/1/0/yes/no/on/off)."""
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    text = raw.strip().lower()
    if text in _TRUE_VALUES:
        return True
    if text in _FALSE_VALUES:
        return False
    raise ConfigError(f"{name} must be a boolean (true/false), got {raw!r}")


def _get_choice(
    env: Mapping[str, str], name: str, default: str, choices: Tuple[str, ...], upper: bool = False
) -> str:
    """Return a string setting restricted to ``choices``."""
    value = _get_str(env, name, default)
    value = value.upper() if upper else value.lower()
    if value not in choices:
        raise ConfigError(f"{name} must be one of {', '.join(choices)}, got {value!r}")
    return value


def _parse_namespace_allowlist(raw: str) -> Tuple[str, ...]:
    """Parse and validate a comma-separated namespace allow-list."""
    namespaces: List[str] = []
    for item in raw.split(","):
        name = item.strip()
        if not name:
            continue
        if name == "*" or "*" in name:
            raise ConfigError(
                "KUBERNETES_NAMESPACE_ALLOWLIST must list explicit namespaces; wildcards are not allowed"
            )
        if len(name) > 63 or not _NAMESPACE_RE.match(name):
            raise ConfigError(f"Invalid Kubernetes namespace name in allow-list: {name!r}")
        if name not in namespaces:
            namespaces.append(name)
    if not namespaces:
        raise ConfigError("KUBERNETES_NAMESPACE_ALLOWLIST must contain at least one namespace")
    return tuple(namespaces)


# ---------------------------------------------------------------------------
# Settings object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Settings:
    """Immutable, validated application settings."""

    app_name: str
    app_env: str
    log_level: str

    api_host: str
    api_port: int
    api_key: str = field(repr=False)
    api_key_generated: bool

    database_path: str

    gemini_api_key: str = field(repr=False)
    gemini_model: str
    gemini_timeout_seconds: float

    namespace_allowlist: Tuple[str, ...]
    detector_interval_seconds: int
    unhealthy_pod_grace_seconds: int

    auto_remediate: bool
    rollback_mode: str
    max_remediation_attempts: int
    scale_target_replicas: int
    verification_timeout_seconds: int
    verification_interval_seconds: int

    incident_cooldown_seconds: int
    injection_max_age_seconds: int

    # -- derived helpers ----------------------------------------------------

    @property
    def is_production(self) -> bool:
        """True when running with APP_ENV=production."""
        return self.app_env == "production"

    @property
    def gemini_enabled(self) -> bool:
        """True when a Gemini API key is configured."""
        return bool(self.gemini_api_key)

    def is_namespace_allowed(self, namespace: str) -> bool:
        """Return True only for namespaces explicitly in the allow-list."""
        return namespace in self.namespace_allowlist

    def secrets_to_redact(self) -> List[str]:
        """Return secret values that must never appear in logs."""
        return [
            s
            for s in (self.api_key, self.gemini_api_key)
            if s and len(s) >= _MIN_REDACTABLE_SECRET_LENGTH
        ]

    def redacted(self) -> Dict[str, Any]:
        """Return a dict of settings that is safe to log or display."""
        data: Dict[str, Any] = {
            name: getattr(self, name) for name in self.__dataclass_fields__
        }
        data["api_key"] = "***set***" if self.api_key else "***unset***"
        data["gemini_api_key"] = "***set***" if self.gemini_api_key else "***unset***"
        data["namespace_allowlist"] = list(self.namespace_allowlist)
        return data

    # -- construction -------------------------------------------------------

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Settings":
        """Build validated settings.

        Args:
            env: Optional mapping to read from. When ``None`` the ``.env`` file
                is loaded (without overriding real environment variables) and
                ``os.environ`` is used.

        Raises:
            ConfigError: if any value is invalid or a production safety
                requirement is not met.
        """
        if env is None:
            load_dotenv(override=False)
            env = os.environ

        app_env = _get_choice(env, "APP_ENV", "development", VALID_APP_ENVS)

        # --- API key -------------------------------------------------------
        configured_key = env.get("API_KEY", "").strip()
        api_key_generated = False
        if configured_key:
            if app_env == "production":
                if len(configured_key) < MIN_PRODUCTION_API_KEY_LENGTH:
                    raise ConfigError(
                        f"API_KEY must be at least {MIN_PRODUCTION_API_KEY_LENGTH} characters "
                        "when APP_ENV=production"
                    )
                if configured_key.lower() in _WEAK_API_KEYS:
                    raise ConfigError("API_KEY is a well-known weak value and cannot be used in production")
            api_key = configured_key
        else:
            if app_env == "production":
                raise ConfigError("API_KEY must be configured when APP_ENV=production")
            api_key = secrets.token_urlsafe(32)
            api_key_generated = True

        # --- numeric relationships ----------------------------------------
        verification_timeout = _get_int(env, "VERIFICATION_TIMEOUT_SECONDS", 120, 1, 3600)
        verification_interval = _get_int(env, "VERIFICATION_INTERVAL_SECONDS", 5, 1, 300)
        if verification_interval > verification_timeout:
            raise ConfigError(
                "VERIFICATION_INTERVAL_SECONDS must not exceed VERIFICATION_TIMEOUT_SECONDS"
            )

        database_path = _get_str(env, "DATABASE_PATH", "./data/incidentiq.db")
        if database_path == ":memory:" or database_path.startswith("file:"):
            raise ConfigError(
                "DATABASE_PATH must be a filesystem path; a new connection is opened per "
                "operation, so ':memory:' and URI databases are not supported"
            )

        return cls(
            app_name=_get_str(env, "APP_NAME", "IncidentIQ"),
            app_env=app_env,
            log_level=_get_choice(env, "LOG_LEVEL", "INFO", VALID_LOG_LEVELS, upper=True),
            api_host=_get_str(env, "API_HOST", "0.0.0.0"),
            api_port=_get_int(env, "API_PORT", 8000, 1, 65535),
            api_key=api_key,
            api_key_generated=api_key_generated,
            database_path=database_path,
            gemini_api_key=_get_str(env, "GEMINI_API_KEY", ""),
            gemini_model=_get_str(env, "GEMINI_MODEL", "gemini-2.5-flash"),
            gemini_timeout_seconds=_get_float(env, "GEMINI_TIMEOUT_SECONDS", 30.0, 1.0, 300.0),
            namespace_allowlist=_parse_namespace_allowlist(
                _get_str(env, "KUBERNETES_NAMESPACE_ALLOWLIST", "default")
            ),
            detector_interval_seconds=_get_int(env, "DETECTOR_INTERVAL_SECONDS", 10, 1, 3600),
            unhealthy_pod_grace_seconds=_get_int(env, "UNHEALTHY_POD_GRACE_SECONDS", 30, 0, 86400),
            auto_remediate=_get_bool(env, "AUTO_REMEDIATE", False),
            rollback_mode=_get_choice(env, "ROLLBACK_MODE", "python", VALID_ROLLBACK_MODES),
            max_remediation_attempts=_get_int(
                env, "MAX_REMEDIATION_ATTEMPTS", 2, 1, MAX_ALLOWED_REMEDIATION_ATTEMPTS
            ),
            scale_target_replicas=_get_int(env, "SCALE_TARGET_REPLICAS", 2, 1, 10),
            verification_timeout_seconds=verification_timeout,
            verification_interval_seconds=verification_interval,
            incident_cooldown_seconds=_get_int(env, "INCIDENT_COOLDOWN_SECONDS", 60, 0, 86400),
            injection_max_age_seconds=_get_int(env, "INJECTION_MAX_AGE_SECONDS", 600, 1, 86400),
        )


# ---------------------------------------------------------------------------
# Process-wide settings cache
# ---------------------------------------------------------------------------

_settings: Optional[Settings] = None
_settings_lock = threading.Lock()


def get_settings() -> Settings:
    """Return the process-wide settings, loading them on first use."""
    global _settings
    with _settings_lock:
        if _settings is None:
            _settings = Settings.from_env()
            if _settings.api_key_generated:
                logger.warning(
                    "API_KEY is not configured; generated a temporary development key for this "
                    "process. Set API_KEY in .env to use a stable key."
                )
        return _settings


def reset_settings() -> None:
    """Forget cached settings so the next :func:`get_settings` call reloads them."""
    global _settings
    with _settings_lock:
        _settings = None


def reload_settings() -> Settings:
    """Discard cached settings and load them again from the environment."""
    reset_settings()
    return get_settings()


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


class _RedactingFilter(logging.Filter):
    """Replace configured secret values with ``***`` in every log record."""

    def __init__(self, secret_values: List[str]) -> None:
        super().__init__()
        self._secrets = [s for s in secret_values if s]

    def filter(self, record: logging.LogRecord) -> bool:
        if self._secrets:
            message = record.getMessage()
            for secret in self._secrets:
                if secret in message:
                    message = message.replace(secret, "***")
            record.msg = message
            record.args = ()
        return True


_LOG_FORMAT = "%(asctime)s level=%(levelname)s logger=%(name)s msg=%(message)s"


def setup_logging(settings: Optional[Settings] = None) -> None:
    """Configure structured, secret-redacting logging. Safe to call repeatedly."""
    settings = settings or get_settings()
    root = logging.getLogger()
    root.setLevel(settings.log_level)

    handler = next((h for h in root.handlers if getattr(h, "_incidentiq", False)), None)
    if handler is None:
        handler = logging.StreamHandler()
        setattr(handler, "_incidentiq", True)
        root.addHandler(handler)

    handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    handler.filters = [f for f in handler.filters if not isinstance(f, _RedactingFilter)]
    handler.addFilter(_RedactingFilter(settings.secrets_to_redact()))
