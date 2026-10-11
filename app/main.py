"""shop-api: demo application for IncidentIQ with four selectable behaviours.

The behaviour is chosen by the ``APP_VERSION`` environment variable, which the
Dockerfile bakes into each image (``shop-api:v1`` ... ``shop-api:v4``).

=======  ==========================  ==========================================
Version  Behaviour                   Kubernetes symptom
=======  ==========================  ==========================================
v1       Healthy                     Pods Running and Ready
v2       Startup failure             CrashLoopBackOff
         (``DB_URL`` is not set)
v3       ``/health`` returns 500     Pods Running but never Ready
v4       Allocates memory gradually  OOMKilled (needs a container memory limit)
=======  ==========================  ==========================================

Safety for v4: memory is only allocated when a container memory limit is
detected (cgroup v2 ``memory.max`` or cgroup v1 ``memory.limit_in_bytes``).
Without a limit the allocator refuses to run, so the demo cannot exhaust the
memory of a developer machine. A hard ceiling (``MEM_MAX_MB``) applies as well.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator, List, Optional

from fastapi import FastAPI
from fastapi.responses import JSONResponse

SUPPORTED_VERSIONS = ("v1", "v2", "v3", "v4")

# cgroup files that expose the container memory limit (v2 first, then v1).
CGROUP_MEMORY_LIMIT_FILES = (
    "/sys/fs/cgroup/memory.max",
    "/sys/fs/cgroup/memory/memory.limit_in_bytes",
)
# Values at or above this are the kernel's way of saying "no limit".
_UNLIMITED_THRESHOLD_BYTES = 1 << 60

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("shop-api")


def _env_number(name: str, default: float, minimum: float) -> float:
    """Read a numeric environment variable and validate its lower bound."""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {raw!r}") from exc
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}")
    return value


def _env_bool(name: str, default: bool = False) -> bool:
    """Read a boolean environment variable (true/false/1/0/yes/no)."""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"{name} must be a boolean, got {raw!r}")


def detect_memory_limit_bytes(
    paths: tuple[str, ...] = CGROUP_MEMORY_LIMIT_FILES,
) -> Optional[int]:
    """Return the container memory limit in bytes, or None if there is none."""
    for path in paths:
        try:
            raw = Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if raw == "max":
            return None
        try:
            value = int(raw)
        except ValueError:
            continue
        if value >= _UNLIMITED_THRESHOLD_BYTES:
            return None
        return value
    return None


class MemoryHog:
    """Allocate memory in steps from a background thread (used by v4 only)."""

    def __init__(
        self,
        step_mb: int,
        interval_seconds: float,
        max_mb: int,
        allow_unbounded: bool = False,
        limit_bytes: Optional[int] = None,
    ) -> None:
        self.step_mb = step_mb
        self.interval_seconds = interval_seconds
        self.max_mb = max_mb
        self.allow_unbounded = allow_unbounded
        self.limit_bytes = limit_bytes
        self.refused_reason: Optional[str] = None
        self._chunks: List[bytearray] = []
        self._allocated_mb = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def allocated_mb(self) -> int:
        """Megabytes allocated so far."""
        return self._allocated_mb

    def start(self) -> bool:
        """Start allocating. Returns False if the safety guard refuses to run."""
        if self.limit_bytes is None and not self.allow_unbounded:
            self.refused_reason = (
                "no container memory limit detected; refusing to allocate memory "
                "(set ALLOW_UNBOUNDED_MEMORY=true only for a throwaway test)"
            )
            logger.error("Memory allocation disabled: %s", self.refused_reason)
            return False
        limit_text = (
            f"{self.limit_bytes // (1024 * 1024)} MiB"
            if self.limit_bytes is not None
            else "none"
        )
        logger.warning(
            "Memory exhaustion demo active: +%d MB every %.1fs (ceiling %d MB, "
            "container limit %s)",
            self.step_mb,
            self.interval_seconds,
            self.max_mb,
            limit_text,
        )
        self._thread = threading.Thread(
            target=self._run, name="memory-hog", daemon=True
        )
        self._thread.start()
        return True

    def _run(self) -> None:
        """Allocate one chunk per interval until the ceiling or stop request."""
        while not self._stop.is_set():
            if self._allocated_mb + self.step_mb > self.max_mb:
                logger.warning(
                    "Reached MEM_MAX_MB ceiling (%d MB); allocation stopped",
                    self.max_mb,
                )
                return
            # Multiplying a one-byte bytearray writes every byte, so the pages
            # are really committed and count against the cgroup limit.
            self._chunks.append(bytearray(b"\xaa") * (self.step_mb * 1024 * 1024))
            self._allocated_mb += self.step_mb
            logger.info("Allocated %d MB so far", self._allocated_mb)
            self._stop.wait(self.interval_seconds)

    def stop(self) -> None:
        """Stop the allocator thread and release memory."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._chunks.clear()
        self._allocated_mb = 0


def create_app(version: Optional[str] = None) -> FastAPI:
    """Build the FastAPI application for the given version (default: env)."""
    selected = (version or os.environ.get("APP_VERSION", "v1")).strip().lower()
    if selected not in SUPPORTED_VERSIONS:
        raise ValueError(
            f"Unsupported APP_VERSION {selected!r}; expected one of {SUPPORTED_VERSIONS}"
        )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        hog: Optional[MemoryHog] = None
        if selected == "v2":
            # Deterministic startup failure: the Deployment never sets DB_URL.
            if not os.environ.get("DB_URL"):
                logger.critical(
                    "Startup failed: required environment variable DB_URL is not set"
                )
                raise Exception("DB_URL missing")
        if selected == "v4":
            hog = MemoryHog(
                step_mb=int(_env_number("MEM_STEP_MB", 10, 1)),
                interval_seconds=_env_number("MEM_INTERVAL_SECONDS", 1.0, 0.05),
                max_mb=int(_env_number("MEM_MAX_MB", 512, 1)),
                allow_unbounded=_env_bool("ALLOW_UNBOUNDED_MEMORY", False),
                limit_bytes=detect_memory_limit_bytes(),
            )
            hog.start()
        app.state.hog = hog
        logger.info("shop-api %s started on %s", selected, socket.gethostname())
        try:
            yield
        finally:
            if hog is not None:
                hog.stop()

    app = FastAPI(title="shop-api", version=selected, lifespan=lifespan)
    app.state.version = selected
    app.state.hog = None

    @app.get("/")
    async def root() -> dict:
        """Landing endpoint; always answers 200 once the app is running."""
        return {
            "service": "shop-api",
            "version": selected,
            "status": "ok",
            "hostname": socket.gethostname(),
        }

    @app.get("/health")
    async def health() -> JSONResponse:
        """Readiness endpoint; v3 deliberately fails with HTTP 500."""
        if selected == "v3":
            logger.error("Health check failing on purpose (v3 demo fault)")
            return JSONResponse(
                status_code=500,
                content={"status": "unhealthy", "version": selected},
            )
        body: dict = {"status": "healthy", "version": selected}
        hog: Optional[MemoryHog] = app.state.hog
        if hog is not None:
            body["allocated_mb"] = hog.allocated_mb
            body["allocation_enabled"] = hog.refused_reason is None
        return JSONResponse(status_code=200, content=body)

    return app


app = create_app()
