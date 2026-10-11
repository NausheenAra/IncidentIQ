"""IncidentIQ HTTP API, dashboard hosting and detector lifecycle.

Run locally (single worker: the detector loop lives in this process)::

    python -m uvicorn backend.api:app --host 127.0.0.1 --port 8000
    # or, honouring API_HOST / API_PORT from .env:
    python -m backend.api

Endpoints (see docs/contracts.md):

    GET  /api/incidents                  incident summaries, newest first
    GET  /api/incidents/{id}             incident with evidence, RCA and timeline (404 if missing)
    GET  /api/metrics                    total, resolved, avg_mttd_seconds, avg_mttr_seconds
    GET  /api/status                     detector, Kubernetes and safety-mode snapshot (for the dashboard)
    POST /api/incidents/{id}/approve     [API key] approve the recommended action
    POST /api/injection                  [API key] record the failure-injection time
    GET  /healthz                        liveness probe
    GET  /                               dashboard
    GET  /incidents/{id}                 incident detail page
    GET  /static/*                       dashboard assets (dashboard/ directory)

Protected endpoints require the ``X-API-Key`` header. The key is compared in
constant time and is never logged or echoed in an error response.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi import Path as PathParam
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from kubernetes.client.exceptions import ApiException
from pydantic import BaseModel, Field

from backend import config, db, kube, pipeline

logger = logging.getLogger(__name__)

DEFAULT_DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"

#: SQLite INTEGER is 64-bit signed; larger path ids would raise inside sqlite3.
MAX_INCIDENT_ID = 2**63 - 1

#: Content-Security-Policy for the dashboard pages: same-origin scripts/styles only.
DASHBOARD_CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)

KUBERNETES_PROBE_TTL_SECONDS = 10.0
KUBERNETES_PROBE_TIMEOUT_SECONDS = 3

_K8S_NAME_PATTERN = r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$"
_NAMESPACE_PATTERN = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"

IncidentId = PathParam(..., ge=1, le=MAX_INCIDENT_ID, description="Incident id")


# ---------------------------------------------------------------------------
# Request models and authentication
# ---------------------------------------------------------------------------


class InjectionRequest(BaseModel):
    """Body of ``POST /api/injection`` (the exact shape ``deploy_bad.sh`` sends)."""

    service: str = Field(min_length=1, max_length=253, pattern=_K8S_NAME_PATTERN)
    namespace: str = Field(min_length=1, max_length=63, pattern=_NAMESPACE_PATTERN)


def require_api_key(
    request: Request,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> None:
    """FastAPI dependency: reject requests without the configured API key."""
    expected = config.get_settings().api_key
    provided = x_api_key or ""
    if not provided or not secrets.compare_digest(provided.encode("utf-8"), expected.encode("utf-8")):
        client = request.client.host if request.client else "unknown"
        logger.warning("Rejected %s %s from %s: missing or invalid API key", request.method, request.url.path, client)
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )


# ---------------------------------------------------------------------------
# Kubernetes reachability probe (cached, for the dashboard status card)
# ---------------------------------------------------------------------------


class KubernetesProbe:
    """Cheap, cached check that the Kubernetes API answers for an allow-listed namespace."""

    def __init__(self, ttl_seconds: float = KUBERNETES_PROBE_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._cached: Optional[Dict[str, Any]] = None
        self._cached_at = 0.0

    def get(self) -> Dict[str, Any]:
        """Return ``{"state", "checked_at"}``; state is connected / not_configured / forbidden / unreachable / error."""
        with self._lock:
            if self._cached is not None and time.monotonic() - self._cached_at < self._ttl:
                return dict(self._cached)
            self._cached = self._probe()
            self._cached_at = time.monotonic()
            return dict(self._cached)

    @staticmethod
    def _probe() -> Dict[str, Any]:
        namespace = config.get_settings().namespace_allowlist[0]
        try:
            kube.core_v1().list_namespaced_pod(namespace, limit=1, _request_timeout=KUBERNETES_PROBE_TIMEOUT_SECONDS)
            state = "connected"
        except kube.KubeConfigError:
            state = "not_configured"
        except ApiException as exc:
            state = "forbidden" if exc.status in (401, 403) else "error"
        except Exception:  # noqa: BLE001 - connection refused, timeout, DNS ...
            logger.debug("Kubernetes probe failed", exc_info=True)
            state = "unreachable"
        return {"state": state, "checked_at": db.utc_now_iso()}


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app(
    start_detector: bool = True,
    dashboard_dir: Optional[Path] = None,
    configure_logging: bool = True,
) -> FastAPI:
    """Build the FastAPI application.

    Args:
        start_detector: start the cluster polling loop at startup (tests pass False).
        dashboard_dir: directory holding ``index.html``, ``incident.html`` and assets.
        configure_logging: install IncidentIQ's secret-redacting log handler at startup.
    """
    settings = config.get_settings()
    dash_dir = Path(dashboard_dir) if dashboard_dir is not None else DEFAULT_DASHBOARD_DIR
    loop = pipeline.DetectorLoop()
    probe = KubernetesProbe()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        current = config.get_settings()
        if configure_logging:
            config.setup_logging(current)
        db.init_db()
        recovered = pipeline.recover_interrupted_incidents()
        if recovered:
            logger.warning("Recovered %d interrupted incident(s) at startup", recovered)
        if current.api_key_generated:
            logger.warning("Running with a temporary API key: approvals and injections need the key from .env")
        if start_detector:
            loop.start()
        else:
            logger.warning("Detector loop is disabled for this process")
        try:
            yield
        finally:
            loop.stop()
            if not pipeline.join_workers():
                logger.warning("Some incident workers were still running at shutdown")

    application = FastAPI(
        title=f"{settings.app_name} API",
        version="1.0",
        lifespan=lifespan,
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/openapi.json",
    )
    application.state.detector = loop
    application.state.kubernetes_probe = probe

    # -- error handling -----------------------------------------------------

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
        # Report only where and why; never echo the submitted values back.
        problems = [{"loc": list(err.get("loc", [])), "msg": err.get("msg", "invalid")} for err in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": problems})

    @application.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error("Unhandled error on %s %s", request.method, request.url.path, exc_info=exc)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    @application.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    # -- read-only API ------------------------------------------------------

    @application.get("/healthz")
    def healthz() -> Dict[str, Any]:
        return {"status": "ok", "detector_running": loop.running}

    @application.get("/api/incidents")
    def list_incidents() -> Any:
        return db.list_incidents()

    @application.get("/api/incidents/{incident_id}")
    def get_incident(incident_id: int = IncidentId) -> Any:
        incident = db.get_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
        return incident

    @application.get("/api/metrics")
    def get_metrics() -> Any:
        return db.get_metrics()

    @application.get("/api/status")
    def get_status() -> Dict[str, Any]:
        current = config.get_settings()
        return {
            "app": current.app_name,
            "environment": current.app_env,
            "auto_remediate": current.auto_remediate,
            "rollback_mode": current.rollback_mode,
            "max_remediation_attempts": current.max_remediation_attempts,
            "namespaces": list(current.namespace_allowlist),
            "gemini_enabled": current.gemini_enabled,
            "detector": loop.status(),
            "kubernetes": probe.get(),
        }

    # -- protected operations ----------------------------------------------

    @application.post("/api/incidents/{incident_id}/approve", status_code=202, dependencies=[Depends(require_api_key)])
    def approve_incident(incident_id: int = IncidentId) -> Dict[str, Any]:
        try:
            result = pipeline.approve_incident(incident_id)
        except pipeline.ApprovalError as exc:
            status = {"not_found": 404, "conflict": 409}.get(exc.kind, 422)
            raise HTTPException(status_code=status, detail=str(exc)) from exc
        logger.info("Approval accepted for incident %s (action %s)", incident_id, result["action"])
        return result

    @application.post("/api/injection", status_code=201, dependencies=[Depends(require_api_key)])
    def record_injection(body: InjectionRequest) -> Dict[str, Any]:
        if not config.get_settings().is_namespace_allowed(body.namespace):
            raise HTTPException(status_code=403, detail=f"Namespace {body.namespace!r} is not in the allow-list")
        injected_at = db.record_injection(body.service, body.namespace)
        return {"service": body.service, "namespace": body.namespace, "injected_at": injected_at}

    # -- dashboard ----------------------------------------------------------

    def html_page(filename: str) -> Response:
        path = dash_dir / filename
        if not path.is_file():
            return JSONResponse(
                status_code=404,
                content={"detail": f"Dashboard file {filename} not found in {dash_dir.name}/ (built in Stage 6)"},
            )
        return FileResponse(path, media_type="text/html", headers={"Content-Security-Policy": DASHBOARD_CSP})

    @application.get("/", include_in_schema=False)
    def dashboard_index() -> Response:
        return html_page("index.html")

    @application.get("/incidents/{incident_id}", include_in_schema=False)
    def dashboard_incident(incident_id: int = IncidentId) -> Response:
        return html_page("incident.html")

    if dash_dir.is_dir():
        application.mount("/static", StaticFiles(directory=str(dash_dir)), name="static")

    return application


app = create_app()


def main() -> None:
    """Serve the API using the host and port from the configuration."""
    import uvicorn

    current = config.get_settings()
    uvicorn.run(app, host=current.api_host, port=current.api_port, log_level=current.log_level.lower())


if __name__ == "__main__":
    main()
