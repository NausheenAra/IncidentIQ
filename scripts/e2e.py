#!/usr/bin/env python3
"""IncidentIQ end-to-end scenario runner (Stage 8).

Drives the REAL cluster through the same scripts a person would use and checks what the
IncidentIQ API reports, one failure scenario at a time:

    deploy healthy v1 -> inject a bad version -> wait for the incident -> check evidence + AI/fallback
    diagnosis -> approve (unless AUTO_REMEDIATE=true) -> wait for verified recovery -> check MTTD/MTTR

Usage (backend deployed with scripts/deploy_backend.sh, so the dashboard is on :8080):

    python scripts/e2e.py                       # v2, v3 and v4
    python scripts/e2e.py --scenario v2         # only the crash loop
    python scripts/e2e.py --no-approve          # stop at AWAITING_APPROVAL (checks the gate)
    python scripts/e2e.py --backend-url http://localhost:8000   # backend run locally with uvicorn

The API key is read from INCIDENTIQ_API_KEY, API_KEY or .env. It is never printed.
Standard library only. Exit status 0 means every scenario passed.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

ROOT = Path(__file__).resolve().parent.parent
SERVICE = "shop-api"
NAMESPACE = "default"
ALLOWED_ACTIONS = ("rollback", "restart", "scale")
TERMINAL = ("RESOLVED", "FAILED")
SETTLED = TERMINAL + ("AWAITING_APPROVAL",)
SCENARIOS = ("v2", "v3", "v4")
#: What the detector is expected to report first. A different reason is a warning, not a failure.
EXPECTED_REASONS = {
    "v2": {"CrashLoopBackOff", "HighRestartCount"},
    "v3": {"NotReady"},
    "v4": {"OOMKilled", "CrashLoopBackOff", "HighRestartCount"},
}
REQUIRED_EVIDENCE_KEYS = ("logs", "events", "pods", "last_deploy_time", "rollout_history")


class E2EError(Exception):
    """The backend could not be reached or answered unexpectedly."""


# --------------------------------------------------------------------------- backend


class Backend:
    """Tiny HTTP client for the IncidentIQ API."""

    def __init__(self, base_url: str, api_key: str, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self.timeout = timeout

    def request(self, method: str, path: str, authenticated: bool = False) -> tuple[int, Any]:
        headers = {"Accept": "application/json"}
        if authenticated:
            headers["X-API-Key"] = self._api_key
        req = urllib.request.Request(self.base_url + path, method=method, headers=headers, data=b"" if method == "POST" else None)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:  # noqa: S310 - fixed http(s) base URL
                return response.status, _decode(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, _decode(exc.read())
        except (urllib.error.URLError, OSError) as exc:
            raise E2EError(f"cannot reach {self.base_url}{path}: {exc}") from exc

    def get(self, path: str) -> Any:
        status, body = self.request("GET", path)
        if status != 200:
            raise E2EError(f"GET {path} returned HTTP {status}: {body}")
        return body

    def approve(self, incident_id: int) -> tuple[int, Any]:
        return self.request("POST", f"/api/incidents/{incident_id}/approve", authenticated=True)


def _decode(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8")) if raw else None
    except (ValueError, UnicodeDecodeError):
        return None


def read_api_key(env: Optional[Dict[str, str]] = None, dotenv: Optional[Path] = None) -> str:
    env = os.environ if env is None else env
    for name in ("INCIDENTIQ_API_KEY", "API_KEY"):
        if env.get(name):
            return env[name]
    path = dotenv if dotenv is not None else ROOT / ".env"
    if path.is_file():
        value = ""
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("API_KEY="):
                value = line.split("=", 1)[1].strip().strip('"').strip("'")
        return value
    return ""


# ---------------------------------------------------------------------------- result


@dataclass
class ScenarioResult:
    scenario: str
    incident_id: Optional[int] = None
    status: str = "-"
    reason: str = "-"
    rca_source: str = "-"
    action: str = "-"
    mttd_seconds: Optional[float] = None
    mttr_seconds: Optional[float] = None
    failures: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.failures


Runner = Callable[[Sequence[str], Dict[str, str]], int]


def subprocess_runner(args: Sequence[str], env: Dict[str, str]) -> int:
    """Run one of the repository's bash scripts, streaming its output."""
    return subprocess.call(["bash", *args], cwd=str(ROOT), env={**os.environ, **env})


# ------------------------------------------------------------------------ validation


def validate_rca(rca: Any) -> List[str]:
    if not isinstance(rca, dict):
        return ["no RCA stored on the incident"]
    problems = []
    if not isinstance(rca.get("probable_cause"), str) or not rca["probable_cause"].strip():
        problems.append("RCA probable_cause is empty")
    confidence = rca.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        problems.append(f"RCA confidence {confidence!r} is not a number in [0, 1]")
    if rca.get("recommended_action") not in ALLOWED_ACTIONS:
        problems.append(f"RCA recommended_action {rca.get('recommended_action')!r} is not allowed")
    if rca.get("source") not in ("llm", "fallback"):
        problems.append(f"RCA source {rca.get('source')!r} is not llm/fallback")
    if not isinstance(rca.get("evidence"), list):
        problems.append("RCA evidence is not a list")
    return problems


def validate_evidence(evidence: Any) -> List[str]:
    if not isinstance(evidence, dict):
        return ["no evidence stored on the incident"]
    problems = [f"evidence is missing key '{key}'" for key in REQUIRED_EVIDENCE_KEYS if key not in evidence]
    if not evidence.get("pods"):
        problems.append("evidence contains no pods")
    return problems


# ------------------------------------------------------------------------- scenario


def wait_until(check: Callable[[], Any], timeout: float, interval: float, clock: Callable[[], float], sleep: Callable[[float], None]) -> Any:
    deadline = clock() + timeout
    while True:
        value = check()
        if value:
            return value
        if clock() >= deadline:
            return None
        sleep(interval)


def run_scenario(
    backend: Backend,
    scenario: str,
    runner: Runner,
    *,
    approve: bool = True,
    detect_timeout: float = 120.0,
    resolve_timeout: float = 240.0,
    poll_interval: float = 3.0,
    cooldown_wait: float = 65.0,
    restore: bool = True,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    log: Callable[[str], None] = print,
) -> ScenarioResult:
    result = ScenarioResult(scenario)
    env = {"BACKEND_URL": backend.base_url}

    def fail(message: str) -> ScenarioResult:
        result.failures.append(message)
        return result

    try:
        existing = backend.get("/api/incidents")
        open_incidents = [i for i in existing if i["status"] not in TERMINAL]
        if open_incidents:
            return fail(f"incident #{open_incidents[0]['id']} is still open ({open_incidents[0]['status']}); resolve or approve it first")
        baseline_id = max((i["id"] for i in existing), default=0)

        log(f"[{scenario}] making sure healthy v1 is deployed")
        if runner(["scripts/deploy_good.sh"], env) != 0:
            return fail("scripts/deploy_good.sh failed; the cluster is not in a healthy baseline state")
        if existing and cooldown_wait > 0:
            log(f"[{scenario}] waiting {cooldown_wait:.0f}s so the incident cooldown from the previous run has passed")
            sleep(cooldown_wait)

        log(f"[{scenario}] injecting the failure (records the injection time, then changes the image)")
        if runner(["scripts/deploy_bad.sh", scenario], env) != 0:
            return fail(f"scripts/deploy_bad.sh {scenario} failed (injection not recorded or expected symptom not seen)")

        def new_incident() -> Optional[dict]:
            fresh = [i for i in backend.get("/api/incidents") if i["id"] > baseline_id and i["service"] == SERVICE]
            return fresh[-1] if fresh else None

        log(f"[{scenario}] waiting up to {detect_timeout:.0f}s for IncidentIQ to detect it")
        found = wait_until(new_incident, detect_timeout, poll_interval, clock, sleep)
        if not found:
            return fail(f"no incident was created within {detect_timeout:.0f}s (check detector, RBAC and kubernetes status)")
        result.incident_id = found["id"]
        result.reason = found["reason"]
        log(f"[{scenario}] incident #{found['id']} detected: {found['reason']}")
        if found["reason"] not in EXPECTED_REASONS[scenario]:
            result.warnings.append(f"detector reported {found['reason']}; expected one of {sorted(EXPECTED_REASONS[scenario])}")

        def detail() -> dict:
            return backend.get(f"/api/incidents/{result.incident_id}")

        current = wait_until(lambda: (lambda d: d if d["status"] in SETTLED else None)(detail()),
                             detect_timeout + 60, poll_interval, clock, sleep)
        if not current:
            return fail("incident did not reach AWAITING_APPROVAL/RESOLVED/FAILED (analysis is stuck)")

        for problem in validate_evidence(current.get("evidence")) + validate_rca(current.get("rca")):
            result.failures.append(problem)
        result.status = current["status"]
        rca = current.get("rca") or {}
        result.rca_source = rca.get("source", "-")
        result.action = rca.get("recommended_action", "-")
        if result.rca_source == "fallback":
            result.warnings.append("diagnosis used the deterministic fallback (no Gemini key, or the model failed)")

        if current["status"] == "AWAITING_APPROVAL":
            log(f"[{scenario}] awaiting approval; recommended action: {result.action}")
            if not approve:
                result.warnings.append("stopped at the approval gate (--no-approve); nothing was remediated")
                return result
            code, body = backend.approve(result.incident_id)
            if code != 202:
                return fail(f"approve returned HTTP {code}: {body}")
            log(f"[{scenario}] approved; waiting up to {resolve_timeout:.0f}s for verified recovery")
        elif current["status"] in TERMINAL:
            log(f"[{scenario}] incident already {current['status']} without approval (AUTO_REMEDIATE is on)")

        final = wait_until(lambda: (lambda d: d if d["status"] in TERMINAL else None)(detail()),
                           resolve_timeout, poll_interval, clock, sleep)
        if not final:
            return fail(f"incident did not finish within {resolve_timeout:.0f}s")

        result.status = final["status"]
        result.mttd_seconds = final.get("mttd_seconds")
        result.mttr_seconds = final.get("mttr_seconds")
        steps = [entry["step"] for entry in final.get("timeline", [])]
        for required in ("DETECTED", "ANALYZING", "REMEDIATING", "VERIFYING", final["status"]):
            if required not in steps:
                result.failures.append(f"timeline has no {required} entry")
        if final["status"] != "RESOLVED":
            last = final["timeline"][-1]["message"] if final.get("timeline") else "no timeline"
            result.failures.append(f"incident ended {final['status']}, not RESOLVED: {last}")
        else:
            if result.mttd_seconds is None:
                result.failures.append("MTTD is missing (was the injection recorded before detection?)")
            if result.mttr_seconds is None:
                result.failures.append("MTTR is missing for a resolved incident")

        duplicates = [i for i in backend.get("/api/incidents") if i["id"] > baseline_id and i["service"] == SERVICE]
        if len(duplicates) != 1:
            result.failures.append(f"expected exactly one incident for this failure, found {len(duplicates)}")
        return result
    except E2EError as exc:
        return fail(str(exc))
    finally:
        if result.status == "AWAITING_APPROVAL":
            # Restoring v1 now would leave this incident open forever (and block every later one).
            result.warnings.append(
                f"incident #{result.incident_id} is still AWAITING_APPROVAL and the bad version is still deployed; "
                "approve it in the dashboard, then run scripts/deploy_good.sh if needed"
            )
        elif restore:
            log(f"[{scenario}] restoring healthy v1")
            if runner(["scripts/deploy_good.sh"], env) != 0:
                result.warnings.append("could not restore v1 afterwards; run scripts/deploy_good.sh")


# --------------------------------------------------------------------------- report


def format_seconds(value: Optional[float]) -> str:
    return "-" if value is None else f"{value:.1f}s"


def print_report(results: Sequence[ScenarioResult], out: Callable[[str], None] = print) -> None:
    out("")
    out(f"{'scenario':<9}{'incident':<10}{'status':<18}{'reason':<18}{'rca':<10}{'action':<10}{'MTTD':<9}{'MTTR':<9}result")
    for r in results:
        out(f"{r.scenario:<9}{('#' + str(r.incident_id)) if r.incident_id else '-':<10}{r.status:<18}{r.reason:<18}"
            f"{r.rca_source:<10}{r.action:<10}{format_seconds(r.mttd_seconds):<9}{format_seconds(r.mttr_seconds):<9}"
            f"{'PASS' if r.passed else 'FAIL'}")
    for r in results:
        for message in r.failures:
            out(f"  FAIL [{r.scenario}] {message}")
        for message in r.warnings:
            out(f"  note [{r.scenario}] {message}")
    passed = sum(1 for r in results if r.passed)
    out(f"\n{passed}/{len(results)} scenarios passed")


def preflight(backend: Backend) -> List[str]:
    """Return a list of blocking problems with the environment (empty means ready)."""
    try:
        health = backend.get("/healthz")
        status = backend.get("/api/status")
    except E2EError as exc:
        return [str(exc), "Is the backend running? scripts/deploy_backend.sh, or uvicorn plus --backend-url."]
    problems = []
    if not health.get("detector_running"):
        problems.append("the detector loop is not running")
    state = (status.get("kubernetes") or {}).get("state")
    if state != "connected":
        problems.append(f"the backend cannot talk to Kubernetes (state: {state})")
    if NAMESPACE not in status.get("namespaces", []):
        problems.append(f"namespace '{NAMESPACE}' is not in the backend's allow-list")
    return problems


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="IncidentIQ end-to-end scenario runner")
    parser.add_argument("--backend-url", default=os.environ.get("BACKEND_URL", "http://localhost:8080"))
    parser.add_argument("--scenario", action="append", choices=SCENARIOS, help="repeatable; default: all of v2 v3 v4")
    parser.add_argument("--no-approve", action="store_true", help="stop each scenario at AWAITING_APPROVAL")
    parser.add_argument("--no-restore", action="store_true", help="leave the bad version deployed afterwards")
    parser.add_argument("--detect-timeout", type=float, default=120.0)
    parser.add_argument("--resolve-timeout", type=float, default=240.0)
    parser.add_argument("--cooldown-wait", type=float, default=65.0, help="seconds between scenarios (INCIDENT_COOLDOWN_SECONDS + margin)")
    args = parser.parse_args(argv)

    key = read_api_key()
    if not key and not args.no_approve:
        print("No API key found (INCIDENTIQ_API_KEY, API_KEY or .env). Approval needs it.", file=sys.stderr)
        return 2
    backend = Backend(args.backend_url, key)
    problems = preflight(backend)
    if problems:
        for problem in problems:
            print(f"preflight: {problem}", file=sys.stderr)
        return 2

    names = args.scenario or list(SCENARIOS)
    if args.no_approve and len(names) > 1:
        # The incident stays open at the gate and would block the next scenario.
        print(f"--no-approve leaves the incident open, so only the first scenario ({names[0]}) is run.")
        names = names[:1]
    results = [
        run_scenario(backend, name, subprocess_runner, approve=not args.no_approve, restore=not args.no_restore,
                     detect_timeout=args.detect_timeout, resolve_timeout=args.resolve_timeout, cooldown_wait=args.cooldown_wait)
        for name in names
    ]
    print_report(results)
    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
