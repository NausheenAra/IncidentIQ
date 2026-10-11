"""Stage 8: the end-to-end runner's decision logic, against a scripted fake backend.

No cluster is involved: the scripts (deploy_good / deploy_bad) are replaced by a fake runner and
the IncidentIQ API by a tiny HTTP server that walks an incident through the lifecycle. This proves
the runner passes good runs and, more importantly, FAILS on bad ones. It does not prove that a real
cluster behaves; that is what running scripts/e2e.py against kind is for.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("e2e", Path(__file__).resolve().parent.parent / "scripts" / "e2e.py")
e2e = importlib.util.module_from_spec(SPEC)
sys.modules["e2e"] = e2e  # dataclasses needs the module registered
SPEC.loader.exec_module(e2e)

GOOD_EVIDENCE = {"logs": [{"pod": "p", "container": "c", "source": "previous", "lines": ["boom"], "error": None}], "events": [],
                 "pods": [{"name": "p"}], "last_deploy_time": None, "rollout_history": []}
GOOD_RCA = {"probable_cause": "missing DB_URL", "evidence": ["boom"], "confidence": 0.9, "recommended_action": "rollback", "source": "llm"}


class FakeBackend:
    """Scripted incident lifecycle. ``mode`` selects the behaviour under test."""

    def __init__(self, mode="happy"):
        self.mode = mode
        self.incidents = []
        self.api_key = "good-key"
        self.approve_calls = 0
        self.kube_state = "connected"
        self.detector_running = True

    def inject(self, count=1):
        if self.mode == "never_detected":
            return
        for _ in range(count):
            nid = len(self.incidents) + 1
            self.incidents.append({"id": nid, "service": "shop-api", "namespace": "default", "reason": "CrashLoopBackOff",
                                   "status": "DETECTED", "ticks": 0, "approved": False})
            if self.mode == "duplicate" and count == 1:
                self.inject(count=1) if len(self.incidents) < 2 else None

    def view(self, inc, detail=False):
        self._advance(inc)
        status = inc["status"]
        body = {"id": inc["id"], "service": inc["service"], "namespace": inc["namespace"], "reason": inc["reason"], "status": status,
                "mttd_seconds": None if self.mode == "no_mttd" else 4.2, "mttr_seconds": 30.0 if status == "RESOLVED" else None}
        if detail:
            steps = ["DETECTED"]
            if status != "DETECTED":
                steps.append("ANALYZING")
            if inc["approved"] or self.mode == "auto":
                steps += ["REMEDIATING", "VERIFYING"]
            if status in ("RESOLVED", "FAILED"):
                steps.append(status)
            body["timeline"] = [{"step": s, "message": f"{s.lower()} message", "timestamp": "2026-10-10T00:00:00+00:00"} for s in steps]
            analysed = status != "DETECTED"
            rca = dict(GOOD_RCA)
            if self.mode == "bad_rca":
                rca["recommended_action"] = "delete"
            if self.mode == "fallback":
                rca["source"] = "fallback"
            body["evidence"] = GOOD_EVIDENCE if analysed else None
            body["rca"] = rca if analysed else None
        return body

    def _advance(self, inc):
        inc["ticks"] += 1
        status = inc["status"]
        if status == "DETECTED" and inc["ticks"] >= 2:
            inc["status"] = "RESOLVED" if self.mode == "auto" else "AWAITING_APPROVAL"
        elif status == "REMEDIATING" and inc["ticks"] >= 2:
            inc["status"] = "FAILED" if self.mode == "ends_failed" else "RESOLVED"
        if inc["status"] == "AWAITING_APPROVAL" and inc["approved"]:
            inc["status"] = "REMEDIATING"
            inc["ticks"] = 0


@pytest.fixture()
def server():
    fake = FakeBackend()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # silence
            pass

        def _send(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/healthz":
                return self._send(200, {"status": "ok", "detector_running": fake.detector_running})
            if self.path == "/api/status":
                return self._send(200, {"namespaces": ["default"], "kubernetes": {"state": fake.kube_state}})
            if self.path == "/api/incidents":
                return self._send(200, [fake.view(i) for i in reversed(fake.incidents)])
            if self.path.startswith("/api/incidents/"):
                inc = fake.incidents[int(self.path.rsplit("/", 1)[1]) - 1]
                return self._send(200, fake.view(inc, detail=True))
            self._send(404, {"detail": "nope"})

        def do_POST(self):
            fake.approve_calls += 1
            if self.headers.get("X-API-Key") != fake.api_key:
                return self._send(401, {"detail": "Missing or invalid API key"})
            inc = fake.incidents[int(self.path.split("/")[3]) - 1]
            if inc["status"] != "AWAITING_APPROVAL":
                return self._send(409, {"detail": "not awaiting approval"})
            inc["approved"] = True
            self._send(202, {"id": inc["id"], "status": "REMEDIATING"})

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    fake.url = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield fake
    httpd.shutdown()
    httpd.server_close()


def make_runner(fake, calls, *, good_rc=0, bad_rc=0):
    def runner(args, env):
        calls.append(list(args))
        if args[0].endswith("deploy_bad.sh"):
            assert env["BACKEND_URL"] == fake.url
            if bad_rc == 0:
                fake.inject()
            return bad_rc
        return good_rc
    return runner


def run(fake, mode="happy", key="good-key", scenario="v2", **options):
    fake.mode = mode
    calls: list = []
    runner = options.pop("runner", None) or make_runner(fake, calls)
    options.setdefault("detect_timeout", 2.0)
    options.setdefault("resolve_timeout", 2.0)
    result = e2e.run_scenario(e2e.Backend(fake.url, key), scenario, runner, poll_interval=0.01, cooldown_wait=0, log=lambda m: None, **options)
    return result, calls


def test_happy_path_passes_and_restores_v1(server):
    result, calls = run(server)
    assert result.passed, result.failures
    assert result.status == "RESOLVED" and result.incident_id == 1
    assert result.mttd_seconds == 4.2 and result.mttr_seconds == 30.0
    assert server.approve_calls == 1
    assert [c[0] for c in calls] == ["scripts/deploy_good.sh", "scripts/deploy_bad.sh", "scripts/deploy_good.sh"]
    assert calls[1] == ["scripts/deploy_bad.sh", "v2"]


def test_auto_remediate_needs_no_approval(server):
    result, _ = run(server, mode="auto")
    assert result.status == "RESOLVED" and server.approve_calls == 0
    # the fake's timeline for auto mode contains REMEDIATING/VERIFYING, so this passes
    assert result.passed, result.failures


def test_wrong_api_key_fails_and_leaves_bad_version_for_the_dashboard(server):
    result, calls = run(server, key="wrong")
    assert not result.passed
    assert any("HTTP 401" in f for f in result.failures)
    assert result.status == "AWAITING_APPROVAL"
    assert [c[0] for c in calls].count("scripts/deploy_good.sh") == 1, "must not restore while the incident is still open"
    assert any("still AWAITING_APPROVAL" in w for w in result.warnings)


def test_no_approve_stops_at_the_gate_without_remediating(server):
    result, calls = run(server, approve=False)
    assert result.passed and result.status == "AWAITING_APPROVAL"
    assert server.approve_calls == 0
    assert [c[0] for c in calls].count("scripts/deploy_good.sh") == 1
    assert any("--no-approve" in w for w in result.warnings)


def test_incident_that_ends_failed_is_a_failure_with_the_reason(server):
    result, calls = run(server, mode="ends_failed")
    assert not result.passed and result.status == "FAILED"
    assert any("ended FAILED" in f for f in result.failures)
    assert [c[0] for c in calls][-1] == "scripts/deploy_good.sh", "cluster is still restored after a failure"


def test_no_incident_within_the_timeout_fails(server):
    result, _ = run(server, mode="never_detected", detect_timeout=0.3)
    assert not result.passed and result.incident_id is None
    assert any("no incident was created" in f for f in result.failures)


def test_invalid_rca_action_is_reported(server):
    result, _ = run(server, mode="bad_rca")
    assert not result.passed
    assert any("not allowed" in f for f in result.failures)


def test_missing_mttd_is_a_failure_not_a_zero(server):
    result, _ = run(server, mode="no_mttd")
    assert not result.passed
    assert any("MTTD is missing" in f for f in result.failures)
    assert result.mttd_seconds is None


def test_fallback_diagnosis_passes_with_a_note(server):
    result, _ = run(server, mode="fallback")
    assert result.passed
    assert any("deterministic fallback" in w for w in result.warnings)


def test_duplicate_incidents_for_one_failure_are_flagged(server):
    server.mode = "duplicate"
    calls: list = []

    def runner(args, env):
        calls.append(args[0])
        if args[0].endswith("deploy_bad.sh"):
            server.inject()
            server.incidents.append(dict(server.incidents[0], id=2))
        return 0

    result, _ = run(server, mode="duplicate", runner=runner)
    assert not result.passed
    assert any("exactly one incident" in f for f in result.failures)


def test_bad_baseline_aborts_before_injecting(server):
    calls: list = []
    result, _ = run(server, runner=make_runner(server, calls, good_rc=1))
    assert not result.passed
    assert all(c[0] != "scripts/deploy_bad.sh" for c in calls), "never inject on top of an unhealthy baseline"


def test_failed_injection_script_fails_the_scenario(server):
    calls: list = []
    result, _ = run(server, runner=make_runner(server, calls, bad_rc=1))
    assert not result.passed and any("deploy_bad.sh" in f for f in result.failures)


def test_open_incident_blocks_a_new_run(server):
    server.inject()
    result, calls = run(server, runner=lambda a, e: 0)
    assert not result.passed and any("still open" in f for f in result.failures)


def test_unreachable_backend_is_a_clean_failure():
    backend = e2e.Backend("http://127.0.0.1:1", "k", timeout=0.5)
    result = e2e.run_scenario(backend, "v2", lambda a, e: 0, poll_interval=0.01, log=lambda m: None)
    assert not result.passed and "cannot reach" in result.failures[0]


def test_preflight(server):
    backend = e2e.Backend(server.url, "k")
    assert e2e.preflight(backend) == []
    server.kube_state = "forbidden"
    assert any("forbidden" in p for p in e2e.preflight(backend))
    server.kube_state, server.detector_running = "connected", False
    assert any("detector" in p for p in e2e.preflight(backend))
    assert e2e.preflight(e2e.Backend("http://127.0.0.1:1", "k", timeout=0.5))


def test_read_api_key_prefers_environment_then_dotenv(tmp_path):
    dotenv = tmp_path / ".env"
    dotenv.write_text('X=1\r\nAPI_KEY="from-file"\r\n', encoding="utf-8")
    assert e2e.read_api_key({"INCIDENTIQ_API_KEY": "env-key"}, dotenv) == "env-key"
    assert e2e.read_api_key({"API_KEY": "env2"}, dotenv) == "env2"
    assert e2e.read_api_key({}, dotenv) == "from-file"
    assert e2e.read_api_key({}, tmp_path / "missing") == ""


def test_report_marks_failures(capsys):
    ok = e2e.ScenarioResult("v2", 1, "RESOLVED", "CrashLoopBackOff", "llm", "rollback", 4.2, 30.0)
    bad = e2e.ScenarioResult("v3", 2, "FAILED", failures=["incident ended FAILED"])
    e2e.print_report([ok, bad])
    out = capsys.readouterr().out
    assert "PASS" in out and "FAIL" in out and "1/2 scenarios passed" in out
    assert "incident ended FAILED" in out and "4.2s" in out
