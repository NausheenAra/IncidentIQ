"""RCA tests. Gemini is always mocked: no API key, network or cost is involved."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from backend import config, rca

TRACE = "Exception: DB_URL missing"
CRITICAL = "2026-10-09 10:00:00 CRITICAL shop-api: Startup failed: required environment variable DB_URL is not set"
GEMINI_KEY = "AIza-test-gemini-key-123456"


def iso(minutes_ago):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat(timespec="seconds")


def make_evidence(last_deploy=None):
    return {
        "logs": [{"pod": "p1", "container": "shop-api", "source": "previous",
                  "lines": ["Traceback (most recent call last):", CRITICAL, TRACE], "error": None}],
        "events": [{"type": "Warning", "reason": "BackOff", "message": "Back-off restarting failed container",
                    "involved_object": "Pod/p1", "count": 3, "timestamp": iso(1)}],
        "pods": [{"name": "p1", "phase": "Running", "ready": False, "containers": [
            {"name": "shop-api", "image": "shop-api:v2", "waiting_reason": "CrashLoopBackOff",
             "terminated_reason": None, "last_termination_reason": "Error", "restart_count": 4}]}],
        "last_deploy_time": last_deploy,
        "rollout_history": [],
    }


def good_reply(**overrides):
    data = {"probable_cause": "The v2 release crashes at startup because DB_URL is not set.",
            "evidence": [TRACE], "confidence": 0.93, "recommended_action": "rollback"}
    data.update(overrides)
    return json.dumps(data)


@pytest.fixture()
def gemini(monkeypatch):
    """Enable Gemini and let each test choose the raw reply (or an exception)."""
    monkeypatch.setenv("GEMINI_API_KEY", GEMINI_KEY)
    config.reset_settings()
    state = SimpleNamespace(reply=good_reply(), prompts=[])

    def fake_call(prompt, settings):
        state.prompts.append(prompt)
        if isinstance(state.reply, Exception):
            raise state.reply
        return state.reply

    monkeypatch.setattr(rca, "_call_gemini", fake_call)
    return state


# --------------------------------------------------------------------------
# LLM path
# --------------------------------------------------------------------------


def test_valid_llm_response(gemini):
    result = rca.analyze(make_evidence(iso(2)))
    assert result == {
        "probable_cause": "The v2 release crashes at startup because DB_URL is not set.",
        "evidence": [TRACE], "confidence": 0.93, "recommended_action": "rollback", "source": "llm",
    }


def test_markdown_fenced_json_is_accepted(gemini):
    gemini.reply = "Here you go:\n```json\n" + good_reply() + "\n```\nHope that helps"
    assert rca.analyze(make_evidence())["source"] == "llm"


def test_plain_fence_without_language_is_accepted(gemini):
    gemini.reply = "```\n" + good_reply() + "\n```"
    assert rca.analyze(make_evidence())["source"] == "llm"


@pytest.mark.parametrize("action", ["rollback", "restart", "scale"])
def test_all_allowed_actions_pass(gemini, action):
    gemini.reply = good_reply(recommended_action=action)
    assert rca.analyze(make_evidence())["recommended_action"] == action


def test_confidence_boundaries_accepted(gemini):
    for value in (0, 1, 0.0, 1.0):
        gemini.reply = good_reply(confidence=value)
        assert rca.analyze(make_evidence())["source"] == "llm"


def test_extra_keys_from_model_are_dropped(gemini):
    gemini.reply = good_reply(run_command="kubectl delete ns default")
    result = rca.analyze(make_evidence())
    assert "run_command" not in result
    assert set(result) == {"probable_cause", "evidence", "confidence", "recommended_action", "source"}


def test_empty_evidence_list_is_valid(gemini):
    gemini.reply = good_reply(evidence=[])
    result = rca.analyze(make_evidence())
    assert result["source"] == "llm" and result["evidence"] == []


# --------------------------------------------------------------------------
# Rejections -> fallback
# --------------------------------------------------------------------------


def test_missing_gemini_key_uses_fallback_without_calling_gemini(monkeypatch):
    called = []
    monkeypatch.setattr(rca, "_call_gemini", lambda *a: called.append(1))
    result = rca.analyze(make_evidence(iso(2)))
    assert result["source"] == "fallback" and not called
    assert "not configured" in result["probable_cause"]


@pytest.mark.parametrize("reply", ["this is not json", "", "   ", "[1, 2, 3]", '"just a string"', "{broken"])
def test_invalid_json_uses_fallback(gemini, reply):
    gemini.reply = reply
    assert rca.analyze(make_evidence(iso(2)))["source"] == "fallback"


@pytest.mark.parametrize("action", ["delete", "Rollback", "ROLLBACK", " rollback", "rollback; rm -rf /", "", None, 5])
def test_unsupported_action_uses_fallback(gemini, action):
    gemini.reply = good_reply(recommended_action=action)
    result = rca.analyze(make_evidence(iso(2)))
    assert result["source"] == "fallback"
    assert result["recommended_action"] in rca.ALLOWED_ACTIONS


@pytest.mark.parametrize("confidence", [-0.1, 1.01, 5, "0.9", None, True, float("nan")])
def test_invalid_confidence_uses_fallback(gemini, confidence):
    gemini.reply = good_reply(confidence=confidence) if confidence == confidence else (
        '{"probable_cause": "x", "evidence": [], "confidence": NaN, "recommended_action": "restart"}'
    )
    assert rca.analyze(make_evidence())["source"] == "fallback"


@pytest.mark.parametrize("field,value", [
    ("probable_cause", ""), ("probable_cause", 42), ("probable_cause", None),
    ("evidence", "DB_URL missing"), ("evidence", [1, 2]), ("evidence", None),
])
def test_other_field_type_errors_use_fallback(gemini, field, value):
    gemini.reply = good_reply(**{field: value})
    assert rca.analyze(make_evidence())["source"] == "fallback"


def test_missing_keys_use_fallback(gemini):
    gemini.reply = json.dumps({"probable_cause": "x"})
    assert rca.analyze(make_evidence())["source"] == "fallback"


def test_invented_evidence_is_rejected(gemini):
    gemini.reply = good_reply(evidence=["FATAL: out of disk space on /dev/sda1"])
    assert rca.analyze(make_evidence())["source"] == "fallback"


def test_partially_invented_evidence_keeps_only_real_lines(gemini):
    gemini.reply = good_reply(evidence=[TRACE, "totally made up line"])
    result = rca.analyze(make_evidence())
    assert result["source"] == "llm" and result["evidence"] == [TRACE]


def test_evidence_quoting_is_tolerant_of_quotes_case_and_spacing(gemini):
    gemini.reply = good_reply(evidence=[f'  "{TRACE.lower()}"  '])
    result = rca.analyze(make_evidence())
    assert result["source"] == "llm" and result["evidence"] == [TRACE.lower()]


def test_api_exception_uses_fallback(gemini):
    gemini.reply = ConnectionError("network down")
    result = rca.analyze(make_evidence(iso(2)))
    assert result["source"] == "fallback" and "ConnectionError" in result["probable_cause"]


def test_api_key_never_appears_in_fallback_text(gemini):
    gemini.reply = RuntimeError(f"401 invalid key {GEMINI_KEY}")
    result = rca.analyze(make_evidence())
    assert GEMINI_KEY not in json.dumps(result) and "***" in result["probable_cause"]


def test_analyze_never_raises_on_garbage_evidence(gemini):
    for bad in (None, "text", 5, [], {"logs": "nope", "pods": 7, "events": None}):
        assert rca.analyze(bad)["source"] in ("llm", "fallback")


# --------------------------------------------------------------------------
# Deterministic fallback rule
# --------------------------------------------------------------------------


def test_recent_deployment_recommends_rollback():
    result = rca.fallback_analysis(make_evidence(iso(3)), "test")
    assert result["recommended_action"] == "rollback" and result["source"] == "fallback"


def test_deployment_just_outside_window_recommends_restart():
    assert rca.fallback_analysis(make_evidence(iso(11)), "test")["recommended_action"] == "restart"


def test_old_deployment_recommends_restart():
    assert rca.fallback_analysis(make_evidence(iso(120)), "test")["recommended_action"] == "restart"


@pytest.mark.parametrize("value", [None, "", "not a date", 12345])
def test_missing_or_bad_deploy_time_recommends_restart(value):
    assert rca.fallback_analysis(make_evidence(value), "test")["recommended_action"] == "restart"


def test_window_boundary_is_ten_minutes():
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    inside = (now - timedelta(seconds=599)).isoformat()
    outside = (now - timedelta(seconds=601)).isoformat()
    assert rca.fallback_analysis(make_evidence(inside), "t", now=now)["recommended_action"] == "rollback"
    assert rca.fallback_analysis(make_evidence(outside), "t", now=now)["recommended_action"] == "restart"


def test_z_suffix_and_naive_timestamps_are_understood():
    z = (datetime.now(timezone.utc) - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    naive = (datetime.now(timezone.utc) - timedelta(minutes=2)).replace(tzinfo=None).isoformat()
    assert rca.fallback_analysis(make_evidence(z), "t")["recommended_action"] == "rollback"
    assert rca.fallback_analysis(make_evidence(naive), "t")["recommended_action"] == "rollback"


def test_far_future_deploy_time_is_not_trusted():
    future = (datetime.now(timezone.utc) + timedelta(hours=5)).isoformat()
    assert rca.fallback_analysis(make_evidence(future), "t")["recommended_action"] == "restart"


def test_fallback_evidence_is_verbatim_from_logs_never_invented():
    result = rca.fallback_analysis(make_evidence(iso(1)), "test")
    all_lines = make_evidence()["logs"][0]["lines"]
    assert result["evidence"] and all(line in all_lines for line in result["evidence"])
    assert rca.fallback_analysis({"logs": []}, "test")["evidence"] == []


def test_fallback_mentions_observed_symptoms_and_has_valid_shape():
    result = rca.fallback_analysis(make_evidence(iso(1)), "test")
    assert "CrashLoopBackOff" in result["probable_cause"]
    assert 0 <= result["confidence"] <= 1
    assert set(result) == {"probable_cause", "evidence", "confidence", "recommended_action", "source"}


def test_fallback_after_llm_rejection_follows_the_same_rule(gemini):
    gemini.reply = "garbage"
    assert rca.analyze(make_evidence(iso(2)))["recommended_action"] == "rollback"
    assert rca.analyze(make_evidence(iso(90)))["recommended_action"] == "restart"
    assert rca.analyze(make_evidence(None))["recommended_action"] == "restart"


# --------------------------------------------------------------------------
# Prompt and SDK request
# --------------------------------------------------------------------------


EXACT_INSTRUCTION = (
    "You are an SRE. Use ONLY the evidence below. Return only JSON with keys: probable_cause, "
    "evidence (list of quoted log lines), confidence (0-1), recommended_action (one of rollback, restart, scale)."
)


def test_prompt_begins_with_exact_instruction_followed_by_evidence_json():
    evidence = make_evidence(iso(1))
    prompt = rca.build_prompt(evidence)
    assert prompt.startswith(EXACT_INSTRUCTION)
    payload = prompt[len(EXACT_INSTRUCTION):].split("EVIDENCE (JSON):\n", 1)[1]
    assert json.loads(payload) == evidence


def test_prompt_is_sent_to_gemini_and_contains_no_api_key(gemini):
    rca.analyze(make_evidence())
    assert gemini.prompts[0].startswith(EXACT_INSTRUCTION)
    assert GEMINI_KEY not in gemini.prompts[0]


def test_huge_evidence_is_shrunk_but_keeps_recent_lines():
    evidence = make_evidence()
    evidence["logs"][0]["lines"] = [f"line {i} " + "x" * 400 for i in range(50)]
    text = rca._evidence_text(evidence)
    assert len(text) <= rca.MAX_PROMPT_EVIDENCE_CHARS
    assert "line 49 " in text


def test_sdk_request_uses_configured_model_json_mode_and_timeout(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", GEMINI_KEY)
    monkeypatch.setenv("GEMINI_MODEL", "gemini-test-model")
    monkeypatch.setenv("GEMINI_TIMEOUT_SECONDS", "7")
    config.reset_settings()
    captured = {}

    class FakeModels:
        def generate_content(self, model, contents, config):
            captured.update(model=model, contents=contents, config=config)
            return SimpleNamespace(text=good_reply())

    class FakeClient:
        def __init__(self, api_key=None, http_options=None):
            captured.update(api_key=api_key, http_options=http_options)
            self.models = FakeModels()

    monkeypatch.setattr(rca.genai, "Client", FakeClient)
    result = rca.analyze(make_evidence())
    assert result["source"] == "llm"
    assert captured["model"] == "gemini-test-model"
    assert captured["contents"].startswith(EXACT_INSTRUCTION)
    assert captured["config"].response_mime_type == "application/json"
    assert captured["config"].temperature == 0.0
    assert captured["http_options"].timeout == 7000
    enum = captured["config"].response_schema.properties["recommended_action"].enum
    assert enum == ["rollback", "restart", "scale"]


def test_sdk_returning_no_text_uses_fallback(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", GEMINI_KEY)
    config.reset_settings()

    class FakeClient:
        def __init__(self, **kwargs):
            self.models = SimpleNamespace(generate_content=lambda **kw: SimpleNamespace(text=None))

    monkeypatch.setattr(rca.genai, "Client", FakeClient)
    assert rca.analyze(make_evidence(iso(1)))["source"] == "fallback"
