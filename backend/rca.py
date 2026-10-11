"""AI root-cause analysis with strict validation and a deterministic fallback.

``analyze(evidence)`` returns::

    {
      "probable_cause": str,
      "evidence": [str, ...],           # quoted lines taken from the collected evidence
      "confidence": float,              # 0.0 - 1.0
      "recommended_action": "rollback" | "restart" | "scale",
      "source": "llm" | "fallback",
    }

How it works
------------
1. The prompt starts with the exact SRE instruction required by the project spec,
   followed by the collected evidence as JSON.
2. Gemini is asked for structured JSON output (``response_mime_type`` +
   ``response_schema``). Markdown code fences are stripped if the model adds them.
3. The reply is parsed with ``json.loads`` and validated strictly (types, ranges,
   action allow-list). Every quoted evidence line must actually exist in the
   collected evidence; invented lines are rejected so the dashboard never shows
   fabricated "evidence".
4. If ANYTHING fails (no API key, network/API error, bad JSON, validation error)
   the deterministic fallback is used:
       * deployment changed within the last 10 minutes -> ``rollback``
       * otherwise, or if the deploy time is unknown   -> ``restart``

Security
--------
Logs are untrusted text and may contain instructions aimed at the model (prompt
injection). That is why the model's answer is only ever a *recommendation*: it is
limited to three allow-listed words, and ``remediation.execute`` re-validates the
action, namespace, approval and attempt limits before touching the cluster.
Nothing the model writes is ever executed as a command. The API key is never
logged or included in the prompt.
"""

from __future__ import annotations

import json
import logging
import math
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from google import genai
from google.genai import types

from backend import config

logger = logging.getLogger(__name__)

PROMPT_INSTRUCTION = (
    "You are an SRE. Use ONLY the evidence below. Return only JSON with keys: "
    "probable_cause, evidence (list of quoted log lines), confidence (0-1), "
    "recommended_action (one of rollback, restart, scale)."
)

ALLOWED_ACTIONS = ("rollback", "restart", "scale")

#: A deployment change younger than this makes the fallback recommend a rollback.
FALLBACK_RECENT_DEPLOY_SECONDS = 600
FALLBACK_CONFIDENCE_ROLLBACK = 0.4
FALLBACK_CONFIDENCE_RESTART = 0.3

MAX_PROMPT_EVIDENCE_CHARS = 40_000
MAX_EVIDENCE_ITEMS = 10
MAX_PROBABLE_CAUSE_CHARS = 2000
MAX_EVIDENCE_ITEM_CHARS = 500

_ERROR_LINE = re.compile(
    r"error|exception|traceback|fatal|critical|killed|failed|missing|denied|refused|timeout",
    re.IGNORECASE,
)
_FENCE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)


class RCAError(Exception):
    """Base class for analysis problems that trigger the fallback."""


class RCAParseError(RCAError):
    """The model reply was not parseable JSON."""


class RCAValidationError(RCAError):
    """The model reply was JSON but did not satisfy the contract."""


def _items(value: Any) -> List[Any]:
    """Return ``value`` if it is a list, else an empty list (tolerates malformed evidence)."""
    return value if isinstance(value, list) else []


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------


def _shrink(evidence: Dict[str, Any], level: int) -> Dict[str, Any]:
    """Return a reduced copy of the evidence (higher level = smaller)."""
    log_lines = (25, 10, 5)[min(level, 2)]
    event_count = (20, 12, 6)[min(level, 2)]
    history_count = (5, 3, 2)[min(level, 2)]
    reduced = dict(evidence)
    reduced["logs"] = [
        {**entry, "lines": _items(entry.get("lines"))[-log_lines:]}
        for entry in _items(evidence.get("logs"))
        if isinstance(entry, dict)
    ]
    reduced["events"] = _items(evidence.get("events"))[-event_count:]
    reduced["rollout_history"] = _items(evidence.get("rollout_history"))[:history_count]
    return reduced


def _evidence_text(evidence: Dict[str, Any]) -> str:
    """Serialise evidence to JSON, shrinking it if it would make the prompt too big."""
    text = json.dumps(evidence, default=str, ensure_ascii=False)
    level = 0
    while len(text) > MAX_PROMPT_EVIDENCE_CHARS and level < 3:
        text = json.dumps(_shrink(evidence, level), default=str, ensure_ascii=False)
        level += 1
    if len(text) > MAX_PROMPT_EVIDENCE_CHARS:
        text = text[: MAX_PROMPT_EVIDENCE_CHARS - 16] + " ...[truncated]"
    return text


def build_prompt(evidence: Dict[str, Any]) -> str:
    """Build the prompt: the exact instruction first, then the evidence JSON."""
    return f"{PROMPT_INSTRUCTION}\n\nEVIDENCE (JSON):\n{_evidence_text(evidence)}"


# ---------------------------------------------------------------------------
# Parsing and validation
# ---------------------------------------------------------------------------


def strip_code_fences(text: str) -> str:
    """Remove a Markdown code fence (``` or ```json) around a JSON payload."""
    stripped = text.strip()
    match = _FENCE.search(stripped)
    return match.group(1).strip() if match else stripped


def parse_model_json(text: Optional[str]) -> Dict[str, Any]:
    """Parse the model reply into a dict.

    Raises:
        RCAParseError: empty text, invalid JSON, or JSON that is not an object.
    """
    if not text or not text.strip():
        raise RCAParseError("empty response from model")
    try:
        data = json.loads(strip_code_fences(text))
    except json.JSONDecodeError as exc:
        raise RCAParseError(f"response is not valid JSON ({exc.msg})") from exc
    if not isinstance(data, dict):
        raise RCAParseError("response JSON is not an object")
    return data


def _canonical(text: str) -> str:
    """Case-fold and collapse whitespace for tolerant substring matching."""
    return " ".join(text.split()).casefold()


def _evidence_haystack(evidence: Dict[str, Any]) -> str:
    """All human-readable strings in the evidence a model could legitimately quote."""
    parts: List[str] = []
    for entry in _items(evidence.get("logs")):
        if isinstance(entry, dict):
            parts.extend(str(line) for line in _items(entry.get("lines")))
    for event in _items(evidence.get("events")):
        if isinstance(event, dict):
            parts.extend(str(event.get(k, "")) for k in ("reason", "message"))
    for pod in _items(evidence.get("pods")):
        if not isinstance(pod, dict):
            continue
        for container in _items(pod.get("containers")):
            if not isinstance(container, dict):
                continue
            parts.extend(
                str(container.get(k))
                for k in ("waiting_reason", "terminated_reason", "last_termination_reason")
                if container.get(k)
            )
    return _canonical("\n".join(parts))


def _clean_quote(item: str) -> str:
    """Strip whitespace and one layer of surrounding quotes/backticks."""
    cleaned = item.strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in "\"'`":
        cleaned = cleaned[1:-1].strip()
    return cleaned


def validate_rca(data: Dict[str, Any], evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a parsed model reply and return a clean result (without ``source``).

    Raises:
        RCAValidationError: any contract violation.
    """
    cause = data.get("probable_cause")
    if not isinstance(cause, str) or not cause.strip():
        raise RCAValidationError("probable_cause must be a non-empty string")

    quotes = data.get("evidence")
    if not isinstance(quotes, list) or not all(isinstance(item, str) for item in quotes):
        raise RCAValidationError("evidence must be a list of strings")

    confidence = data.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise RCAValidationError("confidence must be a number")
    if not math.isfinite(confidence) or not 0.0 <= float(confidence) <= 1.0:
        raise RCAValidationError("confidence must be between 0 and 1")

    action = data.get("recommended_action")
    if not isinstance(action, str) or action not in ALLOWED_ACTIONS:
        raise RCAValidationError(
            f"recommended_action must be one of {', '.join(ALLOWED_ACTIONS)}"
        )

    # Every quoted line must really exist in the collected evidence.
    haystack = _evidence_haystack(evidence)
    grounded: List[str] = []
    for raw in quotes:
        quote = _clean_quote(raw)
        if not quote:
            continue
        if _canonical(quote) in haystack:
            if quote not in grounded:
                grounded.append(quote[:MAX_EVIDENCE_ITEM_CHARS])
        else:
            logger.warning("Dropping evidence line not found in collected evidence")
    if quotes and any(q.strip() for q in quotes) and not grounded:
        raise RCAValidationError("none of the quoted evidence exists in the collected evidence")

    return {
        "probable_cause": cause.strip()[:MAX_PROBABLE_CAUSE_CHARS],
        "evidence": grounded[:MAX_EVIDENCE_ITEMS],
        "confidence": float(confidence),
        "recommended_action": action,
    }


# ---------------------------------------------------------------------------
# Gemini call
# ---------------------------------------------------------------------------


def _response_schema() -> types.Schema:
    """Structured-output schema matching the required JSON keys."""
    return types.Schema(
        type=types.Type.OBJECT,
        properties={
            "probable_cause": types.Schema(type=types.Type.STRING),
            "evidence": types.Schema(type=types.Type.ARRAY, items=types.Schema(type=types.Type.STRING)),
            "confidence": types.Schema(type=types.Type.NUMBER),
            "recommended_action": types.Schema(type=types.Type.STRING, enum=list(ALLOWED_ACTIONS)),
        },
        required=["probable_cause", "evidence", "confidence", "recommended_action"],
    )


def _call_gemini(prompt: str, settings: config.Settings) -> str:
    """Send the prompt to Gemini and return the raw text reply."""
    gemini = genai.Client(
        api_key=settings.gemini_api_key,
        http_options=types.HttpOptions(timeout=int(settings.gemini_timeout_seconds * 1000)),
    )
    response = gemini.models.generate_content(
        model=settings.gemini_model,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.0,
            response_mime_type="application/json",
            response_schema=_response_schema(),
        ),
    )
    return response.text or ""


# ---------------------------------------------------------------------------
# Deterministic fallback
# ---------------------------------------------------------------------------


def _parse_time(value: Any) -> Optional[datetime]:
    """Parse an ISO 8601 timestamp into an aware UTC datetime, or ``None``."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _observed_symptoms(evidence: Dict[str, Any]) -> List[str]:
    """Distinct pod/container failure reasons present in the evidence."""
    seen: List[str] = []
    for pod in _items(evidence.get("pods")):
        if not isinstance(pod, dict):
            continue
        for container in _items(pod.get("containers")):
            if not isinstance(container, dict):
                continue
            for key in ("waiting_reason", "terminated_reason", "last_termination_reason"):
                value = container.get(key)
                if value and value not in seen:
                    seen.append(str(value))
    return seen


def _real_error_lines(evidence: Dict[str, Any], limit: int = 3) -> List[str]:
    """Verbatim log lines that look like errors (never invented)."""
    found: List[str] = []
    for entry in _items(evidence.get("logs")):
        if not isinstance(entry, dict):
            continue
        for line in _items(entry.get("lines")):
            text = str(line).strip()
            if text and _ERROR_LINE.search(text) and text not in found:
                found.append(text[:MAX_EVIDENCE_ITEM_CHARS])
    return found[-limit:]


def fallback_analysis(
    evidence: Dict[str, Any], reason: str, now: Optional[datetime] = None
) -> Dict[str, Any]:
    """Deterministic diagnosis used whenever the LLM path is unavailable or invalid."""
    now = now or datetime.now(timezone.utc)
    deployed = _parse_time(evidence.get("last_deploy_time"))
    age = (now - deployed).total_seconds() if deployed else None
    recent = age is not None and -300 <= age <= FALLBACK_RECENT_DEPLOY_SECONDS

    symptoms = _observed_symptoms(evidence)
    seen = f" Observed pod states: {', '.join(symptoms)}." if symptoms else ""
    if recent:
        action, confidence = "rollback", FALLBACK_CONFIDENCE_ROLLBACK
        timing = (
            f"The deployment was last changed {max(age, 0) / 60:.1f} minute(s) ago, within the "
            f"{FALLBACK_RECENT_DEPLOY_SECONDS // 60}-minute window, so that change is the most "
            "likely trigger; rolling back is recommended."
        )
    else:
        action, confidence = "restart", FALLBACK_CONFIDENCE_RESTART
        if age is None:
            timing = "The time of the last deployment could not be established, so the conservative action (restart) is recommended."
        else:
            timing = (
                f"The deployment was last changed {age / 60:.1f} minute(s) ago, outside the "
                f"{FALLBACK_RECENT_DEPLOY_SECONDS // 60}-minute window, so a restart is recommended."
            )
    return {
        "probable_cause": f"AI analysis unavailable ({reason}). Rule-based assessment: {timing}{seen}",
        "evidence": _real_error_lines(evidence),
        "confidence": confidence,
        "recommended_action": action,
        "source": "fallback",
    }


def _safe_reason(exc: Exception, settings: config.Settings) -> str:
    """Describe a failure without leaking secrets."""
    text = f"{type(exc).__name__}: {exc}"
    for secret in settings.secrets_to_redact():
        text = text.replace(secret, "***")
    return text[:200]


# ---------------------------------------------------------------------------
# Public contract
# ---------------------------------------------------------------------------


def analyze(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Diagnose an incident from collected evidence. Never raises.

    Returns a validated result with ``source: "llm"``, or the deterministic
    fallback with ``source: "fallback"``.
    """
    settings = config.get_settings()
    if not isinstance(evidence, dict):
        logger.warning("analyze() received non-dict evidence; using fallback")
        return fallback_analysis({}, "invalid evidence supplied")
    if not settings.gemini_enabled:
        logger.info("GEMINI_API_KEY not configured; using fallback analysis")
        return fallback_analysis(evidence, "Gemini API key not configured")
    try:
        raw = _call_gemini(build_prompt(evidence), settings)
        result = validate_rca(parse_model_json(raw), evidence)
        result["source"] = "llm"
        return result
    except RCAError as exc:
        reason = f"model reply rejected: {exc}"
    except Exception as exc:  # noqa: BLE001 - network, quota, auth, SDK errors
        reason = f"Gemini call failed - {_safe_reason(exc, settings)}"
    logger.warning("Using fallback analysis: %s", reason)
    try:
        return fallback_analysis(evidence, reason)
    except Exception:  # noqa: BLE001 - last line of defence: analyze() must never raise
        logger.exception("Fallback analysis failed unexpectedly")
        return fallback_analysis({}, reason)
