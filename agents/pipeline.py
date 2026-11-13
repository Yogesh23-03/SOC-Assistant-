"""Ties the three agents together for one alert: Triage -> Investigation -> Response.

`analyse_alert()` is the core used by the tests and the CLI. `run_pipeline()` is
its dict-in / dict-out wrapper for other code (M2): it validates the incoming
alert, returns JSON-serializable dicts, and turns any step that cannot produce a
validated answer into a safe escalation instead of an exception.
"""

from __future__ import annotations

from uuid import uuid4

from pydantic import ValidationError

from agents.investigation import investigate
from agents.llm import LLM, LLMError
from agents.response import respond
from agents.triage import triage
from schemas.models import Alert, PipelineResult, Proposal, TARGET_PATTERN, TriageVerdict

FALLBACK_TARGET = "manual-review"


def analyse_alert(alert: Alert, llm: LLM) -> PipelineResult:
    """Run the M1 pipeline. Returns proposals only - nothing is ever executed."""
    verdict = triage(alert, chat_fn=llm.chat)
    false_positive = verdict.label == "false_positive"

    # A false positive skips investigation entirely (no tool calls).
    findings = [] if false_positive else investigate(alert, verdict, chat_fn=llm.chat)
    proposal = respond(alert, verdict, findings, chat_fn=llm.chat)

    return PipelineResult(
        alert_id=alert.alert_id,
        triage=verdict,
        investigation=None if false_positive else findings,
        proposal=proposal,
    )


def _fallback(alert_id: str, reason: str, host: str | None = None) -> dict:
    """The safe result when a step cannot produce a validated answer.

    Label "suspicious" (a person should look), action "escalate" (nothing runs),
    and the reason names the failing step. Code builds all of it; no model output
    is reused when validation failed.
    """
    target = host if host and TARGET_PATTERN.match(host) else FALLBACK_TARGET
    verdict = TriageVerdict(
        alert_id=alert_id,
        label="suspicious",
        confidence=0.0,
        reasoning=reason[:1000],
        explanation=(
            "The automated analysis could not finish, so this alert is treated as "
            "suspicious. A person should review it."
        ),
    )
    proposal = Proposal(
        proposal_id=uuid4().hex[:12],
        alert_id=alert_id,
        action="escalate",
        target=target[:128],
        reason=f"Automated analysis did not complete: {reason}"[:1000],
        explanation=(
            "Nothing was executed and no judgement was made about this alert. "
            "It is escalated so a person can decide."
        ),
    )
    return {
        "verdict": verdict.model_dump(),
        "findings": [],
        "proposal": proposal.model_dump(),
    }


def run_pipeline(alert_dict: dict, llm: LLM | None = None) -> dict:
    """Run sanitise -> triage -> investigation -> response for one alert dict.

    Returns only JSON-serializable data:
    `{"verdict": {...}, "findings": [...], "proposal": {...}}`.

    Never executes a proposed action. If the alert or any step fails validation
    after its retries, returns the safe fallback instead of raising.
    `llm` is injectable for tests; without it a client is built from `.env`.
    """
    if not isinstance(alert_dict, dict):
        return _fallback("unknown", "alert payload must be a JSON object")

    try:
        alert = Alert.model_validate(alert_dict)
    except ValidationError as exc:
        detail = exc.errors()[0].get("msg", "invalid alert") if exc.errors() else "invalid alert"
        return _fallback(str(alert_dict.get("alert_id") or "unknown"), f"alert failed validation: {detail}")

    try:
        result = analyse_alert(alert, llm or LLM())
    except LLMError as exc:
        return _fallback(alert.alert_id, str(exc), alert.host)

    return {
        "verdict": result.triage.model_dump(),
        "findings": [finding.model_dump() for finding in result.investigation or []],
        "proposal": result.proposal.model_dump() if result.proposal else None,
    }
