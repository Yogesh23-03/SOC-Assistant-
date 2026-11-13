"""Response agent: proposes at most one action. Executes nothing.

`respond(alert, triage, findings)` returns a schema-valid `Proposal`. A
false-positive triage returns action "none" without asking the model. This
module imports no tool, shell or network capability, so it cannot run anything.
"""

from __future__ import annotations

import json
from typing import Any, Callable
from uuid import uuid4

from agents import prompts
from agents.llm import LLMError, chat, parse_json_object, validate_model
from agents.sanitize import alert_data
from config import is_allowlisted
from schemas.models import Alert, Finding, Proposal, ProposalAction, TriageVerdict

# The only keys the model is allowed to contribute.
MODEL_FIELDS = ("action", "target", "reason", "explanation")

# One retry with the validation error fed back, in case the model proposes an
# unusable target (a CIDR for block_ip, a command string, ...).
MAX_PROPOSAL_ATTEMPTS = 2


def make_none_proposal(alert_id: str, reason: str, explanation: str) -> Proposal:
    """A Proposal that explicitly does nothing. Built entirely by our code."""
    return Proposal(
        proposal_id=uuid4().hex[:12],
        alert_id=alert_id,
        action="none",
        reason=reason[:1000],
        explanation=explanation[:1000],
    )


def build_proposal(data: dict, alert_id: str, proposal_id: str | None = None) -> Proposal:
    """Turn model JSON into a Proposal, ignoring anything else it sent."""
    if "action" not in data:
        raise LLMError("Model reply had no 'action' field.")

    payload: dict = {
        "proposal_id": proposal_id or uuid4().hex[:12],
        "alert_id": alert_id,
    }
    payload.update({key: data[key] for key in MODEL_FIELDS if key in data})
    # Proposal's own validators enforce the action and IPv4 rules.
    return validate_model(Proposal, payload)


def enforce_allowlist(proposal: Proposal) -> Proposal:
    """Our own infrastructure is never blocked: force `escalate` and say why."""
    if not is_allowlisted(proposal.target):
        return proposal

    note = (
        f"Target {proposal.target} is on the protected allowlist (our own infrastructure), "
        "so blocking it is not allowed; escalate to a human instead."
    )
    reason = proposal.reason if note in proposal.reason else f"{note} {proposal.reason}"[:1000]
    return proposal.model_copy(update={"action": "escalate", "reason": reason})


def respond(
    alert: Alert,
    triage: TriageVerdict,
    findings: list[Finding] | None = None,
    chat_fn: Callable[..., Any] | None = None,
) -> Proposal:
    """Return one schema-valid Proposal for this alert. Nothing is executed."""
    if triage.label == "false_positive":
        # Deterministic: no model call, no tool call, no ambiguity.
        return make_none_proposal(
            alert.alert_id,
            "Triage labelled this alert a false positive.",
            "The triage step found this was expected activity, so no action is proposed.",
        )

    payload = {
        "alert": alert_data(alert),
        "triage": triage.model_dump(),
        "findings": [finding.model_dump() for finding in findings or []],
        "allowed_actions": list(ProposalAction.__args__),  # single source of truth
    }
    messages: list[dict] = [
        {"role": "system", "content": prompts.load_prompt("response")},
        {"role": "user", "content": json.dumps(payload, indent=2)},
    ]

    last_error = "no attempt was made"
    for _ in range(MAX_PROPOSAL_ATTEMPTS):
        reply = (chat_fn or chat)(messages, json_mode=True)
        try:
            proposal = build_proposal(
                parse_json_object(reply.content or ""), alert.alert_id
            )
            return enforce_allowlist(proposal)
        except LLMError as exc:
            last_error = str(exc)[:500]
            messages.append({"role": "assistant", "content": reply.content or ""})
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"That proposal could not be used: {last_error}\n"
                        "Reply again with ONLY a JSON object that satisfies this schema:\n"
                        f"{json.dumps(Proposal.model_json_schema())}"
                    ),
                }
            )

    raise LLMError(
        f"Proposal validation failed after {MAX_PROPOSAL_ATTEMPTS} attempt(s): {last_error}"
    )
