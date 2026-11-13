"""Data contracts for the agents (Pydantic v2).

Everything the agents exchange is one of these types. The closed `Literal`
vocabularies are the allowlists, and `Proposal` cannot represent an executed
action.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Severity = Literal["low", "medium", "high", "critical"]
VerdictLabel = Literal["true_attack", "suspicious", "false_positive"]
ProposalAction = Literal["block_ip", "none", "escalate"]

# A host, IP, CIDR or username: starts alphanumeric, no spaces or shell metacharacters.
TARGET_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._:\-\[\]/]*$")


class Alert(BaseModel):
    """One SIEM alert. `log_text` is attacker-controlled data, never instructions."""

    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(min_length=1)
    timestamp: str
    source_ip: str | None = None
    log_text: str = ""
    rule_name: str
    # Optional context: the read-only tools look hosts up by name.
    host: str | None = None
    severity: Severity | None = None
    user: str | None = None


class TriageVerdict(BaseModel):
    """Triage result. `explanation` is the version a non-expert can read."""

    # Filled by our code from the alert; never trusted from the model.
    alert_id: str = ""
    label: VerdictLabel
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(min_length=1, max_length=1000)
    explanation: str = Field(min_length=1, max_length=1000)


class Finding(BaseModel):
    """One fact that came from a read-only tool."""

    alert_id: str
    source: str  # a tool name from tools.readonly.TOOLS
    detail: str = Field(min_length=1, max_length=1000)


class Proposal(BaseModel):
    """A proposed action. `executed` is Literal[False], so this type cannot act."""

    model_config = ConfigDict(frozen=True)

    proposal_id: str
    alert_id: str
    action: ProposalAction
    target: str = Field(default="", max_length=128)
    reason: str = Field(min_length=1, max_length=1000)
    explanation: str = Field(min_length=1, max_length=1000)
    requires_human_approval: Literal[True] = True
    executed: Literal[False] = False

    @model_validator(mode="after")
    def _target_matches_action(self) -> "Proposal":
        """`none` needs no target; every other action needs a safe, concrete one."""
        if self.action == "none":
            return self
        if not self.target:
            raise ValueError("target is required unless action is 'none'")
        if not TARGET_PATTERN.match(self.target):
            raise ValueError("target must be a host, IP, CIDR or username")
        if self.action == "block_ip":
            try:
                ipaddress.IPv4Address(self.target)
            except ValueError:
                raise ValueError(
                    "target must be a valid IPv4 address when action is 'block_ip'"
                ) from None
        return self


class PipelineResult(BaseModel):
    """Everything M1 produced for a single alert."""

    alert_id: str
    triage: TriageVerdict
    investigation: list[Finding] | None = None
    proposal: Proposal | None = None
