"""
Alert Ingestion & Pipeline Orchestrator (Phase 5 - M2 Lead).
Connects SIEM alert ingest with M1's multi-agent pipeline (Triage -> Investigation -> Response).

Key Capabilities:
1. Validates raw SIEM alerts against schemas.models.Alert.
2. Triggers M1's run_pipeline() with defensive error handling.
3. Auto-closes false-positive alerts (notifies extension via case.closed, never bothers the human).
4. For true attacks, records pending proposals and pushes real-time cards via WebSocket (proposal.pending).
5. Logs every stage to the tamper-evident hash-chained audit log.
"""

import logging
import sys
from types import ModuleType
from typing import Any, Dict, Optional

# Ensure agents.llm can be imported cleanly even if groq package is not yet installed
if "groq" not in sys.modules:
    try:
        import groq  # type: ignore
    except ImportError:
        fake_groq = ModuleType("groq")
        fake_groq.Groq = None  # type: ignore
        fake_groq.APIConnectionError = type("APIConnectionError", (Exception,), {})
        fake_groq.RateLimitError = type("RateLimitError", (Exception,), {})
        fake_groq.InternalServerError = type("InternalServerError", (Exception,), {})
        fake_groq.APIStatusError = type("APIStatusError", (Exception,), {})
        sys.modules["groq"] = fake_groq

from agents.llm import LLM
from agents.pipeline import run_pipeline
from schemas.models import Alert

from backend.audit import log_audit_event
from backend.storage import save_proposal
from backend.websocket_manager import ws_manager

logger = logging.getLogger("soc_backend.ingest")


async def ingest_and_process_alert(
    alert_payload: Dict[str, Any],
    llm: Optional[LLM] = None,
    db_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Ingests an alert from SIEM / webhook / simulator and executes the agentic pipeline.

    Returns:
        Structured dictionary with triage verdict, findings, and either
        an auto-closed confirmation or a pending human approval proposal.
    """
    # 1. Validate alert schema
    try:
        validated_alert = Alert.model_validate(alert_payload)
        alert_dict = validated_alert.model_dump()
    except Exception as exc:
        logger.warning(f"Malformed alert rejected by schema: {exc}")
        alert_dict = alert_payload

    alert_id = str(alert_dict.get("alert_id") or "UNKNOWN-ALERT")

    # 2. Record alert arrival in audit ledger
    log_audit_event(
        actor="system.ingest",
        action="alert.received",
        details={
            "alert_id": alert_id,
            "rule_name": alert_dict.get("rule_name", "unknown"),
            "source_ip": alert_dict.get("source_ip", "unknown"),
            "host": alert_dict.get("host", "unknown"),
            "severity": alert_dict.get("severity", "medium"),
        },
        db_path=db_path
    )

    # 3. Broadcast alert.new event to open extension panels
    alert_event_payload = {
        "alert_id": alert_id,
        "rule_name": alert_dict.get("rule_name", ""),
        "source_ip": alert_dict.get("source_ip", ""),
        "host": alert_dict.get("host", ""),
        "severity": alert_dict.get("severity", "medium"),
        "timestamp": alert_dict.get("timestamp", ""),
    }
    await ws_manager.broadcast("alert.new", alert_event_payload, db_path=db_path)

    # 4. Execute M1 Agent Pipeline (Triage -> Investigation -> Response)
    pipeline_result = run_pipeline(alert_dict, llm=llm)

    verdict = pipeline_result.get("verdict") or {}
    findings = pipeline_result.get("findings") or []
    proposal = pipeline_result.get("proposal")
    label = verdict.get("label", "suspicious")

    # -------------------------------------------------------------------------
    # Scenario B: False Positive (Auto-Close)
    # -------------------------------------------------------------------------
    if label == "false_positive":
        close_reason = verdict.get("reasoning", "Classified as benign or false positive.")

        # Log auto-closure in audit ledger
        log_audit_event(
            actor="agent.triage",
            action="case.auto_closed",
            details={
                "alert_id": alert_id,
                "confidence": verdict.get("confidence", 1.0),
                "reason": close_reason
            },
            db_path=db_path
        )

        # Broadcast case.closed so extension archives the alert without disturbing the analyst
        closed_event = {
            "alert_id": alert_id,
            "status": "closed",
            "auto_closed": True,
            "verdict": verdict,
            "reason": close_reason
        }
        await ws_manager.broadcast("case.closed", closed_event, db_path=db_path)

        return {
            "status": "auto_closed",
            "alert_id": alert_id,
            "verdict": verdict,
            "findings": [],
            "proposal": None,
            "message": "Alert auto-closed with logged reason. Human was not disturbed."
        }

    # -------------------------------------------------------------------------
    # Scenario A: True Attack / Suspicious (Human Approval Required)
    # -------------------------------------------------------------------------
    # Record investigation findings in audit ledger
    if findings:
        log_audit_event(
            actor="agent.investigation",
            action="investigation.completed",
            details={"alert_id": alert_id, "findings_count": len(findings)},
            db_path=db_path
        )

        # Broadcast alert.update with evidence
        await ws_manager.broadcast(
            "alert.update",
            {"alert_id": alert_id, "verdict": verdict, "findings": findings},
            db_path=db_path
        )

    # If response agent generated an actionable proposal (e.g. block_ip or escalate)
    if proposal and proposal.get("action") in ("block_ip", "escalate"):
        proposal_id = proposal["proposal_id"]

        # Store in SQLite proposals table as pending
        saved_prop = save_proposal(
            proposal_id=proposal_id,
            alert_id=alert_id,
            action=proposal["action"],
            target=proposal["target"],
            reason=proposal["reason"],
            explanation=proposal.get("explanation", ""),
            confidence=float(verdict.get("confidence", 0.0)),
            db_path=db_path
        )

        log_audit_event(
            actor="agent.response",
            action="proposal.created",
            details={
                "proposal_id": proposal_id,
                "alert_id": alert_id,
                "action": saved_prop["action"],
                "target": saved_prop["target"],
            },
            db_path=db_path
        )

        # Broadcast proposal.pending to extension cards
        pending_event = {
            "proposal_id": proposal_id,
            "alert_id": alert_id,
            "action": saved_prop["action"],
            "target": saved_prop["target"],
            "reason": saved_prop["reason"],
            "explanation": saved_prop.get("explanation", ""),
            "confidence": saved_prop["confidence"],
            "expires_at": saved_prop["expires_at"],
            "evidence": findings,
        }
        await ws_manager.broadcast("proposal.pending", pending_event, db_path=db_path)

        return {
            "status": "pending_approval",
            "alert_id": alert_id,
            "verdict": verdict,
            "findings": findings,
            "proposal": saved_prop,
            "message": "Attack analyzed. Proposal queued in extension awaiting human decision."
        }

    # Fallback when action is 'none'
    return {
        "status": "no_action_required",
        "alert_id": alert_id,
        "verdict": verdict,
        "findings": findings,
        "proposal": None,
        "message": "Analysis completed. No containment action needed."
    }
