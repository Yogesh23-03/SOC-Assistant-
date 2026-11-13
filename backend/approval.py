"""
Approval Gate State Machine & Decision Engine (M2 Lead).
Coordinates the transition of proposals from 'pending' to 'approved', 'rejected', or 'expired'.

Enforces the project's core safety invariants:
1. Replay prevention: Verifies and consumes unique nonces.
2. Default-to-deny: Expired proposals can never be approved.
3. Allowlist protection: Any attempt to approve blocking an allowlisted IP (10.0.0.1, 127.0.0.1, etc.)
   is strictly refused with HTTP 403.
4. Cryptographic authorization: Generates HMAC-signed approval tokens for the executor.
"""

from typing import Any, Dict, Optional
from fastapi import HTTPException, status

from backend.audit import log_audit_event
from backend.config import PROTECTED_ALLOWLIST
from backend.security import generate_signed_approval_token, verify_and_consume_nonce
from backend.storage import get_proposal, update_proposal_status


def process_analyst_decision(
    proposal_id: str,
    decision: str,
    analyst_id: str,
    nonce: str,
    db_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Processes an analyst's decision ('approve', 'reject', 'investigate_more') on a proposal.

    Returns:
        Dict containing decision confirmation, updated proposal record,
        and the cryptographic signed approval token (if approved).
    """
    decision_clean = decision.lower().strip()
    if decision_clean not in ("approve", "reject", "investigate_more"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid decision '{decision}'. Allowed: approve, reject, investigate_more"
        )

    # 1. Anti-Replay: Verify and consume the nonce
    if not verify_and_consume_nonce(nonce=nonce, proposal_id=proposal_id, db_path=db_path):
        log_audit_event(
            actor=analyst_id,
            action="decision.replay_detected",
            details={"proposal_id": proposal_id, "nonce": nonce},
            db_path=db_path
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nonce already consumed or invalid: potential replay attack"
        )

    # 2. Retrieve proposal record
    proposal = get_proposal(proposal_id=proposal_id, db_path=db_path)
    if not proposal:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Proposal '{proposal_id}' does not exist"
        )

    # 3. Check status & Default-to-Deny for expired proposals
    current_status = proposal["status"]
    if current_status == "expired":
        log_audit_event(
            actor=analyst_id,
            action="decision.refused_expired",
            details={"proposal_id": proposal_id, "expires_at": proposal["expires_at"]},
            db_path=db_path
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Proposal has expired: action refused under default-to-deny policy"
        )

    if current_status != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Proposal is already '{current_status}' and cannot be modified"
        )

    # 4. Critical Safety Rail: Protected Allowlist Check
    target_ip = proposal["target"]
    if decision_clean == "approve" and target_ip in PROTECTED_ALLOWLIST:
        log_audit_event(
            actor=analyst_id,
            action="decision.allowlist_violation_blocked",
            details={
                "proposal_id": proposal_id,
                "target": target_ip,
                "reason": "Attempted to approve block on protected allowlist IP"
            },
            db_path=db_path
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Safety violation: Target '{target_ip}' is in the protected allowlist and cannot be blocked"
        )

    # 5. Handle Approval
    if decision_clean == "approve":
        updated = update_proposal_status(
            proposal_id=proposal_id,
            new_status="approved",
            decision_by=analyst_id,
            db_path=db_path
        )

        # Generate cryptographic HMAC signed token for executor
        signed_token = generate_signed_approval_token(
            proposal=updated,
            nonce=nonce
        )

        log_audit_event(
            actor=analyst_id,
            action="proposal.approved",
            details={
                "proposal_id": proposal_id,
                "action": updated["action"],
                "target": updated["target"],
                "signed_token_sig": signed_token["signature"],
            },
            db_path=db_path
        )

        return {
            "proposal_id": proposal_id,
            "decision": "approved",
            "analyst_id": analyst_id,
            "proposal": updated,
            "signed_token": signed_token,
        }

    # 6. Handle Rejection or Investigate More
    else:
        new_status = "rejected"
        updated = update_proposal_status(
            proposal_id=proposal_id,
            new_status=new_status,
            decision_by=analyst_id,
            db_path=db_path
        )

        log_audit_event(
            actor=analyst_id,
            action=f"proposal.{decision_clean}",
            details={"proposal_id": proposal_id, "action": updated["action"], "target": updated["target"]},
            db_path=db_path
        )

        return {
            "proposal_id": proposal_id,
            "decision": decision_clean,
            "analyst_id": analyst_id,
            "proposal": updated,
            "signed_token": None,
        }
