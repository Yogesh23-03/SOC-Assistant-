"""
Tests for Approval Gate State Machine & Human Decision Enforcement (Phase 3).
Verifies:
1. End-to-end approval generates a valid HMAC signed token.
2. Rejection / Investigate More correctly marks proposal rejected without token.
3. Replay attack rejection via consumed nonces.
4. Proof-of-Skill Failures:
   - Expired proposal -> Refused (Default-to-Deny)
   - Allowlisted target (10.0.0.1) -> Refused (HTTP 403 Forbidden)
"""

import tempfile
import unittest
from pathlib import Path
from fastapi import HTTPException

from backend.approval import process_analyst_decision
from backend.audit import get_audit_entries
from backend.database import init_db
from backend.security import verify_approval_token
from backend.storage import get_proposal, save_proposal


class TestApprovalGate(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_appr.sqlite")
        init_db(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_approve_valid_proposal_generates_signed_token(self):
        """Approving a valid pending proposal must transition status and issue signed token."""
        save_proposal(
            proposal_id="prop-valid-01",
            alert_id="A-100",
            action="block_ip",
            target="198.51.100.50",
            reason="Confirmed brute force",
            db_path=self.db_path
        )

        res = process_analyst_decision(
            proposal_id="prop-valid-01",
            decision="approve",
            analyst_id="analyst_alice",
            nonce="nonce-approve-01",
            db_path=self.db_path
        )

        self.assertEqual(res["decision"], "approved")
        self.assertEqual(res["analyst_id"], "analyst_alice")
        self.assertIsNotNone(res["signed_token"])

        # Check DB state
        prop = get_proposal("prop-valid-01", db_path=self.db_path)
        self.assertEqual(prop["status"], "approved")
        self.assertEqual(prop["decision_by"], "analyst_alice")

        # Verify signed approval token passes cryptographic validation
        is_valid, err = verify_approval_token(res["signed_token"])
        self.assertTrue(is_valid)
        self.assertIsNone(err)

    def test_reject_proposal_marks_rejected_without_token(self):
        """Rejecting a proposal must set status to rejected and issue NO approval token."""
        save_proposal(
            proposal_id="prop-reject-01",
            alert_id="A-101",
            action="block_ip",
            target="203.0.113.88",
            reason="Suspicious scan",
            db_path=self.db_path
        )

        res = process_analyst_decision(
            proposal_id="prop-reject-01",
            decision="reject",
            analyst_id="analyst_bob",
            nonce="nonce-reject-01",
            db_path=self.db_path
        )

        self.assertEqual(res["decision"], "reject")
        self.assertIsNone(res["signed_token"])

        prop = get_proposal("prop-reject-01", db_path=self.db_path)
        self.assertEqual(prop["status"], "rejected")

    def test_replay_attack_rejected(self):
        """Attempting to submit two decisions with the same nonce must be refused."""
        save_proposal(
            proposal_id="prop-replay-01",
            alert_id="A-102",
            action="block_ip",
            target="198.51.100.12",
            reason="Test",
            db_path=self.db_path
        )

        # First attempt with nonce
        process_analyst_decision(
            proposal_id="prop-replay-01",
            decision="reject",
            analyst_id="analyst_charlie",
            nonce="reused-nonce-9999",
            db_path=self.db_path
        )

        # Second attempt with same nonce
        with self.assertRaises(HTTPException) as ctx:
            process_analyst_decision(
                proposal_id="prop-replay-01",
                decision="approve",
                analyst_id="attacker",
                nonce="reused-nonce-9999",
                db_path=self.db_path
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("replay attack", ctx.exception.detail.lower())

    # -------------------------------------------------------------------------
    # Proof of Skill: Core Failure Rejections
    # -------------------------------------------------------------------------
    def test_proof_of_skill_expired_proposal_default_to_deny(self):
        """Proof-of-skill check: Expired proposal must be refused under default-to-deny."""
        save_proposal(
            proposal_id="prop-old-01",
            alert_id="A-103",
            action="block_ip",
            target="198.51.100.15",
            reason="Old alert",
            expires_at="2020-01-01T00:00:00+00:00",  # Expired in past
            db_path=self.db_path
        )

        with self.assertRaises(HTTPException) as ctx:
            process_analyst_decision(
                proposal_id="prop-old-01",
                decision="approve",
                analyst_id="analyst_david",
                nonce="nonce-expired-test",
                db_path=self.db_path
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("expired", ctx.exception.detail.lower())
        self.assertIn("default-to-deny", ctx.exception.detail.lower())

    def test_proof_of_skill_allowlisted_target_blocked(self):
        """Proof-of-skill check: Approving a block on allowlisted IP (10.0.0.1) must be refused (HTTP 403)."""
        # Proposal created with target 10.0.0.1
        save_proposal(
            proposal_id="prop-allowlist-01",
            alert_id="A-104",
            action="block_ip",
            target="10.0.0.1",
            reason="Injected block request",
            db_path=self.db_path
        )

        with self.assertRaises(HTTPException) as ctx:
            process_analyst_decision(
                proposal_id="prop-allowlist-01",
                decision="approve",
                analyst_id="analyst_eve",
                nonce="nonce-allowlist-test",
                db_path=self.db_path
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("protected allowlist", ctx.exception.detail.lower())

        # Check audit log recorded the security event
        entries = get_audit_entries(db_path=self.db_path)
        self.assertTrue(any(e["action"] == "decision.allowlist_violation_blocked" for e in entries))


if __name__ == "__main__":
    unittest.main()
