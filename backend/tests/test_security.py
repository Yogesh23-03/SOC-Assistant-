"""
Tests for Cryptographic Security, Session Tokens & Signed Approval Tokens (Phase 3).
Validates analyst authentication, anti-replay nonce consumption,
and HMAC signature integrity for the target VM executor.
"""

import tempfile
import time
import unittest
from pathlib import Path

from backend.database import init_db
from backend.security import (
    create_analyst_token,
    generate_signed_approval_token,
    verify_analyst_token,
    verify_and_consume_nonce,
    verify_approval_token,
)


class TestSecurity(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_sec.sqlite")
        init_db(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    # -------------------------------------------------------------------------
    # Analyst Session Tokens
    # -------------------------------------------------------------------------
    def test_analyst_token_creation_and_verification(self):
        """Valid analyst token must unpack and verify correctly."""
        token = create_analyst_token("analyst_sarah", role="lead_soc", expires_in_minutes=60)
        payload = verify_analyst_token(token)
        self.assertEqual(payload["sub"], "analyst_sarah")
        self.assertEqual(payload["role"], "lead_soc")
        self.assertGreater(payload["exp"], int(time.time()))

    def test_analyst_token_forgery_rejection(self):
        """Altering a single character of the payload or signature must trigger validation failure."""
        token = create_analyst_token("analyst_bob")
        parts = token.split(".")
        # Tamper with the first character of the signature segment
        tampered_sig = ("X" if parts[2][0] != "X" else "Y") + parts[2][1:]
        forged_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

        with self.assertRaises(ValueError) as ctx:
            verify_analyst_token(forged_token)
        self.assertIn("signature verification failed", str(ctx.exception).lower())

    def test_analyst_token_expiration(self):
        """Tokens past expiration must be rejected."""
        # Create an expired token (expires_in_minutes = -1)
        token = create_analyst_token("analyst_expired", expires_in_minutes=-1)
        with self.assertRaises(ValueError) as ctx:
            verify_analyst_token(token)
        self.assertIn("expired", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # Anti-Replay Nonce Verification
    # -------------------------------------------------------------------------
    def test_nonce_single_use_and_replay_rejection(self):
        """A nonce must only be accepted once; replaying the same nonce must return False."""
        nonce = "unique-nonce-12345"
        proposal_id = "prop-test-01"

        # First use must succeed
        self.assertTrue(verify_and_consume_nonce(nonce, proposal_id, db_path=self.db_path))

        # Replay attempt with same nonce must be rejected
        self.assertFalse(verify_and_consume_nonce(nonce, proposal_id, db_path=self.db_path))

        # Different nonce must succeed
        self.assertTrue(verify_and_consume_nonce("another-nonce-67890", proposal_id, db_path=self.db_path))

    # -------------------------------------------------------------------------
    # Signed Approval Tokens for Target VM Executor
    # -------------------------------------------------------------------------
    def test_signed_approval_token_valid(self):
        """Validly generated approval token must pass executor verification."""
        proposal = {
            "proposal_id": "prop-500",
            "action": "block_ip",
            "target": "198.51.100.77",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "ttl_seconds": 3600,
        }
        signed_token = generate_signed_approval_token(proposal, nonce="nonce-safe-1234")
        self.assertIn("signature", signed_token)

        is_valid, err = verify_approval_token(signed_token)
        self.assertTrue(is_valid)
        self.assertIsNone(err)

    def test_signed_approval_token_tampered_target(self):
        """Proof-of-skill check: If an attacker alters the target IP, executor refuses action."""
        proposal = {
            "proposal_id": "prop-500",
            "action": "block_ip",
            "target": "198.51.100.77",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "ttl_seconds": 3600,
        }
        signed_token = generate_signed_approval_token(proposal, nonce="nonce-safe-1234")

        # Attacker tampers with target to block internal server 10.0.0.1
        tampered_token = dict(signed_token)
        tampered_token["target"] = "10.0.0.1"

        is_valid, err = verify_approval_token(tampered_token)
        self.assertFalse(is_valid)
        self.assertIn("signature verification failed", err.lower())

    def test_signed_approval_token_expired(self):
        """Proof-of-skill check: Expired approval token must be rejected by executor."""
        proposal = {
            "proposal_id": "prop-500",
            "action": "block_ip",
            "target": "198.51.100.77",
            "expires_at": "2020-01-01T00:00:00+00:00",  # Expired in past
            "ttl_seconds": 3600,
        }
        signed_token = generate_signed_approval_token(proposal, nonce="nonce-expired-1234")

        is_valid, err = verify_approval_token(signed_token)
        self.assertFalse(is_valid)
        self.assertIn("expired", err.lower())


if __name__ == "__main__":
    unittest.main()
