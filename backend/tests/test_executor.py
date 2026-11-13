"""
Tests for Signed-Token Firewall Executor & Linux iptables Integration (Phase 4).
Verifies:
1. Valid approval token applies iptables rule (simulated/dry-run) and logs to audit ledger.
2. Proof-of-Skill Failures:
   - Forged token -> Execution refused
   - Expired token -> Execution refused
   - Allowlisted target (10.0.0.1) -> Execution refused
3. Target IP validation (blocks command injection / malformed IPs).
4. Rate limiting (blocks runaway containment cascades).
5. Automatic rule TTL and expiration cleanup.
"""

import tempfile
import unittest
from pathlib import Path

from backend.audit import get_audit_entries
from backend.database import init_db
from backend.executor import (
    RateLimiter,
    execute_approved_action,
    expire_active_blocks,
    global_rate_limiter,
    list_active_blocks,
    validate_ipv4_target,
)
from backend.security import generate_signed_approval_token


class TestExecutor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_exec.sqlite")
        init_db(self.db_path)
        global_rate_limiter.reset()

    def tearDown(self):
        global_rate_limiter.reset()
        self.temp_dir.cleanup()

    # -------------------------------------------------------------------------
    # Input Validation & Defense Against Injection
    # -------------------------------------------------------------------------
    def test_validate_ipv4_target_valid_and_hostile(self):
        """Should accept valid IPv4 and reject hostnames, CIDR masks, and shell injection."""
        # Valid IPv4
        ok, _ = validate_ipv4_target("198.51.100.23")
        self.assertTrue(ok)
        ok, _ = validate_ipv4_target("1.1.1.1")
        self.assertTrue(ok)

        # Hostile or invalid targets
        bad_targets = [
            "; rm -rf /",
            "10.0.0.1; reboot",
            "example.com",
            "0.0.0.0/0",
            "256.256.256.256",
            "198.51.100.23/24",
            "",
            "   ",
        ]
        for bad in bad_targets:
            ok, err = validate_ipv4_target(bad)
            self.assertFalse(ok, f"Target '{bad}' should have been rejected")
            self.assertIsNotNone(err)

    # -------------------------------------------------------------------------
    # Rate Limiting
    # -------------------------------------------------------------------------
    def test_rate_limiter_sliding_window(self):
        """Must allow up to max_requests and block subsequent attempts within the window."""
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        self.assertTrue(limiter.allow_request()[0])
        self.assertTrue(limiter.allow_request()[0])
        self.assertTrue(limiter.allow_request()[0])

        # 4th request must be rejected
        ok, err = limiter.allow_request()
        self.assertFalse(ok)
        self.assertIn("Rate limit exceeded", err)

    # -------------------------------------------------------------------------
    # Valid Execution Flow
    # -------------------------------------------------------------------------
    def test_valid_token_applies_containment_and_logs(self):
        """Valid signed approval token must execute, record active block, and log to audit ledger."""
        proposal = {
            "proposal_id": "prop-exec-01",
            "action": "block_ip",
            "target": "198.51.100.99",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "ttl_seconds": 3600,
        }
        token = generate_signed_approval_token(proposal, nonce="nonce-exec-01")

        result = execute_approved_action(token, dry_run=True, db_path=self.db_path)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["target"], "198.51.100.99")
        self.assertEqual(result["action"], "block_ip")

        # Must be listed in active blocks
        active = list_active_blocks(db_path=self.db_path)
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["target"], "198.51.100.99")

        # Must be recorded in tamper-evident audit log
        entries = get_audit_entries(db_path=self.db_path)
        self.assertTrue(any(e["action"] == "firewall.rule_applied" for e in entries))

    # -------------------------------------------------------------------------
    # Proof-of-Skill: Core Failure Rejections
    # -------------------------------------------------------------------------
    def test_proof_of_skill_forged_token_refused(self):
        """Proof-of-skill check: Forged approval token must be strictly refused by executor."""
        proposal = {
            "proposal_id": "prop-exec-forged",
            "action": "block_ip",
            "target": "198.51.100.77",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "ttl_seconds": 3600,
        }
        token = generate_signed_approval_token(proposal, nonce="nonce-exec-legit")

        # Attacker tampers with signature
        tampered_token = dict(token)
        tampered_token["signature"] = "deadbeef" * 8

        with self.assertRaises(PermissionError) as ctx:
            execute_approved_action(tampered_token, dry_run=True, db_path=self.db_path)
        self.assertIn("signature verification failed", str(ctx.exception).lower())

        # Refusal must be logged in audit ledger
        entries = get_audit_entries(db_path=self.db_path)
        self.assertTrue(any(e["action"] == "executor.refused_invalid_token" for e in entries))

    def test_proof_of_skill_expired_token_refused(self):
        """Proof-of-skill check: Expired approval token must be strictly refused by executor."""
        proposal = {
            "proposal_id": "prop-exec-expired",
            "action": "block_ip",
            "target": "198.51.100.77",
            "expires_at": "2020-01-01T00:00:00+00:00",  # Expired
            "ttl_seconds": 3600,
        }
        token = generate_signed_approval_token(proposal, nonce="nonce-exec-expired")

        with self.assertRaises(PermissionError) as ctx:
            execute_approved_action(token, dry_run=True, db_path=self.db_path)
        self.assertIn("expired", str(ctx.exception).lower())

    def test_proof_of_skill_allowlisted_target_refused(self):
        """Proof-of-skill check: Executor independently refuses blocking 10.0.0.1 (defense in depth)."""
        proposal = {
            "proposal_id": "prop-exec-allowlist",
            "action": "block_ip",
            "target": "10.0.0.1",  # Internal management IP
            "expires_at": "2099-01-01T00:00:00+00:00",
            "ttl_seconds": 3600,
        }
        token = generate_signed_approval_token(proposal, nonce="nonce-exec-allowlist")

        with self.assertRaises(PermissionError) as ctx:
            execute_approved_action(token, dry_run=True, db_path=self.db_path)
        self.assertIn("protected allowlist", str(ctx.exception).lower())

        # Refusal must be logged in audit ledger
        entries = get_audit_entries(db_path=self.db_path)
        self.assertTrue(any(e["action"] == "executor.refused_allowlisted_target" for e in entries))

    # -------------------------------------------------------------------------
    # Rule Expiration Cleanup
    # -------------------------------------------------------------------------
    def test_expire_active_blocks(self):
        """Rules whose expires_at timestamp has passed must be unblocked and marked expired."""
        from backend.executor import record_active_block
        # Manually seed an active block expired in the past
        from backend.database import get_db
        with get_db(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO active_blocks (target, proposal_id, blocked_at, expires_at, status)
                VALUES ('198.51.100.11', 'p-old', '2020-01-01T00:00:00+00:00', '2020-01-01T01:00:00+00:00', 'active');
                """
            )

        # Trigger rule expiration
        expired_ips = expire_active_blocks(dry_run=True, db_path=self.db_path)
        self.assertEqual(len(expired_ips), 1)
        self.assertEqual(expired_ips[0], "198.51.100.11")

        # Active blocks query should now return empty
        active = list_active_blocks(db_path=self.db_path)
        self.assertEqual(len(active), 0)


if __name__ == "__main__":
    unittest.main()
