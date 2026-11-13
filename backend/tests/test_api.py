"""
Unit Tests for FastAPI Endpoint Handlers in M2 Backend.
Directly tests the route handlers (business logic, status codes, database integration,
and HTTPException handling) in an isolated environment without socket overhead.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi import HTTPException

from backend.app import (
    check_health,
    create_proposal,
    get_single_proposal,
    list_pending_proposals,
    read_audit_log,
    sync_events,
    verify_audit,
)
from backend.audit import log_audit_event
from backend.database import init_db
from backend.schemas import ProposalCreateRequest
from agents.llm import Settings
import agents.llm

agents.llm._default_settings = lambda: Settings(api_key="mock-key", model="mock-model", max_retries=0)


def run_coro(coro):
    """Runs a coroutine synchronously without loopback socket requirements."""
    try:
        coro.send(None)
    except StopIteration as exc:
        return exc.value


class TestBackendAPIHandlers(unittest.TestCase):
    def setUp(self):
        # Create an isolated temporary database for each test
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_api.sqlite")
        init_db(self.db_path)

        # Patch DATABASE_PATH in backend.database and backend.config
        self.patcher_cfg = patch("backend.config.DATABASE_PATH", self.db_path)
        self.patcher_db = patch("backend.database.DATABASE_PATH", self.db_path)
        self.patcher_cfg.start()
        self.patcher_db.start()

    def tearDown(self):
        self.patcher_db.stop()
        self.patcher_cfg.stop()
        self.temp_dir.cleanup()

    def test_health_check_handler(self):
        """check_health() must return healthy status, db connectivity, and zero counts initially."""
        res = check_health()
        self.assertEqual(res.status, "healthy")
        self.assertTrue(res.database_connected)
        self.assertEqual(res.pending_proposals, 0)
        self.assertEqual(res.audit_entries_count, 0)
        self.assertIsNotNone(res.timestamp)

    def test_audit_verify_handler_empty_and_populated(self):
        """verify_audit() must confirm cryptographic integrity for empty and active logs."""
        res_empty = verify_audit()
        self.assertTrue(res_empty.valid)
        self.assertEqual(res_empty.entries_verified, 0)

        # Log two events
        log_audit_event("agent.triage", "alert.ingest", {"id": "A-1"}, db_path=self.db_path)
        log_audit_event("agent.investigation", "ip.lookup", {"ip": "1.2.3.4"}, db_path=self.db_path)

        res_populated = verify_audit()
        self.assertTrue(res_populated.valid)
        self.assertEqual(res_populated.entries_verified, 2)
        self.assertIsNone(res_populated.error)

    def test_read_audit_log_pagination(self):
        """read_audit_log() must return ordered audit entries with pagination support."""
        log_audit_event("system", "event1", "detail1", db_path=self.db_path)
        log_audit_event("system", "event2", "detail2", db_path=self.db_path)
        log_audit_event("system", "event3", "detail3", db_path=self.db_path)

        entries = read_audit_log(limit=2, offset=0)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["action"], "event1")
        self.assertEqual(entries[1]["action"], "event2")

    def test_create_and_get_proposal(self):
        """create_proposal() registers a proposal and appends it to the audit log."""
        req = ProposalCreateRequest(
            proposal_id="prop-test-001",
            alert_id="alert-001",
            action="block_ip",
            target="198.51.100.42",
            reason="High-volume brute force",
            confidence=0.92,
            ttl_seconds=3600
        )
        saved = run_coro(create_proposal(req))
        self.assertEqual(saved["proposal_id"], "prop-test-001")
        self.assertEqual(saved["status"], "pending")

        # Must be retrievable by ID
        fetched = get_single_proposal("prop-test-001")
        self.assertEqual(fetched["target"], "198.51.100.42")

        # Must appear in pending proposals
        pending_list = list_pending_proposals()
        self.assertEqual(len(pending_list), 1)
        self.assertEqual(pending_list[0]["proposal_id"], "prop-test-001")

    def test_duplicate_proposal_conflict(self):
        """Registering a proposal with an existing proposal_id must raise 409 Conflict."""
        req = ProposalCreateRequest(
            proposal_id="prop-dup",
            alert_id="alert-001",
            action="block_ip",
            target="198.51.100.42",
            reason="Initial",
        )
        run_coro(create_proposal(req))

        with self.assertRaises(HTTPException) as ctx:
            run_coro(create_proposal(req))
        self.assertEqual(ctx.exception.status_code, 409)

    def test_proposal_not_found(self):
        """Requesting a non-existent proposal ID must raise 404 Not Found."""
        with self.assertRaises(HTTPException) as ctx:
            get_single_proposal("non-existent-id")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_sync_events_handler(self):
        """sync_events() must return replay stream starting after last_seen_event_id."""
        from backend.storage import log_event
        log_event("alert.new", {"alert_id": "A-1"}, db_path=self.db_path)
        log_event("proposal.pending", {"proposal_id": "P-1"}, db_path=self.db_path)

        res = sync_events(last_seen_event_id=1, limit=50)
        self.assertEqual(res.last_seen_event_id, 1)
        self.assertEqual(len(res.events), 1)
        self.assertEqual(res.events[0].event_type, "proposal.pending")

    def test_analyst_login_endpoint(self):
        """POST /auth/token must issue a signed bearer session token."""
        from backend.app import login_analyst
        from backend.schemas import LoginRequest
        req = LoginRequest(analyst_id="analyst_test_01")
        res = login_analyst(req)
        self.assertEqual(res.analyst_id, "analyst_test_01")
        self.assertEqual(res.token_type, "bearer")
        self.assertTrue(len(res.access_token) > 20)

    def test_submit_decision_endpoint(self):
        """POST /api/decisions must approve and broadcast proposal.updated."""
        from backend.app import submit_decision
        from backend.schemas import DecisionRequest

        # Seed proposal
        req_prop = ProposalCreateRequest(
            proposal_id="prop-dec-test",
            alert_id="alert-001",
            action="block_ip",
            target="198.51.100.88",
            reason="Confirmed port scan",
        )
        run_coro(create_proposal(req_prop))

        # Submit decision
        dec_req = DecisionRequest(
            proposal_id="prop-dec-test",
            decision="approve",
            nonce="nonce-api-test-1111"
        )
        res = run_coro(submit_decision(req=dec_req, analyst_id="analyst_tester"))
        self.assertEqual(res["decision"], "approved")
        self.assertEqual(res["proposal"]["status"], "approved")
        self.assertIsNotNone(res["signed_token"])

    def test_executor_apply_and_blocks_endpoints(self):
        """POST /api/executor/apply executes with signed token; GET /api/executor/blocks lists it."""
        from backend.app import apply_containment_action, get_active_blocks
        from backend.executor import global_rate_limiter
        from backend.schemas import SignedApprovalTokenSchema
        from backend.security import generate_signed_approval_token

        global_rate_limiter.reset()

        proposal = {
            "proposal_id": "prop-exec-endpoint",
            "action": "block_ip",
            "target": "198.51.100.105",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "ttl_seconds": 1800,
        }
        token_data = generate_signed_approval_token(proposal, nonce="nonce-api-exec-01")
        token_schema = SignedApprovalTokenSchema(**token_data)

        # Apply action
        result = run_coro(apply_containment_action(token=token_schema))
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["target"], "198.51.100.105")

        # Check list of active blocks
        active = get_active_blocks()
        self.assertTrue(any(b["target"] == "198.51.100.105" for b in active))

    def test_alert_ingest_endpoint(self):
        """POST /api/alerts triggers pipeline and returns valid analysis result."""
        from backend.app import ingest_alert
        raw_alert = {
            "alert_id": "API-ALERT-01",
            "timestamp": "2026-11-13T12:00:00Z",
            "source_ip": "198.51.100.99",
            "log_text": "Failed password for root",
            "rule_name": "SSH Failure",
            "host": "srv-web",
            "severity": "medium",
        }
        res = run_coro(ingest_alert(alert=raw_alert))
        self.assertIn("status", res)
        self.assertIn("verdict", res)
        self.assertEqual(res["alert_id"], "API-ALERT-01")


if __name__ == "__main__":
    unittest.main()
