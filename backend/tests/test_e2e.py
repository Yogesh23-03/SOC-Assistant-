"""
End-to-End Proof-of-Skill Test Suite (Phase 6 - M2 Lead).

Exercises the complete M2 backend across all safety invariants in a single
in-process test run with an isolated SQLite temp database per test.

Covered Scenarios:
  Test 1 — test_end_to_end_attack_to_containment
      Alert → Pipeline → Proposal → Approve → Signed Token → Executor
      Verifies: audit trail has alert.received, investigation.completed,
                proposal.approved, firewall.rule_applied

  Test 2 — test_proof_of_skill_forged_token_full_flow
      Approve valid proposal → tamper HMAC sig → executor must reject
      Verifies: PermissionError raised; 'executor.refused_invalid_token' in audit

  Test 3 — test_proof_of_skill_expired_proposal_full_flow
      Force proposal to 'expired' status → try to approve → HTTP 400
      Verifies: 'decision.refused_expired' in audit log

  Test 4 — test_proof_of_skill_allowlisted_target_full_flow
      Save proposal targeting 10.0.0.1 → approve → HTTP 403
      Verifies: 'decision.allowlist_violation_blocked' in audit log

  Test 5 — test_websocket_event_replay_after_disconnect
      Broadcast 3 events → reconnect with last_seen=1 → assert 2+ events replayed
      + sync.complete sentinel sent

  Test 6 — test_audit_chain_integrity_after_full_flow
      Run full attack scenario → call verify_audit_chain() → valid=True + ≥5 entries
"""

import json
import sys
import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, List

# ---------------------------------------------------------------------------
# Offline groq stub — must precede all agents.* imports
# ---------------------------------------------------------------------------
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

from agents.llm import LLM, Settings
import agents.llm

# Patch default settings so tests run offline (no GROQ_API_KEY required)
agents.llm._default_settings = lambda: Settings(
    api_key="test-key-e2e", model="mock-model", max_retries=0
)

from backend.approval import process_analyst_decision
from backend.audit import get_audit_entries, verify_audit_chain
from backend.database import get_db, init_db
from backend.executor import execute_approved_action, global_rate_limiter
from backend.ingest import ingest_and_process_alert
from backend.security import generate_signed_approval_token
from backend.storage import get_events_since, get_pending_proposals, save_proposal
from backend.websocket_manager import ConnectionManager


# ---------------------------------------------------------------------------
# Shared Utilities
# ---------------------------------------------------------------------------

def run_coro(coro: Any) -> Any:
    """
    Drives a single-step async coroutine to completion without an event loop.
    Required because asyncio.run() hangs on the Windows sandbox.
    """
    try:
        coro.send(None)
    except StopIteration as exc:
        return exc.value


class FakeCompletions:
    """Returns pre-canned LLM replies one-by-one (simulates Groq API)."""

    def __init__(self, replies: List[Any]) -> None:
        self.replies = list(replies)

    def create(self, **kwargs: Any) -> Any:
        if not self.replies:
            raise AssertionError("FakeCompletions exhausted all canned replies")
        reply = self.replies.pop(0)
        # Support both raw string replies and tool-call namespace replies
        message = reply if hasattr(reply, "tool_calls") else SimpleNamespace(
            content=reply, tool_calls=None
        )
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])


class FakeClient:
    """Minimal Groq-compatible fake client backed by FakeCompletions."""

    def __init__(self, replies: List[Any]) -> None:
        self.chat = SimpleNamespace(completions=FakeCompletions(replies))


def make_llm(*replies: Any) -> LLM:
    """Builds an offline LLM configured with canned pipeline replies."""
    return LLM(
        settings=Settings(api_key="test-key-e2e", model="mock-model", max_retries=0),
        client=FakeClient(list(replies)),
    )


class FakeWebSocket:
    """
    Minimal async-compatible fake WebSocket that records all sent messages.
    Used to verify WebSocket replay without a real network socket.
    Hashable so it can be stored in ConnectionManager.active_connections (a set).
    Supports both send_json (broadcast path) and send_text (replay/ping path).
    """

    def __init__(self) -> None:
        self.sent: List[Any] = []

    async def send_json(self, data: Any) -> None:  # noqa: D401
        """Called by broadcast() on the happy path."""
        self.sent.append(data)

    async def send_text(self, text: str) -> None:
        """Called by handle_sync_request() replay and handle_ping() paths."""
        import json as _json
        self.sent.append(_json.loads(text))

    async def receive_json(self) -> Any:
        return {}

    # Required for set membership (active_connections is a set)
    def __hash__(self) -> int:
        return id(self)

    def __eq__(self, other: object) -> bool:
        return self is other


# ---------------------------------------------------------------------------
# LLM reply factories — mirrors realistic pipeline JSON
# ---------------------------------------------------------------------------

def _triage_true_attack(alert_id: str) -> str:
    return json.dumps({
        "alert_id": alert_id,
        "label": "true_attack",
        "confidence": 0.95,
        "reasoning": "Web shell command execution observed.",
        "explanation": "Critical RCE payload detected.",
    })


def _investigation_tool_call(source_ip: str) -> SimpleNamespace:
    return SimpleNamespace(
        content=None,
        tool_calls=[SimpleNamespace(
            id="call_e2e_1",
            function=SimpleNamespace(
                name="search_logs",
                arguments=json.dumps({"ip": source_ip})
            )
        )]
    )


def _investigation_finish(source_ip: str) -> str:
    return f"Found 47 suspicious POST requests from {source_ip} in last 10 min."


def _response_block(alert_id: str, source_ip: str, proposal_id: str) -> str:
    return json.dumps({
        "proposal_id": proposal_id,
        "alert_id": alert_id,
        "action": "block_ip",
        "target": source_ip,
        "reason": f"Hostile web shell upload from {source_ip}.",
        "explanation": "Block attacker at the perimeter firewall.",
        "requires_human_approval": True,
        "executed": False,
    })


# ---------------------------------------------------------------------------
# Helper: run the full attack pipeline and return (ingest_result, proposal)
# ---------------------------------------------------------------------------

def run_attack_pipeline(
    alert_id: str,
    source_ip: str,
    proposal_id: str,
    db_path: str,
) -> tuple:
    """
    Runs the ingestion → pipeline → pending proposal flow.
    Returns (ingest_result, pending_proposal_dict).
    """
    alert_payload = {
        "alert_id": alert_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "log_text": f"POST /upload.php 200 — eval(base64_decode($_POST['c'])) from {source_ip}",
        "rule_name": "Web Shell Upload Detected",
        "host": "web-srv-01",
        "severity": "critical",
    }
    llm = make_llm(
        _triage_true_attack(alert_id),
        _investigation_tool_call(source_ip),
        _investigation_finish(source_ip),
        _response_block(alert_id, source_ip, proposal_id),
    )
    ingest_result = run_coro(ingest_and_process_alert(alert_payload, llm=llm, db_path=db_path))
    pending = get_pending_proposals(db_path=db_path)
    prop = next((p for p in pending if p["alert_id"] == alert_id), None)
    return ingest_result, prop


# ===========================================================================
# Test Suite
# ===========================================================================

class TestEndToEnd(unittest.TestCase):
    """End-to-End Proof-of-Skill tests for the M2 Agentic SOC Backend."""

    # -------------------------------------------------------------------------
    # Test Lifecycle
    # -------------------------------------------------------------------------

    def setUp(self) -> None:
        """Creates a fresh temporary SQLite database for each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "e2e_test.sqlite")
        init_db(self.db_path)
        global_rate_limiter.reset()   # prevent cross-test rate-limit bleed

    def tearDown(self) -> None:
        """Removes the temporary database directory after each test."""
        self.temp_dir.cleanup()

    # =========================================================================
    # Test 1 — Full Attack-to-Containment Happy Path
    # =========================================================================

    def test_end_to_end_attack_to_containment(self) -> None:
        """
        PROOF-OF-SKILL TEST 1: Complete happy-path E2E flow.
        Ingest alert → pipeline → proposal → approve → signed token → executor applies rule.
        Verifies: audit trail must include all 4 critical events.
        """
        alert_id = "E2E-ATTACK-001"
        source_ip = "198.51.100.42"
        proposal_id = f"prop-e2e-{uuid.uuid4().hex[:8]}"

        # 1. Ingest alert and run pipeline
        ingest_result, prop = run_attack_pipeline(alert_id, source_ip, proposal_id, self.db_path)
        self.assertEqual(ingest_result["status"], "pending_approval",
                         "Pipeline must queue proposal for human approval")
        self.assertIsNotNone(prop, "Pending proposal must appear in analyst queue")
        self.assertEqual(prop["target"], source_ip)

        # 2. Analyst approves
        nonce = uuid.uuid4().hex
        decision_result = process_analyst_decision(
            proposal_id=prop["proposal_id"],
            decision="approve",
            analyst_id="test-analyst",
            nonce=nonce,
            db_path=self.db_path,
        )
        self.assertEqual(decision_result["decision"], "approved")
        self.assertIsNotNone(decision_result["signed_token"],
                             "Signed HMAC token must be returned on approval")

        # 3. Executor applies the firewall rule (dry-run)
        exec_result = execute_approved_action(
            decision_result["signed_token"],
            dry_run=True,
            db_path=self.db_path,
        )
        self.assertEqual(exec_result["status"], "success")
        self.assertEqual(exec_result["target"], source_ip)

        # 4. Verify audit trail completeness — all 4 critical events must be present
        entries = get_audit_entries(db_path=self.db_path)
        actions = {e["action"] for e in entries}
        self.assertIn("alert.received", actions,
                      "Audit log must record alert ingestion")
        self.assertIn("investigation.completed", actions,
                      "Audit log must record investigation completion")
        self.assertIn("proposal.approved", actions,
                      "Audit log must record analyst approval")
        self.assertIn("firewall.rule_applied", actions,
                      "Audit log must record firewall rule application")

    # =========================================================================
    # Test 2 — Forged Token Rejection
    # =========================================================================

    def test_proof_of_skill_forged_token_full_flow(self) -> None:
        """
        PROOF-OF-SKILL TEST 2: Tampered HMAC token must be refused by executor.
        Verifies: PermissionError raised; 'executor.refused_invalid_token' in audit.
        """
        # Build a valid signed token (no need to run the full pipeline for this test)
        prop = {
            "proposal_id": f"prop-forge-{uuid.uuid4().hex[:8]}",
            "action": "block_ip",
            "target": "172.16.100.1",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "ttl_seconds": 3600,
        }
        nonce = uuid.uuid4().hex
        valid_token = generate_signed_approval_token(proposal=prop, nonce=nonce)

        # Tamper the first character of the hex signature (always changes decoded bytes)
        original_sig = valid_token["signature"]
        forged_char = "0" if original_sig[0] != "0" else "1"
        forged_token = {**valid_token, "signature": forged_char + original_sig[1:]}

        # Executor must reject with PermissionError
        with self.assertRaises(PermissionError,
                               msg="Executor must raise PermissionError for forged token"):
            execute_approved_action(forged_token, dry_run=True, db_path=self.db_path)

        # Audit log must record the security event
        entries = get_audit_entries(db_path=self.db_path)
        refusal_entries = [e for e in entries if e["action"] == "executor.refused_invalid_token"]
        self.assertGreater(len(refusal_entries), 0,
                           "'executor.refused_invalid_token' must be written to audit log")

    # =========================================================================
    # Test 3 — Expired Proposal Rejection (Default-to-Deny)
    # =========================================================================

    def test_proof_of_skill_expired_proposal_full_flow(self) -> None:
        """
        PROOF-OF-SKILL TEST 3: Expired proposal must be rejected (default-to-deny).
        Verifies: HTTPException 400 raised; 'decision.refused_expired' in audit.
        """
        proposal_id = f"prop-expired-{uuid.uuid4().hex[:8]}"

        # Save a proposal to the database
        save_proposal(
            proposal_id=proposal_id,
            alert_id="E2E-EXP-001",
            action="block_ip",
            target="10.20.30.50",
            reason="Demo expired proposal",
            explanation="",
            confidence=0.90,
            db_path=self.db_path,
        )

        # Force the proposal to 'expired' status with a past timestamp
        with get_db(self.db_path) as conn:
            conn.execute(
                "UPDATE proposals SET status='expired', expires_at=? WHERE proposal_id=?;",
                ("2000-01-01T00:00:00+00:00", proposal_id),
            )

        # Analyst tries to approve the expired proposal — must be refused
        nonce = uuid.uuid4().hex
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            process_analyst_decision(
                proposal_id=proposal_id,
                decision="approve",
                analyst_id="test-analyst",
                nonce=nonce,
                db_path=self.db_path,
            )

        # Must be HTTP 400 Bad Request
        self.assertEqual(ctx.exception.status_code, 400,
                         "Expired proposal approval must return HTTP 400")
        self.assertIn("expired", ctx.exception.detail.lower(),
                      "Error detail must mention 'expired'")

        # Audit log must record the refusal
        entries = get_audit_entries(db_path=self.db_path)
        refusal_entries = [e for e in entries if e["action"] == "decision.refused_expired"]
        self.assertGreater(len(refusal_entries), 0,
                           "'decision.refused_expired' must be written to audit log")

    # =========================================================================
    # Test 4 — Allowlisted Target Rejection
    # =========================================================================

    def test_proof_of_skill_allowlisted_target_full_flow(self) -> None:
        """
        PROOF-OF-SKILL TEST 4: Protected allowlist target (10.0.0.1) must be refused.
        Verifies: HTTPException 403 raised; 'decision.allowlist_violation_blocked' in audit.
        """
        protected_ip = "10.0.0.1"   # hard-coded in config.PROTECTED_ALLOWLIST
        proposal_id = f"prop-allow-{uuid.uuid4().hex[:8]}"

        # Save a proposal whose target is the protected management host
        save_proposal(
            proposal_id=proposal_id,
            alert_id="E2E-ALLOW-001",
            action="block_ip",
            target=protected_ip,
            reason="Suspicious traffic from management host (allowlist test)",
            explanation="",
            confidence=0.70,
            db_path=self.db_path,
        )

        # Analyst attempts to approve — must be refused at HTTP 403
        nonce = uuid.uuid4().hex
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            process_analyst_decision(
                proposal_id=proposal_id,
                decision="approve",
                analyst_id="test-analyst",
                nonce=nonce,
                db_path=self.db_path,
            )

        # Must be HTTP 403 Forbidden
        self.assertEqual(ctx.exception.status_code, 403,
                         "Allowlisted target approval must return HTTP 403")
        self.assertIn("allowlist", ctx.exception.detail.lower(),
                      "Error detail must mention 'allowlist'")

        # Audit log must record the security violation
        entries = get_audit_entries(db_path=self.db_path)
        violation_entries = [e for e in entries
                             if e["action"] == "decision.allowlist_violation_blocked"]
        self.assertGreater(len(violation_entries), 0,
                           "'decision.allowlist_violation_blocked' must be written to audit log")

    # =========================================================================
    # Test 5 — WebSocket Event Replay After Disconnect
    # =========================================================================

    def test_websocket_event_replay_after_disconnect(self) -> None:
        """
        PROOF-OF-SKILL TEST 5: Reconnecting client must receive missed events via sync.request.
        Verifies: events after last_seen_id=1 are replayed; sync.complete is sent.
        """
        manager = ConnectionManager()

        # Broadcast 3 events into the SQLite events ledger (no live WS connections)
        run_coro(manager.broadcast("alert.new", {"alert_id": "REPLAY-E2E-001"}, db_path=self.db_path))
        run_coro(manager.broadcast("alert.update", {"alert_id": "REPLAY-E2E-002"}, db_path=self.db_path))
        run_coro(manager.broadcast("proposal.pending", {"proposal_id": "prop-rp-01"}, db_path=self.db_path))

        # Confirm all 3 are in the events ledger (last_seen_event_id=0 → fetch everything)
        all_events = get_events_since(last_seen_event_id=0, db_path=self.db_path)
        self.assertGreaterEqual(len(all_events), 3,
                                "All 3 events must be persisted in the events table")

        # Simulate a client reconnecting with last_seen_event_id=1
        # (should receive events 2 and 3)
        fake_ws = FakeWebSocket()
        manager.active_connections.add(fake_ws)

        run_coro(manager.handle_sync_request(
            websocket=fake_ws,
            last_seen_event_id=1,
            db_path=self.db_path,
        ))

        # Verify replay messages were sent.
        # Replayed events use wire format: {"event_id": N, "type": <event_type>, "is_replay": True, ...}
        # The sync.complete sentinel has "type": "sync.complete" and no "event_id".
        replay_events = [m for m in fake_ws.sent if m.get("is_replay") is True]
        self.assertGreaterEqual(len(replay_events), 2,
                                "At least 2 missed events must be replayed to the reconnecting client")

        # Verify the sync.complete sentinel was sent
        sync_complete = any(m.get("type") == "sync.complete" for m in fake_ws.sent)
        self.assertTrue(sync_complete,
                        "sync.complete sentinel must be sent after event replay finishes")

    # =========================================================================
    # Test 6 — Audit Chain Integrity After Full Flow
    # =========================================================================

    def test_audit_chain_integrity_after_full_flow(self) -> None:
        """
        PROOF-OF-SKILL TEST 6: Hash-chain audit log must be valid and have ≥5 entries
        after a complete attack-to-containment flow.
        """
        alert_id = "E2E-CHAIN-001"
        source_ip = "198.51.100.99"
        proposal_id = f"prop-chain-{uuid.uuid4().hex[:8]}"

        # Run the complete pipeline
        _, prop = run_attack_pipeline(alert_id, source_ip, proposal_id, self.db_path)
        self.assertIsNotNone(prop, "Pipeline must produce a pending proposal")

        # Analyst approves
        nonce = uuid.uuid4().hex
        decision_result = process_analyst_decision(
            proposal_id=prop["proposal_id"],
            decision="approve",
            analyst_id="test-analyst-chain",
            nonce=nonce,
            db_path=self.db_path,
        )

        # Executor applies the rule
        execute_approved_action(
            decision_result["signed_token"],
            dry_run=True,
            db_path=self.db_path,
        )

        # Verify audit chain
        # verify_audit_chain returns (valid: bool, checked_entries: int, error: Optional[str])
        chain_valid, chain_count, chain_err = verify_audit_chain(db_path=self.db_path)
        self.assertTrue(chain_valid,
                        f"Audit chain must be valid after full flow. Error: {chain_err}")

        # Must have at least 5 audit entries covering each stage of the flow
        self.assertGreaterEqual(chain_count, 5,
                                "Full flow must generate at least 5 audit log entries")


# ---------------------------------------------------------------------------
# Allow running directly: python -m backend.tests.test_e2e
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    unittest.main(verbosity=2)
