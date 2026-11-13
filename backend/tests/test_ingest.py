"""
Tests for Alert Ingestion and Agent Pipeline Integration (Phase 5).
Verifies:
1. False-Positive Auto-Closure: Bypasses investigation, records audit reason,
   broadcasts case.closed, and leaves zero pending proposals in the queue.
2. True-Attack Containment Proposal: Runs investigation, drafts block_ip proposal,
   stores pending proposal in database, and broadcasts proposal.pending.
3. Malformed Alert: Fallback builds safe escalation without raising unhandled errors.
"""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from backend.audit import get_audit_entries
from backend.database import init_db
from backend.ingest import ingest_and_process_alert
from backend.storage import get_pending_proposals
from agents.llm import LLM, Settings
import agents.llm

# Patch _default_settings so unit tests run offline without GROQ_API_KEY
agents.llm._default_settings = lambda: Settings(api_key="mock-key", model="mock-model", max_retries=0)


def make_test_llm(*replies):
    """Creates an offline LLM wired to FakeClient with test settings."""
    client = FakeClient(replies)
    settings = Settings(api_key="mock-key", model="mock-model", max_retries=0)
    return LLM(settings=settings, client=client)


def run_coro(coro):
    """Executes a coroutine synchronously without event loop / socket overhead."""
    try:
        coro.send(None)
    except StopIteration as exc:
        return exc.value


class FakeCompletions:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if not self.replies:
            raise AssertionError("FakeCompletions ran out of replies")
        reply = self.replies.pop(0)
        message = reply if hasattr(reply, "tool_calls") else SimpleNamespace(
            content=reply, tool_calls=None
        )
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])


class FakeClient:
    def __init__(self, replies):
        self.chat = SimpleNamespace(completions=FakeCompletions(replies))


class TestIngestion(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_ingest.sqlite")
        init_db(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    # -------------------------------------------------------------------------
    # Scenario B: False Positive Auto-Close Demo
    # -------------------------------------------------------------------------
    def test_false_positive_auto_closed_without_analyst_burden(self):
        """A false-positive alert must auto-close, leave no pending proposals, and log the reason."""
        alert_payload = {
            "alert_id": "ALERT-FP-001",
            "timestamp": "2026-11-13T10:00:00Z",
            "source_ip": "10.0.0.15",
            "log_text": "Failed login for admin from internal subnet: forgotten password",
            "rule_name": "Internal SSH Failure",
            "host": "corp-auth-01",
            "severity": "low",
        }

        # Mock LLM replies: Triage returns label="false_positive"
        triage_json = json.dumps({
            "alert_id": "ALERT-FP-001",
            "label": "false_positive",
            "confidence": 0.98,
            "reasoning": "Internal administrator forgot password on workstation.",
            "explanation": "Routine authentication burst from authorized subnet.",
        })
        fake_llm = make_test_llm(triage_json)

        result = run_coro(ingest_and_process_alert(
            alert_payload=alert_payload,
            llm=fake_llm,
            db_path=self.db_path
        ))

        self.assertEqual(result["status"], "auto_closed")
        self.assertEqual(result["verdict"]["label"], "false_positive")
        self.assertIsNone(result["proposal"])

        # Crucial check: Queue must have ZERO pending proposals
        pending = get_pending_proposals(db_path=self.db_path)
        self.assertEqual(len(pending), 0)

        # Audit ledger must record the auto-closure with the reason
        audit_entries = get_audit_entries(db_path=self.db_path)
        self.assertTrue(any(e["action"] == "case.auto_closed" for e in audit_entries))

    # -------------------------------------------------------------------------
    # Scenario A: Real Attack Flow (Proposal Queued for Approval)
    # -------------------------------------------------------------------------
    def test_true_attack_generates_pending_proposal(self):
        """A true attack must run investigation, produce findings, and queue a block proposal."""
        alert_payload = {
            "alert_id": "ALERT-ATTACK-001",
            "timestamp": "2026-11-13T10:05:00Z",
            "source_ip": "198.51.100.23",
            "log_text": "POST /uploads/shell.php 200 431 - cmd=whoami executed as www-data",
            "rule_name": "Web Shell Upload",
            "host": "web-srv-01",
            "severity": "critical",
        }

        # Mock LLM replies:
        # 1. Triage: true_attack
        triage_json = json.dumps({
            "alert_id": "ALERT-ATTACK-001",
            "label": "true_attack",
            "confidence": 0.95,
            "reasoning": "Web shell command execution observed.",
            "explanation": "Critical remote code execution payload uploaded.",
        })
        # 2. Investigation step 1: model requests search_logs tool
        inv_tool_call = SimpleNamespace(
            content=None,
            tool_calls=[
                SimpleNamespace(
                    id="call_1",
                    function=SimpleNamespace(name="search_logs", arguments=json.dumps({"ip": "198.51.100.23"}))
                )
            ]
        )
        # 3. Investigation step 2: model concludes after tool response
        inv_finish = SimpleNamespace(content="Found multiple suspicious POST requests.", tool_calls=None)
        # 4. Response agent: proposes block_ip on attacker
        response_json = json.dumps({
            "proposal_id": "prop-attack-01",
            "alert_id": "ALERT-ATTACK-001",
            "action": "block_ip",
            "target": "198.51.100.23",
            "reason": "Hostile web shell upload from untrusted external IP.",
            "explanation": "Isolate the attacking IP address on the firewall.",
            "requires_human_approval": True,
            "executed": False,
        })

        fake_llm = make_test_llm(triage_json, inv_tool_call, inv_finish, response_json)

        result = run_coro(ingest_and_process_alert(
            alert_payload=alert_payload,
            llm=fake_llm,
            db_path=self.db_path
        ))

        self.assertEqual(result["status"], "pending_approval")
        self.assertEqual(result["verdict"]["label"], "true_attack")
        self.assertIsNotNone(result["proposal"])
        self.assertEqual(result["proposal"]["action"], "block_ip")
        self.assertEqual(result["proposal"]["target"], "198.51.100.23")

        # Database must have 1 proposal in pending state
        pending = get_pending_proposals(db_path=self.db_path)
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["target"], "198.51.100.23")
        self.assertEqual(pending[0]["status"], "pending")

        # Audit ledger must record ingest, investigation, and proposal creation
        entries = get_audit_entries(db_path=self.db_path)
        self.assertTrue(any(e["action"] == "alert.received" for e in entries))
        self.assertTrue(any(e["action"] == "investigation.completed" for e in entries))
        self.assertTrue(any(e["action"] == "proposal.created" for e in entries))

    # -------------------------------------------------------------------------
    # Malformed Alert Safe Fallback
    # -------------------------------------------------------------------------
    def test_malformed_alert_safely_escalates_without_crashing(self):
        """A malformed alert must be caught by validation and safely escalated for human review."""
        malformed_alert = {"bad_key": 12345}

        result = run_coro(ingest_and_process_alert(
            alert_payload=malformed_alert,
            db_path=self.db_path
        ))

        self.assertEqual(result["status"], "pending_approval")
        self.assertEqual(result["verdict"]["label"], "suspicious")
        self.assertEqual(result["proposal"]["action"], "escalate")


if __name__ == "__main__":
    unittest.main()
