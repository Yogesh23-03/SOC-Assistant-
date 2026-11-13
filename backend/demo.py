"""
Agentic SOC Assistant — End-to-End Proof-of-Skill Demo (Phase 6 - M2 Lead).

Self-contained CLI script that demonstrates every critical safety invariant
without needing a live server or browser extension.

Proof-of-Skill Scenarios:
  1. Full Attack Containment Flow:  Alert → Pipeline → Proposal → Approve → Execute
  2. Forged Token Rejection:        Tampered HMAC signature must be refused by executor
  3. Expired Proposal Rejection:    Default-to-deny policy blocks stale approvals
  4. Allowlisted Target Rejection:  Protected IP (10.0.0.1) can never be blocked
  5. WebSocket Event Replay:        Missed events are replayed on reconnect via sync.request

Usage:
    cd SOC-Assistant-
    python -m backend.demo
"""

import json
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Offline groq stub — must run before any agents.* import
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

# Patch default settings to run offline (no GROQ_API_KEY required)
agents.llm._default_settings = lambda: Settings(
    api_key="demo-offline-key", model="mock-model", max_retries=0
)

from backend.approval import process_analyst_decision
from backend.audit import get_audit_entries, verify_audit_chain
from backend.database import init_db
from backend.executor import execute_approved_action, global_rate_limiter
from backend.ingest import ingest_and_process_alert
from backend.security import generate_signed_approval_token
from backend.storage import get_pending_proposals, save_proposal
from backend.websocket_manager import ConnectionManager


# ---------------------------------------------------------------------------
# ANSI Colour Helpers
# ---------------------------------------------------------------------------
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

PASS = f"{GREEN}[PASS]{RESET}"
FAIL = f"{RED}[FAIL]{RESET}"


def banner(title: str) -> None:
    """Prints a decorated section banner."""
    width = 70
    print(f"\n{BOLD}{CYAN}{'=' * width}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * width}{RESET}")


def step(label: str, detail: str = "") -> None:
    """Prints a formatted demo step."""
    suffix = f"  {YELLOW}{detail}{RESET}" if detail else ""
    print(f"  {CYAN}>>{RESET} {label}{suffix}")


def result(label: str, ok: bool, detail: str = "") -> None:
    """Prints PASS / FAIL result with optional detail."""
    badge = PASS if ok else FAIL
    suffix = f"  ({detail})" if detail else ""
    print(f"  {badge}  {label}{suffix}")


# ---------------------------------------------------------------------------
# Offline FakeClient — no network calls
# ---------------------------------------------------------------------------
class FakeCompletions:
    """Returns pre-canned LLM replies one by one (simulates Groq API)."""

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
    """Builds an offline LLM configured with canned replies."""
    return LLM(
        settings=Settings(api_key="demo-offline-key", model="mock-model", max_retries=0),
        client=FakeClient(replies),
    )


# ---------------------------------------------------------------------------
# Coroutine helper (avoids asyncio.run() which hangs on Windows sandbox)
# ---------------------------------------------------------------------------
def run_coro(coro: Any) -> Any:
    """Drives a single-step async coroutine to completion without an event loop."""
    try:
        coro.send(None)
    except StopIteration as exc:
        return exc.value


# ---------------------------------------------------------------------------
# LLM reply factories — build realistic JSON for each agent
# ---------------------------------------------------------------------------

def _triage_attack_reply(alert_id: str, source_ip: str) -> str:
    return json.dumps({
        "alert_id": alert_id,
        "label": "true_attack",
        "confidence": 0.95,
        "reasoning": "Web shell command execution observed with reverse-shell patterns.",
        "explanation": "Critical RCE payload uploaded; attacker likely establishing persistence.",
    })


def _investigation_tool_call_reply(source_ip: str) -> SimpleNamespace:
    return SimpleNamespace(
        content=None,
        tool_calls=[
            SimpleNamespace(
                id="call_demo_1",
                function=SimpleNamespace(
                    name="search_logs",
                    arguments=json.dumps({"ip": source_ip})
                )
            )
        ]
    )


def _investigation_finish_reply(source_ip: str) -> str:
    return f"Found 47 suspicious POST requests from {source_ip} to /upload.php in last 10 minutes."


def _response_block_reply(alert_id: str, source_ip: str, proposal_id: str) -> str:
    return json.dumps({
        "proposal_id": proposal_id,
        "alert_id": alert_id,
        "action": "block_ip",
        "target": source_ip,
        "reason": f"Hostile web shell uploaded from {source_ip}.",
        "explanation": "Block attacker at the perimeter firewall to halt further exploitation.",
        "requires_human_approval": True,
        "executed": False,
    })


# ===========================================================================
# SCENARIO 1 — Full Attack-to-Containment Flow
# ===========================================================================

def demo_full_attack_flow(db_path: str) -> bool:
    """
    Demonstrates the complete happy path:
    SIEM alert → pipeline → pending proposal → analyst approves →
    signed HMAC token → executor applies iptables rule.
    """
    banner("SCENARIO 1 — Full Attack-to-Containment Flow")

    alert_id = "DEMO-A-001"
    source_ip = "198.51.100.42"
    proposal_id = f"prop-{uuid.uuid4().hex[:8]}"

    # --- Stage 1: Ingest Alert ---
    step("Ingesting SIEM alert", f"alert_id={alert_id}  source_ip={source_ip}")
    alert_payload = {
        "alert_id": alert_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "log_text": "POST /upload.php 200 — eval(base64_decode($_POST['c']))",
        "rule_name": "Web Shell Upload Detected",
        "host": "web-srv-01",
        "severity": "critical",
    }
    llm = make_llm(
        _triage_attack_reply(alert_id, source_ip),
        _investigation_tool_call_reply(source_ip),
        _investigation_finish_reply(source_ip),
        _response_block_reply(alert_id, source_ip, proposal_id),
    )
    ingest_result = run_coro(ingest_and_process_alert(alert_payload, llm=llm, db_path=db_path))
    ok_stage1 = ingest_result["status"] == "pending_approval"
    result("Alert ingested; proposal queued as 'pending'", ok_stage1,
           f"status={ingest_result['status']}")

    # --- Stage 2: Retrieve pending proposal ---
    step("Retrieving pending proposals from analyst queue")
    pending = get_pending_proposals(db_path=db_path)
    # Find our specific proposal
    prop = next((p for p in pending if p["alert_id"] == alert_id), None)
    ok_stage2 = prop is not None and prop["status"] == "pending"
    result("Proposal visible in analyst queue", ok_stage2,
           f"proposal_id={prop['proposal_id'] if prop else 'NOT FOUND'}")

    if not prop:
        return False

    # --- Stage 3: Analyst approves ---
    step("Analyst submitting APPROVE decision", f"target={prop['target']}")
    nonce = uuid.uuid4().hex
    decision_result = process_analyst_decision(
        proposal_id=prop["proposal_id"],
        decision="approve",
        analyst_id="analyst-demo",
        nonce=nonce,
        db_path=db_path,
    )
    ok_stage3 = (
        decision_result["decision"] == "approved"
        and decision_result["signed_token"] is not None
    )
    result("Analyst decision accepted; HMAC token issued", ok_stage3,
           f"sig_prefix={decision_result['signed_token']['signature'][:16]}…")

    # --- Stage 4: Executor applies firewall rule ---
    step("Executor validating token and applying iptables rule (dry-run)")
    global_rate_limiter.reset()   # ensure rate limit is clean
    signed_token = decision_result["signed_token"]
    exec_result = execute_approved_action(signed_token, dry_run=True, db_path=db_path)
    ok_stage4 = exec_result["status"] == "success"
    result("Firewall rule applied (dry-run)", ok_stage4,
           f"target={exec_result['target']}  expires_at={exec_result['expires_at'][:19]}")

    # --- Stage 5: Audit chain integrity ---
    step("Verifying hash-chained audit log integrity")
    # verify_audit_chain returns (valid: bool, checked_entries: int, error: Optional[str])
    chain_valid, chain_count, chain_err = verify_audit_chain(db_path=db_path)
    ok_stage5 = chain_valid is True
    result("Audit chain is intact", ok_stage5, f"entries={chain_count}")

    # Print a subset of audit events for demo readability
    entries = get_audit_entries(db_path=db_path)
    print(f"\n  {BOLD}Audit trail for this flow:{RESET}")
    for e in entries:
        print(f"    [{e['timestamp'][:19]}] {e['actor']:22s} -> {e['action']}")

    overall = all([ok_stage1, ok_stage2, ok_stage3, ok_stage4, ok_stage5])
    return overall


# ===========================================================================
# SCENARIO 2 — Forged Token Rejection (Proof-of-Skill)
# ===========================================================================

def demo_forged_token_rejection(db_path: str) -> bool:
    """
    Demonstrates that the executor rejects a cryptographically forged token and
    writes 'executor.refused_invalid_token' to the audit log.
    """
    banner("SCENARIO 2 — Forged HMAC Token Rejection")

    # Build a valid token first…
    prop = {
        "proposal_id": f"prop-forge-{uuid.uuid4().hex[:8]}",
        "action": "block_ip",
        "target": "10.20.30.40",
        "expires_at": "2099-01-01T00:00:00+00:00",
        "ttl_seconds": 3600,
    }
    nonce = uuid.uuid4().hex
    valid_token = generate_signed_approval_token(proposal=prop, nonce=nonce)

    # …then tamper the first character of the signature (guaranteed to change decoded bytes)
    original_sig = valid_token["signature"]
    # Flip first hex char so the signature always differs
    first_char = original_sig[0]
    tampered_char = "0" if first_char != "0" else "1"
    forged_token = dict(valid_token)
    forged_token["signature"] = tampered_char + original_sig[1:]

    step("Submitting tampered HMAC token to executor")
    rejected = False
    try:
        execute_approved_action(forged_token, dry_run=True, db_path=db_path)
    except PermissionError as exc:
        rejected = True
        step("Executor raised PermissionError", str(exc)[:60])

    # Verify audit log recorded the refusal
    entries = get_audit_entries(db_path=db_path)
    logged = any(e["action"] == "executor.refused_invalid_token" for e in entries)

    result("Forged token rejected by executor", rejected)
    result("'executor.refused_invalid_token' written to audit log", logged)
    return rejected and logged


# ===========================================================================
# SCENARIO 3 — Expired Proposal Rejection (Proof-of-Skill)
# ===========================================================================

def demo_expired_proposal_rejection(db_path: str) -> bool:
    """
    Demonstrates the default-to-deny policy: a proposal whose TTL has elapsed
    can never be approved, even by a valid analyst.
    """
    banner("SCENARIO 3 — Expired Proposal Rejection (Default-to-Deny)")

    proposal_id = f"prop-expired-{uuid.uuid4().hex[:8]}"
    # Save a proposal with an expiry timestamp in the past
    past_expires = "2000-01-01T00:00:00+00:00"
    save_proposal(
        proposal_id=proposal_id,
        alert_id="DEMO-EXP-001",
        action="block_ip",
        target="10.20.30.50",
        reason="Stale demo proposal for expiry test",
        explanation="",
        confidence=0.90,
        db_path=db_path,
    )

    # Manually force the expiry timestamp to the past using direct DB access
    from backend.database import get_db
    with get_db(db_path) as conn:
        conn.execute(
            "UPDATE proposals SET status='expired', expires_at=? WHERE proposal_id=?;",
            (past_expires, proposal_id),
        )

    step("Submitting APPROVE decision on expired proposal", f"proposal_id={proposal_id}")
    rejected = False
    nonce = uuid.uuid4().hex
    try:
        process_analyst_decision(
            proposal_id=proposal_id,
            decision="approve",
            analyst_id="analyst-demo",
            nonce=nonce,
            db_path=db_path,
        )
    except Exception as exc:
        # FastAPI HTTPException carries a 'detail' field
        detail = getattr(exc, "detail", str(exc))
        rejected = "expired" in detail.lower() or "default-to-deny" in detail.lower()
        step("Backend raised exception", detail[:70])

    # Verify audit log recorded the refusal
    entries = get_audit_entries(db_path=db_path)
    logged = any(e["action"] == "decision.refused_expired" for e in entries)

    result("Expired proposal rejected (default-to-deny)", rejected)
    result("'decision.refused_expired' written to audit log", logged)
    return rejected and logged


# ===========================================================================
# SCENARIO 4 — Allowlisted Target Rejection (Proof-of-Skill)
# ===========================================================================

def demo_allowlisted_target_rejection(db_path: str) -> bool:
    """
    Demonstrates that the protected allowlist invariant is enforced:
    no one — not even a valid analyst — can approve blocking 10.0.0.1.
    """
    banner("SCENARIO 4 — Protected Allowlist Target Rejection")

    protected_ip = "10.0.0.1"   # hard-coded in config.PROTECTED_ALLOWLIST
    proposal_id = f"prop-allow-{uuid.uuid4().hex[:8]}"

    save_proposal(
        proposal_id=proposal_id,
        alert_id="DEMO-ALLOW-001",
        action="block_ip",
        target=protected_ip,   # deliberately targeting the management host
        reason="Suspicious traffic from management host (demo test)",
        explanation="",
        confidence=0.70,
        db_path=db_path,
    )

    step("Analyst attempting to approve block on protected IP", f"target={protected_ip}")
    rejected = False
    nonce = uuid.uuid4().hex
    try:
        process_analyst_decision(
            proposal_id=proposal_id,
            decision="approve",
            analyst_id="analyst-demo",
            nonce=nonce,
            db_path=db_path,
        )
    except Exception as exc:
        detail = getattr(exc, "detail", str(exc))
        # Expect HTTP 403 with 'allowlist' in detail
        rejected = "allowlist" in detail.lower() or "protected" in detail.lower()
        step("Backend raised exception", detail[:70])

    # Allowlist violation should be in audit log
    entries = get_audit_entries(db_path=db_path)
    logged = any(e["action"] == "decision.allowlist_violation_blocked" for e in entries)

    result("Allowlisted target blocked (HTTP 403)", rejected)
    result("'decision.allowlist_violation_blocked' written to audit log", logged)
    return rejected and logged


# ===========================================================================
# SCENARIO 5 — WebSocket Event Replay (Proof-of-Skill)
# ===========================================================================

def demo_websocket_event_replay(db_path: str) -> bool:
    """
    Demonstrates that the WebSocket sync.request mechanism replays missed events
    for a reconnecting extension session.

    Flow:
      1. Broadcast 3 events (simulating a disconnected client)
      2. Client reconnects and sends sync.request with last_seen_event_id=1
      3. Assert that events 2 & 3 are replayed and sync.complete is sent
    """
    banner("SCENARIO 5 — WebSocket Event Replay (Reconnect & Catch-Up)")

    manager = ConnectionManager()

    # --- Broadcast 3 events into the SQLite events ledger ---
    step("Broadcasting 3 events (client was disconnected)")
    run_coro(manager.broadcast("alert.new",    {"alert_id": "REPLAY-001"}, db_path=db_path))
    run_coro(manager.broadcast("alert.update", {"alert_id": "REPLAY-002"}, db_path=db_path))
    run_coro(manager.broadcast("proposal.pending", {"proposal_id": "prop-rp-01"}, db_path=db_path))

    # Verify all 3 were persisted
    from backend.storage import get_events_since
    all_events = get_events_since(last_seen_event_id=0, db_path=db_path)
    result("3 events persisted to SQLite events ledger", len(all_events) >= 3,
           f"count={len(all_events)}")

    # --- Simulate a WebSocket connection with event replay ---
    step("Client reconnects; sends sync.request with last_seen_event_id=1")

    # We capture the messages sent back via a fake WebSocket
    class FakeWebSocket:
        """Minimal fake WebSocket that records sent JSON messages. Hashable for set storage."""

        def __init__(self) -> None:
            self.sent: List[Dict[str, Any]] = []

        async def send_json(self, data: Dict[str, Any]) -> None:  # noqa: D401
            self.sent.append(data)

        async def send_text(self, text: str) -> None:
            """Replay uses send_text; decode to dict for assertion convenience."""
            import json as _j
            self.sent.append(_j.loads(text))

        async def receive_json(self) -> Dict[str, Any]:
            return {}  # not used in handle_sync_request

        def __hash__(self) -> int:
            return id(self)

        def __eq__(self, other: object) -> bool:
            return self is other

    fake_ws = FakeWebSocket()
    # Inject it into the manager's active connections set
    manager.active_connections.add(fake_ws)

    # Trigger event replay for events after id=1
    run_coro(manager.handle_sync_request(
        websocket=fake_ws,
        last_seen_event_id=1,
        db_path=db_path
    ))

    # --- Validate replay output ---
    # Replayed events have "is_replay": True; sync.complete sentinel has "type": "sync.complete"
    sync_complete_sent = any(msg.get("type") == "sync.complete" for msg in fake_ws.sent)
    replay_events = [m for m in fake_ws.sent if m.get("is_replay") is True]

    result(f"Missed events replayed to reconnecting client", len(replay_events) >= 2,
           f"replayed_count={len(replay_events)}")
    result("sync.complete sentinel sent after replay", sync_complete_sent)

    return len(replay_events) >= 2 and sync_complete_sent


# ===========================================================================
# MAIN ENTRY POINT
# ===========================================================================

def main() -> None:
    """Runs all Proof-of-Skill scenarios in sequence against a fresh temp DB."""
    print(f"\n{BOLD}{'=' * 70}")
    print("   Agentic SOC Assistant — Proof-of-Skill Demo (M2 Backend)")
    print(f"{'=' * 70}{RESET}")
    print("  Running all 5 scenarios against a temporary in-memory SQLite DB.")
    print("  Every scenario prints structured step logs and a PASS / FAIL badge.\n")

    # Use a temporary directory so each demo run starts clean
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = str(Path(tmp_dir) / "demo_soc.sqlite")
        init_db(db_path)
        global_rate_limiter.reset()

        outcomes: Dict[str, bool] = {}

        # Run scenarios sequentially; each uses the same DB (cumulative audit trail)
        outcomes["1. Full Attack-to-Containment"] = demo_full_attack_flow(db_path)
        outcomes["2. Forged Token Rejection"] = demo_forged_token_rejection(db_path)
        outcomes["3. Expired Proposal Rejection"] = demo_expired_proposal_rejection(db_path)
        outcomes["4. Allowlisted Target Rejection"] = demo_allowlisted_target_rejection(db_path)
        outcomes["5. WebSocket Event Replay"] = demo_websocket_event_replay(db_path)

        # --- Summary ---
        banner("DEMO SUMMARY")
        all_passed = True
        for scenario, passed in outcomes.items():
            badge = PASS if passed else FAIL
            print(f"  {badge}  {scenario}")
            if not passed:
                all_passed = False

        print()
        if all_passed:
            print(f"  {GREEN}{BOLD}ALL PROOF-OF-SKILL SCENARIOS PASSED [OK]{RESET}\n")
        else:
            print(f"  {RED}{BOLD}SOME SCENARIOS FAILED -- see output above [FAIL]{RESET}\n")
            sys.exit(1)


if __name__ == "__main__":
    main()
