"""
Signed-Token Firewall Executor & Linux iptables Integration (M2 Lead).
Executes containment actions on the target VM only after validating cryptographic HMAC tokens.

Safety Rails Enforced:
1. Cryptographic HMAC token verification (rejects forged/tampered tokens).
2. Default-to-deny expiration checks (rejects expired approval tokens).
3. Hardcoded allowlist protection (10.0.0.1, 127.0.0.1, gateway can NEVER be blocked).
4. Strict IPv4 schema validation (prevents command injection via target string).
5. Sliding-window rate limiting (prevents runaway blocking cascades).
6. Automatic rule TTL and expiration cleanup.
"""

import ipaddress
import json
import logging
import platform
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.audit import get_utc_timestamp, log_audit_event
from backend.config import PROTECTED_ALLOWLIST
from backend.database import get_db
from backend.security import verify_approval_token

logger = logging.getLogger("soc_backend.executor")


class RateLimitError(RuntimeError):
    pass


class TokenReplayError(RuntimeError):
    pass


class RateLimiter:
    """
    Sliding-window rate limiter.
    Limits containment executions to prevent denial of service or runaway cascades.
    """

    def __init__(self, max_requests: int = 5, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.history: List[float] = []

    def allow_request(self) -> Tuple[bool, Optional[str]]:
        now = time.time()
        # Prune timestamps outside current sliding window
        self.history = [ts for ts in self.history if now - ts < self.window_seconds]

        if len(self.history) >= self.max_requests:
            remaining = int(self.window_seconds - (now - self.history[0]))
            return False, f"Rate limit exceeded: max {self.max_requests} blocks per {self.window_seconds}s. Retry in {remaining}s."

        self.history.append(now)
        return True, None

    def reset(self) -> None:
        """Clears execution history (useful for tests)."""
        self.history.clear()


# Global rate limiter instance (5 blocks per minute)
global_rate_limiter = RateLimiter(max_requests=5, window_seconds=60)


def validate_ipv4_target(target: str) -> Tuple[bool, Optional[str]]:
    """
    Validates that target is a strict, standard IPv4 address.
    Rejects hostnames, CIDR masks (e.g. 0.0.0.0/0), shell characters, and invalid octets.
    """
    if not target or not isinstance(target, str):
        return False, "Target must be a non-empty string"

    target_clean = target.strip()
    try:
        addr = ipaddress.ip_address(target_clean)
        if addr.version != 4:
            return False, f"IPv6 addresses are not currently supported: '{target_clean}'"
        return True, None
    except ValueError:
        return False, f"Invalid IPv4 address format: '{target_clean}'"


def run_iptables_command(args: List[str], dry_run: bool = False) -> Tuple[int, str, str]:
    """
    Runs an iptables command safely.
    Only explicit dry_run simulates commands; real execution requires Linux.
    """
    cmd = ["iptables"] + args
    is_linux = platform.system().lower() == "linux"

    if not dry_run and not is_linux:
        return 1, "", "Unsupported platform: real firewall execution requires Linux"

    if dry_run:
        mock_output = f"[MOCK/DRY-RUN] {' '.join(cmd)}"
        logger.info(mock_output)
        return 0, mock_output, ""

    try:
        # Prepend sudo on Linux if not root
        full_cmd = ["sudo", "iptables"] + args
        proc = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False
        )
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:
        logger.error(f"Failed to execute iptables command: {exc}")
        return 1, "", str(exc)


def apply_iptables_block(target_ip: str, dry_run: bool = False) -> Tuple[bool, str]:
    """
    Applies an iptables DROP rule for target_ip.
    Checks if rule already exists before appending to prevent duplicate rules.
    """
    # 1. Check if rule already exists: iptables -C INPUT -s <target_ip> -j DROP
    retcode, _, _ = run_iptables_command(["-C", "INPUT", "-s", target_ip, "-j", "DROP"], dry_run=dry_run)
    if retcode == 0 and not dry_run:
        return True, f"Rule for {target_ip} already present in iptables"

    # 2. Append rule: iptables -A INPUT -s <target_ip> -j DROP
    retcode, stdout, stderr = run_iptables_command(["-A", "INPUT", "-s", target_ip, "-j", "DROP"], dry_run=dry_run)
    if retcode == 0:
        return True, f"Successfully blocked {target_ip} via iptables"
    return False, f"iptables error: {stderr.strip() or stdout.strip()}"


def remove_iptables_block(target_ip: str, dry_run: bool = False) -> Tuple[bool, str]:
    """
    Deletes an iptables DROP rule for target_ip.
    """
    retcode, stdout, stderr = run_iptables_command(["-D", "INPUT", "-s", target_ip, "-j", "DROP"], dry_run=dry_run)
    if retcode == 0:
        return True, f"Successfully unblocked {target_ip}"
    return False, f"Failed to delete rule for {target_ip}: {stderr.strip() or stdout.strip()}"


# -----------------------------------------------------------------------------
# Active Blocks & Rule Expiration
# -----------------------------------------------------------------------------

def record_active_block(
    target: str,
    proposal_id: str,
    ttl_seconds: int = 3600,
    db_path: Optional[str] = None
) -> Dict[str, Any]:
    """Records an applied firewall block with its expiration timestamp in SQLite."""
    now_ts = get_utc_timestamp()
    now_dt = datetime.fromisoformat(now_ts)
    expires_at = datetime.fromtimestamp(now_dt.timestamp() + ttl_seconds, timezone.utc).isoformat()

    with get_db(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO active_blocks (target, proposal_id, blocked_at, expires_at, status)
            VALUES (?, ?, ?, ?, 'active');
            """,
            (target, proposal_id, now_ts, expires_at)
        )

    return {
        "target": target,
        "proposal_id": proposal_id,
        "blocked_at": now_ts,
        "expires_at": expires_at,
        "status": "active"
    }


def list_active_blocks(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Returns all currently active firewall blocks."""
    with get_db(db_path) as conn:
        cursor = conn.execute(
            """
            SELECT target, proposal_id, blocked_at, expires_at, status
            FROM active_blocks
            WHERE status = 'active'
            ORDER BY blocked_at DESC;
            """
        )
        return [dict(row) for row in cursor.fetchall()]


def expire_active_blocks(dry_run: bool = False, db_path: Optional[str] = None) -> List[str]:
    """
    Queries active blocks whose TTL deadline has passed, removes their iptables rules,
    and updates their status to 'expired'.
    """
    now_ts = get_utc_timestamp()
    expired_targets: List[str] = []
    completed_rows = []

    with get_db(db_path) as conn:
        cursor = conn.execute(
            """
            SELECT target, proposal_id, expires_at
            FROM active_blocks
            WHERE status = 'active' AND expires_at < ?;
            """,
            (now_ts,)
        )
        overdue_rows = [dict(row) for row in cursor.fetchall()]

        for row in overdue_rows:
            target_ip = row["target"]
            # Remove from firewall
            success, message = remove_iptables_block(target_ip, dry_run=dry_run)
            if not success or dry_run:
                logger.warning("Rule removal not committed for %s: %s", target_ip, message)
                continue
            completed_rows.append(row)

            # Update DB status
            conn.execute(
                "UPDATE active_blocks SET status = 'expired' WHERE target = ?;",
                (target_ip,)
            )

    # Record in audit log after committing the update transaction
    for row in completed_rows:
        target_ip = row["target"]
        log_audit_event(
            actor="executor.reaper",
            action="firewall.rule_expired",
            details={"target": target_ip, "proposal_id": row["proposal_id"]},
            db_path=db_path
        )
        expired_targets.append(target_ip)

    return expired_targets


# -----------------------------------------------------------------------------
# Main Execution Entry Point
# -----------------------------------------------------------------------------

def execute_approved_action(
    token_data: Dict[str, Any],
    dry_run: bool = False,
    secret_key: Optional[str] = None,
    db_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    High-Security Containment Executor.
    Validates token signature, checks safety rails, and applies iptables rule.

    Raises:
        ValueError / PermissionError on any security violation.
    """
    # 1. Verification 1: Cryptographic HMAC Signature & Expiry
    is_valid, sig_err = verify_approval_token(token_data, secret_key=secret_key)
    if not is_valid:
        log_audit_event(
            actor="executor",
            action="executor.refused_invalid_token",
            details={"error": sig_err, "token_proposal_id": token_data.get("proposal_id")},
            db_path=db_path
        )
        raise PermissionError(f"Security refusal: {sig_err}")

    target = token_data["target"]
    action = token_data["action"]
    proposal_id = token_data["proposal_id"]
    ttl_seconds = token_data.get("ttl_seconds", 3600)

    # 2. Verification 2: Strict Action Schema
    if action != "block_ip":
        log_audit_event(
            actor="executor",
            action="executor.refused_unknown_action",
            details={"action": action, "proposal_id": proposal_id},
            db_path=db_path
        )
        raise ValueError(f"Executor only supports action 'block_ip'. Received '{action}'")

    # 3. Verification 3: IPv4 Schema Validation
    ip_ok, ip_err = validate_ipv4_target(target)
    if not ip_ok:
        log_audit_event(
            actor="executor",
            action="executor.refused_malformed_ip",
            details={"target": target, "error": ip_err},
            db_path=db_path
        )
        raise ValueError(f"Target validation failed: {ip_err}")

    # 4. Verification 4: Defense-in-Depth Allowlist Check
    if target in PROTECTED_ALLOWLIST:
        log_audit_event(
            actor="executor",
            action="executor.refused_allowlisted_target",
            details={"target": target, "proposal_id": proposal_id},
            db_path=db_path
        )
        raise PermissionError(f"Safety invariant violated: Target '{target}' is on the protected allowlist and can NEVER be blocked.")

    # Commit a reservation before the OS operation: uncertain execution fails closed.
    with get_db(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        execution_nonce = "executor:" + token_data["signature"]
        if conn.execute("SELECT 1 FROM used_nonces WHERE nonce = ?", (execution_nonce,)).fetchone():
            raise TokenReplayError("Executor token already spent")
        proposal = conn.execute("SELECT * FROM proposals WHERE proposal_id = ?", (proposal_id,)).fetchone()
        if not proposal or proposal["status"] != "approved":
            raise PermissionError("Proposal must still be approved at execution time")
        if any(proposal[field] != token_data[field] for field in ("action", "target", "ttl_seconds", "expires_at")):
            raise PermissionError("Token does not match the approved proposal")
        if not dry_run:
            conn.execute("INSERT INTO used_nonces (nonce, proposal_id, used_at) VALUES (?, ?, ?)",
                         (execution_nonce, proposal_id, get_utc_timestamp()))
    # 5. Verification 5: Sliding-Window Rate Limiting
    rate_ok, rate_err = global_rate_limiter.allow_request()
    if not rate_ok:
        log_audit_event(
            actor="executor",
            action="executor.refused_rate_limit",
            details={"target": target, "error": rate_err},
            db_path=db_path
        )
        raise RateLimitError(rate_err)

    success, msg = apply_iptables_block(target, dry_run=dry_run)
    if not success:
        log_audit_event(actor="executor", action="executor.iptables_failure",
                        details={"target": target, "error": msg}, db_path=db_path)
        raise RuntimeError(f"Firewall execution failed: {msg}")
    if dry_run:
        log_audit_event(actor="executor", action="firewall.simulated",
                        details={"proposal_id": proposal_id, "target": target}, db_path=db_path)
        return {"status": "simulated", "action": action, "target": target, "proposal_id": proposal_id}
    block_record = record_active_block(target, proposal_id, ttl_seconds, db_path)

    # 8. Record in Tamper-Evident Audit Ledger
    log_audit_event(
        actor="executor",
        action="firewall.rule_applied",
        details={
            "proposal_id": proposal_id,
            "target": target,
            "action": action,
            "ttl_seconds": ttl_seconds,
            "expires_at": block_record["expires_at"],
            "iptables_result": msg,
        },
        db_path=db_path
    )

    return {
        "status": "success",
        "action": action,
        "target": target,
        "proposal_id": proposal_id,
        "blocked_at": block_record["blocked_at"],
        "expires_at": block_record["expires_at"],
        "message": msg,
    }
