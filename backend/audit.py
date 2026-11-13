"""
Cryptographic Hash-Chained Audit Log Manager (M2 Security Requirement).
Guarantees tamper-evidence for all security actions, agent verdicts, and human approvals.

Every entry links to the previous entry using SHA-256:
  entry_hash = SHA256(prev_hash + ":" + timestamp + ":" + actor + ":" + action + ":" + details)
The first entry (entry_id = 1) links to a 64-character zero genesis hash.
If any past row in the database is modified or deleted, the hash chain breaks.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.database import get_db

# Genesis hash for the initial entry in the chain
GENESIS_HASH = "0" * 64


def get_utc_timestamp() -> str:
    """Returns current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def compute_entry_hash(prev_hash: str, timestamp: str, actor: str, action: str, details: str) -> str:
    """
    Computes a deterministic SHA-256 hash for an audit log entry.
    All fields are serialized consistently to ensure reproducible hashes.
    """
    raw_payload = f"{prev_hash}:{timestamp}:{actor}:{action}:{details}".encode("utf-8")
    return hashlib.sha256(raw_payload).hexdigest()


def log_audit_event(
    actor: str,
    action: str,
    details: Any,
    timestamp: Optional[str] = None,
    db_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Appends a new event to the audit log, chaining it to the previous entry's hash.

    Args:
        actor: System component or user (e.g. 'analyst.john', 'agent.triage', 'executor')
        action: Event name (e.g. 'alert.ingested', 'proposal.approved', 'firewall.rule_added')
        details: Payload dictionary or string describing the event
        timestamp: Optional ISO timestamp override (defaults to current UTC time)
        db_path: Optional SQLite DB path override (useful for testing)

    Returns:
        The newly inserted audit entry as a dictionary.
    """
    ts = timestamp or get_utc_timestamp()
    details_str = json.dumps(details, sort_keys=True) if isinstance(details, (dict, list)) else str(details)

    with get_db(db_path) as conn:
        # 1. Fetch the hash of the latest entry
        cursor = conn.execute("SELECT entry_hash FROM audit_log ORDER BY entry_id DESC LIMIT 1;")
        row = cursor.fetchone()
        prev_hash = row["entry_hash"] if row else GENESIS_HASH

        # 2. Compute the current entry's hash
        entry_hash = compute_entry_hash(prev_hash, ts, actor, action, details_str)

        # 3. Store in the append-only database table
        cursor = conn.execute(
            """
            INSERT INTO audit_log (timestamp, actor, action, details, prev_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            (ts, actor, action, details_str, prev_hash, entry_hash)
        )
        entry_id = cursor.lastrowid

        return {
            "entry_id": entry_id,
            "timestamp": ts,
            "actor": actor,
            "action": action,
            "details": details_str,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
        }


def get_audit_entries(
    limit: int = 100,
    offset: int = 0,
    db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieves paginated audit log entries ordered from oldest to newest."""
    with get_db(db_path) as conn:
        cursor = conn.execute(
            """
            SELECT entry_id, timestamp, actor, action, details, prev_hash, entry_hash
            FROM audit_log
            ORDER BY entry_id ASC
            LIMIT ? OFFSET ?;
            """,
            (limit, offset)
        )
        return [dict(row) for row in cursor.fetchall()]


def verify_audit_chain(db_path: Optional[str] = None) -> Tuple[bool, int, Optional[str]]:
    """
    Verifies the complete cryptographic integrity of the audit log hash chain.

    Returns:
        (is_valid, total_entries_checked, error_message_if_any)
    """
    with get_db(db_path) as conn:
        cursor = conn.execute(
            """
            SELECT entry_id, timestamp, actor, action, details, prev_hash, entry_hash
            FROM audit_log
            ORDER BY entry_id ASC;
            """
        )
        rows = cursor.fetchall()

    if not rows:
        return True, 0, None

    expected_prev = GENESIS_HASH

    for idx, row in enumerate(rows):
        entry_id = row["entry_id"]
        ts = row["timestamp"]
        actor = row["actor"]
        action = row["action"]
        details = row["details"]
        stored_prev = row["prev_hash"]
        stored_entry = row["entry_hash"]

        # Check 1: Does the row point to the correct previous hash?
        if stored_prev != expected_prev:
            return (
                False,
                idx,
                f"Broken chain at entry {entry_id}: expected prev_hash '{expected_prev}', found '{stored_prev}'"
            )

        # Check 2: Does the row's hash match its actual content?
        recalculated_hash = compute_entry_hash(stored_prev, ts, actor, action, details)
        if stored_entry != recalculated_hash:
            return (
                False,
                idx,
                f"Tampered data at entry {entry_id}: stored hash '{stored_entry}' does not match recalculation '{recalculated_hash}'"
            )

        # Next row must point to this row's entry_hash
        expected_prev = stored_entry

    return True, len(rows), None
