"""
Storage Layer for Proposals and Real-Time Event Ledger (M2 Lead).
Manages state persistence for the analyst queue and WebSocket event streams.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.audit import get_utc_timestamp
from backend.database import get_db


# -----------------------------------------------------------------------------
# Proposals Management
# -----------------------------------------------------------------------------

def save_proposal(
    proposal_id: str,
    alert_id: str,
    action: str,
    target: str,
    reason: str,
    explanation: Optional[str] = None,
    confidence: float = 0.0,
    ttl_seconds: int = 3600,
    expires_at: Optional[str] = None,
    db_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Saves a new pending proposal from M1 Response agent into the database.
    """
    now_ts = get_utc_timestamp()
    if not expires_at:
        # Default 5-minute expiry if not specified
        now_dt = datetime.fromisoformat(now_ts)
        expires_at = datetime.fromtimestamp(now_dt.timestamp() + 300, timezone.utc).isoformat()

    with get_db(db_path) as conn:
        conn.execute(
            """
            INSERT INTO proposals (
                proposal_id, alert_id, action, target, reason, explanation,
                status, confidence, ttl_seconds, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?);
            """,
            (
                proposal_id, alert_id, action, target, reason,
                explanation or "", confidence, ttl_seconds, now_ts, expires_at
            )
        )

    return get_proposal(proposal_id, db_path=db_path)  # type: ignore


def get_proposal(proposal_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieves a proposal by its unique ID.
    Automatically checks and marks expired proposals if their deadline has passed.
    """
    with get_db(db_path) as conn:
        cursor = conn.execute(
            """
            SELECT proposal_id, alert_id, action, target, reason, explanation,
                   status, confidence, ttl_seconds, created_at, expires_at,
                   decision_by, decision_at
            FROM proposals
            WHERE proposal_id = ?;
            """,
            (proposal_id,)
        )
        row = cursor.fetchone()
        if not row:
            return None

        data = dict(row)

        # Check if pending proposal has expired
        if data["status"] == "pending":
            now_ts = get_utc_timestamp()
            if data["expires_at"] < now_ts:
                conn.execute(
                    "UPDATE proposals SET status = 'expired' WHERE proposal_id = ?;",
                    (proposal_id,)
                )
                data["status"] = "expired"

        return data


def get_pending_proposals(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Returns all proposals currently awaiting an analyst decision.
    Automatically expires overdue items.
    """
    with get_db(db_path) as conn:
        now_ts = get_utc_timestamp()

        # 1. Update any expired items
        conn.execute(
            "UPDATE proposals SET status = 'expired' WHERE status = 'pending' AND expires_at < ?;",
            (now_ts,)
        )

        # 2. Return remaining active pending proposals
        cursor = conn.execute(
            """
            SELECT proposal_id, alert_id, action, target, reason, explanation,
                   status, confidence, ttl_seconds, created_at, expires_at
            FROM proposals
            WHERE status = 'pending'
            ORDER BY created_at ASC;
            """
        )
        return [dict(row) for row in cursor.fetchall()]


def update_proposal_status(
    proposal_id: str,
    new_status: str,
    decision_by: Optional[str] = None,
    db_path: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Transitions a proposal to 'approved', 'rejected', or 'expired'.
    """
    decision_ts = get_utc_timestamp()
    with get_db(db_path) as conn:
        cursor = conn.execute(
            """
            UPDATE proposals
            SET status = ?, decision_by = ?, decision_at = ?
            WHERE proposal_id = ?;
            """,
            (new_status, decision_by, decision_ts, proposal_id)
        )
        if cursor.rowcount == 0:
            return None

    return get_proposal(proposal_id, db_path=db_path)


# -----------------------------------------------------------------------------
# Event Log Management (WebSocket Sync & Replay)
# -----------------------------------------------------------------------------

def log_event(
    event_type: str,
    payload: Any,
    db_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Appends an event to the sequential events ledger.
    Every event gets an auto-incrementing integer `event_id`.
    Used by the extension to recover missed alerts after a disconnect.
    """
    now_ts = get_utc_timestamp()
    payload_str = json.dumps(payload, sort_keys=True) if isinstance(payload, (dict, list)) else str(payload)

    with get_db(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO events (event_type, payload, created_at)
            VALUES (?, ?, ?);
            """,
            (event_type, payload_str, now_ts)
        )
        event_id = cursor.lastrowid

        return {
            "event_id": event_id,
            "event_type": event_type,
            "payload": payload if isinstance(payload, (dict, list)) else payload_str,
            "created_at": now_ts,
        }


def get_events_since(
    last_seen_event_id: int,
    limit: int = 100,
    db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Replays all events that occurred after `last_seen_event_id`.
    This powers the `sync.request` handler for extension reconnects.
    """
    with get_db(db_path) as conn:
        cursor = conn.execute(
            """
            SELECT event_id, event_type, payload, created_at
            FROM events
            WHERE event_id > ?
            ORDER BY event_id ASC
            LIMIT ?;
            """,
            (last_seen_event_id, limit)
        )
        results = []
        for row in cursor.fetchall():
            item = dict(row)
            try:
                item["payload"] = json.loads(item["payload"])
            except Exception:
                pass
            results.append(item)
        return results
