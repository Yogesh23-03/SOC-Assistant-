"""
SQLite Database Engine for M2 Backend.
Handles connection pooling, table migrations, and concurrency controls.

Tables Managed:
1. audit_log - Append-only cryptographic hash chain of all system actions.
2. proposals - Life-cycle tracking for analyst containment proposals.
3. events    - Sequential event ledger used for WebSocket real-time push and resync.
"""

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional

from backend.config import DATABASE_PATH

# Reentrant thread lock to protect SQLite writes across threads safely
_db_lock = threading.RLock()


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Creates and returns a configured SQLite connection.
    Enables WAL mode and foreign keys for high reliability and concurrency.
    """
    path = db_path or DATABASE_PATH

    # Ensure parent directory exists for file-based databases
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(path, check_same_thread=False, timeout=10.0)
    conn.row_factory = sqlite3.Row  # Access columns by name: row["column_name"]

    # Optimization pragmas
    with conn:
        if path != ":memory:":
            conn.execute("PRAGMA journal_mode=WAL;")  # Write-Ahead Logging for concurrency
        conn.execute("PRAGMA foreign_keys=ON;")      # Enforce foreign key constraints
        conn.execute("PRAGMA busy_timeout=5000;")    # Wait up to 5s if locked

    return conn


@contextmanager
def get_db(db_path: Optional[str] = None) -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager for database transactions.
    Safely acquires the write lock and commits or rolls back automatically.
    """
    conn = get_connection(db_path)
    try:
        with _db_lock:
            yield conn
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Optional[str] = None) -> None:
    """
    Creates all required tables and indexes if they do not already exist.
    Safe to call multiple times (idempotent).
    """
    with get_db(db_path) as conn:
        # 1. Audit Log Table (Cryptographic Hash Chaining)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_entry_id ON audit_log(entry_id);")

        # 2. Proposals Table (Pending, Approved, Rejected, Expired)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS proposals (
                proposal_id TEXT PRIMARY KEY,
                alert_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                reason TEXT NOT NULL,
                explanation TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                confidence REAL DEFAULT 0.0,
                ttl_seconds INTEGER DEFAULT 3600,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                decision_by TEXT,
                decision_at TEXT
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_proposals_status ON proposals(status);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_proposals_alert_id ON proposals(alert_id);")

        # 3. Events Table (Sequential Event Stream for WebSocket Resync)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_id ON events(event_id);")

        # 4. Used Nonces Table (Replay Attack Defense)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS used_nonces (
                nonce TEXT PRIMARY KEY,
                proposal_id TEXT NOT NULL,
                used_at TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_nonces_proposal ON used_nonces(proposal_id);")

        # 5. Active Blocks Table (Firewall Rules with TTL Expiry)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS active_blocks (
                target TEXT PRIMARY KEY,
                proposal_id TEXT NOT NULL,
                blocked_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active'
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_blocks_status ON active_blocks(status);")
