"""
Tests for the Cryptographic Hash-Chained Audit Log (M2 Security Requirement).
Verifies hash generation, sequential chaining, and detection of data tampering.
"""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from backend.audit import (
    GENESIS_HASH,
    compute_entry_hash,
    get_audit_entries,
    log_audit_event,
    verify_audit_chain,
)
from backend.database import init_db


class TestAuditLog(unittest.TestCase):
    def setUp(self):
        # Create an isolated temporary SQLite database for each test
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_audit.sqlite")
        init_db(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_genesis_entry_hash_chain(self):
        """The first entry must point to the 64-zero GENESIS_HASH."""
        entry = log_audit_event(
            actor="system",
            action="init",
            details={"status": "ready"},
            db_path=self.db_path
        )
        self.assertEqual(entry["entry_id"], 1)
        self.assertEqual(entry["prev_hash"], GENESIS_HASH)

        expected_hash = compute_entry_hash(
            GENESIS_HASH,
            entry["timestamp"],
            "system",
            "init",
            json.dumps({"status": "ready"}, sort_keys=True)
        )
        self.assertEqual(entry["entry_hash"], expected_hash)

    def test_sequential_hash_linkage(self):
        """Each entry must link directly to the preceding entry's entry_hash."""
        e1 = log_audit_event("agent.triage", "alert.ingest", {"id": "A-1"}, db_path=self.db_path)
        e2 = log_audit_event("agent.investigation", "ip.lookup", {"ip": "1.2.3.4"}, db_path=self.db_path)
        e3 = log_audit_event("analyst.bob", "proposal.approved", {"id": "P-1"}, db_path=self.db_path)

        self.assertEqual(e2["prev_hash"], e1["entry_hash"])
        self.assertEqual(e3["prev_hash"], e2["entry_hash"])

        # Chain verification must report 100% valid
        is_valid, count, err = verify_audit_chain(self.db_path)
        self.assertTrue(is_valid)
        self.assertEqual(count, 3)
        self.assertIsNone(err)

    def test_tampering_detection_modified_content(self):
        """If an attacker modifies row content directly in SQLite, the chain breaks."""
        log_audit_event("actor1", "action1", "legit content", db_path=self.db_path)
        log_audit_event("actor2", "action2", "second entry", db_path=self.db_path)

        # Directly tamper with row 1's details in SQLite
        conn = sqlite3.connect(self.db_path)
        with conn:
            conn.execute("UPDATE audit_log SET details = 'MALICIOUS_ALTERATION' WHERE entry_id = 1;")
        conn.close()

        # Chain verification must fail and catch the tampered entry
        is_valid, count, err = verify_audit_chain(self.db_path)
        self.assertFalse(is_valid)
        self.assertIn("Tampered data at entry 1", err)

    def test_tampering_detection_deleted_entry(self):
        """If an attacker deletes a row from the audit log, the chain breaks."""
        log_audit_event("actor1", "action1", "first", db_path=self.db_path)
        log_audit_event("actor2", "action2", "second", db_path=self.db_path)
        log_audit_event("actor3", "action3", "third", db_path=self.db_path)

        # Delete entry 2
        conn = sqlite3.connect(self.db_path)
        with conn:
            conn.execute("DELETE FROM audit_log WHERE entry_id = 2;")
        conn.close()

        # Chain verification must fail because entry 3's prev_hash points to deleted entry 2
        is_valid, count, err = verify_audit_chain(self.db_path)
        self.assertFalse(is_valid)
        self.assertIn("Broken chain", err)


if __name__ == "__main__":
    unittest.main()
