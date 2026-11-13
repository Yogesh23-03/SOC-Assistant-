"""
Tests for Proposal Storage and Event Ledger (M2 Lead).
Verifies proposal lifecycle, automatic expiry, and event replay ordering.
"""

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from backend.database import init_db
from backend.storage import (
    get_events_since,
    get_pending_proposals,
    get_proposal,
    log_event,
    save_proposal,
    update_proposal_status,
)


class TestStorage(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_storage.sqlite")
        init_db(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_save_and_retrieve_proposal(self):
        """Should save a pending proposal and retrieve it by ID."""
        saved = save_proposal(
            proposal_id="prop-001",
            alert_id="alert-001",
            action="block_ip",
            target="198.51.100.25",
            reason="Repeated SSH failed logins",
            confidence=0.95,
            ttl_seconds=1800,
            db_path=self.db_path
        )
        self.assertEqual(saved["proposal_id"], "prop-001")
        self.assertEqual(saved["status"], "pending")

        retrieved = get_proposal("prop-001", db_path=self.db_path)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["target"], "198.51.100.25")

    def test_proposal_lifecycle_update(self):
        """Updating proposal status to approved records decision metadata."""
        save_proposal(
            proposal_id="prop-002",
            alert_id="alert-002",
            action="block_ip",
            target="203.0.113.10",
            reason="Malicious port scan",
            db_path=self.db_path
        )

        updated = update_proposal_status(
            proposal_id="prop-002",
            new_status="approved",
            decision_by="analyst_alice",
            db_path=self.db_path
        )
        self.assertEqual(updated["status"], "approved")
        self.assertEqual(updated["decision_by"], "analyst_alice")
        self.assertIsNotNone(updated["decision_at"])

        # Should no longer appear in pending queue
        pending = get_pending_proposals(db_path=self.db_path)
        self.assertEqual(len(pending), 0)

    def test_proposal_automatic_expiry(self):
        """Proposals whose expires_at is in the past must automatically transition to expired."""
        past_ts = "2020-01-01T00:00:00+00:00"
        save_proposal(
            proposal_id="prop-expired",
            alert_id="alert-old",
            action="block_ip",
            target="192.0.2.1",
            reason="Test expiry",
            expires_at=past_ts,
            db_path=self.db_path
        )

        prop = get_proposal("prop-expired", db_path=self.db_path)
        self.assertEqual(prop["status"], "expired")

        # Must not be listed in pending queue
        pending = get_pending_proposals(db_path=self.db_path)
        self.assertEqual(len(pending), 0)

    def test_event_logging_and_resync_replay(self):
        """Events must receive incremental IDs and replay properly with sync.request."""
        e1 = log_event("alert.new", {"id": "A-1"}, db_path=self.db_path)
        e2 = log_event("proposal.pending", {"id": "P-1"}, db_path=self.db_path)
        e3 = log_event("case.closed", {"id": "A-1"}, db_path=self.db_path)

        self.assertEqual(e1["event_id"], 1)
        self.assertEqual(e2["event_id"], 2)
        self.assertEqual(e3["event_id"], 3)

        # Simulate extension waking up with last_seen_event_id = 1
        missed = get_events_since(last_seen_event_id=1, db_path=self.db_path)
        self.assertEqual(len(missed), 2)
        self.assertEqual(missed[0]["event_id"], 2)
        self.assertEqual(missed[1]["event_id"], 3)


if __name__ == "__main__":
    unittest.main()
