"""
Tests for WebSocket Connection Manager and Event Streaming (Phase 2).
Validates real-time broadcast, heartbeat keepalive, dead-socket pruning,
and event replay handling (sync.request).
"""

import json
import tempfile
import unittest
from pathlib import Path

from backend.database import init_db
from backend.storage import get_events_since, log_event
from backend.websocket_manager import ConnectionManager


def run_coro(coro):
    """Executes a coroutine synchronously without event loop / socket overhead."""
    try:
        coro.send(None)
    except StopIteration as exc:
        return exc.value


class MockWebSocket:
    """Mock WebSocket for testing manager send/receive without real network ports."""

    def __init__(self, should_fail: bool = False):
        self.accepted = False
        self.sent_messages = []
        self.should_fail = should_fail

    async def accept(self):
        self.accepted = True

    async def send_text(self, text: str):
        if self.should_fail:
            raise RuntimeError("Simulated socket connection failure")
        self.sent_messages.append(text)


class TestWebSocketManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_ws.sqlite")
        init_db(self.db_path)
        self.manager = ConnectionManager()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_connect_and_disconnect(self):
        """Should register active sockets on connect and remove them on disconnect."""
        ws1 = MockWebSocket()
        ws2 = MockWebSocket()

        run_coro(self.manager.connect(ws1))
        run_coro(self.manager.connect(ws2))
        self.assertEqual(len(self.manager.active_connections), 2)
        self.assertTrue(ws1.accepted)

        run_coro(self.manager.disconnect(ws1))
        self.assertEqual(len(self.manager.active_connections), 1)
        self.assertNotIn(ws1, self.manager.active_connections)
        self.assertIn(ws2, self.manager.active_connections)

    def test_broadcast_event_reaches_all_and_persists_to_db(self):
        """Broadcast must push to all active connections and record in SQLite events table."""
        ws1 = MockWebSocket()
        ws2 = MockWebSocket()
        run_coro(self.manager.connect(ws1))
        run_coro(self.manager.connect(ws2))

        payload = {"alert_id": "A-999", "severity": "high"}
        msg = run_coro(self.manager.broadcast("alert.new", payload, db_path=self.db_path))

        self.assertEqual(msg["type"], "alert.new")
        self.assertEqual(msg["event_id"], 1)

        # Both mock sockets should have received the exact same JSON payload
        self.assertEqual(len(ws1.sent_messages), 1)
        self.assertEqual(len(ws2.sent_messages), 1)

        data1 = json.loads(ws1.sent_messages[0])
        self.assertEqual(data1["event_id"], 1)
        self.assertEqual(data1["type"], "alert.new")
        self.assertEqual(data1["payload"]["alert_id"], "A-999")

        # Verify persisted in database
        events = get_events_since(0, db_path=self.db_path)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_id"], 1)

    def test_broadcast_handles_dropped_connection(self):
        """A broken socket should be pruned from the active pool without crashing other broadcasts."""
        good_ws = MockWebSocket(should_fail=False)
        bad_ws = MockWebSocket(should_fail=True)

        run_coro(self.manager.connect(good_ws))
        run_coro(self.manager.connect(bad_ws))
        self.assertEqual(len(self.manager.active_connections), 2)

        run_coro(self.manager.broadcast("test.event", {"data": 123}, db_path=self.db_path))

        # Good socket should have received the message
        self.assertEqual(len(good_ws.sent_messages), 1)
        # Bad socket must have been removed from active connections
        self.assertNotIn(bad_ws, self.manager.active_connections)
        self.assertEqual(len(self.manager.active_connections), 1)

    def test_handle_sync_request_replays_missed_events(self):
        """When an extension asks for sync with last_seen_event_id=1, only events > 1 are sent."""
        # Seed database with 3 events
        log_event("alert.new", {"id": "A-1"}, db_path=self.db_path)
        log_event("proposal.pending", {"id": "P-1"}, db_path=self.db_path)
        log_event("case.closed", {"id": "A-1"}, db_path=self.db_path)

        ws = MockWebSocket()
        run_coro(self.manager.connect(ws))

        # Request replay after event 1
        replayed_count = run_coro(self.manager.handle_sync_request(
            websocket=ws,
            last_seen_event_id=1,
            db_path=self.db_path
        ))

        self.assertEqual(replayed_count, 2)
        # Should have sent event 2, event 3, and sync.complete
        self.assertEqual(len(ws.sent_messages), 3)

        msg2 = json.loads(ws.sent_messages[0])
        msg3 = json.loads(ws.sent_messages[1])
        completion = json.loads(ws.sent_messages[2])

        self.assertEqual(msg2["event_id"], 2)
        self.assertTrue(msg2["is_replay"])
        self.assertEqual(msg3["event_id"], 3)
        self.assertEqual(completion["type"], "sync.complete")
        self.assertEqual(completion["replayed_count"], 2)

    def test_heartbeat_ping_pong(self):
        """Ping keepalive must trigger immediate pong response."""
        ws = MockWebSocket()
        run_coro(self.manager.connect(ws))

        run_coro(self.manager.handle_ping(ws))
        self.assertEqual(len(ws.sent_messages), 1)

        pong = json.loads(ws.sent_messages[0])
        self.assertEqual(pong["type"], "pong")
        self.assertIn("timestamp", pong)


if __name__ == "__main__":
    unittest.main()
