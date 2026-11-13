"""
WebSocket Connection & Event Streaming Manager for M2 Backend.
Handles real-time push to the Chrome/Edge extension, heartbeat keepalive,
and event replay on extension reconnection (sync.request).
"""

import json
import logging
from typing import Any, Dict, List, Optional, Set

from fastapi import WebSocket, WebSocketDisconnect

from backend.audit import get_utc_timestamp
from backend.storage import get_events_since, log_event

logger = logging.getLogger("soc_backend.websocket")


class ConnectionManager:
    """
    Manages active WebSocket connections to Chrome Extension side-panels.
    Provides real-time broadcasting and automatic event replay after disconnection.
    """

    def __init__(self):
        # Set of active WebSocket connections
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        """Accepts and registers a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"Extension connected. Total active connections: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket) -> None:
        """Removes a closed or disconnected WebSocket from active pool."""
        self.active_connections.discard(websocket)
        logger.info(f"Extension disconnected. Total active connections: {len(self.active_connections)}")

    async def send_personal_message(self, message: Dict[str, Any], websocket: WebSocket) -> bool:
        """Sends a JSON message to a single specific client."""
        try:
            await websocket.send_text(json.dumps(message))
            return True
        except Exception as exc:
            logger.warning(f"Failed to send message to extension: {exc}")
            return False

    async def broadcast(
        self,
        event_type: str,
        payload: Any,
        db_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        1. Persists the event in the SQLite events ledger with an auto-incrementing event_id.
        2. Broadcasts the event to all active Chrome Extension connections.

        Message Protocol:
        {
            "event_id": 1,
            "type": "alert.new" | "proposal.pending" | "case.closed",
            "payload": { ... },
            "created_at": "2026-11-13T..."
        }
        """
        # Step 1: Record event in sequential SQLite ledger
        stored = log_event(event_type=event_type, payload=payload, db_path=db_path)

        wire_message = {
            "event_id": stored["event_id"],
            "type": event_type,
            "payload": stored["payload"],
            "created_at": stored["created_at"],
        }
        wire_text = json.dumps(wire_message)

        # Step 2: Push to all connected extensions
        stale_connections = []
        for connection in list(self.active_connections):
            try:
                await connection.send_text(wire_text)
            except Exception as exc:
                logger.warning(f"Connection dropped during broadcast: {exc}")
                stale_connections.append(connection)

        # Clean up any dead sockets
        for dead_conn in stale_connections:
            self.active_connections.discard(dead_conn)

        return wire_message

    async def handle_sync_request(
        self,
        websocket: WebSocket,
        last_seen_event_id: int,
        db_path: Optional[str] = None
    ) -> int:
        """
        Processes a `sync.request` from an extension that reconnected after sleep.
        Queries the database for all events with event_id > last_seen_event_id and replays them.
        """
        missed_events = get_events_since(
            last_seen_event_id=last_seen_event_id,
            limit=200,
            db_path=db_path
        )

        for ev in missed_events:
            wire_message = {
                "event_id": ev["event_id"],
                "type": ev["event_type"],
                "payload": ev["payload"],
                "created_at": ev["created_at"],
                "is_replay": True,
            }
            await websocket.send_text(json.dumps(wire_message))

        # Send sync completion confirmation
        completion_message = {
            "type": "sync.complete",
            "replayed_count": len(missed_events),
            "last_replayed_event_id": missed_events[-1]["event_id"] if missed_events else last_seen_event_id,
            "timestamp": get_utc_timestamp(),
        }
        await websocket.send_text(json.dumps(completion_message))
        return len(missed_events)

    async def handle_ping(self, websocket: WebSocket) -> None:
        """Responds to extension keepalive heartbeats to prevent MV3 worker shutdown."""
        pong_message = {
            "type": "pong",
            "timestamp": get_utc_timestamp(),
        }
        await websocket.send_text(json.dumps(pong_message))


# Global singleton manager instance
ws_manager = ConnectionManager()
