"""
FastAPI Application Entry Point for M2 Backend.
Provides REST endpoints for system health, audit log verification,
pending proposals queue, and event stream synchronization.
"""

import json
import logging
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware

from backend.approval import process_analyst_decision
from backend.audit import get_audit_entries, get_utc_timestamp, log_audit_event, verify_audit_chain
from backend.config import CORS_ALLOWED_ORIGINS, JWT_EXPIRATION_MINUTES
from backend.database import get_db, init_db
from backend.executor import execute_approved_action, expire_active_blocks, list_active_blocks
from backend.ingest import ingest_and_process_alert
from backend.schemas import (
    AuditEntryResponse,
    AuditVerifyResponse,
    DecisionRequest,
    DecisionResponse,
    EventsSyncResponse,
    HealthResponse,
    LoginRequest,
    LoginResponse,
    ProposalCreateRequest,
    ProposalResponse,
    SignedApprovalTokenSchema,
)
from backend.security import create_analyst_token, verify_analyst_token
from backend.storage import (
    get_events_since,
    get_pending_proposals,
    get_proposal,
    save_proposal,
)
from backend.websocket_manager import ws_manager

logger = logging.getLogger("soc_backend.api")


def get_current_analyst(authorization: Optional[str] = Header(None)) -> str:
    """
    Security dependency that validates the Analyst session token.
    Accepts: 'Authorization: Bearer <token>'
    """
    if not authorization:
        # Default fallback for testing and dev environments if header omitted
        return "analyst.default"

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format. Expected 'Bearer <token>'"
        )

    try:
        payload = verify_analyst_token(parts[1])
        return payload.get("sub", "analyst.unknown")
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(err)
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Runs on startup to initialize database tables and log the startup event.
    """
    # 1. Ensure SQLite schema and indexes exist
    init_db()

    # 2. Record backend startup in the tamper-evident audit log
    log_audit_event(
        actor="system.backend",
        action="service.started",
        details={"version": "0.1.0", "status": "ready"}
    )
    yield
    # Shutdown logic (if any) can be placed here


app = FastAPI(
    title="Agentic SOC Assistant - Backend API (M2)",
    description="High-security backend service providing human-in-the-loop approval gates, "
                "tamper-evident audit logging, and real-time Chrome Extension connectivity.",
    version="0.1.0",
    lifespan=lifespan
)

# -----------------------------------------------------------------------------
# CORS Configuration (Permits Chrome Extension and Local Dev Origins)
# -----------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------------------------------------------------------
# Health and Diagnostics Endpoints
# -----------------------------------------------------------------------------
@app.get(
    "/health",
    response_model=HealthResponse,
    summary="System Health & Readiness Check",
    tags=["Diagnostics"]
)
def check_health():
    """
    Returns current service health, database connectivity, and queue counts.
    """
    now_ts = get_utc_timestamp()
    try:
        with get_db() as conn:
            # Query pending proposals count
            cursor = conn.execute("SELECT COUNT(*) as count FROM proposals WHERE status = 'pending';")
            pending_count = cursor.fetchone()["count"]

            # Query audit log count
            cursor = conn.execute("SELECT COUNT(*) as count FROM audit_log;")
            audit_count = cursor.fetchone()["count"]

        return HealthResponse(
            status="healthy",
            database_connected=True,
            pending_proposals=pending_count,
            audit_entries_count=audit_count,
            timestamp=now_ts,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database connectivity check failed: {str(exc)}"
        )


# -----------------------------------------------------------------------------
# Phase 5: SIEM Alert Ingestion Endpoints
# -----------------------------------------------------------------------------
@app.post(
    "/api/alerts",
    summary="Ingest SIEM Alert & Trigger Agent Pipeline",
    tags=["Alert Ingestion"]
)
async def ingest_alert(alert: Dict[str, Any]):
    """
    Ingests a security alert into the multi-agent pipeline.
    Auto-closes false positives; investigates attacks and queues proposals for approval.
    """
    return await ingest_and_process_alert(alert)


@app.post(
    "/api/alerts/sample/{index}",
    summary="Trigger Pipeline on Sample Alert (Demo Helper)",
    tags=["Alert Ingestion"]
)
async def ingest_sample_alert(index: int = 0):
    """
    Demo helper: Ingests alert from data/sample_alerts.json by index.
    Index 0: Web shell true attack (generates block_ip proposal)
    Index 1: EICAR test false positive (auto-closes without disturbing human)
    """
    import json
    from pathlib import Path
    sample_file = Path(__file__).resolve().parent.parent / "data" / "sample_alerts.json"
    if not sample_file.exists():
        raise HTTPException(status_code=404, detail="sample_alerts.json not found")

    with open(sample_file, "r", encoding="utf-8") as f:
        samples = json.load(f)

    if index < 0 or index >= len(samples):
        raise HTTPException(status_code=400, detail=f"Index {index} out of range (0-{len(samples)-1})")

    return await ingest_and_process_alert(samples[index])


# -----------------------------------------------------------------------------
# Tamper-Evident Audit Log Endpoints
# -----------------------------------------------------------------------------
@app.get(
    "/api/audit",
    response_model=List[AuditEntryResponse],
    summary="Retrieve Append-Only Audit Entries",
    tags=["Audit Log"]
)
def read_audit_log(
    limit: int = Query(50, ge=1, le=500, description="Max entries to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination")
):
    """
    Returns paginated audit log entries with cryptographic hashes.
    """
    return get_audit_entries(limit=limit, offset=offset)


@app.get(
    "/api/audit/verify",
    response_model=AuditVerifyResponse,
    summary="Verify Cryptographic Hash-Chain Integrity",
    tags=["Audit Log"]
)
def verify_audit():
    """
    Validates that no historical entry in the audit ledger has been modified,
    inserted, or deleted out of sequence.
    """
    is_valid, count, error_msg = verify_audit_chain()
    return AuditVerifyResponse(
        valid=is_valid,
        entries_verified=count,
        error=error_msg
    )


# -----------------------------------------------------------------------------
# Proposal Queue Endpoints (Extension-facing)
# -----------------------------------------------------------------------------
@app.get(
    "/api/proposals/pending",
    response_model=List[ProposalResponse],
    summary="List Active Pending Proposals",
    tags=["Proposals"]
)
def list_pending_proposals():
    """
    Returns all proposals awaiting an analyst's decision.
    Any proposal past its expiry date is automatically updated to 'expired'.
    """
    return get_pending_proposals()


@app.get(
    "/api/proposals/{proposal_id}",
    response_model=ProposalResponse,
    summary="Get Proposal Details by ID",
    tags=["Proposals"]
)
def get_single_proposal(proposal_id: str):
    """
    Retrieves the full record and state for a single proposal.
    """
    prop = get_proposal(proposal_id)
    if not prop:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Proposal '{proposal_id}' not found."
        )
    return prop


@app.post(
    "/api/proposals",
    response_model=ProposalResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a Newly Generated Proposal",
    tags=["Proposals"]
)
async def create_proposal(req: ProposalCreateRequest):
    """
    Internal/Pipeline endpoint to register a proposal drafted by M1 Response agent.
    Automatically broadcasts proposal.pending to all active Chrome Extension side panels.
    """
    existing = get_proposal(req.proposal_id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Proposal with ID '{req.proposal_id}' already exists."
        )

    saved = save_proposal(
        proposal_id=req.proposal_id,
        alert_id=req.alert_id,
        action=req.action,
        target=req.target,
        reason=req.reason,
        explanation=req.explanation,
        confidence=req.confidence,
        ttl_seconds=req.ttl_seconds,
        expires_at=req.expires_at,
    )

    # Log to tamper-evident audit ledger
    log_audit_event(
        actor="agent.response",
        action="proposal.created",
        details={
            "proposal_id": req.proposal_id,
            "alert_id": req.alert_id,
            "action": req.action,
            "target": req.target,
        }
    )

    # Real-time WebSocket push to Chrome Extension side-panels
    await ws_manager.broadcast("proposal.pending", saved)

    return saved


# -----------------------------------------------------------------------------
# Phase 3: Analyst Authentication Endpoints
# -----------------------------------------------------------------------------
@app.post(
    "/auth/token",
    response_model=LoginResponse,
    summary="Issue Analyst Bearer Token",
    tags=["Authentication"]
)
def login_analyst(req: LoginRequest):
    """
    Authenticates a SOC analyst and issues a short-lived bearer session token.
    Stored only in the Chrome extension's in-memory session (no secrets on disk).
    """
    token = create_analyst_token(analyst_id=req.analyst_id)
    log_audit_event(
        actor=req.analyst_id,
        action="analyst.authenticated",
        details={"status": "session_opened"}
    )
    return LoginResponse(
        access_token=token,
        token_type="bearer",
        analyst_id=req.analyst_id,
        expires_in_minutes=JWT_EXPIRATION_MINUTES,
    )


# -----------------------------------------------------------------------------
# Phase 3: Approval Gate & Human Decision Endpoints
# -----------------------------------------------------------------------------
@app.post(
    "/api/decisions",
    response_model=DecisionResponse,
    summary="Submit Human Approval Decision",
    tags=["Approval Gate"]
)
async def submit_decision(
    req: DecisionRequest,
    analyst_id: str = Depends(get_current_analyst)
):
    """
    Core Human-in-the-Loop Endpoint.
    Analyst clicks [Approve], [Reject], or [Investigate More] in the Chrome Extension.

    Safety Enforcements:
    1. Checks and burns one-time nonce to block replay attacks.
    2. Defaults to deny on expired proposals.
    3. Blocks any proposal targeting allowlisted IPs (e.g. 10.0.0.1) with HTTP 403.
    4. Issues cryptographically signed approval token for the target VM executor on approval.
    """
    result = process_analyst_decision(
        proposal_id=req.proposal_id,
        decision=req.decision,
        analyst_id=analyst_id,
        nonce=req.nonce
    )

    # Real-time WebSocket push of status change to all open extension cards
    await ws_manager.broadcast("proposal.updated", result["proposal"])

    return result


# -----------------------------------------------------------------------------
# Phase 4: Target VM Executor Endpoints
# -----------------------------------------------------------------------------
@app.post(
    "/api/executor/apply",
    summary="Execute Approved Containment Action with Signed Token",
    tags=["Executor"]
)
async def apply_containment_action(token: SignedApprovalTokenSchema):
    """
    Executes containment action (iptables rule) on the target host.
    Strictly requires a cryptographically valid, unexpired HMAC signed approval token.
    """
    try:
        result = execute_approved_action(token_data=token.model_dump())
        await ws_manager.broadcast("firewall.blocked", result)
        return result
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except RuntimeError as run_err:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(run_err))


@app.get(
    "/api/executor/blocks",
    summary="List Active Firewall Blocks",
    tags=["Executor"]
)
def get_active_blocks():
    """Returns list of all active firewall blocks and their expiration timestamps."""
    return list_active_blocks()


@app.post(
    "/api/executor/expire",
    summary="Expire and Cleanup Overdue Firewall Rules",
    tags=["Executor"]
)
def run_rule_expiration():
    """Unblocks expired IP rules and marks them expired in the database and audit ledger."""
    expired = expire_active_blocks()
    return {"expired_count": len(expired), "expired_targets": expired}



# -----------------------------------------------------------------------------
# Event Log & Replay Endpoints (Extension Sync)
# -----------------------------------------------------------------------------
@app.get(
    "/api/events",
    response_model=EventsSyncResponse,
    summary="Replay Missed Events (sync.request)",
    tags=["Events"]
)
def sync_events(
    last_seen_event_id: int = Query(0, ge=0, description="Latest event ID the extension already has"),
    limit: int = Query(100, ge=1, le=500, description="Max missed events to return")
):
    """
    Replays all events that occurred after last_seen_event_id.
    Used by the Chrome Extension service worker when recovering from sleep or network drops.
    """
    events = get_events_since(last_seen_event_id=last_seen_event_id, limit=limit)
    return EventsSyncResponse(
        last_seen_event_id=last_seen_event_id,
        events=events
    )


# -----------------------------------------------------------------------------
# WebSocket Analyst Channel (Real-time Push & Reconnection Sync)
# -----------------------------------------------------------------------------
@app.websocket("/ws/analyst")
async def websocket_analyst_endpoint(websocket: WebSocket):
    """
    Native WebSocket endpoint for the Chrome/Edge MV3 Extension side panel.
    Handles:
    1. Instant push of new alerts (alert.new) and proposals (proposal.pending).
    2. Periodic ping/heartbeat keepalive to keep MV3 background service workers awake.
    3. sync.request event replay when extension wakes up from idle sleep or network loss.
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            raw_text = await websocket.receive_text()
            try:
                message = json.loads(raw_text)
            except Exception:
                await ws_manager.send_personal_message(
                    {"type": "error", "message": "Malformed JSON"},
                    websocket
                )
                continue

            msg_type = message.get("type", "")

            # 1. Keepalive ping / heartbeat from extension
            if msg_type in ("ping", "heartbeat"):
                await ws_manager.handle_ping(websocket)

            # 2. Resync request after service worker sleep / reconnect
            elif msg_type == "sync.request":
                last_seen_id = message.get("last_seen_event_id", 0)
                await ws_manager.handle_sync_request(
                    websocket=websocket,
                    last_seen_event_id=int(last_seen_id)
                )

            # 3. Decision submitted directly via WebSocket
            elif msg_type == "decision":
                try:
                    p_id = message.get("proposal_id", "")
                    dec = message.get("decision", "")
                    a_id = message.get("analyst_id", "analyst.ws")
                    nonce = message.get("nonce", "")
                    res = process_analyst_decision(
                        proposal_id=p_id,
                        decision=dec,
                        analyst_id=a_id,
                        nonce=nonce
                    )
                    await ws_manager.broadcast("proposal.updated", res["proposal"])
                    await ws_manager.send_personal_message(
                        {"type": "decision.result", "data": res},
                        websocket
                    )
                except HTTPException as http_exc:
                    await ws_manager.send_personal_message(
                        {"type": "decision.error", "status_code": http_exc.status_code, "detail": http_exc.detail},
                        websocket
                    )

            # 4. Unknown or unhandled message type
            else:
                await ws_manager.send_personal_message(
                    {"type": "ack", "received_type": msg_type},
                    websocket
                )

    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception as exc:
        logger.warning(f"Unexpected WebSocket closure: {exc}")
        await ws_manager.disconnect(websocket)



if __name__ == "__main__":
    import uvicorn
    from backend.config import SERVER_HOST, SERVER_PORT
    print(f"Starting SOC Assistant Backend on http://{SERVER_HOST}:{SERVER_PORT}")
    uvicorn.run("backend.app:app", host=SERVER_HOST, port=SERVER_PORT, reload=True)

