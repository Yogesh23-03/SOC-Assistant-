"""
Pydantic API Schemas for M2 Backend.
Defines typed request and response contracts for the FastAPI REST interface.
"""

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """System health check summary."""
    status: Literal["healthy", "degraded", "unhealthy"] = "healthy"
    database_connected: bool = True
    pending_proposals: int = Field(ge=0, description="Count of proposals currently awaiting analyst approval")
    audit_entries_count: int = Field(ge=0, description="Total verified entries in the audit hash chain")
    timestamp: str


class AuditEntryResponse(BaseModel):
    """An individual entry in the tamper-evident audit log."""
    entry_id: int
    timestamp: str
    actor: str
    action: str
    details: str
    prev_hash: str
    entry_hash: str


class AuditVerifyResponse(BaseModel):
    """Result of the cryptographic hash-chain integrity verification."""
    valid: bool
    entries_verified: int
    error: Optional[str] = None


class ProposalCreateRequest(BaseModel):
    """Schema to register a newly generated proposal from M1 Response agent."""
    proposal_id: str
    alert_id: str
    action: Literal["block_ip", "escalate", "none"]
    target: str
    reason: str
    explanation: Optional[str] = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    ttl_seconds: int = Field(default=3600, ge=60)
    expires_at: Optional[str] = None


class ProposalResponse(BaseModel):
    """Full representation of a proposal including approval state."""
    proposal_id: str
    alert_id: str
    action: str
    target: str
    reason: str
    explanation: Optional[str] = None
    status: Literal["pending", "approved", "rejected", "expired", "investigating"]
    confidence: float
    ttl_seconds: int
    created_at: str
    expires_at: str
    decision_by: Optional[str] = None
    decision_at: Optional[str] = None


class EventItemResponse(BaseModel):
    """Sequential event item for WebSocket stream and event replay."""
    event_id: int
    event_type: str
    payload: Any
    created_at: str


class EventsSyncResponse(BaseModel):
    """Replay bundle returned to extension upon reconnection."""
    last_seen_event_id: int
    events: List[EventItemResponse]


# -----------------------------------------------------------------------------
# Phase 3: Auth & Decision Schemas
# -----------------------------------------------------------------------------

class LoginRequest(BaseModel):
    """Analyst authentication request from Chrome Extension."""
    analyst_id: str = Field(min_length=2, max_length=64, description="Analyst identifier")
    password: Optional[str] = Field(default=None, description="Optional analyst credentials")


class LoginResponse(BaseModel):
    """Analyst session bearer token."""
    access_token: str
    token_type: str = "bearer"
    analyst_id: str
    expires_in_minutes: int


class DecisionRequest(BaseModel):
    """Human decision payload submitted by Chrome Extension."""
    proposal_id: str
    decision: Literal["approve", "reject", "investigate_more"]
    nonce: str = Field(min_length=8, description="Cryptographic one-time nonce to prevent replay attacks")


class SignedApprovalTokenSchema(BaseModel):
    """Cryptographic authorization token required by the target VM executor."""
    proposal_id: str
    action: str
    target: str
    ttl_seconds: int
    expires_at: str
    nonce: str
    signature: str
    issued_at: str


class DecisionResponse(BaseModel):
    """Result of analyst decision, including signed token if approved."""
    proposal_id: str
    decision: str
    analyst_id: str
    proposal: ProposalResponse
    signed_token: Optional[SignedApprovalTokenSchema] = None

