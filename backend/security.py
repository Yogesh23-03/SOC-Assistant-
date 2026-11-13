"""
Cryptographic Security, Session Tokens & Nonce Verification (M2 Lead).
Implements analyst authentication, replay protection, and HMAC-signed approval tokens.
"""

import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from backend.audit import get_utc_timestamp
from backend.config import HMAC_SECRET_KEY, JWT_EXPIRATION_MINUTES, JWT_SECRET_KEY
from backend.database import get_db


# -----------------------------------------------------------------------------
# Analyst Session Tokens (Tamper-Proof HMAC Session Tokens)
# -----------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    """Encodes bytes into URL-safe base64 string without padding."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    """Decodes URL-safe base64 string handling missing padding."""
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def create_analyst_token(
    analyst_id: str,
    role: str = "soc_analyst",
    expires_in_minutes: int = JWT_EXPIRATION_MINUTES,
    secret: Optional[str] = None
) -> str:
    """
    Creates a signed, time-limited analyst bearer token for the Chrome Extension.
    Format: <header_b64>.<payload_b64>.<signature_b64>
    """
    secret_bytes = (secret or JWT_SECRET_KEY).encode("utf-8")
    now_epoch = int(time.time())
    exp_epoch = now_epoch + (expires_in_minutes * 60)

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": analyst_id,
        "role": role,
        "iat": now_epoch,
        "exp": exp_epoch,
    }

    hdr_b64 = _b64url_encode(json.dumps(header, sort_keys=True).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, sort_keys=True).encode("utf-8"))

    signing_input = f"{hdr_b64}.{payload_b64}".encode("utf-8")
    sig = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)

    return f"{hdr_b64}.{payload_b64}.{sig_b64}"


def verify_analyst_token(
    token: str,
    secret: Optional[str] = None
) -> Dict[str, Any]:
    """
    Validates the analyst token's signature and expiration time.
    Raises ValueError on invalid format, bad signature, or expired token.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid token format: must have 3 segments")

    hdr_b64, payload_b64, sig_b64 = parts
    secret_bytes = (secret or JWT_SECRET_KEY).encode("utf-8")

    # Verify HMAC signature
    signing_input = f"{hdr_b64}.{payload_b64}".encode("utf-8")
    expected_sig = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
    provided_sig = _b64url_decode(sig_b64)

    if not hmac.compare_digest(expected_sig, provided_sig):
        raise ValueError("Token signature verification failed: forged or altered token")

    # Verify expiration
    payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    now_epoch = int(time.time())
    if payload.get("exp", 0) < now_epoch:
        raise ValueError("Token has expired: session timed out")

    return payload


# -----------------------------------------------------------------------------
# Anti-Replay Nonce Verification
# -----------------------------------------------------------------------------

def verify_and_consume_nonce(
    nonce: str,
    proposal_id: str,
    db_path: Optional[str] = None
) -> bool:
    """
    Ensures each decision request contains a fresh, unique nonce.
    If the nonce was already used in a previous request, it is rejected (anti-replay).
    Returns True if valid & consumed; False if duplicate / replayed.
    """
    if not nonce or len(nonce.strip()) < 8:
        return False

    now_ts = get_utc_timestamp()
    try:
        with get_db(db_path) as conn:
            conn.execute(
                """
                INSERT INTO used_nonces (nonce, proposal_id, used_at)
                VALUES (?, ?, ?);
                """,
                (nonce.strip(), proposal_id, now_ts)
            )
        return True
    except Exception:
        # SQLite PRIMARY KEY violation means nonce was already used
        return False


# -----------------------------------------------------------------------------
# HMAC Signed Approval Token for the Target VM Executor
# -----------------------------------------------------------------------------

def compute_approval_signature(
    proposal_id: str,
    action: str,
    target: str,
    expires_at: str,
    nonce: str,
    secret_key: Optional[str] = None
) -> str:
    """
    Computes a deterministic HMAC-SHA256 signature for the approved firewall action.
    Format string: {proposal_id}:{action}:{target}:{expires_at}:{nonce}
    """
    secret_bytes = (secret_key or HMAC_SECRET_KEY).encode("utf-8")
    canonical_payload = f"{proposal_id}:{action}:{target}:{expires_at}:{nonce}".encode("utf-8")
    return hmac.new(secret_bytes, canonical_payload, hashlib.sha256).hexdigest()


def generate_signed_approval_token(
    proposal: Dict[str, Any],
    nonce: str,
    secret_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Issues the cryptographically signed authorization token required by the target VM executor.
    The executor will only execute the iptables rule if this signature matches.
    """
    proposal_id = proposal["proposal_id"]
    action = proposal["action"]
    target = proposal["target"]
    expires_at = proposal["expires_at"]
    ttl_seconds = proposal.get("ttl_seconds", 3600)

    signature = compute_approval_signature(
        proposal_id=proposal_id,
        action=action,
        target=target,
        expires_at=expires_at,
        nonce=nonce,
        secret_key=secret_key
    )

    return {
        "proposal_id": proposal_id,
        "action": action,
        "target": target,
        "ttl_seconds": ttl_seconds,
        "expires_at": expires_at,
        "nonce": nonce,
        "signature": signature,
        "issued_at": get_utc_timestamp(),
    }


def verify_approval_token(
    token_data: Dict[str, Any],
    secret_key: Optional[str] = None
) -> Tuple[bool, Optional[str]]:
    """
    Verifies that an approval token submitted to the executor is valid, unexpired,
    and untampered.

    Returns:
        (is_valid: bool, error_reason: Optional[str])
    """
    required_fields = ["proposal_id", "action", "target", "expires_at", "nonce", "signature"]
    for field in required_fields:
        if field not in token_data:
            return False, f"Missing required token field: '{field}'"

    # 1. Check expiration
    now_ts = get_utc_timestamp()
    if token_data["expires_at"] < now_ts:
        return False, "Approval token has expired: action cannot be executed"

    # 2. Check cryptographic signature
    expected_sig = compute_approval_signature(
        proposal_id=token_data["proposal_id"],
        action=token_data["action"],
        target=token_data["target"],
        expires_at=token_data["expires_at"],
        nonce=token_data["nonce"],
        secret_key=secret_key
    )

    if not hmac.compare_digest(expected_sig, token_data["signature"]):
        return False, "Signature verification failed: forged or altered token"

    return True, None
