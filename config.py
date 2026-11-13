"""Local policy configuration. Not secrets - safe to read and review.

`ALLOWLIST` holds the targets the assistant must never block: our own server,
loopback, and the default gateway. `agents/response.py` forces `escalate` for any
proposal that targets one of them.
"""

from __future__ import annotations

GATEWAY_IP = "10.0.0.254"

ALLOWLIST: frozenset[str] = frozenset({"10.0.0.1", "127.0.0.1", GATEWAY_IP})


def is_allowlisted(target: str | None) -> bool:
    """True when `target` is one of the addresses we must never block."""
    return bool(target) and target.strip() in ALLOWLIST
