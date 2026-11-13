"""Default-deny gate for tool calls, with or without Hermes.

`run_tool()` refuses anything it does not positively recognise: a dangerous name,
an unknown name, malformed arguments, or a policy hook that returns nothing, a
malformed value, or raises. Every refusal is logged, and the tool body is never
reached.

This exists because a framework hook can fail open: Hermes treats a `None`
return, a non-dict return, or `{"action": "block"}` without a message as "no
opinion" and runs the tool. A gate that only lives in a plugin therefore has no
floor. This module is that floor: it does not depend on any plugin being
installed, enabled or loaded.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from tools import readonly

log = logging.getLogger(__name__)

# Tools that change state. Refused even when no policy hook is installed.
DANGEROUS_TOOLS = frozenset(
    {
        "block_ip",
        "unblock_ip",
        "dummy_block_ip",
        "delete_everything",
        "run_command",
        "run_shell",
        "shell_exec",
    }
)

# The only tools this wrapper will call: read-only lookups from tools/readonly.py.
READ_ONLY_TOOLS: dict[str, Callable[[str], dict]] = {
    "lookup_ip": readonly.lookup_ip,
    "search_logs": readonly.search_logs,
    "threat_intel": readonly.threat_intel,
}

Policy = Callable[[str, dict], Any]


def _key(name: Any) -> str | None:
    """Lower-case and drop all whitespace, so ' DUMMY_BLOCK_IP ' cannot slip past."""
    if not isinstance(name, str):
        return None
    return "".join(name.split()).lower() or None


def _refuse(name: Any, reason: str) -> dict:
    """Build a refusal and log it. This is the only refusal shape callers see."""
    record = {"ok": False, "refused": True, "tool": name, "reason": reason}
    log.warning("gate refused tool=%r: %s", name, reason)
    return record


def _ask_policy(policy: Policy, key: str, args: dict) -> tuple[bool, str]:
    """Any doubt is a refusal: an exception, None or a malformed value is not consent."""
    try:
        decision = policy(key, args)
    except Exception as exc:  # a crashing gate must not become an open gate
        return False, f"policy raised {type(exc).__name__}: {str(exc)[:200]}"
    if decision is None:
        return False, "policy returned no decision (default-deny)"
    if not isinstance(decision, dict):
        return False, f"policy returned {type(decision).__name__}, not a decision object"
    action = decision.get("action")
    if action == "allow":
        return True, ""
    if action == "block":
        return False, str(decision.get("message") or "blocked by policy")[:500]
    return False, f"policy returned unknown action {action!r}"


def run_tool(name: Any, args: dict | None = None, policy: Policy | None = None) -> dict:
    """Run one read-only tool, or refuse.

    Returns ``{"ok": True, "refused": False, "tool": ..., "result": {...}}`` on
    success, or ``{"ok": False, "refused": True, "tool": ..., "reason": ...}``.

    A policy can only add refusals, never grant them: the dangerous-tool and
    unknown-tool checks run first, and a policy is consulted after both.
    """
    key = _key(name)
    if key is None:
        return _refuse(name, "tool name is missing or not a string")
    if key in DANGEROUS_TOOLS:
        return _refuse(name, "dangerous tool - refused regardless of policy")
    if key not in READ_ONLY_TOOLS:
        return _refuse(name, "unknown tool - default deny")
    if not isinstance(args, dict):
        return _refuse(name, "arguments must be a JSON object")

    ip = args.get("ip")
    if not isinstance(ip, str) or not ip.strip():
        return _refuse(name, "missing 'ip' argument")

    if policy is not None:
        allowed, note = _ask_policy(policy, key, args)
        if not allowed:
            return _refuse(name, note)

    try:
        result = READ_ONLY_TOOLS[key](ip.strip())
    except Exception as exc:  # a broken lookup must not crash the caller
        return _refuse(name, f"tool failed: {type(exc).__name__}")
    return {"ok": True, "refused": False, "tool": key, "result": result}
