"""soc_gate_demo: a dangerous-looking tool that a pre_tool_call hook refuses.

Two things are registered, and they are deliberately separate:

* ``dummy_block_ip(ip)`` prints ``WOULD BLOCK <ip>`` and touches a marker file.
  It changes nothing - no firewall call, no network, no shell.
* ``on_pre_tool_call`` returns ``{"action": "block", "message": ...}`` for that
  tool, which is the documented Hermes directive that becomes the tool result.

The marker file is the proof: if the body ever runs, ``dummy_block_ip_ran.log``
appears next to this file. A blocked call leaves only ``soc_gate_demo.log``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

TOOL_NAME = "dummy_block_ip"
_HERE = Path(__file__).resolve().parent
RAN_MARKER = _HERE / "dummy_block_ip_ran.log"
GATE_LOG = _HERE / "soc_gate_demo.log"

# OpenAI-style function schema; register_tool(schema=...) takes this shape.
TOOL_SCHEMA = {
    "name": TOOL_NAME,
    "description": (
        "DEMO ONLY. Would block an IP address. It performs no firewall change; "
        "the pre_tool_call gate refuses this tool before it executes."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "IPv4 address that would be blocked"}
        },
        "required": ["ip"],
    },
}


def _append(path: Path, line: str) -> None:
    """Append one line to a small local log; never raise into the agent loop."""
    try:
        previous = path.read_text(encoding="utf-8") if path.is_file() else ""
        path.write_text(previous + line + "\n", encoding="utf-8")
    except OSError:
        logger.warning("soc_gate_demo: could not write %s", path)


def dummy_block_ip(args: dict | None = None, **_: Any) -> str:
    """The dangerous body. If this runs, it leaves a marker behind."""
    ip = str((args or {}).get("ip", ""))
    RAN_MARKER.write_text(f"RAN {TOOL_NAME} ip={ip}\n", encoding="utf-8")
    print(f"WOULD BLOCK {ip}", flush=True)
    return json.dumps({"ok": True, "would_block": ip})


def on_pre_tool_call(tool_name: str = "", args: Any = None, **_: Any):
    """Veto only this tool. None (the normal return) lets every other tool through."""
    key = "".join(str(tool_name).split()).lower()
    if key != TOOL_NAME:
        return None

    ip = str(args.get("ip", "?")) if isinstance(args, dict) else "?"
    message = (
        f"soc_gate_demo: refusing {TOOL_NAME}({ip}) before execution - "
        "dangerous tools are gated in this demo. Nothing was blocked on the network."
    )
    _append(GATE_LOG, f"BLOCKED {TOOL_NAME} ip={ip}")
    logger.warning(message)
    return {"action": "block", "message": message}


def register(ctx) -> None:
    """Hermes calls this once at startup."""
    ctx.register_tool(
        name=TOOL_NAME,
        toolset="soc_gate_demo",
        schema=TOOL_SCHEMA,
        handler=dummy_block_ip,
    )
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
