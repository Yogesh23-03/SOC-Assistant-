"""READ-ONLY tools the Investigation agent may ask for.

Deliberately boring: each tool looks a string up in bundled data (JSON files or
the mock tables below). No writes, no shell, no network, no arbitrary paths - so
a tool call influenced by attacker text still cannot change anything.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
MAX_ARG_CHARS = 64


def _load(name: str) -> object:
    """Read a bundled JSON file. The filename is a constant, never model input."""
    return json.loads((DATA_DIR / name).read_text(encoding="utf-8"))


def lookup_asset(host: str) -> dict:
    """Inventory record for a host (owner, OS, criticality, exposure)."""
    assets = _load("assets.json")
    record = assets.get(host.lower()) if isinstance(assets, dict) else None
    if record is None:
        return {"found": False, "host": host}
    return {"found": True, "host": host, **record}


def lookup_threat_intel(indicator: str) -> dict:
    """Reputation of one IP / domain from the bundled threat-intel feed."""
    feed = _load("threat_intel.json")
    record = feed.get(indicator.strip().lower()) if isinstance(feed, dict) else None
    if record is None:
        return {"found": False, "indicator": indicator}
    return {"found": True, "indicator": indicator, **record}


def recent_alerts_for_host(host: str) -> dict:
    """Up to 5 earlier alerts for the same host, newest first, for context."""
    history = _load("alert_history.json")
    if not isinstance(history, list):
        return {"host": host, "count": 0, "alerts": []}
    matches = [a for a in history if str(a.get("host", "")).lower() == host.lower()]
    return {"host": host, "count": len(matches), "alerts": matches[:5]}


MOCK_MALICIOUS_IPS = {"203.0.113.5"}


def lookup_ip(ip: str) -> dict:
    """Mock IP reputation lookup for the tool-calling demo.

    203.0.113.5 comes back malicious; every other address is benign.
    """
    target = ip.strip().lower()
    if target in MOCK_MALICIOUS_IPS:
        return {"ip": ip, "reputation": "malicious", "reports": 7}
    return {"ip": ip, "reputation": "benign", "reports": 0}


# --- mock data for the Investigation agent ---------------------------------
# Stand-ins until a real SIEM / threat-intel API is plugged in.
MOCK_LOGS: dict[str, list[str]] = {
    "198.51.100.23": [
        "2026-11-11T03:12:44Z web-01 nginx: POST /uploads/shell.php 200",
        "2026-11-11T03:12:45Z web-01 nginx: GET /uploads/shell.php?cmd=id 200",
        "2026-11-11T03:13:02Z web-01 nginx: GET /uploads/shell.php?cmd=curl 200",
    ],
    "203.0.113.5": [
        "2026-11-11T15:02:40Z web-02 nginx: TLS session to 203.0.113.5:443, 41 in 41 min",
        "2026-11-11T15:03:40Z web-02 nginx: TLS session to 203.0.113.5:443, JA3 match",
    ],
    "45.155.205.233": [
        "2026-11-11T06:19:31Z jump-01 sshd: 37 failed root logins",
        "2026-11-11T06:21:02Z jump-01 sshd: Accepted password for root",
    ],
    "10.0.0.5": [
        "2026-11-11T07:05:52Z web-02 nessus: TCP scan 20-1024 (1004 ports in 63s)",
    ],
}

MOCK_INTEL: dict[str, dict] = {
    "198.51.100.23": {"reputation": "unknown", "score": 40, "reports": 1},
    "203.0.113.5": {"reputation": "malicious", "score": 95, "reports": 7},
    "45.155.205.233": {"reputation": "malicious", "score": 88, "reports": 12},
    "185.220.101.4": {"reputation": "suspicious", "score": 60, "reports": 3},
    "10.0.0.5": {"reputation": "benign", "score": 0, "reports": 0},
}


def search_logs(ip: str) -> dict:
    """Mock log search: the stored log lines that mention one IP address."""
    lines = MOCK_LOGS.get(ip.strip().lower(), [])
    return {"ip": ip, "hits": len(lines), "lines": lines[:5]}


def threat_intel(ip: str) -> dict:
    """Mock reputation for one IP address; unknown addresses report 'unknown'."""
    record = MOCK_INTEL.get(ip.strip().lower())
    if record is None:
        return {"ip": ip, "reputation": "unknown", "score": 0, "reports": 0}
    return {"ip": ip, **record}


TOOLS: dict[str, Callable[[str], dict]] = {
    "lookup_asset": lookup_asset,
    "lookup_threat_intel": lookup_threat_intel,
    "recent_alerts_for_host": recent_alerts_for_host,
    "search_logs": search_logs,
    "threat_intel": threat_intel,
}

TOOL_NAMES: tuple[str, ...] = tuple(TOOLS)

_DESCRIPTIONS = {
    "lookup_asset": "Inventory record for a host name, e.g. web-01.",
    "lookup_threat_intel": "Reputation of an IP or domain, e.g. 203.0.113.66.",
    "recent_alerts_for_host": "Earlier alerts recorded for a host name.",
    "search_logs": "Log lines that mention one IP address.",
    "threat_intel": "Reputation and report count for one IP address.",
}


def api_tool_specs(names: tuple[str, ...] | None = None) -> list[dict]:
    """OpenAI-style tool definitions for the named tools, for the chat API."""
    return [
        {
            "type": "function",
            "function": {
                "name": name,
                "description": _DESCRIPTIONS[name],
                "parameters": {
                    "type": "object",
                    "properties": {"ip": {"type": "string", "description": "IPv4 address"}},
                    "required": ["ip"],
                },
            },
        }
        for name in (names or TOOL_NAMES)
        if name in TOOLS
    ]


def run_tool(name: str, arg: str) -> str:
    """Execute one whitelisted lookup and return a JSON string. Never raises.

    Validation here is code-side: the model chooses from TOOL_NAMES and passes
    one short string, and the string is only ever used as a dict key.
    """
    if name not in TOOLS:
        return json.dumps({"tool": name, "ok": False, "error": "unknown tool"})
    if not isinstance(arg, str) or not arg.strip():
        return json.dumps({"tool": name, "ok": False, "error": "arg must be a non-empty string"})
    if len(arg) > MAX_ARG_CHARS:
        return json.dumps({"tool": name, "ok": False, "error": "arg too long"})

    try:
        result = TOOLS[name](arg.strip())
    except Exception as exc:  # a broken data file must not crash the investigation
        return json.dumps({"tool": name, "ok": False, "error": type(exc).__name__})
    return json.dumps({"tool": name, "ok": True, "result": result})
