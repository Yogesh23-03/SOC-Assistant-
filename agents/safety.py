"""Compatibility shim: untrusted-text handling now lives in `agents/sanitize.py`.

Kept so older imports keep working. New code should import from `agents.sanitize`.
"""

from __future__ import annotations

from agents.sanitize import (
    LOG_TAG,
    MAX_LOG_CHARS,
    MAX_UNTRUSTED_CHARS,
    TOOL_TAG,
    alert_data,
    sanitize_log_text,
    wrap_untrusted,
)

__all__ = [
    "LOG_TAG",
    "MAX_LOG_CHARS",
    "MAX_UNTRUSTED_CHARS",
    "TOOL_TAG",
    "alert_data",
    "sanitize_log_text",
    "wrap_untrusted",
]
