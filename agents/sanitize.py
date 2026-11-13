"""The one place that decides how untrusted log text is presented to the model.

`sanitize_log_text()` is the guard: it normalises, removes control and invisible
characters, neutralises any `<log_data>` look-alike, and caps the length.
`wrap_untrusted()` then puts the cleaned text inside the data fence, and
`alert_data()` is the only way an alert becomes prompt input - so triage,
investigation and response all get sanitised text before they build a prompt.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from schemas.models import Alert

LOG_TAG = "log_data"
TOOL_TAG = "tool_data"
MAX_LOG_CHARS = 2000
MAX_UNTRUSTED_CHARS = MAX_LOG_CHARS  # older name, still imported by tests
TRUNCATION_MARK = "\n...[truncated]"
TAG_MARK = "[neutralised-tag]"

# <log_data>, </log_data>, "< / LOG_DATA >" and the like, in any casing.
_LOG_TAG = re.compile(r"<\s*/?\s*log_data\s*>", re.IGNORECASE)


def _tag_pattern(tag: str) -> re.Pattern[str]:
    """Matches <tag>, </tag>, < / tag > in any casing."""
    return re.compile(rf"<\s*/?\s*{tag}\s*>", re.IGNORECASE)


def _strip_control_chars(text: str) -> str:
    """Drop control, zero-width and other invisible formatting characters."""
    return "".join(
        ch for ch in text if ch in "\n\t" or not unicodedata.category(ch).startswith("C")
    )


def sanitize_log_text(text: str | None, limit: int = MAX_LOG_CHARS) -> str:
    """Return log text that cannot break out of the data fence.

    Order matters: NFKC turns full-width look-alikes into plain characters and
    removes zero-width characters first, so `</log_\\u200bdata>` and
    `<\\uff0flog_data>` are both caught by the tag pattern - not just the plain
    form. The result never exceeds `limit` characters.
    """
    if not text:
        return ""

    cleaned = unicodedata.normalize("NFKC", str(text))
    cleaned = _strip_control_chars(cleaned)
    cleaned = _LOG_TAG.sub(TAG_MARK, cleaned)
    if len(cleaned) > limit:
        cleaned = cleaned[: max(0, limit - len(TRUNCATION_MARK))] + TRUNCATION_MARK
    return cleaned


def wrap_untrusted(text: str, tag: str = LOG_TAG, limit: int = MAX_LOG_CHARS) -> str:
    """Return `text` sanitised and fenced as data between <tag> and </tag>."""
    cleaned = _tag_pattern(tag).sub(TAG_MARK, sanitize_log_text(text, limit))
    return f"<{tag}>\n{cleaned}\n</{tag}>"


def alert_data(alert: Alert) -> dict[str, Any]:
    """The alert as a plain dict, with the free-text log already sanitised and fenced."""
    data = alert.model_dump()
    data["log_text"] = wrap_untrusted(alert.log_text)
    return data
