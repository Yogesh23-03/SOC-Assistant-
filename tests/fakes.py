"""Tiny builders for fake Groq chat replies used by the tool-calling tests.

Shape matches what the real SDK returns: `.content` and `.tool_calls`, where each
tool call has `.id` and `.function.name` / `.function.arguments`.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any


def tool_call(name: str, arguments: dict, call_id: str = "call_1") -> SimpleNamespace:
    return SimpleNamespace(
        id=call_id,
        function=SimpleNamespace(name=name, arguments=json.dumps(arguments)),
    )


def reply(content: str | None = None, tool_calls: list[Any] | None = None) -> SimpleNamespace:
    return SimpleNamespace(content=content, tool_calls=tool_calls or None)
