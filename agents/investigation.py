"""Investigation agent: a few READ-ONLY tool calls, then a list of Findings.

The model may only call `INVESTIGATION_TOOLS`, at most `MAX_TOOL_CALLS` times.
Each Finding is built by our code from the tool's output (never from model
prose), and stored per alert in a plain dict that can be swapped for a database.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Callable

from agents import prompts
from agents.llm import chat
from agents.sanitize import alert_data
from schemas.models import Alert, Finding, TriageVerdict
from tools import readonly

INVESTIGATION_TOOLS: tuple[str, ...] = ("search_logs", "threat_intel")
MAX_TOOL_CALLS = 3

# In-memory store: alert_id -> findings. Swap for Hermes SessionDB later.
_FINDINGS: dict[str, list[Finding]] = {}


def save_findings(alert_id: str, findings: list[Finding]) -> None:
    _FINDINGS[alert_id] = list(findings)


def get_findings(alert_id: str) -> list[Finding]:
    """A copy, so callers cannot mutate what is stored."""
    return list(_FINDINGS.get(alert_id, []))


def clear_findings() -> None:
    _FINDINGS.clear()


def _summarise(tool: str, result: dict) -> str:
    """One factual line per finding, derived from the tool output."""
    if tool == "search_logs":
        hits = result.get("hits", 0)
        detail = f"{hits} log line(s) mention {result.get('ip')}"
        first = (result.get("lines") or [""])[0]
        return f"{detail}: {first}"[:1000] if first else detail[:1000]
    return (
        f"reputation={result.get('reputation')}, score={result.get('score')}, "
        f"reports={result.get('reports')}"
    )[:1000]


_tool_observer = ContextVar("soc_tool_observer", default=None)
_tool_runner = ContextVar("soc_tool_runner", default=None)


@contextmanager
def tool_context(observer=None, runner=None):
    """Request-local audit/provider adapters; ordinary M1 use remains read-only."""
    observer_token = _tool_observer.set(observer)
    runner_token = _tool_runner.set(runner)
    try:
        yield
    finally:
        _tool_observer.reset(observer_token)
        _tool_runner.reset(runner_token)


def _call_tool(name: str, raw_arguments: str) -> dict:
    """Validate one model request and run it. Only INVESTIGATION_TOOLS may run."""
    if name not in INVESTIGATION_TOOLS:
        return {"ok": False, "error": f"unknown tool: {name}"}
    try:
        arguments = json.loads(raw_arguments or "{}")
    except json.JSONDecodeError:
        return {"ok": False, "error": "arguments were not valid JSON"}
    ip = arguments.get("ip") if isinstance(arguments, dict) else None
    if not isinstance(ip, str) or not ip.strip():
        return {"ok": False, "error": "missing 'ip'"}
    return json.loads((_tool_runner.get() or readonly.run_tool)(name, ip))


def _assistant_echo(reply: Any) -> dict:
    """The assistant turn that requested the tools, as the API expects it back."""
    return {
        "role": "assistant",
        "content": reply.content,
        "tool_calls": [
            {
                "id": call.id,
                "type": "function",
                "function": {
                    "name": call.function.name,
                    "arguments": call.function.arguments,
                },
            }
            for call in reply.tool_calls
        ],
    }


def investigate(
    alert: Alert,
    triage: TriageVerdict,
    chat_fn: Callable[..., Any] | None = None,
) -> list[Finding]:
    """Collect read-only evidence for one alert and return the Findings.

    `chat_fn` is injectable so tests can run offline; the pipeline passes `llm.chat`.
    """
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": prompts.load_prompt("investigation")},
        {
            "role": "user",
            "content": json.dumps(
                {"alert": alert_data(alert), "triage": triage.model_dump()}, indent=2
            ),
        },
    ]

    findings: list[Finding] = []
    attempts = 0

    for _ in range(MAX_TOOL_CALLS):  # also bounds rounds if the model keeps asking
        reply = (chat_fn or chat)(
            messages, tools=readonly.api_tool_specs(INVESTIGATION_TOOLS)
        )
        if not reply.tool_calls:
            break  # the model answered in text: it is done

        messages.append(_assistant_echo(reply))

        for call in reply.tool_calls:
            if attempts >= MAX_TOOL_CALLS:
                break
            attempts += 1
            name = call.function.name
            result = _call_tool(name, call.function.arguments)
            observer = _tool_observer.get()
            if observer:
                observer(name, str(call.function.arguments or "")[:512], result)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call.id,
                    "name": name,
                    "content": json.dumps(result),
                }
            )
            if result.get("ok"):
                findings.append(
                    Finding(
                        alert_id=alert.alert_id,
                        source=name,
                        detail=_summarise(name, result["result"]),
                    )
                )

        if attempts >= MAX_TOOL_CALLS:
            break

    save_findings(alert.alert_id, findings)
    return findings
