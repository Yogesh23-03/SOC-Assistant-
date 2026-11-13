"""Demo: let the model call lookup_ip through Groq's tool-calling API.

    python tool_demo.py

Flow: question -> model replies with tool_calls -> we run the Python function ->
send the result back as a "tool" message -> model answers.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from agents.llm import LLMError, chat
from tools.readonly import lookup_ip

QUESTION = "Is 203.0.113.5 dangerous?"
MAX_ROUNDS = 3  # stop if the model keeps asking for tools

# OpenAI-style schema Groq expects. Only the name, description and JSON arguments.
TOOL_SPEC: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "lookup_ip",
        "description": "Look up the reputation of one IP address.",
        "parameters": {
            "type": "object",
            "properties": {"ip": {"type": "string", "description": "IPv4 address, e.g. 203.0.113.5"}},
            "required": ["ip"],
        },
    },
}

# Dispatch table: a name the model may ask for, mapped to a real, harmless function.
TOOL_FUNCTIONS: dict[str, Callable[[str], dict]] = {"lookup_ip": lookup_ip}


def _run_tool(name: str, arguments: dict) -> dict:
    """Run one requested tool with code-side validation. Never runs anything else."""
    func = TOOL_FUNCTIONS.get(name)
    if func is None:
        return {"error": f"unknown tool: {name}"}
    ip = arguments.get("ip")
    if not isinstance(ip, str) or not ip.strip():
        return {"error": "missing 'ip' argument"}
    return func(ip)


def run(chat_fn: Callable = chat) -> str:
    """Run the loop and return the model's final text. `chat_fn` is injectable for tests."""
    messages: list[dict[str, Any]] = [
        {
            "role": "system",
            "content": "You are a SOC analyst. Call lookup_ip before answering. "
            "Reply in one short sentence.",
        },
        {"role": "user", "content": QUESTION},
    ]

    for _ in range(MAX_ROUNDS):
        reply = chat_fn(messages, tools=[TOOL_SPEC])

        if not reply.tool_calls:
            return reply.content or ""

        # Echo the assistant's tool request back into the conversation, as the API requires.
        messages.append(
            {
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
        )

        # Actually run each requested tool ourselves, then append the output as a tool message.
        for call in reply.tool_calls:
            name = call.function.name
            arguments = json.loads(call.function.arguments or "{}")
            result = _run_tool(name, arguments)
            print(f"[tool] {name}({json.dumps(arguments)}) -> {json.dumps(result)}")
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call.id,
                    "name": name,
                    "content": json.dumps(result),
                }
            )

    return "stopped: the model kept requesting tools"


def main() -> int:
    print(f"Q: {QUESTION}")
    try:
        answer = run()
    except LLMError as exc:
        print(f"error: {exc}")
        return 1
    print(f"A: {answer}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
