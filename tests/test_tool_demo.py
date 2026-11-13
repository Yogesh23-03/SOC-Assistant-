"""The tool-calling additions: mock lookup, chat() plumbing, demo loop."""

import json
from types import SimpleNamespace

import pytest

from agents import llm as llm_module
from agents.llm import LLMError, chat
from tool_demo import _run_tool, run
from tools.readonly import lookup_ip


def test_lookup_ip_marks_the_known_bad_address():
    assert lookup_ip("203.0.113.5") == {"ip": "203.0.113.5", "reputation": "malicious", "reports": 7}


@pytest.mark.parametrize("ip", ["8.8.8.8", "203.0.113.6", "10.0.0.5"])
def test_lookup_ip_treats_everything_else_as_benign(ip):
    assert lookup_ip(ip)["reputation"] == "benign"


def test_run_tool_rejects_unknown_names_and_missing_args():
    assert "error" in _run_tool("delete_everything", {"ip": "203.0.113.5"})
    assert "error" in _run_tool("lookup_ip", {})
    assert "error" in _run_tool("lookup_ip", {"ip": 42})


def _fake_reply(content, tool_calls=()):
    return SimpleNamespace(content=content, tool_calls=list(tool_calls) or None)


def _fake_call(name, arguments):
    return SimpleNamespace(
        id="call_1", function=SimpleNamespace(name=name, arguments=json.dumps(arguments))
    )


def test_chat_passes_tools_and_json_mode(monkeypatch, make_llm):
    _, client = make_llm('{"ok": true}')
    monkeypatch.setattr(llm_module, "_default_client", lambda: client)
    monkeypatch.setattr(
        llm_module, "_default_settings", lambda: llm_module.Settings("k", "tool-model")
    )

    chat([{"role": "user", "content": "hi"}], tools=[{"type": "function"}], json_mode=True)

    sent = client.chat.completions.calls[0]
    assert sent["model"] == "tool-model"
    assert sent["tools"] == [{"type": "function"}]
    assert sent["response_format"] == {"type": "json_object"}
    assert sent["messages"] == [{"role": "user", "content": "hi"}]


def test_chat_reports_provider_errors_as_llmerror(monkeypatch, make_llm):
    _, client = make_llm(TimeoutError("slow"))
    monkeypatch.setattr(llm_module, "_default_client", lambda: client)
    monkeypatch.setattr(
        llm_module, "_default_settings", lambda: llm_module.Settings("k", "m", max_retries=0)
    )

    with pytest.raises(LLMError):
        chat([{"role": "user", "content": "hi"}])


def test_demo_loop_runs_the_tool_and_returns_the_final_answer(capsys):
    replies = [
        _fake_reply(None, [_fake_call("lookup_ip", {"ip": "203.0.113.5"})]),
        _fake_reply("Yes, 203.0.113.5 is malicious."),
    ]
    seen_messages = []

    def fake_chat(messages, tools=None, json_mode=False):
        seen_messages.append(list(messages))
        return replies.pop(0)

    answer = run(chat_fn=fake_chat)

    assert answer == "Yes, 203.0.113.5 is malicious."
    assert '"reputation": "malicious"' in capsys.readouterr().out
    # The second call saw the tool output; the API needs assistant + tool messages in order.
    second = seen_messages[1]
    assert [m["role"] for m in second] == ["system", "user", "assistant", "tool"]
    assert json.loads(second[-1]["content"])["reputation"] == "malicious"
    assert second[-1]["tool_call_id"] == "call_1"
