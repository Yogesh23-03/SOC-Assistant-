"""Investigation: only the two read-only tools, at most three calls, Findings stored."""

import json

import pytest

from agents.investigation import (
    INVESTIGATION_TOOLS,
    MAX_TOOL_CALLS,
    clear_findings,
    get_findings,
    investigate,
)
from schemas.models import Finding, TriageVerdict
from tests.fakes import reply, tool_call

TRIAGE = TriageVerdict(
    alert_id="A-001", label="true_attack", confidence=0.9, reasoning="r", explanation="e"
)


@pytest.fixture(autouse=True)
def empty_store():
    clear_findings()
    yield
    clear_findings()


def test_only_the_two_read_only_tools_are_offered(alert):
    seen_tools = []

    def fake_chat(messages, tools=None, json_mode=False):
        seen_tools.append(tools)
        return reply("done")

    investigate(alert, TRIAGE, chat_fn=fake_chat)

    names = [spec["function"]["name"] for spec in seen_tools[0]]
    assert names == list(INVESTIGATION_TOOLS)
    assert set(names) == {"search_logs", "threat_intel"}


def test_tool_calls_become_findings_and_are_stored(alert):
    calls = [
        reply(None, [tool_call("search_logs", {"ip": "198.51.100.23"}, "c1")]),
        reply(None, [tool_call("threat_intel", {"ip": "198.51.100.23"}, "c2")]),
        reply("Two sources agree the address is suspicious."),
    ]
    seen = []

    def fake_chat(messages, tools=None, json_mode=False):
        seen.append([dict(m) for m in messages])
        return calls.pop(0)

    findings = investigate(alert, TRIAGE, chat_fn=fake_chat)

    assert [f.source for f in findings] == ["search_logs", "threat_intel"]
    assert all(isinstance(f, Finding) for f in findings)
    assert all(f.alert_id == alert.alert_id for f in findings)
    assert "3 log line(s) mention 198.51.100.23" in findings[0].detail
    assert "reputation=unknown" in findings[1].detail

    stored = get_findings(alert.alert_id)
    assert [f.detail for f in stored] == [f.detail for f in findings]

    # The tool output is fed back to the model before it answers.
    last = seen[-1]
    assert [m["role"] for m in last] == ["system", "user", "assistant", "tool", "assistant", "tool"]
    assert json.loads(last[-1]["content"])["ok"] is True


def test_at_most_three_tool_calls_are_executed(alert, monkeypatch):
    executed = []
    monkeypatch.setattr(
        "tools.readonly.run_tool",
        lambda name, arg: executed.append((name, arg)) or json.dumps({"ok": False, "error": "x"}),
    )
    five = [tool_call("search_logs", {"ip": f"10.0.0.{i}"}, f"c{i}") for i in range(5)]

    def fake_chat(messages, tools=None, json_mode=False):
        return reply(None, five)

    investigate(alert, TRIAGE, chat_fn=fake_chat)

    assert len(executed) == MAX_TOOL_CALLS == 3


def test_an_unknown_tool_is_refused_and_never_run(alert, monkeypatch):
    executed = []
    monkeypatch.setattr(
        "tools.readonly.run_tool",
        lambda name, arg: executed.append((name, arg)) or json.dumps({"ok": True, "result": {}}),
    )
    seen = []
    replies = [
        reply(None, [tool_call("delete_everything", {"ip": "198.51.100.23"})]),
        reply("nothing else to do"),
    ]

    def fake_chat(messages, tools=None, json_mode=False):
        seen.append([dict(m) for m in messages])
        return replies.pop(0)

    findings = investigate(alert, TRIAGE, chat_fn=fake_chat)

    assert executed == []
    assert findings == []
    assert "unknown tool" in seen[1][-1]["content"]


@pytest.mark.parametrize(
    "arguments",
    [{}, {"ip": ""}, {"ip": 42}, {"target": "1.2.3.4"}],
)
def test_a_bad_argument_produces_no_finding(alert, arguments):
    replies = [
        reply(None, [tool_call("search_logs", arguments)]),
        reply("done"),
    ]

    def fake_chat(messages, tools=None, json_mode=False):
        return replies.pop(0)

    assert investigate(alert, TRIAGE, chat_fn=fake_chat) == []


def test_bad_json_arguments_produce_no_finding(alert):
    broken = tool_call("threat_intel", {"ip": "1.2.3.4"})
    broken.function.arguments = "not json"

    replies = [reply(None, [broken]), reply("done")]

    def fake_chat(messages, tools=None, json_mode=False):
        return replies.pop(0)

    assert investigate(alert, TRIAGE, chat_fn=fake_chat) == []


def test_findings_are_keyed_by_alert_and_returned_as_copies(alert):
    replies = [
        reply(None, [tool_call("threat_intel", {"ip": "203.0.113.5"})]),
        reply("malicious"),
    ]

    def fake_chat(messages, tools=None, json_mode=False):
        return replies.pop(0)

    findings = investigate(alert, TRIAGE, chat_fn=fake_chat)
    stored = get_findings(alert.alert_id)
    stored.clear()

    assert findings  # the stored list was a copy, so ours survives
    assert get_findings("A-999") == []
    assert "reputation=malicious" in findings[0].detail
