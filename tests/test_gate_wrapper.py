"""The plain-Python gate: dangerous tools never run, read-only lookups do.

Every refusal case is asserted through the public `run_tool()` contract, and the
dangerous body is proven untouched by spying on the handler table.
"""

import logging

import pytest

from agents.gate_wrapper import DANGEROUS_TOOLS, READ_ONLY_TOOLS, run_tool


def test_dummy_block_ip_is_refused_and_the_refusal_is_logged(caplog):
    with caplog.at_level(logging.WARNING):
        result = run_tool("dummy_block_ip", {"ip": "10.0.0.1"})

    assert result["ok"] is False
    assert result["refused"] is True
    assert "dangerous" in result["reason"]
    assert "dummy_block_ip" in caplog.text


def test_the_dangerous_body_is_never_called(monkeypatch):
    """Even if a handler exists under a dangerous name, the gate stops before it."""
    ran = []
    monkeypatch.setitem(READ_ONLY_TOOLS, "dummy_block_ip", lambda ip: ran.append(ip) or {})

    result = run_tool("dummy_block_ip", {"ip": "10.0.0.1"})

    assert result["refused"] is True
    assert ran == []


def test_lookup_ip_still_runs_without_a_policy():
    result = run_tool("lookup_ip", {"ip": "203.0.113.5"})

    assert result["ok"] is True
    assert result["refused"] is False
    assert result["result"]["reputation"] == "malicious"
    assert result["result"]["reports"] == 7


def test_lookup_ip_runs_when_the_policy_allows_it():
    result = run_tool(
        "lookup_ip", {"ip": "198.51.100.23"}, policy=lambda name, args: {"action": "allow"}
    )

    assert result["ok"] is True
    assert result["result"]["reputation"] == "benign"


def test_a_policy_can_block_a_read_only_tool():
    result = run_tool(
        "lookup_ip",
        {"ip": "203.0.113.5"},
        policy=lambda name, args: {"action": "block", "message": "lookups are frozen"},
    )

    assert result["refused"] is True
    assert "lookups are frozen" in result["reason"]


# --- fail-open cases, from demo/failopen_cases.md --------------------------- #


def test_hook_returning_none_is_a_refusal():
    """Hermes ignores None (fail open); this wrapper refuses."""
    result = run_tool("lookup_ip", {"ip": "203.0.113.5"}, policy=lambda name, args: None)

    assert result["refused"] is True
    assert "no decision" in result["reason"]


def test_a_malformed_hook_return_is_a_refusal():
    result = run_tool(
        "lookup_ip", {"ip": "203.0.113.5"}, policy=lambda name, args: "block please"
    )

    assert result["refused"] is True
    assert "not a decision object" in result["reason"]


def test_an_unknown_hook_action_is_a_refusal():
    result = run_tool(
        "lookup_ip", {"ip": "203.0.113.5"}, policy=lambda name, args: {"action": "maybe"}
    )

    assert result["refused"] is True
    assert "unknown action" in result["reason"]


def test_a_block_without_a_message_is_still_a_refusal():
    result = run_tool("lookup_ip", {"ip": "203.0.113.5"}, policy=lambda name, args: {"action": "block"})

    assert result["refused"] is True
    assert "blocked by policy" in result["reason"]


def test_a_raising_hook_is_a_refusal():
    def boom(name, args):
        raise RuntimeError("hook crashed")

    result = run_tool("lookup_ip", {"ip": "203.0.113.5"}, policy=boom)

    assert result["refused"] is True
    assert "RuntimeError" in result["reason"]


@pytest.mark.parametrize(
    "name", ["DUMMY_BLOCK_IP", " dummy_block_ip ", "\tDummy_Block_Ip\n", "dummy_block_ip "]
)
def test_name_casing_and_whitespace_cannot_bypass_the_gate(name):
    assert run_tool(name, {"ip": "10.0.0.1"})["refused"] is True


def test_unknown_tool_is_refused_before_dispatch():
    result = run_tool("frobnicate", {"ip": "203.0.113.5"})

    assert result["refused"] is True
    assert "unknown" in result["reason"]


def test_an_allowing_policy_cannot_unblock_a_dangerous_tool():
    result = run_tool(
        "dummy_block_ip", {"ip": "10.0.0.1"}, policy=lambda name, args: {"action": "allow"}
    )

    assert result["refused"] is True
    assert "dangerous" in result["reason"]


def test_no_policy_means_no_plugin_and_dangerous_still_fails_closed():
    """The 'plugin not enabled' case: the gate is in the wrapper, not the plugin."""
    assert run_tool("dummy_block_ip", {"ip": "10.0.0.1"}, policy=None)["refused"] is True
    assert run_tool("lookup_ip", {"ip": "203.0.113.5"}, policy=None)["ok"] is True


@pytest.mark.parametrize("args", [None, ["ip", "203.0.113.5"], "ip=203.0.113.5"])
def test_non_object_arguments_are_refused(args):
    assert run_tool("lookup_ip", args)["refused"] is True


@pytest.mark.parametrize("args", [{}, {"ip": ""}, {"ip": "   "}, {"ip": 5}])
def test_missing_or_non_string_ip_is_refused(args):
    assert run_tool("lookup_ip", args)["refused"] is True


def test_the_dangerous_set_and_the_read_only_set_do_not_overlap():
    assert DANGEROUS_TOOLS.isdisjoint(READ_ONLY_TOOLS)
