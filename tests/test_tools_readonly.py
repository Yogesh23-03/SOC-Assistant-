"""Tools are the only thing the model can trigger, so they must be harmless."""

import json

import pytest

from tools import readonly


def test_registry_contains_only_lookups():
    assert set(readonly.TOOL_NAMES) == {
        "lookup_asset",
        "lookup_threat_intel",
        "recent_alerts_for_host",
        "search_logs",
        "threat_intel",
    }
    assert "lookup_ip" not in readonly.TOOLS  # demo mock, not an agent tool
    assert not [
        name
        for name in readonly.TOOL_NAMES
        if any(word in name for word in ("write", "delete", "exec", "run", "update"))
    ]


def test_asset_lookup_known_host():
    out = json.loads(readonly.run_tool("lookup_asset", "web-01"))

    assert out["ok"] is True
    assert out["result"]["found"] is True
    assert out["result"]["exposure"] == "internet-facing"


def test_asset_lookup_unknown_host_is_not_an_error():
    out = json.loads(readonly.run_tool("lookup_asset", "no-such-host"))

    assert out["ok"] is True
    assert out["result"]["found"] is False


def test_threat_intel_and_history():
    intel = json.loads(readonly.run_tool("lookup_threat_intel", "203.0.113.66"))
    history = json.loads(readonly.run_tool("recent_alerts_for_host", "db-01"))

    assert intel["result"]["verdict"] == "malicious"
    assert history["result"]["count"] >= 1


def test_search_logs_mock_returns_matching_lines():
    known = json.loads(readonly.run_tool("search_logs", "198.51.100.23"))
    unknown = json.loads(readonly.run_tool("search_logs", "8.8.8.8"))

    assert known["ok"] is True
    assert known["result"]["hits"] == 3
    assert "shell.php" in known["result"]["lines"][0]
    assert unknown["result"] == {"ip": "8.8.8.8", "hits": 0, "lines": []}


def test_threat_intel_mock_reports_malicious_and_unknown():
    malicious = json.loads(readonly.run_tool("threat_intel", "203.0.113.5"))
    unknown = json.loads(readonly.run_tool("threat_intel", "8.8.8.8"))

    assert malicious["result"]["reputation"] == "malicious"
    assert malicious["result"]["reports"] == 7
    assert unknown["result"] == {
        "ip": "8.8.8.8",
        "reputation": "unknown",
        "score": 0,
        "reports": 0,
    }


def test_api_tool_specs_only_describe_the_requested_tools():
    specs = readonly.api_tool_specs(("search_logs", "threat_intel"))

    assert [spec["function"]["name"] for spec in specs] == ["search_logs", "threat_intel"]
    assert all(spec["type"] == "function" for spec in specs)
    assert specs[0]["function"]["parameters"]["required"] == ["ip"]
    assert readonly.api_tool_specs(("not_a_tool",)) == []


def test_unknown_tool_is_refused():
    out = json.loads(readonly.run_tool("delete_everything", "all"))

    assert out["ok"] is False
    assert out["error"] == "unknown tool"


@pytest.mark.parametrize("arg", ["", "   ", "a" * (readonly.MAX_ARG_CHARS + 1), None, 42])
def test_bad_arguments_are_refused(arg):
    out = json.loads(readonly.run_tool("lookup_asset", arg))

    assert out["ok"] is False


def test_a_crashing_tool_returns_an_error_instead_of_raising(monkeypatch):
    def boom(_arg):
        raise RuntimeError("data file missing")

    monkeypatch.setitem(readonly.TOOLS, "lookup_asset", boom)

    out = json.loads(readonly.run_tool("lookup_asset", "web-01"))

    assert out["ok"] is False
    assert out["error"] == "RuntimeError"
