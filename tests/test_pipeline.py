"""End to end: Triage -> Investigation -> Response, with a canned model."""

import json

from agents.investigation import clear_findings, get_findings
from agents.pipeline import analyse_alert, run_pipeline
from tests.fakes import reply, tool_call


def _triage(label: str) -> str:
    return json.dumps(
        {
            "label": label,
            "confidence": 0.9,
            "reasoning": "fixture",
            "explanation": "fixture in plain words",
        }
    )


def test_false_positive_stops_after_triage(make_llm, alert):
    clear_findings()
    llm, client = make_llm(_triage("false_positive"))

    result = analyse_alert(alert, llm)

    assert result.triage.label == "false_positive"
    assert result.investigation is None
    assert result.proposal.action == "none"  # deterministic, no model call
    assert result.proposal.executed is False
    assert len(client.chat.completions.calls) == 1  # triage only: no tools, no proposal call


def test_true_attack_runs_every_stage_and_only_proposes(make_llm, alert):
    clear_findings()
    llm, client = make_llm(
        _triage("true_attack"),
        reply(None, [tool_call("search_logs", {"ip": "198.51.100.23"})]),
        reply("the address appears in the web server log"),
        json.dumps(
            {
                "action": "block_ip",
                "target": "198.51.100.23",
                "reason": "active web shell traffic from this address",
                "explanation": "This address is attacking the web server, so we suggest blocking it.",
            }
        ),
    )

    result = analyse_alert(alert, llm)

    assert len(client.chat.completions.calls) == 4  # triage, 2 investigation rounds, response
    assert result.triage.label == "true_attack"
    assert [f.source for f in result.investigation] == ["search_logs"]
    assert result.investigation[0].alert_id == alert.alert_id
    assert result.proposal.action == "block_ip"
    assert result.proposal.alert_id == alert.alert_id
    assert result.proposal.executed is False
    assert [f.detail for f in get_findings(alert.alert_id)] == [result.investigation[0].detail]


# --- run_pipeline(): the dict-in / dict-out entry point --------------------- #


def test_run_pipeline_returns_serialisable_dicts(make_llm, alert):
    clear_findings()
    llm, _ = make_llm(_triage("false_positive"))

    result = run_pipeline(alert.model_dump(), llm)

    assert set(result) == {"verdict", "findings", "proposal"}
    assert result["verdict"]["alert_id"] == alert.alert_id
    assert result["verdict"]["label"] == "false_positive"
    assert result["findings"] == []
    assert result["proposal"]["action"] == "none"
    json.dumps(result)  # must be JSON-serialisable as-is


def test_run_pipeline_carries_findings_and_never_executes(make_llm, alert):
    clear_findings()
    llm, _ = make_llm(
        _triage("true_attack"),
        reply(None, [tool_call("search_logs", {"ip": "198.51.100.23"})]),
        reply("the address appears in the web server log"),
        json.dumps(
            {
                "action": "block_ip",
                "target": "198.51.100.23",
                "reason": "active web shell traffic",
                "explanation": "This address is attacking the web server.",
            }
        ),
    )

    result = run_pipeline(alert.model_dump(), llm)

    assert [finding["source"] for finding in result["findings"]] == ["search_logs"]
    assert result["proposal"]["action"] == "block_ip"
    assert result["proposal"]["executed"] is False
    assert result["proposal"]["requires_human_approval"] is True


def test_run_pipeline_falls_back_when_triage_never_validates(make_llm, alert):
    # get_validated() retries per MAX_RETRIES (2 in the fixture), so three bad replies.
    llm, _ = make_llm("this is not json", "this is not json", "this is not json")

    result = run_pipeline(alert.model_dump(), llm)

    assert result["verdict"]["label"] == "suspicious"
    assert result["verdict"]["confidence"] == 0.0
    assert result["findings"] == []
    assert result["proposal"]["action"] == "escalate"
    assert result["proposal"]["target"] == alert.host  # web-01, from the alert itself
    assert result["proposal"]["executed"] is False
    assert result["proposal"]["reason"].startswith("Automated analysis did not complete:")


def test_run_pipeline_falls_back_on_an_invalid_alert_dict():
    result = run_pipeline({"alert_id": "X-1"})  # no timestamp / rule_name

    assert result["verdict"]["alert_id"] == "X-1"
    assert result["verdict"]["label"] == "suspicious"
    assert result["proposal"]["action"] == "escalate"
    assert result["proposal"]["target"] == "manual-review"


def test_run_pipeline_refuses_a_non_object_payload():
    result = run_pipeline(["not", "an", "alert"])  # type: ignore[arg-type]

    assert result["verdict"]["alert_id"] == "unknown"
    assert result["verdict"]["label"] == "suspicious"
    assert result["proposal"]["action"] == "escalate"
