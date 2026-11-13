"""All ten fixture alerts produce a valid TriageVerdict.

The model is canned, so these tests prove the plumbing (prompt, fenced log,
schema validation, alert_id ownership) rather than model judgement.
"""

import json

import pytest

from agents.safety import LOG_TAG
from agents.triage import triage
from schemas.models import TriageVerdict

# What each fixture is meant to be; rotate labels to exercise all three.
INTENT = [
    "true_attack",  # A-001 web shell uploaded and executed
    "false_positive",  # A-002 analyst downloaded the EICAR test file
    "suspicious",  # A-003 DNS exfil-shaped volume, nothing else
    "true_attack",  # A-004 brute force then successful root login
    "false_positive",  # A-005 sanctioned Nessus port scan
    "true_attack",  # A-006 LSASS credential dump
    "suspicious",  # A-007 encoded PowerShell, no follow-on
    "true_attack",  # A-008 beaconing to known AsyncRAT C2
    "false_positive",  # A-009 nightly backup account login
    "true_attack",  # A-010 kerberoasting, with an injection note attached
]


def test_there_are_ten_varied_alerts(sample_alerts):
    assert len(sample_alerts) == 10
    assert len({a.alert_id for a in sample_alerts}) == 10
    assert len({a.rule_name for a in sample_alerts}) == 10  # no duplicates
    assert {a.severity for a in sample_alerts} <= {"low", "medium", "high", "critical"}


@pytest.mark.parametrize("index", range(10))
def test_each_alert_returns_a_valid_verdict(make_llm, sample_alerts, index):
    alert = sample_alerts[index]
    reply = json.dumps(
        {
            "alert_id": alert.alert_id,
            "label": INTENT[index],
            "confidence": 0.7,
            "reasoning": "fixture reasoning",
            "explanation": "fixture explanation in plain words",
        }
    )
    llm, client = make_llm(reply)

    verdict = triage(alert, chat_fn=llm.chat)

    assert isinstance(verdict, TriageVerdict)
    assert verdict.label in {"true_attack", "suspicious", "false_positive"}
    assert 0.0 <= verdict.confidence <= 1.0
    assert verdict.reasoning and verdict.explanation
    assert verdict.alert_id == alert.alert_id

    user = client.chat.completions.last_user_message
    assert f"<{LOG_TAG}>" in user and f"</{LOG_TAG}>" in user
    # Raw log text is sent, fenced; json.dumps gives the escaped form as it appears.
    assert json.dumps(alert.log_text.splitlines()[0])[1:-1] in user


def test_the_model_cannot_rename_the_alert(make_llm, sample_alerts):
    alert = sample_alerts[0]
    reply = json.dumps(
        {
            "alert_id": "A-DIFFERENT",
            "label": "false_positive",
            "confidence": 0.5,
            "reasoning": "r",
            "explanation": "e",
        }
    )
    llm, _ = make_llm(reply)

    verdict = triage(alert, chat_fn=llm.chat)

    assert verdict.alert_id == alert.alert_id  # our id wins
