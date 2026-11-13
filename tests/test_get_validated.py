"""get_validated(): JSON in, valid model out, with the error fed back on retry."""

from types import SimpleNamespace

import pytest
from pydantic import BaseModel, Field

from agents import llm as llm_module
from agents.llm import LLMError, get_validated


class Verdict(BaseModel):
    """A tiny stand-in schema, so this test does not depend on models.py."""

    label: str
    confidence: float = Field(ge=0, le=1)


def _reply(content):
    return SimpleNamespace(content=content)


@pytest.fixture(autouse=True)
def two_retries(monkeypatch):
    monkeypatch.setattr(
        llm_module, "_default_settings", lambda: llm_module.Settings("k", "m", max_retries=2)
    )


def test_a_valid_first_reply_costs_one_call():
    calls = []

    def fake_chat(messages, tools=None, json_mode=False):
        calls.append(json_mode)
        return _reply('{"label": "true_attack", "confidence": 0.9}')

    verdict = get_validated(
        Verdict, [{"role": "user", "content": "classify"}], chat_fn=fake_chat
    )

    assert verdict.label == "true_attack"
    assert len(calls) == 1
    assert calls[0] is True  # JSON mode was requested


def test_bad_then_good_retries_and_shows_the_model_its_error():
    replies = ["not json at all", '{"label": "true_attack", "confidence": 0.9}']
    seen = []

    def fake_chat(messages, tools=None, json_mode=False):
        seen.append(messages)
        return _reply(replies.pop(0))

    verdict = get_validated(
        Verdict, [{"role": "user", "content": "classify"}], chat_fn=fake_chat
    )

    assert verdict.label == "true_attack"
    assert len(seen) == 2
    retry_messages = seen[1]
    assert retry_messages[-2] == {"role": "assistant", "content": "not json at all"}
    feedback = retry_messages[-1]["content"]
    assert "could not be validated" in feedback
    assert "confidence" in feedback  # the schema is included


def test_schema_violation_also_retries():
    replies = ['{"confidence": 1.5}', '{"label": "suspicious", "confidence": 0.5}']

    def fake_chat(messages, tools=None, json_mode=False):
        return _reply(replies.pop(0))

    verdict = get_validated(
        Verdict, [{"role": "user", "content": "classify"}], chat_fn=fake_chat
    )

    assert verdict.label == "suspicious"


def test_gives_up_after_max_retries():
    calls = []

    def fake_chat(messages, tools=None, json_mode=False):
        calls.append(1)
        return _reply("still not json")

    with pytest.raises(LLMError) as err:
        get_validated(Verdict, [{"role": "user", "content": "classify"}], chat_fn=fake_chat)

    assert len(calls) == 3  # MAX_RETRIES=2 means 3 attempts in total
    assert "Verdict" in str(err.value)


def test_caller_messages_are_not_mutated():
    messages = [{"role": "user", "content": "classify"}]
    replies = ["nope", '{"label": "false_positive", "confidence": 0.8}']

    def fake_chat(conversation, tools=None, json_mode=False):
        return _reply(replies.pop(0))

    get_validated(Verdict, messages, chat_fn=fake_chat)

    assert messages == [{"role": "user", "content": "classify"}]
