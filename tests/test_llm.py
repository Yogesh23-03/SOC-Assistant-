"""The wrapper is the only door to the provider, so it gets the most tests."""

import pytest

from agents import llm as llm_module
from agents.llm import LLMError, Settings, validate_model
from schemas.models import TriageVerdict


def test_complete_sends_the_expected_request(make_llm):
    llm, client = make_llm('{"verdict": "suspicious"}')

    text = llm.complete("system text", "user text")

    assert text == '{"verdict": "suspicious"}'
    call = client.chat.completions.calls[0]
    assert call["model"] == "test-model"
    assert call["temperature"] == 0.0
    assert call["response_format"] == {"type": "json_object"}
    assert call["messages"] == [
        {"role": "system", "content": "system text"},
        {"role": "user", "content": "user text"},
    ]


def test_complete_json_strips_a_markdown_fence(make_llm):
    llm, _ = make_llm('```json\n{"ok": true}\n```')
    assert llm.complete_json("s", "u") == {"ok": True}


@pytest.mark.parametrize("reply", ["not json at all", "[1, 2]", ""])
def test_unusable_json_raises_llmerror(make_llm, reply):
    llm, _ = make_llm(reply)
    with pytest.raises(LLMError):
        llm.complete_json("s", "u")


def test_transient_error_is_retried(make_llm):
    llm, client = make_llm(TimeoutError("slow"), '{"ok": true}', max_retries=1)

    assert llm.complete_json("s", "u") == {"ok": True}
    assert len(client.chat.completions.calls) == 2


def test_non_retryable_provider_error_is_not_retried(make_llm):
    import httpx
    from groq import NotFoundError

    request = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
    rejection = NotFoundError(
        "model_not_found", response=httpx.Response(404, request=request), body=None
    )
    llm, client = make_llm(rejection, '{"ok": true}', max_retries=3)

    with pytest.raises(LLMError) as err:
        llm.complete("s", "u")

    assert len(client.chat.completions.calls) == 1  # no pointless retries
    assert "model_not_found" in str(err.value)


def test_retries_are_bounded(make_llm):
    llm, client = make_llm(TimeoutError("slow"), max_retries=0)

    with pytest.raises(LLMError):
        llm.complete("s", "u")
    assert len(client.chat.completions.calls) == 1


def test_settings_read_from_environment(monkeypatch):
    monkeypatch.setattr(llm_module, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setenv("GROQ_API_KEY", "secret-value")
    monkeypatch.setenv("GROQ_MODEL", "some-model")
    monkeypatch.setenv("MAX_RETRIES", "4")

    settings = Settings.from_env()

    assert settings.model == "some-model"
    assert settings.max_retries == 4


def test_missing_model_names_the_variable_but_not_the_key(monkeypatch):
    monkeypatch.setattr(llm_module, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setenv("GROQ_API_KEY", "secret-value")
    monkeypatch.delenv("GROQ_MODEL", raising=False)

    with pytest.raises(LLMError) as err:
        Settings.from_env()

    assert "GROQ_MODEL" in str(err.value)
    assert "secret-value" not in str(err.value)


def test_non_numeric_max_retries_raises(monkeypatch):
    monkeypatch.setattr(llm_module, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setenv("GROQ_API_KEY", "k")
    monkeypatch.setenv("GROQ_MODEL", "m")
    monkeypatch.setenv("MAX_RETRIES", "many")

    with pytest.raises(LLMError):
        Settings.from_env()


def test_validate_model_wraps_pydantic_errors():
    with pytest.raises(LLMError):
        validate_model(
            TriageVerdict,
            {"alert_id": "A-1", "label": "definitely_not_a_label", "confidence": 0.5},
        )
