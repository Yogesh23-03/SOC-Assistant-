"""Shared fixtures: a fake Groq client, so no test ever touches the network."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from agents.llm import LLM, Settings
from schemas import loaders
from schemas.models import Alert

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


class FakeCompletions:
    """Stands in for client.chat.completions: replays queued replies, records calls."""

    def __init__(self, replies: tuple) -> None:
        self.replies = list(replies)
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if not self.replies:
            raise AssertionError("FakeCompletions ran out of replies")
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        # Either a plain string, or a prepared message (content + tool_calls).
        message = reply if hasattr(reply, "tool_calls") else SimpleNamespace(
            content=reply, tool_calls=None
        )
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    @property
    def last_system_message(self) -> str:
        return self.calls[-1]["messages"][0]["content"]

    @property
    def last_user_message(self) -> str:
        return self.calls[-1]["messages"][1]["content"]


class FakeClient:
    def __init__(self, replies: tuple) -> None:
        self.chat = SimpleNamespace(completions=FakeCompletions(replies))


@pytest.fixture(autouse=True)
def offline_llm_settings(request, monkeypatch):
    """get_validated() reads settings from the environment; keep unit tests offline.

    Tests marked `live` are exempt: they are meant to call the real model.
    """
    if request.node.get_closest_marker("live"):
        return
    monkeypatch.setattr(
        "agents.llm._default_settings",
        lambda: Settings(api_key="test-key", model="test-model", max_retries=2),
    )


@pytest.fixture
def make_llm():
    """make_llm(reply1, reply2, ...) -> (LLM wired to a fake client, fake client)."""

    def _make(*replies, max_retries: int = 0):
        client = FakeClient(replies)
        settings = Settings(api_key="test-key", model="test-model", max_retries=max_retries)
        return LLM(settings=settings, client=client), client

    return _make


def _load(name: str) -> list[Alert]:
    """Same loader as main.py: fixture-only keys are stripped, never sent to Alert."""
    return loaders.load_alerts(DATA_DIR / name)


@pytest.fixture(scope="session")
def sample_alerts() -> list[Alert]:
    return _load("sample_alerts.json")


@pytest.fixture(scope="session")
def poisoned_alerts() -> list[Alert]:
    return _load("poisoned_logs.json")


@pytest.fixture
def alert(sample_alerts) -> Alert:
    """The first sample alert (A-001, a web shell upload)."""
    return sample_alerts[0]
