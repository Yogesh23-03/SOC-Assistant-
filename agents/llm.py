"""The single place in this project that talks to the LLM provider.

Every agent goes through `LLM.complete()` / `LLM.complete_json()`, so retries,
JSON mode and settings live in exactly one file. Nothing else imports `groq`.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

import groq
from dotenv import load_dotenv
from groq import Groq
from pydantic import BaseModel, ValidationError
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

ENV_FILE = Path(__file__).resolve().parents[1] / ".env"

# Errors worth retrying: network blips, provider overload and rate limits.
# (Bad requests / bad API keys are not retried - retrying cannot fix them.)
RETRYABLE = (
    groq.APIConnectionError,
    groq.RateLimitError,
    groq.InternalServerError,
    TimeoutError,
)


class LLMError(RuntimeError):
    """Bad config, failed transport, or unusable model output. Never carries a key."""


@dataclass(frozen=True)
class Settings:
    """LLM configuration, read once from the environment."""

    api_key: str
    model: str
    max_retries: int = 2
    temperature: float = 0.0

    @classmethod
    def from_env(cls) -> "Settings":
        """Read GROQ_API_KEY / GROQ_MODEL / MAX_RETRIES from .env or the environment."""
        load_dotenv(ENV_FILE)

        api_key = os.getenv("GROQ_API_KEY", "").strip()
        model = os.getenv("GROQ_MODEL", "").strip()
        raw_retries = os.getenv("MAX_RETRIES", "2").strip()

        if not api_key:
            raise LLMError("GROQ_API_KEY is missing. Copy .env.example to .env and fill it in.")
        if not model:
            raise LLMError("GROQ_MODEL is missing. Set it in .env (e.g. a Groq chat model id).")
        try:
            max_retries = int(raw_retries)
        except ValueError:
            raise LLMError("MAX_RETRIES must be a whole number, e.g. 2.") from None
        if max_retries < 0:
            raise LLMError("MAX_RETRIES must be 0 or more.")

        return cls(api_key=api_key, model=model, max_retries=max_retries)


class LLM:
    """Thin wrapper: one chat call in, one string (or dict) out.

    `client` is injectable so tests can pass a fake and never touch the network.
    """

    def __init__(self, settings: Settings | None = None, client: Any | None = None) -> None:
        self.settings = settings or Settings.from_env()
        self._client = client if client is not None else Groq(api_key=self.settings.api_key)

    def complete(self, system: str, user: str) -> str:
        """Send one system + one user message and return the raw reply text."""
        message = _send(
            self._client,
            self.settings,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            json_mode=True,
        )
        return message.content or ""

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        """Same as complete(), but the reply must be a single JSON object."""
        return parse_json_object(self.complete(system, user))

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        json_mode: bool = False,
    ) -> Any:
        """Instance-level version of chat(), so get_validated() can use this client."""
        return _send(self._client, self.settings, messages, tools=tools, json_mode=json_mode)


# Models sometimes wrap JSON in a markdown fence even in JSON mode; accept that.
_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


@lru_cache(maxsize=1)
def _default_settings() -> Settings:
    return Settings.from_env()


@lru_cache(maxsize=1)
def _default_client() -> Groq:
    """One reusable client, built from the key in .env (never logged)."""
    return Groq(api_key=_default_settings().api_key)


def _send(
    client: Any,
    settings: Settings,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    json_mode: bool = False,
) -> Any:
    """One chat completion with retry/backoff. Returns the assistant message object."""
    attempts = settings.max_retries + 1  # MAX_RETRIES = extra attempts

    @retry(
        reraise=True,
        stop=stop_after_attempt(attempts),
        wait=wait_exponential(multiplier=0.5, min=0.5, max=4),
        retry=retry_if_exception_type(RETRYABLE),
    )
    def _call() -> Any:
        kwargs: dict[str, Any] = {
            "model": settings.model,
            "temperature": settings.temperature,
            "messages": messages,
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        if tools:
            kwargs["tools"] = tools
        return client.chat.completions.create(**kwargs).choices[0].message

    try:
        return _call()
    except RETRYABLE as exc:
        raise LLMError(
            f"LLM request failed after {attempts} attempt(s): {type(exc).__name__}"
        ) from exc
    except groq.GroqError as exc:
        # Not retryable (bad model id, bad key, malformed request): report, do not loop.
        raise LLMError(f"LLM request rejected ({type(exc).__name__}): {str(exc)[:300]}") from exc


def chat(
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    json_mode: bool = False,
) -> Any:
    """One Groq chat call using the .env settings.

    Returns the assistant message (so callers can read `.tool_calls`), and retries
    rate limits / connection errors with exponential backoff up to MAX_RETRIES extra tries.
    """
    return _send(_default_client(), _default_settings(), messages, tools=tools, json_mode=json_mode)


def parse_json_object(text: str) -> dict[str, Any]:
    """Turn model text into a dict, or raise LLMError."""
    cleaned = _FENCE.sub("", text.strip()).strip()
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise LLMError("Model reply was not valid JSON.") from exc
    if not isinstance(data, dict):
        raise LLMError("Model reply was JSON but not an object.")
    return data


def validate_model(model_cls: type[BaseModel], data: dict[str, Any]) -> Any:
    """Validate model output against a schema, re-raising as LLMError."""
    try:
        return model_cls.model_validate(data)
    except ValidationError as exc:
        raise LLMError(f"Model output failed {model_cls.__name__} validation.") from exc


def get_validated(
    model_cls: type[BaseModel],
    messages: list[dict[str, Any]],
    chat_fn: Callable[..., Any] | None = None,
) -> Any:
    """Ask for JSON, validate it, and retry by showing the model its own error.

    Uses up to MAX_RETRIES extra attempts. Each retry appends the model's bad reply
    plus the validation error and the target JSON schema, so the second try is
    informed rather than identical. `chat_fn` is injectable for tests.
    """
    settings = _default_settings()
    conversation = [dict(message) for message in messages]  # never mutate the caller's list
    attempts = settings.max_retries + 1  # MAX_RETRIES = extra attempts
    last_error = "no attempt was made"

    for _ in range(attempts):
        reply = (chat_fn or chat)(conversation, json_mode=True)
        text = reply.content or ""
        try:
            return model_cls.model_validate(parse_json_object(text))
        except (LLMError, ValidationError) as exc:
            last_error = str(exc)[:500]
            conversation.append({"role": "assistant", "content": text})
            conversation.append(
                {
                    "role": "user",
                    "content": (
                        f"That reply could not be validated: {last_error}\n"
                        "Reply again with ONLY a JSON object that satisfies this schema:\n"
                        f"{json.dumps(model_cls.model_json_schema())}"
                    ),
                }
            )

    raise LLMError(
        f"{model_cls.__name__} validation failed after {attempts} attempt(s): {last_error}"
    )
