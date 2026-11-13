"""Triage agent: one alert in, one validated TriageVerdict out.

Uses get_validated(), so a malformed reply is retried with the error fed back
to the model instead of failing the alert.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from agents import prompts
from agents.llm import get_validated
from agents.sanitize import alert_data
from schemas.models import Alert, TriageVerdict


def triage(alert: Alert, chat_fn: Callable[..., Any] | None = None) -> TriageVerdict:
    """Classify one alert.

    `alert_data()` sanitises `log_text` before it reaches the prompt.
    `chat_fn` is injectable so tests can run offline; the pipeline passes `llm.chat`.
    """
    messages = [
        {"role": "system", "content": prompts.load_prompt("triage")},
        {"role": "user", "content": json.dumps({"alert": alert_data(alert)}, indent=2)},
    ]
    verdict: TriageVerdict = get_validated(TriageVerdict, messages, chat_fn=chat_fn)
    # The model is asked to copy the id, but the alert itself is the authority.
    return verdict.model_copy(update={"alert_id": alert.alert_id})
