"""Loads the static instruction text from prompts/*.md.

Prompts live in files (easy to review and tune), while all dynamic data is sent
in the user message. Nothing here formats or interpolates model input.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

PROMPTS_DIR = Path(__file__).resolve().parents[1] / "prompts"


@lru_cache(maxsize=None)
def load_prompt(name: str) -> str:
    """Read prompts/<name>.md as the system message for one agent step."""
    path = PROMPTS_DIR / f"{name}.md"
    if not path.is_file():
        raise FileNotFoundError(f"Prompt file not found: {path}")
    return path.read_text(encoding="utf-8").strip()
