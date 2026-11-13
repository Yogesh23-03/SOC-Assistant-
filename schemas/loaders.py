"""Turning alert files into validated models, in one place.

`data/poisoned_logs.json` carries an `expected_label` next to each alert for
reporting, while `Alert` deliberately forbids unknown fields. Fixture metadata is
therefore stripped here - the single loader used by `main.py`, the tests and the
injection harness - instead of in each caller.
"""

from __future__ import annotations

import json
from pathlib import Path

from schemas.models import Alert

# Keys that belong to the fixture file, not to the production Alert contract.
FIXTURE_KEYS = frozenset({"expected_label"})


def alert_records(path: Path | str) -> list[dict]:
    """Read a JSON file that is either a list of alerts or {"alerts": [...]}."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    items = raw.get("alerts") if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        raise ValueError(f"{path} must contain a list, or an object with an 'alerts' list")
    return [item for item in items if isinstance(item, dict)]


def alert_payload(record: dict) -> dict:
    """Drop fixture-only keys so the alert validates against the real contract."""
    return {key: value for key, value in record.items() if key not in FIXTURE_KEYS}


def load_alerts(path: Path | str) -> list[Alert]:
    """Validated alerts from a JSON file, with fixture metadata removed."""
    return [Alert.model_validate(alert_payload(record)) for record in alert_records(path)]


def expected_labels(path: Path | str) -> dict[str, str]:
    """`alert_id -> expected_label` for records that carry one."""
    return {
        str(record.get("alert_id")): record["expected_label"]
        for record in alert_records(path)
        if isinstance(record.get("expected_label"), str)
    }
