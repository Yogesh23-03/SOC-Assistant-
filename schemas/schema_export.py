"""Write the JSON Schemas for the agent contracts to schemas/json/.

    python -m schemas.schema_export

`tests/test_schema_export.py` fails when a file is missing or out of date, so a
schema change must include the regenerated files.
"""

from __future__ import annotations

import json
from pathlib import Path

from schemas.models import Alert, Finding, Proposal, TriageVerdict

SCHEMA_DIR = Path(__file__).resolve().parent / "json"

MODELS = {
    "Alert": Alert,
    "TriageVerdict": TriageVerdict,
    "Finding": Finding,
    "Proposal": Proposal,
}


def export_schemas(directory: Path | None = None) -> list[Path]:
    """Write one `<Model>.json` per model and return the paths written."""
    target = directory or SCHEMA_DIR
    target.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, model in MODELS.items():
        path = target / f"{name}.json"
        path.write_text(
            json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        written.append(path)
    return written


if __name__ == "__main__":
    for written_path in export_schemas():
        print(written_path)
