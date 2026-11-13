"""The committed schemas/json/*.json must match the Pydantic models."""

import json

from schemas.schema_export import MODELS, SCHEMA_DIR


def test_every_contract_has_an_exported_schema():
    missing = [name for name in MODELS if not (SCHEMA_DIR / f"{name}.json").is_file()]

    assert missing == [], f"missing schema files: {missing}; run `python -m schemas.schema_export`"


def test_exported_schemas_are_up_to_date():
    stale = [
        name
        for name, model in MODELS.items()
        if json.loads((SCHEMA_DIR / f"{name}.json").read_text(encoding="utf-8"))
        != model.model_json_schema()
    ]

    assert stale == [], f"stale schema files: {stale}; run `python -m schemas.schema_export`"
