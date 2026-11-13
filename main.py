"""CLI: run the Triage -> Investigation -> Response pipeline over a JSON file of alerts.

    python main.py                          # data/sample_alerts.json
    python main.py data/poisoned_logs.json  # injection fixtures
    python main.py data/sample_alerts.json --limit 2
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agents.llm import LLM, LLMError
from agents.pipeline import run_pipeline
from schemas import loaders
from schemas.models import Alert


def load_alerts(path: Path) -> list[Alert]:
    """Read alert JSON, ignoring fixture-only keys such as `expected_label`."""
    return loaders.load_alerts(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SOC assistant agents (M1) - proposals only.")
    parser.add_argument("path", nargs="?", default="data/sample_alerts.json", help="alert JSON file")
    parser.add_argument("--limit", type=int, default=None, help="process only the first N alerts")
    args = parser.parse_args(argv)

    try:
        llm = LLM()
    except LLMError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    try:
        alerts = load_alerts(Path(args.path))
    except (OSError, ValueError) as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return 2

    for alert in alerts[: args.limit]:
        # run_pipeline() never raises for a bad step: it returns the safe fallback.
        result = run_pipeline(alert.model_dump(), llm)
        print(json.dumps({"alert_id": alert.alert_id, **result}, indent=2))

    print(f"\n{len(alerts[: args.limit])} alert(s) processed. "
          "Proposals need human approval; nothing was executed.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
