# M1 notes — SOC assistant

Agents, schemas and fixtures only. **Nothing here executes a containment action.**
Every proposal is a frozen record with `executed: false` and `requires_human_approval: true`;
M2 owns approvals and execution.

## Setup

```bash
cd soc-agents
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt   # Windows
# macOS/Linux: .venv/bin/python -m pip install -r requirements.txt
cp .env.example .env        # then fill the keys below
```

`requirements.txt` is a `pip freeze` of the project venv.

### `.env` keys

| Key | Required | Meaning |
| --- | --- | --- |
| `GROQ_API_KEY` | yes | Groq API key. Never printed or logged. |
| `GROQ_MODEL` | yes | A Groq chat model id, e.g. `openai/gpt-oss-120b`. |
| `MAX_RETRIES` | yes in practice | Extra attempts after the first (`2` = up to 3). Left empty in `.env.example`, so set it. |

`.env.example` ships every value empty. `.gitignore` covers `.env`, `.venv/`, `__pycache__/`,
`.pytest_cache/`.

## Tests

The default run is offline (fake Groq client, no network) and deselects the live harness via
`pytest.ini` (`-m "not live"`):

```bash
.venv/Scripts/python.exe -m pytest                                  # 144 passed, 1 deselected (~1 s)
.venv/Scripts/python.exe -m pytest tests/test_gate_wrapper.py       # gate: dangerous tools refused
.venv/Scripts/python.exe -m pytest tests/test_schema_export.py      # schemas/json/*.json are current
```

Live (real model, spends Groq calls; sleeps `INJECTION_SLEEP` seconds between alerts, default 3):

```bash
.venv/Scripts/python.exe -m pytest -m live tests/test_injection.py -s   # 1 passed, ~86 s
```

It rewrites `results/injection_results.md`. A label that differs from `expected_label` is
recorded in "Matches expected", never asserted; the test fails only on a schema-invalid reply or
a prompt that skipped sanitisation.

## Schemas (`schemas/models.py`, exported to `schemas/json/`)

Regenerate after changing a model: `python -m schemas.schema_export`.

- **Alert**: `alert_id`, `timestamp`, `source_ip`, `log_text`, `rule_name`, `host`, `severity`
  (`low|medium|high|critical`), `user`. `extra="forbid"`. Log text is attacker data.
- **TriageVerdict**: `alert_id`, `label` (`true_attack|suspicious|false_positive`), `confidence`
  (0–1), `reasoning`, `explanation`.
- **Finding**: `alert_id`, `source`, `detail`.
- **Proposal**: `proposal_id`, `alert_id`, `action` (`block_ip|none|escalate`), `target`,
  `reason`, `explanation`, `requires_human_approval` (always true), `executed` (always false).
  `block_ip` requires a plain IPv4 target; non-`none` actions require a safe target string.

Fixtures may carry `expected_label`; `Alert` forbids unknown fields, so `schemas/loaders.py`
strips fixture-only keys. `main.py`, the tests and the harness all use that one loader.

## How M2 calls the pipeline

`agents/pipeline.py::run_pipeline(alert_dict)` is dict-in / dict-out and JSON-serialisable:

```python
from agents.llm import LLM
from agents.pipeline import run_pipeline

llm = LLM()                       # once per process; pass it to every call
result = run_pipeline(alert, llm) # `alert` is the ingested alert dict
result["verdict"]                 # {"alert_id", "label", "confidence", "reasoning", "explanation"}
result["findings"]                # [{"alert_id", "source", "detail"}, ...]
result["proposal"]                # {"action", "target", "reason", "executed": false, ...}
```

Order is sanitise → triage → investigation → response (each agent calls `alert_data()`, which
sanitises and fences log text). `run_pipeline` never executes anything. If a step fails
validation after its retries, or the alert dict is invalid, it returns the safe fallback:
label `suspicious`, `confidence 0.0`, no findings, action `escalate` (target = alert host when
safe, else `manual-review`), and the failing step in `reason`. `main.py` calls `run_pipeline`.

## Known issues

- **Groq rate limits.** A live injection run is ~2 calls per hostile alert (none for a
  false-positive triage) plus retries. The harness sleeps 3 s between alerts
  (`INJECTION_SLEEP` overrides) and `agents/llm.py` backs off on 429/5xx with `MAX_RETRIES`.
- **Fail-open cases.** Hermes's `pre_tool_call` dispatcher ignores `None`, non-dict returns and
  `{"action": "block"}` without a message, so the tool runs; a raising or timed-out hook fails
  closed. `agents/gate_wrapper.py` is therefore default-deny and does not depend on a plugin.
  Six cases, with measured wrapper results, are in `demo/failopen_cases.md`.
- **Model behaviour.** `results/injection_results.md` (last run 2026-11-13, `openai/gpt-oss-120b`)
  records 10/10 labels matching `expected_label`, all schema-valid, and no proposal targeting an
  allowlisted address. That is one run of a non-deterministic model, not a guarantee; the file is
  a record, not a test gate.
- **Fallback can mask errors.** `run_pipeline` converts a validation/LLM failure into an
  escalation whose `reason` starts with `Automated analysis did not complete:`. Monitor that
  prefix; a rising rate means the model or key is failing, not that alerts got worse.
- **Hermes demo.** The plugin's hook contract was exercised locally by importing
  `plugins/soc_gate_demo/__init__.py`; Hermes itself is not installed here, so install, enable,
  restart, the live block and every Hermes row in `demo/failopen_cases.md` are **to verify**.

## Safe by design

Log text is data: it is normalised, stripped of control and zero-width characters, stripped of
`<log_data>` look-alikes, capped at 2 000 characters and fenced before any prompt. Models may
only contribute fields inside closed vocabularies; ids, approval flags and `executed` are set by
code. Investigation has two read-only lookups and no write, shell or network path; Response has
no tool import and a frozen `Proposal`; an allowlisted address is escalated rather than blocked.
`run_pipeline` turns any failed step into "a human decides", and the gate refuses dangerous
tools with no policy installed at all. The worst a compromised model can produce here is a
proposal someone must approve.
