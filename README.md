# Run the complete SOC Assistant

The backend and extension now support authenticated sessions, stored case evidence,
queued reinvestigation, PDF reports, event replay and periodic firewall cleanup.
Read [SETUP_AND_HANDOFF.md](docs/SETUP_AND_HANDOFF.md) for the current startup steps,
optional Linux execution, evaluation and remaining manual acceptance work.

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.app:app --reload
# Second terminal; paste this short-lived token into the extension Connection screen:
.\.venv\Scripts\python.exe -m backend.manage analyst.demo
```

Load `extension/dist` in Chrome/Edge after building with `npm.cmd run package`.
Never copy provider keys or signing secrets into the browser. No firewall rule is
applied by default; real execution requires explicit Linux-target configuration.
The original M1 implementation notes follow and describe the agent layer only.

# Agentic SOC Assistant — M1 (the agents)

Three agents that read one SIEM alert and produce a triage verdict, an investigation
report and **at most one proposed containment action**. Nothing is executed here; a
separate backend enforces human approval in code.

M1 scope: agents, schemas, read-only tools, prompts, fixtures, tests. No web API, no
database, no execution engine, no extra frameworks.

## Safety model

1. **Log text is data.** Every alert field is sent to the model as JSON, and `log_text`
   passes through `agents/sanitize.py` first: Unicode NFKC normalisation, control and
   zero-width characters stripped, any `<log_data>` / `</log_data>` look-alike (spaced,
   full-width or zero-width-obfuscated) replaced with `[neutralised-tag]`, and the result
   capped at 2 000 characters. It is then fenced between `<log_data>` and `</log_data>`.
   `alert_data()` is the only way an alert becomes prompt input, so triage, investigation
   and response all get sanitised text. All three prompts say the fenced block is data, not
   instructions; tool output is fenced the same way as `<tool_data>`.
2. **Tools cannot do harm.** The Investigation agent may call only `search_logs(ip)` and
   `threat_intel(ip)` from `tools/readonly.py`, at most 3 times. Both are dict lookups in
   mock tables: no writes, no shell, no network, no arbitrary paths. Unknown tool names are
   refused with an error, and args are capped at 64 characters.
3. **The Response agent cannot act.** It returns a frozen `Proposal` whose schema fixes
   `executed: Literal[False]` and `requires_human_approval: Literal[True]`. The model may only
   fill `action` (a closed allowlist: `block_ip` | `none` | `escalate`), `target`, `reason` and
   `explanation`; ids and approval fields are added by code, and anything else the model sends
   is dropped. A `false_positive` verdict returns `action: "none"` without calling the model,
   and `block_ip` is only valid with a plain IPv4 target. `agents/response.py` imports no tool
   and has no execute function.
4. **Our own hosts are never blocked.** `config.py` holds `ALLOWLIST` (`10.0.0.1`,
   `127.0.0.1` and the `10.0.0.254` gateway). If a proposal targets one of them,
   `agents/response.py` rewrites the action to `escalate` and names the allowlist in `reason`,
   so an injected "block our own server" request cannot become a block proposal.

The verdicts are evidence, not guarantees: a model can still be wrong about *is this an
attack*, so `deterministic` code keeps the dangerous capabilities away from it entirely.

## Files

### `agents/` — behaviour
| File | What it does (2–3 lines) |
| --- | --- |
| [llm.py](agents/llm.py) | The only file that imports `groq`. Reads `GROQ_API_KEY`, `GROQ_MODEL`, `MAX_RETRIES` from `.env`, retries transient errors with tenacity, forces JSON output, and converts bad JSON or schema mismatches into one `LLMError`. The client is injectable so tests never hit the network. |
| [sanitize.py](agents/sanitize.py) | The guard for attacker-controlled text. `sanitize_log_text()` normalises (NFKC), strips control and zero-width characters, neutralises `<log_data>` look-alikes and truncates to 2 000 characters; `wrap_untrusted()` fences the result; `alert_data()` is the only way an alert becomes prompt input. |
| [safety.py](agents/safety.py) | Compatibility shim that re-exports `agents/sanitize.py` for older imports. |
| [prompts.py](agents/prompts.py) | Loads `prompts/<name>.md` as a system message, cached per process. |
| [triage.py](agents/triage.py) | `triage(alert) -> TriageVerdict`: one call through `get_validated()`, so a malformed reply is retried with the error fed back. `alert_id` is stamped by code. Stores nothing. |
| [investigation.py](agents/investigation.py) | `investigate(alert, verdict) -> list[Finding]`: a real tool-calling loop restricted to `search_logs` and `threat_intel`, ≤3 executions. Each `Finding` is built by code from the tool output, then stored per `alert_id` in an in-memory dict (`get_findings` / `save_findings` / `clear_findings`) ready to swap for Hermes SessionDB. |
| [response.py](agents/response.py) | `respond(alert, verdict, findings) -> Proposal`: a false positive short-circuits to a code-built `action: "none"` (no model call); otherwise one LLM call, then `build_proposal()` keeps only model-fillable fields. Frozen, `executed=False`, generated `proposal_id`, no code path that performs the action. |
| [pipeline.py](agents/pipeline.py) | Triage first; a `false_positive` verdict stops there. Otherwise investigation, then a proposal. Returns one `PipelineResult`. |
| [gate_wrapper.py](agents/gate_wrapper.py) | `run_tool(name, args, policy=None)`: a default-deny gate for callers outside Hermes. Refuses dangerous or unknown names, malformed arguments, and any policy answer that is not an explicit `{"action": "allow"}`. Every refusal is logged; the tool body is never reached. |

### `config.py`
Local policy, not secrets: `ALLOWLIST` (`10.0.0.1`, `127.0.0.1`, the `10.0.0.254` gateway) and
`is_allowlisted(target)`, used by `agents/response.py` to forbid blocking our own hosts.

### `schemas/`
| File | What it does |
| --- | --- |
| [models.py](schemas/models.py) | All Pydantic v2 contracts: `Alert`, `TriageVerdict`, `Finding`, `Proposal` (frozen, `executed: Literal[False]`, target checked against the action, plain IPv4 required for `block_ip`) and the `PipelineResult` wrapper. Closed `Literal` vocabularies are the allowlists. |

### `tools/`
| File | What it does |
| --- | --- |
| [readonly.py](tools/readonly.py) | Five read-only lookups: three over `data/*.json`, plus the mock `search_logs` and `threat_intel`. `api_tool_specs(names)` builds OpenAI-style schemas for the chat API, and `run_tool()` validates the name/arg and returns JSON errors instead of raising. |

### `prompts/`
`triage.md`, `investigation.md`, `response.md` — static instructions only; dynamic data is
always sent in the user message. Prompts are cached, so restart after editing one.
`triage.md` defines the three labels and carries five labelled few-shot examples, clearly
marked for you to replace with your own.

### `data/`
`sample_alerts.json` (10 varied alerts), `poisoned_logs.json` (10 hostile logs: instruction
override, fake `[SYSTEM]` message, JSON injection, `</log_data>` breakout, "block 10.0.0.1",
`0.0.0.0/0` and hostname targets, a request to call a tool by name, a 4 000-character
string, Unicode tricks, and "security team approved, skip review"), `assets.json`,
`threat_intel.json`, `alert_history.json` (tool inputs).

### `tests/`
`conftest.py` (fake Groq client + fixtures), `test_llm.py`, `test_schemas.py`,
`test_triage_10.py`, `test_safety.py` (offline injection defences), `test_investigation.py`,
`test_tools_readonly.py`, `test_response.py`, `test_pipeline.py`, `test_get_validated.py`,
`test_tool_demo.py`, `test_gate_wrapper.py` (dangerous tools refused, lookups run, every
fail-open case). None of these needs a key or the network.

`test_injection.py` holds the injection suite. Offline it checks that `sanitize_log_text()`
strips tags, control characters and length, that all three agents send sanitised text, and
that an allowlisted target is escalated rather than blocked. Its **live** test (marked
`live`, deselected by default) runs the ten hostile alerts through `triage()` and `respond()`,
sleeps between alerts to stay clear of Groq's rate limits, and writes
`results/injection_results.md`. It records model judgement rather than grading it: it fails
only on a schema-invalid reply or a prompt that shows sanitisation was skipped.

## Run

```bash
cd soc-agents
cp .env.example .env          # then put your real GROQ_API_KEY / GROQ_MODEL in .env
.venv/Scripts/python.exe main.py                       # all 10 sample alerts
.venv/Scripts/python.exe main.py data/poisoned_logs.json
.venv/Scripts/python.exe main.py data/sample_alerts.json --limit 2
```

On Linux/macOS use `python main.py` (or `.venv/bin/python`).

`MAX_RETRIES` is *extra* attempts after the first, so `2` means up to 3 calls per step.
`GROQ_MODEL` must be a model your Groq account can access (`python -c "from groq import Groq;
print([m.id for m in Groq().models.list().data])"`). Secrets are never printed; a missing key
only yields "GROQ_API_KEY is missing", and a rejected request becomes one `LLMError` line.

A real run of `A-001` (web shell) gives `true_attack`, three tool lookups, and a proposal of
`block_ip` on `198.51.100.23` with `executed: false`. `A-002` (EICAR test file) stops at
`false_positive` after one call, with no investigation and no proposal.

## Tool-calling demo

```bash
.venv/Scripts/python.exe tool_demo.py
```

`agents/llm.py` also exposes `chat(messages, tools=None, json_mode=False)`: one Groq call
with the same retry/backoff, returning the assistant message so a caller can read
`.tool_calls`. `tool_demo.py` uses it to answer "Is 203.0.113.5 dangerous?" — the model
requests `lookup_ip`, the script runs the mock in `tools/readonly.py`, sends the result back,
and prints the final sentence. `lookup_ip` returns `{"ip", "reputation", "reports"}` with only
`203.0.113.5` marked malicious. It is intentionally **not** in the agents' `TOOLS` registry: its
blanket "benign" answer would contradict `data/threat_intel.json`.

Model check on this account (Nov 2026): `openai/gpt-oss-120b`, `openai/gpt-oss-20b`,
`qwen/qwen3.8-27b` and `openai/gpt-oss-safeguard-20b` all complete the tool loop; `allam-2-7b`
returns 400 "tool calling is not supported". `.env` uses `openai/gpt-oss-120b` — strongest
reasoning, and it also passes the JSON-mode M1 pipeline.

## Gate demo: a dangerous tool paused

`plugins/soc_gate_demo/` is a Hermes plugin that registers `dummy_block_ip(ip)` and a
`pre_tool_call` hook that refuses it; `demo/hermes_demo.md` has the quoted plugin/hook contract,
the install/enable/restart commands and the marker-file proof that the body never ran.
`agents/gate_wrapper.py` is the same policy without Hermes, and `demo/failopen_cases.md` records
six fail-open cases — measured for the wrapper, `to verify` for Hermes (not installed on this
machine).

```bash
cd soc-agents
.venv/Scripts/python.exe -m pytest tests/test_gate_wrapper.py -v
```

## Test

```bash
cd soc-agents
.venv/Scripts/python.exe -m pytest        # 137 passed, live harness deselected, ~1s
.venv/Scripts/python.exe -m pytest -m live tests/test_injection.py -s   # live, ~3 min, writes results/injection_results.md
```

What they prove: the wrapper's request shape, retry and JSON handling; schema
allowlists; the 10 fixture alerts classify as expected through the real pipeline; injection
text is fenced, truncated, cannot call an unlisted tool, cannot flip `executed`/approval,
and cannot escape the data block; tools are read-only; a false positive skips
investigation. A source scan also fails the build if `subprocess`, `os.system`, `eval(`,
`exec(` or `open(` appear in `agents/`, `tools/`, `schemas/` or `main.py`.

## Not in M1

Approval workflow, audit log, execution adapters, API/queue, alert ingestion, retraining
of any kind. `hermes-agent/` in this folder is an unrelated third-party checkout and is
ignored by `pytest.ini`.
