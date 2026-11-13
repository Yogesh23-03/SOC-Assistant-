# Fail-open cases — the gate

"Fail open" means the safety check did not block, so the dangerous tool ran. "Fail closed"
means anything unclear refused the call.

Two enforcement points are covered:

- **Wrapper** (`agents/gate_wrapper.py`) — measured here. Every case below has a test.
- **Hermes plugin** (`plugins/soc_gate_demo/`) — **to verify**: Hermes is not installed on
  this machine, so those rows cite the source and give the exact reproduction steps. They are
  not measurements.

Run the measured cases:

```bash
cd soc-agents
.venv/Scripts/python.exe -m pytest tests/test_gate_wrapper.py -v
```

Summary (measured column from that run):

| # | Case | Wrapper (measured) | Tool ran? | Hermes (source says) | Tool ran? |
| --- | --- | --- | --- | --- | --- |
| 1 | Hook returns `None` | refused: "policy returned no decision (default-deny)" | no | `None` is ignored by the dispatcher → gate is absent | **yes** (fail open) |
| 2 | Malformed return (`"block"`, `{"action":"block"}` with no message, unknown action) | refused | no | ignored by the dispatcher | **yes** (fail open) |
| 3 | Hook raises | refused: "policy raised RuntimeError: ..." | no | `pre_tool_call` fails closed | no (fail closed) |
| 4 | Tool name casing / whitespace (`DUMMY_BLOCK_IP`, `" dummy_block_ip "`) | refused (name normalised) | no | registry names are exact; hook match is the plugin's job — to verify | to verify |
| 5 | Unknown tool name (`frobnicate`) | refused: "unknown tool - default deny" | no | no handler registered — to verify | to verify |
| 6 | Plugin not enabled | dangerous tool still refused; `lookup_ip` runs | no | plugin's tool is not registered either — to verify | to verify |

---

## 1. Hook returns `None`

**What happened (wrapper).** `None` is not consent: `_ask_policy()` treats it as "no decision"
and `run_tool()` refuses, logging `gate refused tool='lookup_ip': policy returned no decision
(default-deny)`.

Test: `test_hook_returning_none_is_a_refusal` — **passes**, tool did not run.

**What Hermes does (source).** `_get_pre_tool_call_directive_details` starts from "no
directive" and only changes it for a valid block/approve dict; the loop skips anything else:

```python
for result in hook_results:
    if not isinstance(result, dict):
        continue
```

`plugins/security-guidance/__init__.py` states the convention directly: `None = let it
through`. So a plugin that forgets to return a directive fails open. **TO VERIFY** on a live
install: temporarily make `on_pre_tool_call` return `None` unconditionally, restart, run the
prompt in §3 of `hermes_demo.md`; expect `WOULD BLOCK 10.0.0.1` and a created marker file.

**Did the tool run?** Wrapper: no. Hermes: yes, per source (to verify).

**Fix.** Never encode safety as "return nothing". Return an explicit
`{"action": "block", "message": "..."}` and keep a default-deny layer (the wrapper) that does
not depend on the plugin's return value at all.

---

## 2. Malformed return value

**What happened (wrapper).** A string, a dict without a known action, or
`{"action": "block"}` with no message is refused:
`policy returned str, not a decision object` / `policy returned unknown action 'maybe'` /
`blocked by policy`.

Tests: `test_a_malformed_hook_return_is_a_refusal`,
`test_an_unknown_hook_action_is_a_refusal`,
`test_a_block_without_a_message_is_still_a_refusal` — **pass**, tool did not run.

**What Hermes does (source).** The dispatcher ignores exactly these shapes:

```python
if action not in ("block", "approve"):
    continue
...
if action == "block" and not message:
    continue
```

A block directive **requires** a non-empty string message; without it the hook has no effect
and the tool runs. **TO VERIFY**: return `{"action": "block"}` (no message) from
`on_pre_tool_call`, restart, rerun; expect the tool to execute.

**Did the tool run?** Wrapper: no. Hermes: yes, per source (to verify).

**Fix.** Include `message`; unit-test the hook's return value (shape + non-empty message)
instead of trusting it. The wrapper refuses every malformed shape.

---

## 3. Exception inside the hook

**What happened (wrapper).** A raising policy is a refusal, and the reason names the exception:
`policy raised RuntimeError: hook crashed`. Test: `test_a_raising_hook_is_a_refusal` —
**passes**, tool did not run.

**What Hermes does (source).** `pre_tool_call` is the one hook in
`_HOOK_TIMEOUT_FAIL_CLOSED_HOOKS`, and a raising callback becomes a block directive built by
`_policy_error_block_directive()`:

```python
return {"action": "block",
        "message": f"{hook_name} plugin callback {callback_name} raised {type(exc).__name__}: ..."}
```

The docs say the same for timeouts ("Timed-out or still-running `pre_tool_call` callbacks fail
closed"). So Hermes itself does **not** fail open here. **TO VERIFY**: add
`raise RuntimeError("boom")` at the top of the hook, restart, rerun; expect the tool result to
be the block message naming `on_pre_tool_call` and `RuntimeError`.

**Did the tool run?** Wrapper: no. Hermes: no, per source (to verify).

**Fix.** Nothing to change for safety; the crash is loud on purpose. Keep the hook small and
exception-free so a real block is not confused with a broken one.

---

## 4. Tool name with different casing or whitespace

**What happened (wrapper).** The name is normalised with `"".join(name.split()).lower()`, so
`DUMMY_BLOCK_IP`, `" dummy_block_ip "`, `"\tDummy_Block_Ip\n"` all hit the dangerous set.
Parameterised test: `test_name_casing_and_whitespace_cannot_bypass_the_gate` — **4/4 pass**,
nothing ran.

**What Hermes does (source).** The dispatcher passes the registry's `tool_name` as-is; there is
no case folding. A hook comparing against a hard-coded name is correct only if the plugin's
registered name is exactly what the model was offered. This is *not* a Hermes fail-open by
itself — it becomes one when a hook compares loosely (`in`, `startswith`) or the tool is
registered under a different name than the hook checks. **TO VERIFY**: ask the model for
`DUMMY_BLOCK_IP`; expect an unknown-tool error and no marker file; then rename the registered
tool to `dummy_block_ip_v2` without updating the hook and confirm the block silently stops
applying.

**Did the tool run?** Wrapper: no. Hermes: to verify.

**Fix.** Normalise on both sides and derive the guarded name from one constant
(`TOOL_NAME` here), never a second literal. Keep the wrapper's normalisation as the floor.

---

## 5. Unknown tool name

**What happened (wrapper).** The wrapper is an allowlist, not a denylist: only
`lookup_ip`, `search_logs` and `threat_intel` are reachable, so `frobnicate` is refused before
any dispatch (`unknown tool - default deny`). Test:
`test_unknown_tool_is_refused_before_dispatch` — **passes**, nothing ran.

**What Hermes does (source).** A name with no registered handler cannot be dispatched; the
model gets an unknown-tool error. The `pre_tool_call` hook may not even see it. **TO VERIFY**:
call `dummy_block_ip_v9`; expect a tool-not-found error from Hermes and no marker file.

**Did the tool run?** Wrapper: no. Hermes: to verify.

**Fix.** Prefer allowlists for what may run. A denylist only refuses names someone remembered
to list; an unknown name should never default to "run it".

---

## 6. Plugin not enabled

**What happened (wrapper).** With no policy installed (`policy=None`) the dangerous set still
refuses `dummy_block_ip`, and `lookup_ip` still runs. Test:
`test_no_policy_means_no_plugin_and_dangerous_still_fails_closed` — **passes**.

**What Hermes does (source).** A disabled plugin is not loaded, so neither its tool nor its
hook exists: there is nothing to block. That is safe by absence for this demo, but it means a
gate that ships *inside* the same plugin as the tool provides no protection if the tool is
later registered elsewhere, or if someone copies the tool without the hook. **TO VERIFY**:
`hermes plugins disable soc_gate_demo`, `hermes gateway restart`, then ask for
`dummy_block_ip`; expect the tool to be unknown. Then re-enable it with the hook removed to
see the body run.

**Did the tool run?** Wrapper: no (tool still gated). Hermes: no tool to run (to verify).

**Fix.** Keep enforcement outside the plugin (this wrapper) and treat the plugin hook as an
extra layer, not the only one. Add `hermes plugins list` to the deployment check so a disabled
gate is visible.

---

## The rule this leaves behind

A hook is a request to the framework, and frameworks define what "no opinion" means. Hermes
runs the tool on `None`, on a non-dict, and on a block without a message. So the gate must be
default-deny, own its own allowlist, and treat every unclear answer — including silence — as
"no".
