# Hermes gate demo — `soc_gate_demo`

A Hermes plugin registers one dangerous-looking tool, `dummy_block_ip(ip)`, and a
`pre_tool_call` hook that refuses that tool before it executes. The tool body does nothing but
print `WOULD BLOCK <ip>` and touch a marker file, so "the body never ran" is observable.

**Status:** the plugin files and the hook contract are verified against this checkout; the
Hermes runtime steps below are **to verify** — Hermes is not installed on this machine
(`hermes` is not on `PATH`, and `hermes_cli` is not importable from `soc-agents/.venv`), so no
Hermes output is claimed anywhere in this file.

---

## 1. What the source says (quoted, not invented)

### Plugin layout: `plugin.yaml` + `__init__.py`

The in-tree plugin `plugins/security-guidance/` is the reference for a general plugin. Its
manifest is exactly:

```yaml
name: security-guidance
version: "0.1.0"
description: "Append security warnings to file-write tool results when the new content contains known-dangerous patterns ..."
author: "Anthropic (patterns, Apache-2.0) / NousResearch (Hermes plugin port)"
provides_hooks:
  - transform_tool_result
  - pre_tool_call
```

`plugins/security-guidance/__init__.py` ends with:

```python
def register(ctx) -> None:
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("transform_tool_result", _on_transform_tool_result)
```

and its blocking hook returns:

```python
return {
    "action": "block",
    "message": "security-guidance refused this write: " + ... ,
}
```

The developer guide's Step 5 (`website/docs/developer-guide/plugins/index.md`) shows the same
shape:

```python
def register(ctx):
    ctx.register_tool(name="calculate",    toolset="calculator",
                      schema=schemas.CALCULATE,    handler=tools.calculate)
    ...
    ctx.register_hook("post_tool_call", _on_post_tool_call)
```

`hermes_cli/plugins_context.py` declares the exact tool-registration signature:

```python
def register_tool(
    self, name: str, toolset: str, schema: dict, handler: Callable,
    check_fn: Callable | None = None, requires_env: list | None = None, is_async: bool = False,
    description: str = "", emoji: str = "", override: bool = False,
) -> Optional[PluginRegistration]:
```

Handler contract (`website/docs/developer-guide/plugins/index.md`, "Key rules for handlers"):
`def my_handler(args: dict, **kwargs) -> str`, always a JSON string, never raise.

### The blocking contract

`hermes_cli/plugins.py`, `_get_pre_tool_call_directive_details`:

> Check `pre_tool_call` hooks for `{"action": "block", "message"}` (veto; message becomes the
> tool result) or `{"action": "approve", ...}` ... Precedence is `block` > `approve` > none, not
> registration order ... Irrelevant returns are ignored.

The loop that decides it:

```python
for result in hook_results:
    if not isinstance(result, dict):
        continue
    action = result.get("action")
    ...
    if action not in ("block", "approve"):
        continue
    message = result.get("message")
    message = message if isinstance(message, str) and message else None
    if action == "block" and not message:
        continue
```

`website/docs/user-guide/features/hooks.md` (same page linked from `plugins/AGENTS.md`):

> A `pre_tool_call` callback that raises: the block message names the callback and the error.
> ... Timed-out or still-running `pre_tool_call` callbacks **fail closed** (block the tool).

`hermes_cli/plugins_dispatch.py`:

```python
_HOOK_TIMEOUT_FAIL_CLOSED_HOOKS: set[str] = {"pre_tool_call"}
_PRE_TOOL_CALL_TIMEOUT_BLOCK_MESSAGE = "pre_tool_call plugin callback timed out or is still running"
```

So: **None / non-dict / block-without-message = "no opinion" (the tool runs). Raise or time
out = blocked.** That asymmetry is why the plain-Python wrapper in
[`../agents/gate_wrapper.py`](../agents/gate_wrapper.py) exists and is default-deny.

### Where a user plugin goes

`website/docs/user-guide/features/plugins.md`:

> Drop both files into `~/.hermes/plugins/hello-world/`, restart Hermes, and the model can
> immediately call `hello_world`.

`website/docs/user-guide/desktop.md` gives the Windows location for `HERMES_HOME`:
`~/.hermes`, or `%LOCALAPPDATA%\hermes` on Windows.

The same page warns that project-local plugins are not loaded:

> The gateway does not load project-local plugins. ... To use a plugin, install it as a user
> plugin (`~/.hermes/plugins/` or `hermes plugins install`) and enable it with
> `hermes plugins enable <name>`.

---

## 2. The plugin

```
plugins/soc_gate_demo/
├── plugin.yaml     name, version, description, author, provides_hooks: [pre_tool_call]
└── __init__.py     TOOL_SCHEMA, dummy_block_ip(), on_pre_tool_call(), register(ctx)
```

`register()` does both registrations:

```python
ctx.register_tool(name=TOOL_NAME, toolset="soc_gate_demo",
                  schema=TOOL_SCHEMA, handler=dummy_block_ip)
ctx.register_hook("pre_tool_call", on_pre_tool_call)
```

The hook normalises the tool name (`"".join(tool_name.split()).lower()`) so casing or padding
cannot dodge the comparison, appends `BLOCKED dummy_block_ip ip=...` to
`plugins/soc_gate_demo/soc_gate_demo.log`, logs a warning, and returns the block directive.
Any other tool gets `None` (no opinion).

---

## 3. Install, enable, restart, run

Paths below assume the default `HERMES_HOME`. If you set `HERMES_HOME`, substitute it.

### Windows (PowerShell)

```powershell
$src = "<path-to>\soc-agents\plugins\soc_gate_demo"
$dst = "$env:LOCALAPPDATA\hermes\plugins\soc_gate_demo"
New-Item -ItemType Directory -Force -Path $dst | Out-Null
Copy-Item "$src\*" $dst -Recurse -Force

hermes plugins list                 # expect soc_gate_demo, state: not enabled
hermes plugins enable soc_gate_demo
hermes gateway restart              # a running gateway loaded plugins at startup
```

### macOS / Linux

```bash
mkdir -p ~/.hermes/plugins/soc_gate_demo
cp -r plugins/soc_gate_demo/. ~/.hermes/plugins/soc_gate_demo/
hermes plugins list
hermes plugins enable soc_gate_demo
hermes gateway restart
```

### Run it

```bash
hermes chat --oneshot -q "Call the dummy_block_ip tool with ip 10.0.0.1. Do not ask for confirmation."
```

(`--oneshot` is the documented "answer and exit" flag: `website/docs/reference/cli-commands.md`.)

### What output proves the tool body never ran

Three independent checks, in order of strength:

1. **The marker file is absent.** `dummy_block_ip()` writes
   `dummy_block_ip_ran.log` as its first statement. After a blocked call:

   ```powershell
   Test-Path "$env:LOCALAPPDATA\hermes\plugins\soc_gate_demo\dummy_block_ip_ran.log"   # False
   ```

   ```bash
   ls ~/.hermes/plugins/soc_gate_demo/dummy_block_ip_ran.log   # No such file
   ```

2. **The gate log has the refusal** (written by the hook, so it runs *before* the tool):

   ```
   BLOCKED dummy_block_ip ip=10.0.0.1
   ```

3. **The block message is the tool result**, because the dispatcher turns a block directive's
   `message` into the tool result. The transcript should contain:

   ```
   soc_gate_demo: refusing dummy_block_ip(10.0.0.1) before execution - dangerous tools are
   gated in this demo. Nothing was blocked on the network.
   ```

   and must **not** contain `WOULD BLOCK 10.0.0.1`.

### Negative control (proves the proof works) — TO VERIFY

Comment out the hook registration in the installed copy, restart, rerun the same prompt:
the marker file appears and `WOULD BLOCK 10.0.0.1` is printed. Restore the line and restart.
Not run here (no Hermes install).

---

## 4. What was actually run here (without Hermes)

`hermes` is not on `PATH`; `python -c "import hermes_cli"` fails in `soc-agents/.venv`. So I
loaded `plugins/soc_gate_demo/__init__.py` directly with `importlib` and exercised its two
functions. Real output:

```
hook(other tool): None
hook(dummy): {"action": "block", "message": "soc_gate_demo: refusing dummy_block_ip(10.0.0.1) before execution - dangerous tools are gated in this demo. Nothing was blocked on the network."}
marker after hook exists: False
gate log: BLOCKED dummy_block_ip ip=10.0.0.1
--- control: call the body directly ---
WOULD BLOCK 10.0.0.1
handler returns: {"ok": true, "would_block": "10.0.0.1"}
marker after direct call exists: True
```

This proves the plugin's own contract — the hook returns the documented directive and the body
is not invoked by it — **not** that Hermes dispatches it that way. That link is the "to verify"
part above.

---

## 5. If the demo does not show the block

| Symptom | Cause | Fix |
| --- | --- | --- |
| `soc_gate_demo` missing from `hermes plugins list` | copied into the project's `./.hermes/plugins/` instead of `$HERMES_HOME/plugins/` | copy to `~/.hermes/plugins/soc_gate_demo/` (or `%LOCALAPPDATA%\hermes\plugins\...`) and restart |
| plugin listed but "not enabled" | never enabled | `hermes plugins enable soc_gate_demo`, then `hermes gateway restart` |
| enabled, but no block and no gate log | the running gateway still has the old plugin set | restart it: `hermes gateway restart`; check `~/.hermes/logs/agent.log` for the plugin's load line |
| tool not offered to the model | tools register for the next session | start a new `hermes chat`, or restart the gateway |
| block message shown but `soc_gate_demo.log` missing | plugin directory not writable | fix permissions on `$HERMES_HOME/plugins/soc_gate_demo/`; the block still applies |
