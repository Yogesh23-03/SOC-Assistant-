# Setup and handoff

## What is implemented

- Verified analyst-token login in the extension; the identity and expiry come from `/api/session`.
- Authenticated WebSocket subprotocol, authenticated SSE fallback, REST replay and polling.
- Durable SQLite case runs, original alerts, tool observations, findings, proposals and decisions.
- Investigate more queues a durable job, obtains fresh read-only evidence, and creates a new proposal.
  The previous proposal becomes non-actionable. Failed jobs are visible and can be retried.
- Backend-generated plain-text and PDF reports, accessible only with a bearer token.
- Case counters, automatic expired-rule cleanup, and optional execution after approval on Linux.
- Threat-intelligence adapters with cache/stale indicators and a lab log-feed utility.
- Offline/live benchmark commands, extension tests, packaging and CI configuration.

This uses our own SQLite case store and code gate. Hermes SessionDB integration and
live verification of the Hermes plugin are still separate work; the plugin demo
must not be presented as a measured production gate.

## Windows startup

Run from the SOC-Assistant- directory. Keep your existing private `.env`.

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn backend.app:app --reload
```

In a second terminal:

```powershell
.\.venv\Scripts\python.exe -m backend.manage analyst.demo
```

This intentionally prints a short-lived session token. Open Chrome/Edge Extensions,
enable Developer mode, load `extension/dist`, then open SOC Assistant > Connection.
Save `http://127.0.0.1:8000`, paste the session token, and select Start lab session.
Refresh an expired session by issuing a new token; never paste SOC_JWT_SECRET,
SOC_HMAC_SECRET or GROQ_API_KEY into the extension. They stay on the backend.

Rebuild/repackage after extension source changes:

```powershell
cd extension
npm.cmd ci
npm.cmd run package
```

Reload the unpacked extension after rebuilding. The zip is
`extension/soc-assistant-extension.zip`; extract it before loading unpacked.

## Try the full analysis

Use `/docs` or the authenticated feed utility. Set a temporary session variable in
the terminal; do not put analyst tokens into committed files:

```powershell
$env:SOC_ANALYST_TOKEN = .\.venv\Scripts\python.exe -m backend.manage analyst.demo
.\.venv\Scripts\python.exe -m backend.feed --dataset data/sample_alerts.json
```

The dataset command calls the configured model and consumes its quota. No firewall
rule is applied while SOC_EXECUTE_ON_APPROVAL=false (the default). Review an alert,
request more investigation, wait for the new proposal, and download its PDF report.
Approving a proposal authorizes execution; check execution records separately.

## Linux target and real execution — user setup required

1. Supply the authorized Ubuntu target, Kali VM, networking and VM snapshots.
2. Install Python dependencies and iptables on the target. Run the backend on the
   target itself so commands affect the intended host. The current executor has no
   remote-host selector; do not point it at a different server in a proposal.
3. Configure least-privilege execution access for iptables and confirm protected
   management/analyst IPs in backend/config.py. The executor invokes sudo iptables.
4. Set SOC_EXECUTE_ON_APPROVAL=true only on that target, then restart the backend.
   Approval through the extension now invokes the backend executor; the extension
   does not retain or forward executor tokens and never contacts the firewall directly.
5. Verify `sudo iptables -C INPUT -s <attacker-ip> -j DROP` after approval, and verify
   removal after TTL. A failure stays visible in executor audit entries. Failed
   removals retain the active row and retry during the next cleanup interval.

Windows returns an explicit unsupported-platform error for real execution. It is
suitable for analysis, UI development and simulation. The CLI dry-run uses the
same proposal database, logs firewall.simulated, and creates no active rule.
Execution failures spend the token to avoid replay after an uncertain OS result;
investigate the error and create/approve a new proposal rather than replaying it.
Run one backend worker for the current maintenance/job scheduler.

## Live logs and threat intelligence

The authenticated webhook `/api/alerts` accepts the Alert schema. For auth.log:

```bash
export SOC_ANALYST_TOKEN='<short-lived-session-token>'
python -m backend.feed --auth-log /var/log/auth.log --host server-01 --follow
```

The watcher handles appended lines, truncation and rotation; it sends SSH failure,
invalid-user and password-success lines as alerts. Read permission for auth.log is
required. Current investigation searches recent ingested logs; this is not Wazuh.

SOC_DATA_MODE defaults to fixture. Set it to live for persisted-log search and
external reputation lookup. Add ABUSEIPDB_API_KEY and/or VIRUSTOTAL_API_KEY only to
.env, then restart. Only public IPv4 indicators are queried. Results are cached;
provider failures are unknown or explicitly stale, never silently benign.
Adapters are tested with mock HTTP responses; you must supply keys and verify the
live services. API references: [AbuseIPDB](https://docs.abuseipdb.com/#check-endpoint),
[VirusTotal](https://docs.virustotal.com/reference/ip-info).

## Evaluation

```powershell
.\.venv\Scripts\python.exe -m backend.benchmark --mode offline
# Explicit live run: consumes the configured model's quota.
.\.venv\Scripts\python.exe -m backend.benchmark --mode live --delay 3
```

Reports go into results/ as JSON and Markdown. Offline mode uses scripted verdicts
and must not be cited as model accuracy. Live mode measures labelled accuracy,
false-positive auto-close rate, unsafe auto-closes, confusion counts and median
alert-to-proposal time. The supplied labelled set has only ten alerts; expand and
review it for a meaningful final benchmark (about 30+ for the shortened plan).
Pipeline output execution flags are recorded; real unauthorized-action claims need
executor-negative tests and lab evidence, not only this benchmark.

## Optional TLS/container setup

`docker compose up --build` starts the backend and a Caddy proxy. This configuration
keeps real execution disabled and stores case data in a named Docker volume.
Docker is optional and was not assumed to be installed on your machine.

For https://soc-backend.lab.local you must map that hostname to the lab host and
trust Caddy's local root certificate on the demo machine. Export the certificate
from the caddy-data volume, verify it, and install it through your operating
system certificate UI. Never disable certificate verification. Use localhost HTTP
until this is configured. The compose stack does not control the VM host firewall.

## Tests and manual acceptance

```powershell
.\.venv\Scripts\python.exe -m pytest tests backend/tests
cd extension
npm.cmd test
npm.cmd run test:e2e
```

If Playwright needs a browser: `npx.cmd playwright install chromium`, or set
PLAYWRIGHT_CHROMIUM_EXECUTABLE to a compatible installed Chromium executable.
The real-backend browser test creates a separate temporary SQLite database and
forces the safe validation-failure path; it never queries a live LLM or firewall.

You still need to:

- Load the build in your actual Chrome and Edge profiles and verify native notifications.
- Stop the extension service worker from the browser extension page with DevTools
  closed, ingest an alert, reopen the panel and confirm pending state/evidence recover.
- Demonstrate network outage/recovery and no duplicated decisions.
- Perform the real authorized lab attack/approve/block/TTL-removal sequence.
- Run the live benchmark with reviewed labels; record actual results.
- Add member names, college format and submission date to the presentation draft.
- Rehearse and record the three demos and a backup video.

No production-deployment or Hermes-integration completion is claimed here.
