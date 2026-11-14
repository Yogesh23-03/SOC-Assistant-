# SOC Assistant — M3 browser extension

Chrome/Edge MV3 side panel for the existing M2 backend. Requires Chrome/Edge 120+ and Node 22.12+.

## Install now

1. Open `chrome://extensions` or `edge://extensions`.
2. Enable **Developer mode**, choose **Load unpacked**, and select this folder's `dist` directory.
3. Pin **SOC Assistant**, then click its toolbar icon to open the side panel.
4. Open **Connection**, enter `http://localhost:8000`, and save.
5. Run `python -m backend.manage analyst.demo` in the trusted backend terminal, paste its short-lived token in **Session token**, and choose **Start lab session**. Start M2 separately with `python -m uvicorn backend.app:app --port 8000` in its configured Python environment.

The packaged `soc-assistant-extension.zip` contains the same build. Extract it before loading unpacked. This is a lab build, not a Web Store release.

## Develop and check

```powershell
cd extension
npm ci
npm run build
npm test
npm run package
```

For the loaded-extension browser test: run `npx playwright install chromium`, then `npm run test:e2e`. Set `PLAYWRIGHT_CHROMIUM_EXECUTABLE` to use an existing compatible Chromium installation.

`npm run dev` watches and rebuilds. Reload the extension in the browser after worker or manifest changes. All JavaScript is bundled locally; no CDN scripts or content scripts.

## Features

- Approval queue, severity, case evidence, verdicts and plain-text case export.
- Approve, reject and investigate-more decisions with an explicit confirmation and unique nonce.
- Background WebSocket heartbeat every 20 seconds, exponential reconnect and a 30-second alarm fallback.
- Paginated REST event replay and canonical pending snapshot after reconnect. WebSocket events trigger a sync rather than advancing the cursor out of order.
- Cached case history in local extension storage; short-lived analyst token only in `chrome.storage.session`. Signing out clears the token; cached cases remain within the browser profile.
- Browser notifications and a pending-count toolbar badge. No decision retries or executor calls.
- Hostile evidence is rendered through React text nodes, never HTML.

## Existing backend boundaries

The backend requires bearer authentication. The extension verifies a provisioned
session through `/api/session`; WebSockets carry it in a negotiated subprotocol,
and SSE uses an Authorization header. No signing secrets or provider keys enter
the extension. `/auth/token` renews an existing authenticated identity only.

Approval issues authorization. By default an operator executes through M2; a Linux
target can explicitly enable SOC_EXECUTE_ON_APPROVAL=true. The extension never
calls the executor and never treats approval alone as proof of execution.

Investigate more now queues a durable backend job and obtains a fresh proposal.
Failed jobs expose a retry action. Case history and evidence are restored from the
backend on sync; reports include every stored investigation and decision. Full
text and PDF downloads require the current session. SSE and polling supplement
WebSocket reconnects. Dashboard counters come from `/api/metrics`.

Only localhost HTTP and `https://soc-backend.lab.local` are permitted. For a different lab origin update `public/manifest.json` host permissions/CSP and `settingsSchema` together, rebuild and reload. Provider keys and signing secrets must never enter the extension.

## Manual acceptance checks

1. Ingest an attack with M2. Check the queue, evidence and badge; approve and confirm once. Verify M2 records the analyst and proposal as approved without claiming the rule ran.
2. Ingest a false positive. Check Cases shows auto-closed and no pending proposal.
3. Stop the backend. Refresh fails visibly and decisions are disabled. Restart and refresh; pending proposals return without duplicate rows.
4. Close worker DevTools, stop the worker from the browser extension page, and create events. Reopen the panel or wait for the alarm; check recovered pending items and evidence. Keeping DevTools open changes worker lifetime.
5. Test forged/expired tokens, expired proposals and protected targets against M2. Confirm errors are visible and no execution request leaves the extension.
6. Include `<script>` and HTML in findings. They must appear literally and never execute.
7. Load the package in Chrome and Edge and check at 360px and 480px panel widths.

Automated checks cover replay, duplicates, canonical snapshots, expiry and backend URL restrictions. A real-backend Chromium integration test covers authentication, WebSocket connection, stored hostile evidence, PDF download, reinvestigation and panel reload. A loaded-extension Chromium test against an isolated HTTP test backend also verifies session setup, hostile evidence rendering, explicit confirmation and one authenticated decision. Real M2/VM integration and service-worker sleep recovery remain manual acceptance checks.
