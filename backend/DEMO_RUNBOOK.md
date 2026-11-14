# Secure setup

Set private SOC_HMAC_SECRET and SOC_JWT_SECRET values in the repository .env
before starting the backend. Missing secrets and legacy development defaults fail startup.
Generate each with `python -c "import secrets; print(secrets.token_urlsafe(48))"`.

Provision an initial analyst session from a trusted server terminal:

```bash
python -c "from backend.security import create_analyst_token; print(create_analyst_token('analyst.demo'))"
```

Set TOKEN to that value. All /api routes require Authorization: Bearer $TOKEN.
/auth/token only renews an authenticated session for the same analyst; an analyst
name/password alone cannot create a session. WebSockets require the bearer header
or /ws/analyst?token=<session-token>; use TLS and redact token query parameters in logs.
The CLI executor requires access to the same proposal database as the backend.

# Agentic SOC Assistant — M2 Backend Demo Runbook

> **Role:** M2 (Shashank Patil — Backend & Security Lead)  
> **Date:** Demo Day / Milestone Review  
> **Scope:** Phase 6 — End-to-End Proof-of-Skill Demonstration

---

## 1. Prerequisites

| Requirement | Check |
|---|---|
| Python 3.11+ installed | `python --version` |
| Working directory is `SOC-Assistant-` | `cd "c:\Users\...\SOC-Assistant-"` |
| SQLite available (bundled with Python) | `python -c "import sqlite3; print('ok')"` |
| `wscat` installed (for WebSocket demo) | `wscat --version` or `npx wscat --version` |
| All 52+ unit tests pass | see §2 |

---

## 2. Run All Unit Tests (Pre-Demo Verification)

```bash
cd "SOC-Assistant-"
python -m unittest discover -s backend/tests -v
```

**Expected output:**
```
Ran 52 tests in 4.2s
OK
```

> Any test failure before demo is a blocker — fix before proceeding.

---

## 3. Automated Proof-of-Skill Demo (No Browser Required)

The fastest way to demonstrate all five proof-of-skill scenarios is the
self-contained CLI demo script:

```bash
cd "SOC-Assistant-"
python -m backend.demo
```

**Expected output:**
```
======================================================================
   Agentic SOC Assistant — Proof-of-Skill Demo (M2 Backend)
======================================================================

======================================================================
  SCENARIO 1 — Full Attack-to-Containment Flow
======================================================================
  → Ingesting SIEM alert  alert_id=DEMO-A-001  source_ip=198.51.100.42
  ✔ PASS  Alert ingested; proposal queued as 'pending'
  ✔ PASS  Proposal visible in analyst queue
  ✔ PASS  Analyst decision accepted; HMAC token issued
  ✔ PASS  Firewall rule applied (dry-run)
  ✔ PASS  Audit chain is intact

======================================================================
  SCENARIO 2 — Forged HMAC Token Rejection
======================================================================
  → Executor raised PermissionError   Security refusal: Signature verification…
  ✔ PASS  Forged token rejected by executor
  ✔ PASS  'executor.refused_invalid_token' written to audit log

[…scenarios 3, 4, 5…]

======================================================================
  DEMO SUMMARY
======================================================================
  ✔ PASS  1. Full Attack-to-Containment
  ✔ PASS  2. Forged Token Rejection
  ✔ PASS  3. Expired Proposal Rejection
  ✔ PASS  4. Allowlisted Target Rejection
  ✔ PASS  5. WebSocket Event Replay

  ALL PROOF-OF-SKILL SCENARIOS PASSED ✔
```

---

## 4. Live Server Demo (Full HTTP + WebSocket)

### 4a. Start the Backend Server

```bash
cd "SOC-Assistant-"
python -m uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload
```

**Swagger UI:** http://localhost:8000/docs  
**Health Check:** http://localhost:8000/health

---

### 4b. Analyst Authentication

```bash
curl -s -X POST http://localhost:8000/auth/token \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"analyst_id": "analyst-demo", "password": "soc-analyst-pass"}' | python -m json.tool
```

**Expected response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in_minutes": 120,
  "analyst_id": "analyst-demo",
  "role": "soc_analyst"
}
```

> Copy the `access_token` and set `TOKEN=<paste_here>` in your shell.

---

### 4c. Scenario 1 — Ingest a Real Attack Alert

```bash
curl -s -X POST http://localhost:8000/api/alerts/sample/0 | python -m json.tool
```

This triggers the M1 pipeline with the pre-loaded Web Shell attack sample. Response:
```json
{
  "status": "pending_approval",
  "alert_id": "A-001",
  ...
  "proposal": { "action": "block_ip", "target": "...", "status": "pending" }
}
```

**Get the pending proposal list:**
```bash
curl -s http://localhost:8000/api/proposals/pending \
  -H "Authorization: Bearer $TOKEN" | python -m json.tool
```

> Copy `proposal_id` and `target` from the response.

---

### 4d. Scenario 1 (continued) — Analyst Approves the Proposal

```bash
curl -s -X POST http://localhost:8000/api/decisions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "proposal_id": "<PROPOSAL_ID>",
    "decision": "approve",
    "nonce": "demo-nonce-001-unique"
  }' | python -m json.tool
```

Response includes the `signed_token` with HMAC signature. Copy `signed_token` object.

---

### 4e. Execute Containment Action

Save the exact `signed_token` object from the decision response to approval_token.json.
The REST body is flat: do not wrap it in token_data or supply dry_run.

```bash
curl -s -X POST http://localhost:8000/api/executor/apply \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @approval_token.json
```

Linux with working sudo/iptables returns HTTP 200 and status success. Windows and
other unsupported platforms return HTTP 503 with an unsupported platform error.
A spent token returns HTTP 409; failed attempts also spend the token to prevent
retries after an uncertain OS result. Investigate failures and approve a new proposal.

For simulation only, on the same backend database:

```bash
python -m backend.cli_executor --file approval_token.json --dry-run
```

Simulation returns status simulated, logs firewall.simulated, and does not create
an active block or consume the executor token.

### 4f. Scenario 2 — Forged Token Rejection

Take the `signed_token` from §4d and change the first character of `signature`:

```bash
curl -s -X POST http://localhost:8000/api/executor/apply \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
      "proposal_id": "prop-xxx",
      "action": "block_ip",
      "target": "198.51.100.42",
      "ttl_seconds": 3600,
      "expires_at": "2099-01-01T00:00:00+00:00",
      "nonce": "demo-nonce-001-unique",
      "signature": "0ORGED_SIGNATURE_REPLACE_FIRST_CHAR_HERE",
      "issued_at": "2026-11-13T12:00:00+00:00"
  }' | python -m json.tool
```

**Expected response (HTTP 403):**
```json
{
  "detail": "Security refusal: Signature verification failed: forged or altered token"
}
```

---

### 4g. Scenario 3 — Expired Proposal Rejection

Approve any proposal that has already timed out. The backend returns:

```json
{
  "detail": "Proposal has expired: action refused under default-to-deny policy"
}
```

> HTTP status: **400 Bad Request**

---

### 4h. Scenario 4 — Allowlisted Target Rejection (10.0.0.1)

Create a proposal targeting the management host `10.0.0.1`:

```bash
curl -s -X POST http://localhost:8000/api/proposals \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "proposal_id": "allow-test-001",
    "alert_id": "DEMO-ALLOW-999",
    "action": "block_ip",
    "target": "10.0.0.1",
    "reason": "Demo allowlist test",
    "explanation": "",
    "confidence": 0.5
  }' | python -m json.tool
```

Then attempt to approve it:
```bash
curl -s -X POST http://localhost:8000/api/decisions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "proposal_id": "allow-test-001",
    "decision": "approve",
    "nonce": "allow-unique-nonce-999"
  }' | python -m json.tool
```

**Expected response (HTTP 403):**
```json
{
  "detail": "Safety violation: Target '10.0.0.1' is in the protected allowlist and cannot be blocked"
}
```

---

### 4i. Scenario 5 — WebSocket Event Replay (wscat)

**Terminal 1 — Start server** (if not already running)
```bash
python -m uvicorn backend.app:app --port 8000
```

**Terminal 2 — Connect the analyst extension WebSocket**
```bash
npx wscat -c "ws://localhost:8000/ws/analyst"
```

After connection, the server sends a welcome message. Now simulate some activity by injecting sample alerts via Terminal 3.

**Terminal 3 — Inject 3 alerts**
```bash
curl -s -X POST http://localhost:8000/api/alerts/sample/0 > /dev/null
curl -s -X POST http://localhost:8000/api/alerts/sample/1 > /dev/null
curl -s -X POST http://localhost:8000/api/alerts/sample/2 > /dev/null
```

**Back in Terminal 2** — you see real-time events arrive:
```json
{"event_type": "alert.new", "data": {...}}
{"event_type": "proposal.pending", "data": {...}}
```

**Simulate disconnect:** `Ctrl+C`  
**Reconnect with sync.request to replay missed events:**
```bash
npx wscat -c "ws://localhost:8000/ws/analyst"
```

After connection, send:
```json
{"type": "sync.request", "last_seen_event_id": 1}
```

**Expected output:**
```json
{"event_type": "alert.new", "data": {...}, "event_id": 2}
{"event_type": "proposal.pending", "data": {...}, "event_id": 3}
{"type": "sync.complete", "replayed": 2, "last_event_id": 3}
```

---

## 5. Audit Log Verification

```bash
curl -s http://localhost:8000/api/audit?limit=20 \
  -H "Authorization: Bearer $TOKEN" | python -m json.tool
```

**Verify hash-chain integrity:**
```bash
curl -s http://localhost:8000/api/audit/verify \
  -H "Authorization: Bearer $TOKEN" | python -m json.tool
```

**Expected response:**
```json
{
  "valid": true,
  "checked_entries": 18,
  "message": "Audit chain integrity verified: all 18 entries are consistent"
}
```

---

## 6. Active Blocks & TTL Expiry

**List current active firewall blocks:**
```bash
curl -s http://localhost:8000/api/executor/blocks \
  -H "Authorization: Bearer $TOKEN" | python -m json.tool
```

**Trigger TTL expiry cleanup:**
```bash
curl -s -X POST http://localhost:8000/api/executor/expire \
  -H "Authorization: Bearer $TOKEN" | python -m json.tool
```

---

## 7. Proof-of-Skill Checklist

| Requirement | How to Demonstrate | Evidence |
|---|---|---|
| ✅ Full E2E flow (alert → executor) | §4c → §4e or `python -m backend.demo` | HTTP 200 `{"status":"success"}` |
| ✅ Forged token rejected | §4f | HTTP 403, `executor.refused_invalid_token` in audit |
| ✅ Expired proposal rejected | §4g | HTTP 400, `decision.refused_expired` in audit |
| ✅ Allowlisted target rejected | §4h | HTTP 403, `decision.allowlist_violation_blocked` in audit |
| ✅ WebSocket event replay | §4i | 2+ events replayed + `sync.complete` message |
| ✅ Audit chain intact | §5 | `{"valid": true, "checked_entries": N}` |
| ✅ 52+ unit tests pass | §2 | `Ran 52 tests in Xs — OK` |

---

## 8. Troubleshooting

| Issue | Likely Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: groq` | groq not installed | `demo.py` and tests auto-stub it; run via `python -m backend.demo` |
| Port 8000 already in use | Another process | Use `--port 8001` and update curl commands accordingly |
| Nonce already consumed error | Reusing the same nonce string | Always use a unique nonce per decision (e.g. a UUID) |
| Rate limit exceeded | Too many blocks in 60s | Wait 60s or restart server (resets in-memory rate limiter) |
| `sqlite3.OperationalError: database is locked` | Two processes writing | Only run one uvicorn instance at a time |

---

*Generated by M2 (Shashank Patil) — Agentic SOC Assistant Phase 6 Demo Runbook*
