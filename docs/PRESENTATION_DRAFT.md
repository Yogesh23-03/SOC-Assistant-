# Presentation draft — 10–12 minutes

Replace bracketed fields with team/college details and measured results.

1. **Problem:** Alert fatigue, manual triage delay, and the risk of allowing an AI
   to change a firewall without review. Team: [names].
2. **Related work:** Existing SOC assistants; our focus is a browser console,
   explicit approval, injection resistance, and an auditable execution boundary.
3. **Architecture:** Log/webhook ? triage ? investigation ? proposal ? browser
   decision ? signed authorization ? Linux executor. Show where secrets live.
4. **Safety:** Read-only investigation tools, schema-validated proposals, protected
   IPs, authenticated decisions, nonces, signed TTL, one-time executor tokens,
   append-only hash chain and rule cleanup. Approval is distinct from execution.
5. **Demo:** (A) lab alert/approve/block/report; (B) benign alert auto-close;
   (C) poisoned log cannot block a protected server. Keep a backup video.
6. **Results:** [live model/version], [dataset size], [accuracy], [FP auto-close
   rate], [unsafe auto-closes], [median proposal latency], [negative security-test
   results]. Offline fixture results are not model accuracy. Include browser
   recovery and actual firewall evidence separately.
7. **Limits:** Small evaluation dataset, model mistakes, lab-only identity
   provisioning, single-host execution, own SQLite store rather than integrated
   Hermes SessionDB. Future work: SIEM integration and richer correlation.

## Demo checklist

- Snapshot VMs; confirm management IP protection and time-limited firewall rules.
- Start backend; verify /health; issue a fresh analyst session token.
- Load/reload packaged extension and confirm connection and notifications.
- Keep harmless sample alerts and cached evidence available.
- Prepare a new proposal for each attempt; spent tokens cannot be reused.
- Show actual firewall state and audit chain; do not call a simulation a real block.
- Record the backup video and rehearse twice with a separate narrator and driver.
