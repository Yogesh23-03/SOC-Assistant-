# SOC Assistant

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Chrome/Edge Manifest V3 extension, strict TypeScript, React and Vite, communicating with the existing FastAPI M2 backend. The supplied project plan defines this stack.

## Users

SOC analysts reviewing alerts, evidence and proposed containment during a lab demonstration.

## Product Purpose

Investigate alerts automatically and let an analyst approve, reject or request more investigation. Dangerous actions require backend authorization.

## Operating Context

M1 and M2 are implemented in previous commits. M3 is a narrow browser side panel. Load-unpacked installation and a local lab backend are in scope.

## Capabilities and Constraints

Recover pending proposals after service-worker shutdown, render hostile logs as plain text, keep provider keys out of the extension, and retain only a short-lived analyst token in browser session storage. The extension never calls the executor. Approval authorizes execution; Linux deployments can explicitly enable backend execution on approval. Investigate more queues fresh analysis and a new proposal. Durable case reports support PDF export. Actual VM execution and browser-profile recovery still require manual acceptance.

## Brand Commitments

The user approved a compact, light analyst workspace with severity labels, evidence and explicit approval confirmation.

## Evidence on Hand

Existing backend endpoints, sample alerts, agent schemas, project plan and per-member learning plan. No measured extension reliability results exist yet.

## Product Principles

- Evidence precedes the decision.
- Distinguish approval from execution.
- The backend owns proposal state.
- Label lab authentication and backend limitations honestly.
