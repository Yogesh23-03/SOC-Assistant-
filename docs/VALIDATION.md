# Validation evidence

Local verification on 14 November 2026:

- Python: 220 passed; one live provider/model test deliberately excluded.
- Extension: TypeScript compile and Vite production build passed; 16 unit tests passed.
- Loaded Chromium: two browser tests passed, including an isolated real FastAPI/SQLite
  backend. Covered token login, authenticated WebSocket, inert hostile evidence,
  PDF download, investigate-more processing, panel reload and rejection.
- Independent PDF parsing: a four-page document parsed with pypdf and preserved
  hostile evidence as text.
- Offline proof-of-skill demo: all five scenarios passed, explicitly using simulation.
- Offline benchmark generated results/benchmark_offline.json and .md. These are
  fixture checks, not measured model accuracy.
- pip check: no broken requirements in the project virtual environment.
- Extension archive: seven bundled files; no .env, SQLite or node_modules included.

Not verified: real iptables changes/TTL removal on Ubuntu, native notifications
and stopped-worker recovery in the user's actual Chrome/Edge profiles, trusted
TLS on the lab machine, Docker runtime (daemon was not running), live threat-intel
credentials, a live labelled-model benchmark, or Hermes runtime/SessionDB integration.
The browser tests intentionally avoid model quota and real firewall commands.
