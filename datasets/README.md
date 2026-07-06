# Datasets

Phase 1 will use this folder for small local fixtures and pointers to external datasets.

Near-term sample event types:

- `process_start`
- `network_connect`
- `auth_failure`

Rules:

- Keep checked-in fixtures small.
- Do not commit large generated replay outputs.
- Do not commit real sensitive telemetry.
- Use external dataset pointers or scripts for large data.

Out of scope for Phase 0A:

- No sample event files yet.
- No replay scripts.
- No attack tooling.
