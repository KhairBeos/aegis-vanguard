# Deploy

This folder is reserved for local-first infrastructure used by the lab.

Phase 0 keeps only safe configuration examples. Add Docker Compose files when Phase 1 needs Kafka and storage for the minimal pipeline.

Approved Kafka topic names:

- `raw.telemetry`
- `normalized.events`
- `security.alerts`

Resource rule:

- Keep services single-node and local.
- Do not require HA, multi-region, or enterprise production hardening.
- Do not run all lab components at once unless a demo explicitly needs them.
