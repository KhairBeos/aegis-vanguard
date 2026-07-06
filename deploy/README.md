# Deploy

This folder contains local-first infrastructure contracts for the lab.

Phase 3A defines a minimal local stack:

- Kafka single broker
- ClickHouse single node

It does not include dashboard, backend/API, PostgreSQL, or external telemetry services.

Approved Kafka topic names:

- `raw.telemetry`
- `normalized.events`
- `security.alerts`

Published ports:

| Service | Container | Host port | Purpose |
| --- | --- | --- | --- |
| Kafka | `aegis-kafka` | `29092` | Local Kafka client access |
| ClickHouse HTTP | `aegis-clickhouse` | `8123` | HTTP API and simple checks |
| ClickHouse native | `aegis-clickhouse` | `9000` | Native client access |

Resource rule:

- Keep services single-node and local.
- Do not require HA, multi-region, or enterprise production hardening.
- Do not run all lab components at once unless a demo explicitly needs them.
- Stop services after short verification runs.
