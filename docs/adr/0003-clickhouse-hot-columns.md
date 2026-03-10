# ADR 0003: ClickHouse Hot-Column Extraction Strategy

## Status

Accepted

## Date

2026-03-10

## Owner

Aegis-Vanguard Core Team

## Context

Raw SIEM events are heterogeneous and naturally fit JSON payloads. However, query workloads for detection analytics repeatedly filter and aggregate on a small subset of fields (host, event type, destination IP/port, user identity, process identity).

Using only a single JSON string column would preserve flexibility but degrade query performance at scale.

## Decision Drivers

- Fast filtering and aggregation on high-frequency query keys
- Efficient storage and scan behavior for columnar OLAP
- Retain full payload fidelity for reprocessing and forensics

## Considered Options

1. Store only `event_json` and parse at query time
2. Fully flatten every known field into dedicated columns
3. Hybrid model: keep `event_json` plus selected hot columns

## Decision

Adopt a hybrid storage model:

- Keep `event_json` for full raw payload preservation
- Extract and store hot columns in `raw_events`:
  - `process_guid`
  - `src_ip`
  - `dst_ip`
  - `dst_port`
  - `user_name`

For alerts, add dedicated numeric and identity fields:

- `risk_score`
- `process_guid`

Use `LowCardinality(String)` where appropriate for repeated string dimensions.

## Query Design Notes

- Primary sort key for `raw_events`: `(host, ts, event_type)`
- Primary sort key for `alerts`: `(host, ts, risk_score)`
- Favor bounded-time queries and host/rule filters in dashboard and analytics APIs

## Trade-offs

- Pros: significantly better query latency and aggregation performance
- Pros: preserved full payload for future extraction logic
- Cons: mapper complexity increases in ingestion pipeline
- Cons: schema evolution requires migration planning for extracted columns

## Consequences

- Engine ingestion must map selected payload fields into dedicated columns.
- Contract and SQL schema must remain synchronized.
- Future high-frequency query keys can be promoted to columns via new ADR + migration.

## Related Artifacts

- `docs/api_spec.md`
- `deploy/clickhouse/init/001_create_events.sql`
- `engine/src/` (ingestion and persistence pipeline)
