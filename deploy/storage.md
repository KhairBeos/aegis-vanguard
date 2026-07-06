# Event Storage Design

Phase 3A defines ClickHouse storage for raw and normalized event evidence.

## Goal

Keep enough raw and normalized data to explain this pipeline:

```text
raw source event -> canonical lab-event
```

## `raw_telemetry`

Stores raw source evidence plus the normalized JSON generated from it.

```sql
CREATE TABLE IF NOT EXISTS raw_telemetry
(
  event_id String,
  ingested_at DateTime64(3, 'UTC') DEFAULT now64(3),
  event_timestamp DateTime64(3, 'UTC'),
  tenant_id LowCardinality(String),
  trace_id String,
  host LowCardinality(String),
  source LowCardinality(String),
  event_type LowCardinality(String),
  raw_json String,
  normalized_json String
)
ENGINE = MergeTree
ORDER BY (tenant_id, host, event_timestamp, event_type, event_id);
```

Column mapping:

| Column | Source |
| --- | --- |
| `event_id` | canonical `event_id` |
| `event_timestamp` | canonical `timestamp` |
| `tenant_id` | canonical `tenant_id` |
| `trace_id` | canonical `trace_id` |
| `host` | canonical `host` |
| `source` | canonical `source` |
| `event_type` | canonical `event_type` |
| `raw_json` | original source-shaped event JSON |
| `normalized_json` | canonical `lab-event` JSON |

## `normalized_events`

Stores canonical `lab-event` records for later detection/API/dashboard work.

```sql
CREATE TABLE IF NOT EXISTS normalized_events
(
  event_id String,
  ingested_at DateTime64(3, 'UTC') DEFAULT now64(3),
  event_timestamp DateTime64(3, 'UTC'),
  tenant_id LowCardinality(String),
  trace_id String,
  host LowCardinality(String),
  source LowCardinality(String),
  event_type LowCardinality(String),
  severity LowCardinality(String),
  normalized_json String
)
ENGINE = MergeTree
ORDER BY (tenant_id, host, event_timestamp, event_type, event_id);
```

## Notes

- `raw_json` keeps source fidelity for debugging.
- `normalized_json` keeps the canonical output used by later detection.
- `security_alerts` is future work for Phase 3B/Phase 4 after alert publishing/storage is approved.
- PostgreSQL is not needed for this Phase 3A slice.
- The schema lives in `deploy/clickhouse/init/001_events.sql`.
