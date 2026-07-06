# Raw Event Storage Design

Phase 1 stores evidence, not alerts.

## Goal

Keep enough raw and normalized data to explain the pipeline:

```text
raw source event -> canonical lab-event
```

## ClickHouse Table Draft

```sql
CREATE TABLE raw_telemetry (
  event_id String,
  ingested_at DateTime,
  source LowCardinality(String),
  event_type LowCardinality(String),
  host LowCardinality(String),
  raw_json String,
  normalized_json String
)
ENGINE = MergeTree
ORDER BY (host, ingested_at, event_type);
```

## Notes

- `raw_json` keeps source fidelity for debugging.
- `normalized_json` keeps the canonical output used by later detection.
- Alert storage starts in Phase 2.
- PostgreSQL is not needed for this Phase 1 slice.
