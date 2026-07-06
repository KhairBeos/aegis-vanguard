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
