CREATE DATABASE IF NOT EXISTS aegis;

CREATE TABLE IF NOT EXISTS aegis.raw_events
(
    ts DateTime,
    host LowCardinality(String),
    source LowCardinality(String),
    event_type LowCardinality(String),
    process_guid String,
    src_ip String,
    dst_ip String,
    dst_port UInt16,
    user_name String,
    event_json String
)
ENGINE = MergeTree
ORDER BY (host, ts, event_type);

CREATE TABLE IF NOT EXISTS aegis.alerts
(
    ts DateTime,
    rule_id LowCardinality(String),
    severity LowCardinality(String),
    risk_score UInt8,
    host LowCardinality(String),
    process_guid String,
    summary String,
    context_json String
)
ENGINE = MergeTree
ORDER BY (host, ts, risk_score);
