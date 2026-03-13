# Aegis-Vanguard API Specification

## Version

- Spec version: `v1.1`
- Status: `draft-ready`
- Last updated: `2026-03-12`

## Design Goals

1. Keep a stable event envelope for all producers.
2. Ensure process identity remains stable even when PID is reused.
3. Add quantitative risk scoring for analytics and ranking.
4. Keep storage mapping optimized for high-scale ClickHouse queries.

## Canonical Event Envelope

Every event published to Kafka topic `siem.events` must follow this envelope.

```json
{
	"schema_version": "v1.1",
	"event_id": "01JNW4FXV8D6Q2Q56M4WE6G8W1",
	"ts": "2026-03-10T12:00:00Z",
	"host": "workstation-01",
	"agent_id": "collector-dev-01",
	"source": "collector.ebpf",
	"event_type": "process_start",
	"severity": "info",
	"tenant_id": "default",
	"trace_id": "f4b4a0e1-1a8d-4d82-a96b-c9ff4b608dbf",
	"process_guid": "7df47ab2594db6f7b6b44f332eebc9d2f6c5a6c3f3e2a4b5c7d8e9f0a1b2c3d4",
	"event": {}
}
```

## Event Field Definitions

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `schema_version` | string | yes | Contract version, currently `v1.1`. |
| `event_id` | string | yes | Unique event ID (ULID or UUID). |
| `ts` | string (RFC3339 UTC) | yes | Event timestamp in UTC, example `2026-03-10T12:00:00Z`. |
| `host` | string | yes | Hostname where event originated. |
| `agent_id` | string | yes | Collector agent identifier. |
| `source` | string | yes | Producer source, example `collector.ebpf`, `collector.app`. |
| `event_type` | string | yes | Normalized event name. |
| `severity` | string | yes | One of: `info`, `low`, `medium`, `high`, `critical`. |
| `tenant_id` | string | yes | Tenant or logical environment scope. |
| `trace_id` | string | no | Correlation ID for distributed tracing. |
| `process_guid` | string | conditional | Required for process-bound events. Generated as `hash(host + pid + process_start_time)`. |
| `event` | object | yes | Event-specific payload body. |

## Process Identity Rule

`process_guid` solves PID reuse ambiguity. Use this deterministic strategy:

1. Take `host`.
2. Take process `pid`.
3. Take immutable process start timestamp (`process_start_time`).
4. Compute stable hash: `hash(host + pid + process_start_time)`.

Recommended hash function: SHA-256 (hex encoded).

## Supported Event Types (v1.1)

| `event_type` | Description | Payload Contract | Producer |
| --- | --- | --- | --- |
| `process_start` | Process execution observed | `event.process` | eBPF collector / `rule_engine_daemon` |
| `network_connect` | Outbound network connection | `event.network` | eBPF collector / `log_generator` |
| `file_open` | File access operation | `event.file` | auditd / `log_generator` |
| `auth_failure` | Authentication failure signal | `event.auth` | auth.log / `log_generator` |
| `auth_success` | Successful authentication | `event.auth` | syslog / `log_generator` |
| `process_execution` | Suspicious command execution | `event.process` | auditd / `log_generator` |

### `process_start` Payload

```json
{
	"process": {
		"pid": 1732,
		"ppid": 1120,
		"uid": 1000,
		"user_name": "alice",
		"name": "bash",
		"exe": "/usr/bin/bash",
		"cmdline": "bash -c whoami",
		"process_start_time": "2026-03-10T12:00:00Z"
	}
}
```

### `network_connect` Payload

```json
{
	"network": {
		"pid": 1732,
		"process_guid": "7df47ab2594db6f7b6b44f332eebc9d2f6c5a6c3f3e2a4b5c7d8e9f0a1b2c3d4",
		"protocol": "tcp",
		"src_ip": "10.0.2.15",
		"src_port": 50122,
		"dst_ip": "185.199.108.153",
		"dst_port": 443,
		"direction": "outbound"
	}
}
```

### `file_open` Payload

```json
{
	"file": {
		"pid": 1732,
		"process_guid": "7df47ab2594db6f7b6b44f332eebc9d2f6c5a6c3f3e2a4b5c7d8e9f0a1b2c3d4",
		"user_name": "alice",
		"path": "/etc/shadow",
		"flags": ["O_RDONLY"],
		"result": "success"
	}
}
```

### `auth_failure` Payload

```json
{
	"auth": {
		"user_name": "root",
		"method": "ssh",
		"src_ip": "192.168.1.77",
		"reason": "invalid_password"
	}
}
```

## Alert Contract

Every detection output published to Kafka topic `siem.alerts` should follow this schema.

```json
{
	"schema_version": "v1.1",
	"alert_id": "01JNW4M8E3TAXYQ3C4WNA5DRE5",
	"ts": "2026-03-10T12:01:02Z",
	"rule_id": "linux-suspicious-shell",
	"rule_name": "Suspicious Shell Spawn",
	"severity": "high",
	"risk_score": 82,
	"host": "workstation-01",
	"tenant_id": "default",
	"event_id": "01JNW4FXV8D6Q2Q56M4WE6G8W1",
	"process_guid": "7df47ab2594db6f7b6b44f332eebc9d2f6c5a6c3f3e2a4b5c7d8e9f0a1b2c3d4",
	"summary": "Shell spawned from unusual parent process",
	"context": {
		"pid": 1732,
		"exe": "/usr/bin/bash",
		"parent": "python"
	},
	"tags": ["execution", "linux", "sigma"]
}
```

### Risk Score Rules

- Type: `int`
- Range: `0..100`
- Usage: ranking, thresholding, trend analytics, host risk aggregation.

Suggested baseline mapping:

| Severity | Default risk_score |
| --- | --- |
| `low` | 25 |
| `medium` | 50 |
| `high` | 75 |
| `critical` | 90 |

## Kafka Topic Contracts

### Topic: `siem.events`

- Purpose: ingest normalized raw events from collectors.
- Key: `host` (recommended) for ordering per endpoint.
- Value: canonical event envelope JSON.
- Retention: short to medium (for replay), example 24h to 72h in dev.

### Topic: `siem.alerts`

- Purpose: output detections from engine.
- Key: `host` or `rule_id`.
- Value: alert contract JSON.
- Retention: medium, based on SOC workflow needs.

### Topic: `siem.events.dlq`

- Purpose: dead-letter queue for invalid or unprocessable events.
- Key: original producer key (`host` recommended).
- Value: original payload + parser/validation error metadata.
- Retention: short to medium for troubleshooting and replay.

## ClickHouse Storage Mapping

`event_json` is retained for full-fidelity raw payload storage, but hot query fields are extracted into dedicated columns.

### Table: `raw_events`

Database: `aegis`

| Column | Type | Source |
| --- | --- | --- |
| `ts` | DateTime | `event.ts` |
| `host` | String | `event.host` |
| `source` | String | `event.source` |
| `event_type` | String | `event.event_type` |
| `process_guid` | String | top-level `event.process_guid` or payload fallback |
| `src_ip` | String | `event.network.src_ip` or `event.auth.src_ip` |
| `dst_ip` | String | `event.network.dst_ip` |
| `dst_port` | UInt16 | `event.network.dst_port` |
| `user_name` | String | `event.auth.user_name` or `event.process.user_name` |
| `event_json` | String | full serialized event payload |

### Table: `alerts`

Database: `aegis`

| Column | Type | Source |
| --- | --- | --- |
| `ts` | DateTime | `alert.ts` |
| `rule_id` | String | `alert.rule_id` |
| `severity` | String | `alert.severity` |
| `risk_score` | UInt8 | `alert.risk_score` |
| `host` | String | `alert.host` |
| `process_guid` | String | `alert.process_guid` |
| `summary` | String | `alert.summary` |
| `context_json` | String | serialized `alert.context` |

## Validation Rules

1. Reject events without `schema_version`, `event_id`, `ts`, `host`, `event_type`, or `event`.
2. For process-bound events (`process_start`, `network_connect`, `file_open`), `process_guid` is required.
3. Timestamps must be UTC and RFC3339-compatible.
4. Unknown `event_type` may be accepted only if stored as generic payload and tagged for review.
5. Alert severity must be one of: `low`, `medium`, `high`, `critical`.
6. Alert `risk_score` must be integer in range `0..100`.

## Compatibility Policy

- Additive changes (new optional fields) are allowed within same minor contract.
- Breaking changes require a major version bump (example `v2.0`).
- Producers and consumers must log version mismatch explicitly.

---

## Runtime Pipeline (C++)

Current runtime path is fully C++ for both ingestion and detection:

```
collector (C++)  -> Kafka: siem.events -> engine (C++) -> Kafka: siem.alerts + ClickHouse
```

Collector runtime source options:

- `source=ebpf` for host/kernel telemetry stream mode.
- `source=fixture` for deterministic replay (used by Mordor campaign flow).

Engine runtime behavior:

- Consumes canonical envelopes from `siem.events`.
- Evaluates built-in and external YAML rules.
- Produces alerts in schema `v1.1` to `siem.alerts` and writes to ClickHouse.

## Mordor Campaign Workflow

Manifest-driven campaign orchestration is defined under `scripts/mordor_windows_campaign.json` and executed by `scripts/mordor_pipeline.py`.

Supported replay directions:

1. `direct`:
	`canonical envelopes -> Kafka -> engine`
2. `collector`:
	`canonical envelopes -> fixture records -> collector(C++) -> Kafka -> engine`
3. `both`:
	Runs collector fixture replay and direct replay in sequence.

Generated campaign artifacts are stored under `runtime/mordor/`:

- merged canonical JSONL (`*.aegis.jsonl`)
- merged collector fixture JSONL (`*.fixture.jsonl`)
- replay report (`*.report.json`)

