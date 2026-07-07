# Worker

This folder contains the small Phase 3B local pipeline workers.

The current worker slice proves this local flow:

```text
datasets/raw/*.json
  -> raw.telemetry
  -> normalizer worker
  -> normalized.events
  -> ClickHouse normalized_events
```

Implemented workers:

- fixture producer: read local raw fixtures and publish to `raw.telemetry`
- normalizer worker: consume `raw.telemetry`, normalize to `lab-event`, publish to `normalized.events`
- storage writer: consume `normalized.events` and insert one row into ClickHouse `normalized_events`

Future boundary:

- alert publisher: consume `normalized.events`, reuse Phase 2 detection, publish to `security.alerts`

Keep this local-first and lightweight.

## Dependency

Phase 3B adds one worker dependency:

```powershell
py -m pip install -r worker/requirements.txt
```

`kafka-python` is used for Kafka producer/consumer behavior. ClickHouse writes use Python standard library `urllib`; no ClickHouse client library is used.

## Configuration

Workers read these environment variables, with safe defaults:

| Variable | Default | Purpose |
| --- | --- | --- |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Kafka bootstrap server |
| `KAFKA_TOPIC_RAW` | `raw.telemetry` | Raw telemetry topic |
| `KAFKA_TOPIC_NORMALIZED` | `normalized.events` | Canonical event topic |
| `CLICKHOUSE_HTTP_URL` | `http://localhost:8123` | ClickHouse HTTP endpoint |
| `CLICKHOUSE_DATABASE` | `default` | ClickHouse database |

The current Phase 3A Docker Compose exposes Kafka to the host on `localhost:29092`. If you run workers from the host with that compose file, set:

```powershell
$env:KAFKA_BOOTSTRAP_SERVERS = "localhost:29092"
```

## Commands

Publish one raw fixture:

```powershell
py worker/fixture_producer.py --sample datasets/raw/process_start.json
```

Run the normalizer once:

```powershell
py worker/normalizer_worker.py --once
```

Run the storage writer once:

```powershell
py worker/storage_writer.py --once
```

Run the full Phase 3B smoke check:

```powershell
py worker/pipeline_smoke_check.py --sample datasets/raw/process_start.json
```

Expected smoke output:

```text
OK produced raw.telemetry raw-process-001
OK normalized.events evt-process-001
OK stored normalized_events evt-process-001
Phase 3B pipeline smoke check passed.
```

Repeated smoke runs may insert duplicate demo rows into `normalized_events`. Phase 3B is a local smoke check, not a deduplicating production pipeline.

Other executable behavior still lives in:

- `normalization/normalize.py`
- `detection/detect.py`

See `worker/phase-3-pipeline-plan.md` for worker boundaries and future gaps.
