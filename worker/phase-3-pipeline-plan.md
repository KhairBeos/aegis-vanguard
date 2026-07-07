# Phase 3 Pipeline Worker Plan

Phase 3A defined the local infrastructure contract. Phase 3B adds small one-shot workers for Kafka and ClickHouse.

## Target Flow

```text
datasets/raw/*.json
  -> fixture producer
  -> raw.telemetry
  -> normalizer worker
  -> normalized.events
  -> storage writer
  -> normalized_events
```

`raw_telemetry` remains part of the storage contract, but Phase 3B writes only `normalized_events` to keep the worker slice small.

## Fixture Producer

Purpose:

- Read one checked-in raw fixture from `datasets/raw/`.
- Publish the source-shaped JSON to `raw.telemetry`.

Future input example:

```powershell
py worker/fixture_producer.py --sample datasets/raw/process_start.json
```

Phase 3B status:

- Implemented in `worker/fixture_producer.py`.
- Uses `kafka-python`.
- Uses `raw_event_id` or `event_id` as Kafka key.

## Normalizer Worker

Purpose:

- Consume one message from `raw.telemetry`.
- Reuse `normalization/adapters/sample_adapter.py`.
- Publish canonical `lab-event` JSON to `normalized.events`.

Future input example:

```powershell
py worker/normalizer_worker.py --once
```

Phase 3B status:

- Implemented in `worker/normalizer_worker.py`.
- Reuses `normalization/adapters/sample_adapter.py`.
- Publishes to `normalized.events`.
- Existing normalization contract remains `py normalization/normalize.py --check`.

## Storage Writer

Purpose:

- Consume one canonical event from `normalized.events`.
- Store the canonical event in ClickHouse `normalized_events`.

Input example:

```powershell
py worker/storage_writer.py --once
```

Phase 3B status:

- Implemented in `worker/storage_writer.py`.
- Uses ClickHouse HTTP with Python standard library `urllib`.
- Does not add a ClickHouse client library.
- ClickHouse table contracts live in `deploy/clickhouse/init/001_events.sql`.

## Smoke Check

Purpose:

- Publish one raw fixture.
- Consume and normalize it.
- Publish the canonical event.
- Consume and store it.
- Query ClickHouse for the stored `event_id`.

Input example:

```powershell
py worker/pipeline_smoke_check.py --sample datasets/raw/process_start.json
```

Expected output:

```text
OK produced raw.telemetry raw-process-001
OK normalized.events evt-process-001
OK stored normalized_events evt-process-001
Phase 3B pipeline smoke check passed.
```

Repeated smoke checks may insert duplicate demo rows into `normalized_events`.

## Future Alert Publisher

Purpose:

- Consume canonical events from `normalized.events`.
- Reuse Phase 2 detection logic.
- Publish `lab-alert` records to `security.alerts`.
- Store alerts only after alert storage is explicitly approved.

Current status:

- Reserved for a later approved phase.
- No alert storage table exists.
- No messages are published to `security.alerts`.

## Dependency Boundary

Approved for Phase 3B:

- Kafka: `kafka-python`
- ClickHouse: HTTP via Python standard library `urllib`

Not approved yet:

- ClickHouse Python client library
- Alert publisher
- `security_alerts` table
- Dashboard/backend integration
