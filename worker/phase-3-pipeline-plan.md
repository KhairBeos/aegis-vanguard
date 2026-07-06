# Phase 3A Pipeline Worker Plan

Phase 3A defines worker boundaries only. It does not implement real Kafka or ClickHouse workers yet.

## Target Flow

```text
datasets/raw/*.json
  -> fixture producer
  -> raw.telemetry
  -> normalizer worker
  -> normalized.events
  -> storage writer
  -> raw_telemetry / normalized_events
```

## Fixture Producer

Purpose:

- Read one checked-in raw fixture from `datasets/raw/`.
- Publish the source-shaped JSON to `raw.telemetry`.

Future input example:

```powershell
py worker/fixture_producer.py --sample datasets/raw/process_start.json
```

Phase 3A status:

- Documented only.
- No Kafka client dependency is added yet.

## Normalizer Worker

Purpose:

- Consume one message from `raw.telemetry`.
- Reuse `normalization/adapters/sample_adapter.py`.
- Publish canonical `lab-event` JSON to `normalized.events`.

Future input example:

```powershell
py worker/normalizer_worker.py --once
```

Phase 3A status:

- Documented only.
- Existing normalization contract remains `py normalization/normalize.py --check`.

## Storage Writer

Purpose:

- Store raw source JSON and canonical normalized JSON in ClickHouse.
- Write to `raw_telemetry`.
- Optionally write canonical-only rows to `normalized_events`.

Future input example:

```powershell
py worker/storage_writer.py --once
```

Phase 3A status:

- Documented only.
- ClickHouse table contracts live in `deploy/clickhouse/init/001_events.sql`.

## Future Alert Publisher

Purpose:

- Consume canonical events from `normalized.events`.
- Reuse Phase 2 detection logic.
- Publish `lab-alert` records to `security.alerts`.
- Store alerts only after alert storage is explicitly approved.

Phase 3A status:

- Reserved for Phase 3B/Phase 4.
- No alert storage table is created in Phase 3A.

## Dependency Gate

Real workers should not be implemented until dependencies are approved.

Expected future choices:

- Kafka client library for producer/consumer behavior.
- ClickHouse client library or a small approved HTTP writer.

Do not use subprocess wrappers around Docker CLI as a long-term worker implementation.
