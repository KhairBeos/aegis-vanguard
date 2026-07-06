# Phase 1 Pipeline Plan

Phase 1 proves the data contract before building long-running services.

## Minimal Flow

```text
datasets/raw/*.json
  -> normalization/adapters/sample_adapter.py
  -> canonical lab-event JSON
  -> planned Kafka topics
  -> planned raw storage table
```

## Worker Boundary

No worker daemon is needed yet. `normalization/normalize.py --check` is the local proof that the adapter can produce deterministic canonical events.

When a worker is added later, it should:

1. Read from `raw.telemetry`.
2. Normalize into `lab-event`.
3. Publish to `normalized.events`.
4. Store raw and normalized evidence.

`security.alerts` is reserved for Phase 2 detection output.
