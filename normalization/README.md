# Normalization

Phase 1 uses this folder for canonical event schema work and source adapters.

## Current Scope

- `schema/canonical_event.schema.json`: small explicit canonical event schema.
- `adapters/sample_adapter.py`: maps local sample events to canonical events.
- `normalize.py`: stdlib CLI for one-file normalization and fixture checks.

## Run

On Windows, prefer `py`. If `py` is not available, use `python` or the available Python interpreter path in the current environment.

Normalize one raw sample:

```powershell
py normalization/normalize.py datasets/raw/process_start.json
```

Write normalized output to a file:

```powershell
py normalization/normalize.py datasets/raw/process_start.json --out .tmp/process_start.normalized.json
```

Check all Phase 1 fixtures:

```powershell
py normalization/normalize.py --check
```

## Out Of Scope

- No Kafka publish/consume yet.
- No dashboard.
- No detection rules.
- No external telemetry integrations.

Phase 1 success check:

```text
3 raw samples -> 3 canonical events matching expected fixtures
```
