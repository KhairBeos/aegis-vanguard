# Detection

Phase 2 uses this folder for offline rule evaluation over local normalized fixtures.

## Current Scope

- `alert_schema.json`: small explicit `lab-alert` schema.
- `rule_loader.py`: stdlib JSON rule loading and metadata validation.
- `detect.py`: stdlib CLI for fixture-based detection checks.

## Run

On Windows, prefer `py`. If `py` is not available, use `python` or the available Python interpreter path in the current environment.

Check all Phase 2 fixtures:

```powershell
py detection/detect.py --check
```

Run detection for one fixture and write alerts to `.tmp/`:

```powershell
py detection/detect.py datasets/detection/process_suspicious_shell.json --out .tmp/alerts.json
```

## Out Of Scope

- No Kafka publish/consume yet.
- No ClickHouse writes yet.
- No backend/API.
- No dashboard.
- No external telemetry integrations.

Phase 2 success check:

```text
normalized suspicious fixture -> detection rule match -> expected alert fixture
```
