# Dashboard

Phase 4B adds a dependency-free static SOC lab dashboard served by the local Python API.

## Current Views

- Overview summary with real counts from available local sources.
- Normalized event list from ClickHouse `normalized_events`.
- Event detail with canonical event JSON.
- Rule metadata list from `rules/*.json`.
- Fixture alert list from `datasets/alerts/*.json`.
- Pipeline status and Phase 3B smoke command.

The dashboard clearly labels:

- stored pipeline data
- fixture alerts
- rule metadata

It does not claim alert storage exists. It does not claim production readiness or real-world detection coverage.

## Run

Start the API:

```powershell
py backend/server.py
```

Open:

```text
http://localhost:8000/
```

If ClickHouse is not running, event panels show empty/error guidance while fixture alerts and rule metadata still load.
