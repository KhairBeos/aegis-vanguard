# Phase 4 Verification

Phase 4A/4B verification covers the dependency-free local API and static dashboard.

## What Phase 4 Proves

- The API can serve a dashboard using Python standard library only.
- Rule metadata loads from `rules/*.json`.
- Fixture alerts load from `datasets/alerts/*.json`.
- ClickHouse normalized events can be shown when ClickHouse is running and has data.
- The dashboard labels stored data, fixture alerts, and metadata separately.

## What Phase 4 Does Not Prove

- No alert publisher exists.
- No `security_alerts` table exists.
- Fixture alerts are not stored ClickHouse alerts.
- No backend authentication exists.
- No production deployment exists.
- No real-world detection coverage is claimed.

## Fixture-Only API Check

This check does not require Docker or ClickHouse.

```powershell
py backend/api_check.py --fixtures-only
```

If `py` is not available, use `python` or the available Python interpreter path:

```powershell
python backend/api_check.py --fixtures-only
```

Expected output:

```text
OK /health
OK /rules
OK /alerts
OK /summary
Phase 4 API fixture check passed.
```

## Full Local Dashboard Check

Start ClickHouse if you want stored event rows to appear:

```powershell
docker compose -f deploy/docker-compose.yml up -d clickhouse
```

Start the local API and dashboard:

```powershell
py backend/server.py
```

Check API endpoints:

```powershell
Invoke-RestMethod http://localhost:8000/health
Invoke-RestMethod http://localhost:8000/events
Invoke-RestMethod http://localhost:8000/rules
Invoke-RestMethod http://localhost:8000/alerts
Invoke-RestMethod http://localhost:8000/summary
```

Open the dashboard:

```text
http://localhost:8000/
```

Expected proof:

- stored normalized events are visible when ClickHouse has data
- rules are visible from local metadata files
- fixture alerts are visible and labeled as fixture data
- empty and error states are visible when ClickHouse is unavailable or empty

## Resource Notes

- Kafka does not need to run for dashboard viewing if ClickHouse already has normalized rows.
- ClickHouse is needed only for stored normalized events.
- Fixture rules and alerts work without Docker.
