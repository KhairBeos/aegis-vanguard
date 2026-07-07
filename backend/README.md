# Backend

Phase 4A adds a small dependency-free read-only API for the local dashboard.

## Scope

- Serve the static dashboard from `dashboard/`.
- Read stored normalized events from ClickHouse `normalized_events`.
- Read rule metadata from `rules/*.json`.
- Read Phase 2 alert fixtures from `datasets/alerts/*.json`.

The API does not implement authentication, writes, alert publishing, or production deployment.

## Run

```powershell
py backend/server.py
```

If `py` is not available, use `python` or the available Python interpreter path.

Safe defaults:

| Variable | Default |
| --- | --- |
| `API_HOST` | `127.0.0.1` |
| `API_PORT` | `8000` |
| `CLICKHOUSE_HTTP_URL` | `http://localhost:8123` |
| `CLICKHOUSE_DATABASE` | `default` |

## Endpoints

| Endpoint | Source |
| --- | --- |
| `GET /health` | API runtime metadata and ClickHouse reachability |
| `GET /events` | ClickHouse `normalized_events` |
| `GET /events/{event_id}` | ClickHouse `normalized_events` |
| `GET /rules` | local rule metadata files |
| `GET /alerts` | local Phase 2 alert fixture files |
| `GET /summary` | counts derived from available local sources |
| `GET /` | static dashboard |
| `GET /app.js` | static dashboard script |
| `GET /styles.css` | static dashboard stylesheet |

API responses use this envelope:

```json
{
  "data": [],
  "source_type": "stored",
  "generated_at": "2026-07-07T00:00:00Z",
  "warnings": []
}
```

Source labels:

- `stored`: ClickHouse normalized event rows
- `fixture`: checked-in alert fixtures
- `metadata`: local rule or runtime metadata

## Local Check

```powershell
py backend/api_check.py --fixtures-only
```

This check does not require Docker or ClickHouse.
