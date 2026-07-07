from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_CLICKHOUSE_HTTP_URL = os.environ.get("CLICKHOUSE_HTTP_URL", "http://localhost:8123")
DEFAULT_CLICKHOUSE_DATABASE = os.environ.get("CLICKHOUSE_DATABASE", "default")
NORMALIZED_EVENTS_TABLE = "normalized_events"


class ClickHouseReadError(RuntimeError):
    """Raised when the local ClickHouse HTTP endpoint cannot satisfy a read."""


@dataclass(frozen=True)
class ClickHouseReadResult:
    data: Any
    warnings: list[str]


class ClickHouseReader:
    def __init__(
        self,
        url: str = DEFAULT_CLICKHOUSE_HTTP_URL,
        database: str = DEFAULT_CLICKHOUSE_DATABASE,
        timeout_seconds: int = 5,
        disabled: bool = False,
    ) -> None:
        self.url = url.rstrip("/")
        self.database = _safe_identifier(database)
        self.timeout_seconds = timeout_seconds
        self.disabled = disabled

    def health(self) -> dict[str, Any]:
        if self.disabled:
            return {
                "reachable": False,
                "url": self.url,
                "database": self.database,
                "warning": "ClickHouse check skipped in fixtures-only mode",
            }
        try:
            self._post("SELECT 1")
        except ClickHouseReadError as exc:
            return {
                "reachable": False,
                "url": self.url,
                "database": self.database,
                "warning": str(exc),
            }
        return {
            "reachable": True,
            "url": self.url,
            "database": self.database,
            "warning": None,
        }

    def list_events(self, limit: int = 100) -> ClickHouseReadResult:
        if self.disabled:
            return ClickHouseReadResult([], ["ClickHouse event reads skipped in fixtures-only mode"])
        safe_limit = max(1, min(limit, 500))
        query = f"""
SELECT
  event_id,
  toString(ingested_at) AS ingested_at,
  toString(event_timestamp) AS event_timestamp,
  tenant_id,
  trace_id,
  host,
  source,
  event_type,
  severity,
  normalized_json
FROM {self._qualified_table(NORMALIZED_EVENTS_TABLE)}
ORDER BY event_timestamp DESC, event_id
LIMIT {safe_limit}
FORMAT JSONEachRow
"""
        try:
            rows = [_normalize_event_row(row) for row in self._query_json_each_row(query)]
        except ClickHouseReadError as exc:
            return ClickHouseReadResult([], [str(exc)])
        return ClickHouseReadResult(rows, [])

    def get_event(self, event_id: str) -> ClickHouseReadResult:
        if self.disabled:
            return ClickHouseReadResult(None, ["ClickHouse event reads skipped in fixtures-only mode"])
        query = f"""
SELECT
  event_id,
  toString(ingested_at) AS ingested_at,
  toString(event_timestamp) AS event_timestamp,
  tenant_id,
  trace_id,
  host,
  source,
  event_type,
  severity,
  normalized_json
FROM {self._qualified_table(NORMALIZED_EVENTS_TABLE)}
WHERE event_id = {_quote_sql_string(event_id)}
LIMIT 1
FORMAT JSONEachRow
"""
        try:
            rows = [_normalize_event_row(row) for row in self._query_json_each_row(query)]
        except ClickHouseReadError as exc:
            return ClickHouseReadResult(None, [str(exc)])
        if not rows:
            return ClickHouseReadResult(None, [f"event_id not found: {event_id}"])
        return ClickHouseReadResult(rows[0], [])

    def count_events(self) -> ClickHouseReadResult:
        if self.disabled:
            return ClickHouseReadResult(0, ["ClickHouse count skipped in fixtures-only mode"])
        query = f"SELECT count() FROM {self._qualified_table(NORMALIZED_EVENTS_TABLE)}"
        try:
            result = self._post(query).decode("utf-8").strip()
            return ClickHouseReadResult(int(result.splitlines()[-1]), [])
        except (ClickHouseReadError, IndexError, ValueError) as exc:
            return ClickHouseReadResult(0, [f"ClickHouse event count unavailable: {exc}"])

    def _qualified_table(self, table: str) -> str:
        return f"{self.database}.{_safe_identifier(table)}"

    def _query_json_each_row(self, sql: str) -> list[dict[str, Any]]:
        raw = self._post(sql).decode("utf-8").strip()
        if not raw:
            return []
        rows: list[dict[str, Any]] = []
        for line in raw.splitlines():
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ClickHouseReadError("ClickHouse JSONEachRow response contained a non-object row")
            rows.append(value)
        return rows

    def _post(self, sql: str) -> bytes:
        request = Request(
            self.url,
            data=sql.encode("utf-8"),
            headers={"Content-Type": "text/plain; charset=utf-8"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                return response.read()
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise ClickHouseReadError(f"ClickHouse HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise ClickHouseReadError(f"failed to connect to ClickHouse at {self.url}: {exc}") from exc


def _normalize_event_row(row: dict[str, Any]) -> dict[str, Any]:
    normalized_json = row.get("normalized_json")
    normalized_event: dict[str, Any] | None = None
    parse_warning: str | None = None
    if isinstance(normalized_json, str) and normalized_json:
        try:
            parsed = json.loads(normalized_json)
            if isinstance(parsed, dict):
                normalized_event = parsed
            else:
                parse_warning = "normalized_json did not decode to an object"
        except json.JSONDecodeError as exc:
            parse_warning = f"normalized_json parse failed: {exc}"

    result = {
        "event_id": row.get("event_id"),
        "ingested_at": row.get("ingested_at"),
        "timestamp": row.get("event_timestamp"),
        "tenant_id": row.get("tenant_id"),
        "trace_id": row.get("trace_id"),
        "host": row.get("host"),
        "source": row.get("source"),
        "event_type": row.get("event_type"),
        "severity": row.get("severity"),
        "normalized_event": normalized_event,
    }
    if parse_warning:
        result["parse_warning"] = parse_warning
    return result


def _safe_identifier(value: str) -> str:
    if not value or not value.replace("_", "").isalnum():
        raise ClickHouseReadError(f"unsafe ClickHouse identifier: {value}")
    return value


def _quote_sql_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"
