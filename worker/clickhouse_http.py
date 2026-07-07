from __future__ import annotations

import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_CLICKHOUSE_HTTP_URL = os.environ.get("CLICKHOUSE_HTTP_URL", "http://localhost:8123")
DEFAULT_CLICKHOUSE_DATABASE = os.environ.get("CLICKHOUSE_DATABASE", "default")


class ClickHouseHTTPError(RuntimeError):
    """Raised when ClickHouse HTTP insert or query fails."""


class ClickHouseHTTP:
    def __init__(
        self,
        url: str = DEFAULT_CLICKHOUSE_HTTP_URL,
        database: str = DEFAULT_CLICKHOUSE_DATABASE,
        timeout_seconds: int = 10,
    ) -> None:
        self.url = url.rstrip("/")
        self.database = _safe_identifier(database)
        self.timeout_seconds = timeout_seconds

    def query(self, sql: str) -> str:
        return self._post(sql).decode("utf-8").strip()

    def insert_json_each_row(self, table: str, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        qualified_table = f"{self.database}.{_safe_identifier(table)}"
        lines = "\n".join(_format_json(row) for row in rows)
        self._post(f"INSERT INTO {qualified_table} FORMAT JSONEachRow\n{lines}\n")

    def row_exists_by_event_id(self, table: str, event_id: str) -> bool:
        qualified_table = f"{self.database}.{_safe_identifier(table)}"
        result = self.query(
            f"SELECT count() FROM {qualified_table} "
            f"WHERE event_id = {_quote_sql_string(event_id)}"
        )
        try:
            return int(result.splitlines()[-1]) > 0
        except (IndexError, ValueError) as exc:
            raise ClickHouseHTTPError(f"unexpected ClickHouse count response: {result}") from exc

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
            raise ClickHouseHTTPError(f"ClickHouse HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise ClickHouseHTTPError(f"failed to connect to ClickHouse at {self.url}: {exc}") from exc


def _format_json(row: dict[str, Any]) -> str:
    return json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _safe_identifier(value: str) -> str:
    if not value or not value.replace("_", "").isalnum():
        raise ClickHouseHTTPError(f"unsafe ClickHouse identifier: {value}")
    return value


def _quote_sql_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"
