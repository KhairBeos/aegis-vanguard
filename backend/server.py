from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.api_contracts import error_envelope, response_envelope
from backend.clickhouse_reader import (
    DEFAULT_CLICKHOUSE_DATABASE,
    DEFAULT_CLICKHOUSE_HTTP_URL,
    ClickHouseReader,
)
from backend.fixture_reader import read_alert_fixtures, read_rules


DEFAULT_API_HOST = os.environ.get("API_HOST", "127.0.0.1")
DEFAULT_API_PORT = int(os.environ.get("API_PORT", "8000"))


@dataclass(frozen=True)
class ApiConfig:
    repo_root: Path
    clickhouse_url: str = DEFAULT_CLICKHOUSE_HTTP_URL
    clickhouse_database: str = DEFAULT_CLICKHOUSE_DATABASE
    fixtures_only: bool = False


class AegisHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], config: ApiConfig) -> None:
        super().__init__(server_address, AegisRequestHandler)
        self.config = config


class AegisRequestHandler(BaseHTTPRequestHandler):
    server: AegisHTTPServer

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") if parsed.path != "/" else "/"
        try:
            if path == "/":
                self._send_static("dashboard/index.html", "text/html; charset=utf-8")
            elif path == "/app.js":
                self._send_static("dashboard/app.js", "application/javascript; charset=utf-8")
            elif path == "/styles.css":
                self._send_static("dashboard/styles.css", "text/css; charset=utf-8")
            elif path == "/health":
                self._handle_health()
            elif path == "/events":
                self._handle_events(parsed.query)
            elif path.startswith("/events/"):
                self._handle_event(unquote(path.removeprefix("/events/")))
            elif path == "/rules":
                self._handle_rules()
            elif path == "/alerts":
                self._handle_alerts()
            elif path == "/summary":
                self._handle_summary()
            else:
                self._send_json(error_envelope(f"route not found: {path}"), HTTPStatus.NOT_FOUND)
        except Exception as exc:
            self._send_json(error_envelope(f"internal server error: {exc}"), HTTPStatus.INTERNAL_SERVER_ERROR)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _handle_health(self) -> None:
        reader = self._clickhouse_reader()
        health = reader.health()
        warnings = [health["warning"]] if health.get("warning") else []
        data = {
            "status": "ok",
            "api": "aegis-vanguard-phase-4",
            "mode": "fixtures-only" if self.server.config.fixtures_only else "local",
            "clickhouse": health,
        }
        self._send_json(response_envelope(data, "metadata", warnings))

    def _handle_events(self, query: str) -> None:
        params = parse_qs(query)
        limit = _parse_limit(params.get("limit", ["100"])[0])
        result = self._clickhouse_reader().list_events(limit)
        self._send_json(response_envelope(result.data, "stored", result.warnings))

    def _handle_event(self, event_id: str) -> None:
        if not event_id:
            self._send_json(error_envelope("event_id is required"), HTTPStatus.BAD_REQUEST)
            return
        result = self._clickhouse_reader().get_event(event_id)
        status = HTTPStatus.OK if result.data is not None else HTTPStatus.NOT_FOUND
        self._send_json(response_envelope(result.data, "stored", result.warnings), status)

    def _handle_rules(self) -> None:
        result = read_rules(self.server.config.repo_root)
        self._send_json(response_envelope(result.data, "metadata", result.warnings))

    def _handle_alerts(self) -> None:
        result = read_alert_fixtures(self.server.config.repo_root)
        warnings = [
            "alerts are fixture data from datasets/alerts, not ClickHouse alert storage",
            *result.warnings,
        ]
        self._send_json(response_envelope(result.data, "fixture", warnings))

    def _handle_summary(self) -> None:
        rules = read_rules(self.server.config.repo_root)
        alerts = read_alert_fixtures(self.server.config.repo_root)
        event_count = self._clickhouse_reader().count_events()
        warnings = [*rules.warnings, *alerts.warnings, *event_count.warnings]
        data = {
            "counts": {
                "normalized_events": event_count.data,
                "rules": len(rules.data),
                "fixture_alerts": len(alerts.data),
            },
            "source_labels": {
                "normalized_events": "stored",
                "rules": "metadata",
                "alerts": "fixture",
            },
            "notes": [
                "normalized_events are read from ClickHouse when available",
                "alerts are local Phase 2 fixtures until alert publishing and storage are implemented",
            ],
        }
        self._send_json(response_envelope(data, "metadata", warnings))

    def _clickhouse_reader(self) -> ClickHouseReader:
        config = self.server.config
        return ClickHouseReader(
            url=config.clickhouse_url,
            database=config.clickhouse_database,
            disabled=config.fixtures_only,
        )

    def _send_static(self, relative_path: str, content_type: str) -> None:
        path = self.server.config.repo_root / relative_path
        try:
            body = path.read_bytes()
        except OSError:
            self._send_json(error_envelope(f"static file not found: {relative_path}"), HTTPStatus.NOT_FOUND)
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def build_server(
    host: str = DEFAULT_API_HOST,
    port: int = DEFAULT_API_PORT,
    repo_root: Path = ROOT,
    clickhouse_url: str = DEFAULT_CLICKHOUSE_HTTP_URL,
    clickhouse_database: str = DEFAULT_CLICKHOUSE_DATABASE,
    fixtures_only: bool = False,
) -> AegisHTTPServer:
    config = ApiConfig(
        repo_root=repo_root,
        clickhouse_url=clickhouse_url,
        clickhouse_database=clickhouse_database,
        fixtures_only=fixtures_only,
    )
    return AegisHTTPServer((host, port), config)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the local AEGIS-VANGUARD Phase 4 API/dashboard.")
    parser.add_argument("--host", default=DEFAULT_API_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_API_PORT)
    parser.add_argument("--fixtures-only", action="store_true", help="Skip ClickHouse reads for API checks.")
    args = parser.parse_args(argv)

    server = build_server(host=args.host, port=args.port, fixtures_only=args.fixtures_only)
    address, port = server.server_address
    print(f"AEGIS-VANGUARD API listening on http://{address}:{port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping AEGIS-VANGUARD API")
    finally:
        server.server_close()
    return 0


def _parse_limit(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        return 100
    return max(1, min(parsed, 500))


if __name__ == "__main__":
    raise SystemExit(main())
