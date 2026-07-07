from __future__ import annotations

import argparse
import json
import sys
import threading
from pathlib import Path
from typing import Any
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.server import build_server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the Phase 4 API without external dependencies.")
    parser.add_argument(
        "--fixtures-only",
        action="store_true",
        help="Run checks without requiring ClickHouse.",
    )
    args = parser.parse_args(argv)

    if not args.fixtures_only:
        print("ERROR: only --fixtures-only is implemented for the local dependency-free check", file=sys.stderr)
        return 1

    server = build_server(host="127.0.0.1", port=0, fixtures_only=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base_url = f"http://{host}:{port}"

    try:
        _check_health(base_url)
        print("OK /health")
        _check_rules(base_url)
        print("OK /rules")
        _check_alerts(base_url)
        print("OK /alerts")
        _check_summary(base_url)
        print("OK /summary")
        print("Phase 4 API fixture check passed.")
        return 0
    except (AssertionError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _get_json(base_url: str, path: str) -> dict[str, Any]:
    with urlopen(f"{base_url}{path}", timeout=5) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise AssertionError(f"{path} response must be a JSON object")
    return payload


def _check_envelope(payload: dict[str, Any], source_type: str) -> None:
    assert payload.get("source_type") == source_type, payload
    assert isinstance(payload.get("generated_at"), str), payload
    assert isinstance(payload.get("warnings"), list), payload
    assert "data" in payload, payload


def _check_health(base_url: str) -> None:
    payload = _get_json(base_url, "/health")
    _check_envelope(payload, "metadata")
    data = payload["data"]
    assert isinstance(data, dict), payload
    assert data.get("status") == "ok", payload
    assert data.get("clickhouse", {}).get("reachable") is False, payload


def _check_rules(base_url: str) -> None:
    payload = _get_json(base_url, "/rules")
    _check_envelope(payload, "metadata")
    data = payload["data"]
    assert isinstance(data, list) and data, payload
    for rule in data:
        assert isinstance(rule.get("id"), str), rule
        assert isinstance(rule.get("mitre"), dict), rule


def _check_alerts(base_url: str) -> None:
    payload = _get_json(base_url, "/alerts")
    _check_envelope(payload, "fixture")
    data = payload["data"]
    assert isinstance(data, list) and data, payload
    assert any("fixture data" in warning for warning in payload["warnings"]), payload
    for alert in data:
        assert alert.get("schema") == "lab-alert", alert
        assert isinstance(alert.get("mitre"), dict), alert


def _check_summary(base_url: str) -> None:
    payload = _get_json(base_url, "/summary")
    _check_envelope(payload, "metadata")
    data = payload["data"]
    assert isinstance(data, dict), payload
    counts = data.get("counts")
    labels = data.get("source_labels")
    assert isinstance(counts, dict), payload
    assert isinstance(labels, dict), payload
    assert counts.get("rules", 0) >= 3, payload
    assert counts.get("fixture_alerts", 0) >= 3, payload
    assert labels.get("normalized_events") == "stored", payload
    assert labels.get("rules") == "metadata", payload
    assert labels.get("alerts") == "fixture", payload


if __name__ == "__main__":
    raise SystemExit(main())
