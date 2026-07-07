from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from worker.clickhouse_http import (
    DEFAULT_CLICKHOUSE_DATABASE,
    DEFAULT_CLICKHOUSE_HTTP_URL,
    ClickHouseHTTP,
)
from worker.kafka_client import (
    DEFAULT_BOOTSTRAP_SERVERS,
    DEFAULT_TOPIC_NORMALIZED,
    JsonKafkaConsumer,
    make_group_id,
)


NORMALIZED_EVENTS_TABLE = "normalized_events"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Store one normalized event in ClickHouse.")
    parser.add_argument("--once", action="store_true", default=True, help="Process one message and exit.")
    parser.add_argument("--input-topic", default=DEFAULT_TOPIC_NORMALIZED)
    parser.add_argument("--group-id", default=None)
    parser.add_argument(
        "--bootstrap-server",
        default=DEFAULT_BOOTSTRAP_SERVERS,
        help="Kafka bootstrap server, or set KAFKA_BOOTSTRAP_SERVERS.",
    )
    parser.add_argument("--clickhouse-url", default=DEFAULT_CLICKHOUSE_HTTP_URL)
    parser.add_argument("--clickhouse-database", default=DEFAULT_CLICKHOUSE_DATABASE)
    parser.add_argument("--timeout-ms", type=int, default=10000)
    args = parser.parse_args(argv)

    try:
        event_id = store_one(
            bootstrap_server=args.bootstrap_server,
            input_topic=args.input_topic,
            group_id=args.group_id or make_group_id("aegis-storage-writer"),
            clickhouse_url=args.clickhouse_url,
            clickhouse_database=args.clickhouse_database,
            timeout_ms=args.timeout_ms,
            auto_offset_reset="earliest",
        )
        print(f"OK stored normalized_events {event_id}")
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def store_one(
    *,
    bootstrap_server: str,
    input_topic: str,
    group_id: str,
    clickhouse_url: str,
    clickhouse_database: str,
    timeout_ms: int,
    auto_offset_reset: str,
) -> str:
    clickhouse = ClickHouseHTTP(clickhouse_url, clickhouse_database)
    with JsonKafkaConsumer(
        input_topic,
        group_id=group_id,
        bootstrap_servers=bootstrap_server,
        auto_offset_reset=auto_offset_reset,
        timeout_ms=timeout_ms,
    ) as consumer:
        message = consumer.poll_one()
        event = message.value
        event_id = store_normalized_event(clickhouse, event)
        consumer.commit()
        return event_id


def store_normalized_event(clickhouse: ClickHouseHTTP, event: dict[str, Any]) -> str:
    row = build_normalized_event_row(event)
    clickhouse.insert_json_each_row(NORMALIZED_EVENTS_TABLE, [row])
    event_id = row["event_id"]
    if not isinstance(event_id, str):
        raise ValueError("event_id must be a string")
    return event_id


def build_normalized_event_row(event: dict[str, Any]) -> dict[str, Any]:
    event_id = _require_str(event, "event_id")
    return {
        "event_id": event_id,
        "event_timestamp": _clickhouse_datetime(_require_str(event, "timestamp")),
        "tenant_id": _require_str(event, "tenant_id"),
        "trace_id": _require_str(event, "trace_id"),
        "host": _require_str(event, "host"),
        "source": _require_str(event, "source"),
        "event_type": _require_str(event, "event_type"),
        "severity": _require_str(event, "severity"),
        "normalized_json": json.dumps(
            event,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
    }


def _require_str(event: dict[str, Any], field: str) -> str:
    value = event.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"normalized event missing string field: {field}")
    return value


def _clickhouse_datetime(value: str) -> str:
    if not value.endswith("Z"):
        raise ValueError("timestamp must be UTC and end with Z")
    parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    utc_value = parsed.astimezone(timezone.utc)
    return utc_value.strftime("%Y-%m-%d %H:%M:%S.%f")[:23]


if __name__ == "__main__":
    raise SystemExit(main())
