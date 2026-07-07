from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from normalization.adapters.sample_adapter import normalize
from worker.clickhouse_http import (
    DEFAULT_CLICKHOUSE_DATABASE,
    DEFAULT_CLICKHOUSE_HTTP_URL,
    ClickHouseHTTP,
)
from worker.fixture_producer import event_key, read_json_object
from worker.kafka_client import (
    DEFAULT_BOOTSTRAP_SERVERS,
    DEFAULT_TOPIC_NORMALIZED,
    DEFAULT_TOPIC_RAW,
    JsonKafkaConsumer,
    JsonKafkaProducer,
    make_group_id,
)
from worker.storage_writer import NORMALIZED_EVENTS_TABLE, store_normalized_event


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the one-sample Phase 3B pipeline smoke check.")
    parser.add_argument("--sample", required=True, help="Path to one raw fixture under datasets/raw/.")
    parser.add_argument("--raw-topic", default=DEFAULT_TOPIC_RAW)
    parser.add_argument("--normalized-topic", default=DEFAULT_TOPIC_NORMALIZED)
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
        run_smoke_check(
            sample_path=Path(args.sample),
            bootstrap_server=args.bootstrap_server,
            raw_topic=args.raw_topic,
            normalized_topic=args.normalized_topic,
            clickhouse_url=args.clickhouse_url,
            clickhouse_database=args.clickhouse_database,
            timeout_ms=args.timeout_ms,
        )
        print("Phase 3B pipeline smoke check passed.")
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def run_smoke_check(
    *,
    sample_path: Path,
    bootstrap_server: str,
    raw_topic: str,
    normalized_topic: str,
    clickhouse_url: str,
    clickhouse_database: str,
    timeout_ms: int,
) -> None:
    raw_event = read_json_object(sample_path)
    raw_id = event_key(raw_event)
    clickhouse = ClickHouseHTTP(clickhouse_url, clickhouse_database)

    raw_group_id = make_group_id("aegis-smoke-normalizer")
    normalized_group_id = make_group_id("aegis-smoke-storage")
    with JsonKafkaConsumer(
        raw_topic,
        group_id=raw_group_id,
        bootstrap_servers=bootstrap_server,
        auto_offset_reset="latest",
        timeout_ms=timeout_ms,
    ) as raw_consumer, JsonKafkaConsumer(
        normalized_topic,
        group_id=normalized_group_id,
        bootstrap_servers=bootstrap_server,
        auto_offset_reset="latest",
        timeout_ms=timeout_ms,
    ) as normalized_consumer, JsonKafkaProducer(bootstrap_server) as producer:
        raw_consumer.prime()
        normalized_consumer.prime()

        producer.send_json(raw_topic, raw_event, key=raw_id)
        print(f"OK produced {raw_topic} {raw_id}")

        raw_message = raw_consumer.poll_one()
        normalized_event = normalize(raw_message.value)
        event_id = normalized_event["event_id"]
        if not isinstance(event_id, str) or not event_id:
            raise ValueError("normalized event_id must be a non-empty string")
        producer.send_json(normalized_topic, normalized_event, key=event_id)
        raw_consumer.commit()
        print(f"OK normalized.events {event_id}")

        normalized_message = normalized_consumer.poll_one()
        if normalized_message.value.get("event_id") != event_id:
            raise ValueError(f"unexpected normalized event_id: {normalized_message.value.get('event_id')}")
        stored_event_id = store_normalized_event(clickhouse, normalized_message.value)
        normalized_consumer.commit()
        if not clickhouse.row_exists_by_event_id(NORMALIZED_EVENTS_TABLE, stored_event_id):
            raise ValueError(f"ClickHouse row not found for event_id={stored_event_id}")
        print(f"OK stored normalized_events {stored_event_id}")


if __name__ == "__main__":
    raise SystemExit(main())
