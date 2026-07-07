from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from normalization.adapters.sample_adapter import NormalizationError, normalize
from worker.kafka_client import (
    DEFAULT_BOOTSTRAP_SERVERS,
    DEFAULT_TOPIC_NORMALIZED,
    DEFAULT_TOPIC_RAW,
    JsonKafkaConsumer,
    JsonKafkaProducer,
    make_group_id,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Consume raw telemetry and publish one lab-event.")
    parser.add_argument("--once", action="store_true", default=True, help="Process one message and exit.")
    parser.add_argument("--input-topic", default=DEFAULT_TOPIC_RAW)
    parser.add_argument("--output-topic", default=DEFAULT_TOPIC_NORMALIZED)
    parser.add_argument("--group-id", default=None)
    parser.add_argument(
        "--bootstrap-server",
        default=DEFAULT_BOOTSTRAP_SERVERS,
        help="Kafka bootstrap server, or set KAFKA_BOOTSTRAP_SERVERS.",
    )
    parser.add_argument("--timeout-ms", type=int, default=10000)
    args = parser.parse_args(argv)

    try:
        event_id = normalize_one(
            bootstrap_server=args.bootstrap_server,
            input_topic=args.input_topic,
            output_topic=args.output_topic,
            group_id=args.group_id or make_group_id("aegis-normalizer"),
            timeout_ms=args.timeout_ms,
            auto_offset_reset="earliest",
        )
        print(f"OK normalized.events {event_id}")
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def normalize_one(
    *,
    bootstrap_server: str,
    input_topic: str,
    output_topic: str,
    group_id: str,
    timeout_ms: int,
    auto_offset_reset: str,
) -> str:
    with JsonKafkaConsumer(
        input_topic,
        group_id=group_id,
        bootstrap_servers=bootstrap_server,
        auto_offset_reset=auto_offset_reset,
        timeout_ms=timeout_ms,
    ) as consumer, JsonKafkaProducer(bootstrap_server) as producer:
        message = consumer.poll_one()
        normalized = normalize(message.value)
        event_id = normalized["event_id"]
        if not isinstance(event_id, str) or not event_id:
            raise NormalizationError("normalized event_id must be a non-empty string")
        producer.send_json(output_topic, normalized, key=event_id)
        consumer.commit()
        return event_id


if __name__ == "__main__":
    raise SystemExit(main())
