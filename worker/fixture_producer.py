from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from worker.kafka_client import DEFAULT_BOOTSTRAP_SERVERS, DEFAULT_TOPIC_RAW, JsonKafkaProducer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Publish one raw fixture to Kafka.")
    parser.add_argument("--sample", required=True, help="Path to one JSON file under datasets/raw/.")
    parser.add_argument("--topic", default=DEFAULT_TOPIC_RAW, help="Kafka topic for raw telemetry.")
    parser.add_argument(
        "--bootstrap-server",
        default=DEFAULT_BOOTSTRAP_SERVERS,
        help="Kafka bootstrap server, or set KAFKA_BOOTSTRAP_SERVERS.",
    )
    args = parser.parse_args(argv)

    try:
        raw_event = read_json_object(Path(args.sample))
        raw_id = event_key(raw_event)
        with JsonKafkaProducer(args.bootstrap_server) as producer:
            producer.send_json(args.topic, raw_event, key=raw_id)
        print(f"OK produced {args.topic} {raw_id}")
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def read_json_object(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def event_key(event: dict[str, Any]) -> str:
    for field in ("raw_event_id", "event_id"):
        value = event.get(field)
        if isinstance(value, str) and value:
            return value
    raise ValueError("fixture must include raw_event_id or event_id for Kafka key")


if __name__ == "__main__":
    raise SystemExit(main())
