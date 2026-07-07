from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from typing import Any


DEFAULT_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
DEFAULT_TOPIC_RAW = os.environ.get("KAFKA_TOPIC_RAW", "raw.telemetry")
DEFAULT_TOPIC_NORMALIZED = os.environ.get("KAFKA_TOPIC_NORMALIZED", "normalized.events")
DEFAULT_TOPIC_ALERTS = os.environ.get("KAFKA_TOPIC_ALERTS", "security.alerts")
DEFAULT_CONSUMER_TIMEOUT_MS = 10000


class KafkaClientError(RuntimeError):
    """Raised when a local Kafka worker cannot produce or consume as requested."""


@dataclass(frozen=True)
class KafkaJsonMessage:
    topic: str
    partition: int
    offset: int
    key: str | None
    value: dict[str, Any]


def make_group_id(prefix: str) -> str:
    safe_prefix = prefix.strip() or "aegis-worker"
    return f"{safe_prefix}-{uuid.uuid4().hex}"


def load_kafka_module() -> Any:
    try:
        import kafka  # type: ignore[import-not-found]
    except ImportError as exc:
        raise KafkaClientError(
            "Missing dependency kafka-python. Install it with: "
            "py -m pip install -r worker/requirements.txt"
        ) from exc
    return kafka


class JsonKafkaProducer:
    def __init__(
        self,
        bootstrap_servers: str = DEFAULT_BOOTSTRAP_SERVERS,
        send_timeout_seconds: int = 10,
    ) -> None:
        self.bootstrap_servers = bootstrap_servers
        self.send_timeout_seconds = send_timeout_seconds
        self._producer: Any | None = None

    def __enter__(self) -> JsonKafkaProducer:
        kafka = load_kafka_module()
        try:
            self._producer = kafka.KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                key_serializer=_encode_key,
                value_serializer=_encode_json,
                acks="all",
                retries=0,
                max_block_ms=5000,
                request_timeout_ms=5000,
                api_version_auto_timeout_ms=3000,
            )
        except Exception as exc:  # kafka-python raises different concrete errors per failure path.
            raise KafkaClientError(_connection_hint(self.bootstrap_servers, exc)) from exc
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def send_json(self, topic: str, value: dict[str, Any], key: str | None = None) -> None:
        if self._producer is None:
            raise KafkaClientError("Kafka producer is not open")
        try:
            future = self._producer.send(topic, key=key, value=value)
            future.get(timeout=self.send_timeout_seconds)
            self._producer.flush(timeout=self.send_timeout_seconds)
        except Exception as exc:
            raise KafkaClientError(f"failed to publish to {topic}: {exc}") from exc

    def close(self) -> None:
        if self._producer is not None:
            self._producer.close(timeout=5)
            self._producer = None


class JsonKafkaConsumer:
    def __init__(
        self,
        topic: str,
        group_id: str,
        bootstrap_servers: str = DEFAULT_BOOTSTRAP_SERVERS,
        auto_offset_reset: str = "earliest",
        timeout_ms: int = DEFAULT_CONSUMER_TIMEOUT_MS,
    ) -> None:
        self.topic = topic
        self.group_id = group_id
        self.bootstrap_servers = bootstrap_servers
        self.auto_offset_reset = auto_offset_reset
        self.timeout_ms = timeout_ms
        self._consumer: Any | None = None

    def __enter__(self) -> JsonKafkaConsumer:
        kafka = load_kafka_module()
        try:
            self._consumer = kafka.KafkaConsumer(
                self.topic,
                bootstrap_servers=self.bootstrap_servers,
                group_id=self.group_id,
                auto_offset_reset=self.auto_offset_reset,
                enable_auto_commit=False,
                key_deserializer=_decode_key,
                value_deserializer=_decode_json,
                consumer_timeout_ms=self.timeout_ms,
                max_poll_records=1,
                request_timeout_ms=5000,
                api_version_auto_timeout_ms=3000,
            )
        except Exception as exc:
            raise KafkaClientError(_connection_hint(self.bootstrap_servers, exc)) from exc
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def prime(self) -> None:
        if self._consumer is None:
            raise KafkaClientError("Kafka consumer is not open")
        self._consumer.poll(timeout_ms=1000, max_records=1)

    def poll_one(self) -> KafkaJsonMessage:
        if self._consumer is None:
            raise KafkaClientError("Kafka consumer is not open")
        records = self._consumer.poll(timeout_ms=self.timeout_ms, max_records=1)
        for batch in records.values():
            if not batch:
                continue
            record = batch[0]
            value = record.value
            if not isinstance(value, dict):
                raise KafkaClientError(f"message on {self.topic} must decode to a JSON object")
            return KafkaJsonMessage(
                topic=record.topic,
                partition=record.partition,
                offset=record.offset,
                key=record.key,
                value=value,
            )
        raise KafkaClientError(f"no message available on {self.topic} before timeout")

    def commit(self) -> None:
        if self._consumer is None:
            raise KafkaClientError("Kafka consumer is not open")
        self._consumer.commit()

    def close(self) -> None:
        if self._consumer is not None:
            self._consumer.close()
            self._consumer = None


def _encode_key(value: str | None) -> bytes | None:
    if value is None:
        return None
    return value.encode("utf-8")


def _decode_key(value: bytes | None) -> str | None:
    if value is None:
        return None
    return value.decode("utf-8")


def _encode_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _decode_json(value: bytes) -> dict[str, Any]:
    decoded = json.loads(value.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise KafkaClientError("Kafka message value must be a JSON object")
    return decoded


def _connection_hint(bootstrap_servers: str, exc: Exception) -> str:
    return (
        f"failed to connect to Kafka at {bootstrap_servers}: {exc}. "
        "If you are using deploy/docker-compose.yml from the host, the exposed Kafka port "
        "is currently 29092, so set KAFKA_BOOTSTRAP_SERVERS=localhost:29092."
    )
