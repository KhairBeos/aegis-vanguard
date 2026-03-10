#!/usr/bin/env bash
set -euo pipefail

BOOTSTRAP_SERVER="${KAFKA_BOOTSTRAP_SERVER:-kafka:29092}"
TOPIC_EVENTS="${KAFKA_TOPIC_EVENTS:-siem.events}"
TOPIC_ALERTS="${KAFKA_TOPIC_ALERTS:-siem.alerts}"
TOPIC_EVENTS_DLQ="${KAFKA_TOPIC_EVENTS_DLQ:-siem.events.dlq}"
TOPIC_PARTITIONS="${KAFKA_TOPIC_PARTITIONS:-1}"
TOPIC_REPLICATION_FACTOR="${KAFKA_TOPIC_REPLICATION_FACTOR:-1}"

echo "Waiting for Kafka..."
cub kafka-ready -b "${BOOTSTRAP_SERVER}" 1 30

echo "Creating topics if missing..."
kafka-topics --bootstrap-server "${BOOTSTRAP_SERVER}" --create --if-not-exists --topic "${TOPIC_EVENTS}" --partitions "${TOPIC_PARTITIONS}" --replication-factor "${TOPIC_REPLICATION_FACTOR}"
kafka-topics --bootstrap-server "${BOOTSTRAP_SERVER}" --create --if-not-exists --topic "${TOPIC_ALERTS}" --partitions "${TOPIC_PARTITIONS}" --replication-factor "${TOPIC_REPLICATION_FACTOR}"
kafka-topics --bootstrap-server "${BOOTSTRAP_SERVER}" --create --if-not-exists --topic "${TOPIC_EVENTS_DLQ}" --partitions "${TOPIC_PARTITIONS}" --replication-factor "${TOPIC_REPLICATION_FACTOR}"

echo "Kafka topics are ready: ${TOPIC_EVENTS}, ${TOPIC_ALERTS}, ${TOPIC_EVENTS_DLQ}."
