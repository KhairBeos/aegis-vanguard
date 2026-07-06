# Kafka Topic Plan

Approved local topics:

| Topic | Phase | Purpose |
| --- | --- | --- |
| `raw.telemetry` | Phase 3A | Raw source events before normalization. |
| `normalized.events` | Phase 3A | Canonical `lab-event` records after normalization. |
| `security.alerts` | Reserved | Detection alerts. Reserved until alert publishing/storage is implemented. |

## Local Setup Notes

Do not run Kafka for Phase 1 or Phase 2 fixture checks. Start Kafka only when testing the event bus.

Phase 3A keeps Kafka as one local broker with one partition and replication factor `1`.

Create topics after starting `deploy/docker-compose.yml`:

```powershell
docker exec aegis-kafka kafka-topics.sh --bootstrap-server localhost:9092 --create --if-not-exists --topic raw.telemetry --partitions 1 --replication-factor 1
docker exec aegis-kafka kafka-topics.sh --bootstrap-server localhost:9092 --create --if-not-exists --topic normalized.events --partitions 1 --replication-factor 1
docker exec aegis-kafka kafka-topics.sh --bootstrap-server localhost:9092 --create --if-not-exists --topic security.alerts --partitions 1 --replication-factor 1
```

List topics:

```powershell
docker exec aegis-kafka kafka-topics.sh --bootstrap-server localhost:9092 --list
```

Expected topics:

```text
normalized.events
raw.telemetry
security.alerts
```

Phase 3A does not implement producers or consumers yet.
