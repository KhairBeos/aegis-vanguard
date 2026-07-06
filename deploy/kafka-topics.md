# Kafka Topic Plan

Approved local topics:

| Topic | Phase | Purpose |
| --- | --- | --- |
| `raw.telemetry` | Phase 1 | Raw source events before normalization. |
| `normalized.events` | Phase 1 | Canonical `lab-event` records after normalization. |
| `security.alerts` | Phase 2 | Detection alerts. Reserved only in Phase 1. |

## Local Setup Notes

Do not run Kafka for Phase 1 fixture checks. Start Kafka only when testing the event bus.

Example commands for a future single-broker local Kafka container:

```powershell
docker exec aegis-kafka kafka-topics --bootstrap-server kafka:29092 --create --if-not-exists --topic raw.telemetry --partitions 1 --replication-factor 1
docker exec aegis-kafka kafka-topics --bootstrap-server kafka:29092 --create --if-not-exists --topic normalized.events --partitions 1 --replication-factor 1
docker exec aegis-kafka kafka-topics --bootstrap-server kafka:29092 --create --if-not-exists --topic security.alerts --partitions 1 --replication-factor 1
```

Keep partitions and replication factor at `1` for the personal local lab.
