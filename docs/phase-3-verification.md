# Phase 3A Verification

Phase 3A verification is a local infrastructure smoke check. It should be run only when Docker use is explicitly allowed.

## What Phase 3A Proves

- Docker Compose describes only Kafka and ClickHouse.
- Kafka can be started as a single broker.
- ClickHouse can be started as a single node.
- Approved Kafka topics can be created.
- ClickHouse event tables are available.

## What Phase 3A Does Not Prove

- No real Kafka producer exists yet.
- No real Kafka consumer exists yet.
- No ClickHouse writer exists yet.
- No alert publishing or alert storage exists yet.
- No dashboard or backend/API exists yet.
- No real-world detection coverage is claimed.

## Validate Compose File

```powershell
docker compose -f deploy/docker-compose.yml config
```

## Start Local Infra

Start only Kafka and ClickHouse:

```powershell
docker compose -f deploy/docker-compose.yml up -d kafka clickhouse
```

## Create Kafka Topics

```powershell
docker exec aegis-kafka kafka-topics.sh --bootstrap-server localhost:9092 --create --if-not-exists --topic raw.telemetry --partitions 1 --replication-factor 1
docker exec aegis-kafka kafka-topics.sh --bootstrap-server localhost:9092 --create --if-not-exists --topic normalized.events --partitions 1 --replication-factor 1
docker exec aegis-kafka kafka-topics.sh --bootstrap-server localhost:9092 --create --if-not-exists --topic security.alerts --partitions 1 --replication-factor 1
```

`security.alerts` is reserved until alert publishing/storage is implemented.

## List Kafka Topics

```powershell
docker exec aegis-kafka kafka-topics.sh --bootstrap-server localhost:9092 --list
```

Expected topics:

```text
normalized.events
raw.telemetry
security.alerts
```

## Check ClickHouse Tables

```powershell
docker exec aegis-clickhouse clickhouse-client --query "SHOW TABLES"
```

Expected tables:

```text
normalized_events
raw_telemetry
```

## Stop Local Infra

```powershell
docker compose -f deploy/docker-compose.yml down
```

To remove local volumes after an explicit cleanup decision:

```powershell
docker compose -f deploy/docker-compose.yml down -v
```

Do not use `down -v` if you want to keep local ClickHouse/Kafka data.
