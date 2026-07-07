# Phase 3 Verification

Phase 3 verification is split into an infrastructure smoke check and a one-sample worker smoke check. Docker commands should be run only when Docker use is explicitly allowed.

## What Phase 3A Proves

- Docker Compose describes only Kafka and ClickHouse.
- Kafka can be started as a single broker.
- ClickHouse can be started as a single node.
- Approved Kafka topics can be created.
- ClickHouse event tables are available.

## What Phase 3A Does Not Prove

- No worker message flow is proven unless the Phase 3B smoke check is run.
- No alert publishing or alert storage exists yet.
- No dashboard or backend/API exists yet.
- No real-world detection coverage is claimed.

## What Phase 3B Proves

- One raw fixture can be published to `raw.telemetry`.
- One normalizer worker pass can publish a canonical `lab-event` to `normalized.events`.
- One storage writer pass can insert the canonical event into ClickHouse `normalized_events`.

## What Phase 3B Does Not Prove

- It does not publish to `security.alerts`.
- It does not store alerts.
- It does not implement dashboard/API behavior.
- It does not deduplicate ClickHouse rows.
- It does not claim production readiness.

## Validate Compose File

```powershell
docker compose -f deploy/docker-compose.yml config
```

## Start Local Infra

Start only Kafka and ClickHouse:

```powershell
docker compose -f deploy/docker-compose.yml up -d kafka clickhouse
```

The current compose file exposes Kafka to the host on `localhost:29092`. The worker default is `localhost:9092`, so for host-side worker runs with this compose file use:

```powershell
$env:KAFKA_BOOTSTRAP_SERVERS = "localhost:29092"
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

## Install Worker Dependency

```powershell
py -m pip install -r worker/requirements.txt
```

Phase 3B adds only `kafka-python`. ClickHouse uses HTTP through Python standard library `urllib`.

## Run Phase 3B Pipeline Smoke Check

```powershell
py worker/pipeline_smoke_check.py --sample datasets/raw/process_start.json
```

Expected output:

```text
OK produced raw.telemetry raw-process-001
OK normalized.events evt-process-001
OK stored normalized_events evt-process-001
Phase 3B pipeline smoke check passed.
```

Repeated smoke runs may insert duplicate demo rows into `normalized_events`. That is acceptable for Phase 3B; clean/deduplicated storage is a later design decision.

## Stop Local Infra

```powershell
docker compose -f deploy/docker-compose.yml down
```

To remove local volumes after an explicit cleanup decision:

```powershell
docker compose -f deploy/docker-compose.yml down -v
```

Do not use `down -v` if you want to keep local ClickHouse/Kafka data.
