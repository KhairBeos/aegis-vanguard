# Deploy Notes

## Local Development

1. Copy `deploy/env/.env.example` -> `deploy/env/.env`.
2. Harden secrets in local env file.
3. Start infrastructure stack:

```bash
docker compose --env-file deploy/env/.env -f deploy/docker-compose.yml up -d
```

4. Verify services:

```bash
docker ps
docker exec aegis-kafka kafka-topics --bootstrap-server kafka:29092 --list
docker exec aegis-clickhouse clickhouse-client --query "SHOW TABLES FROM aegis"
```

## Components in Compose

- ClickHouse (storage)
- Zookeeper + Kafka (event bus)
- Kafka init job (topic bootstrap, including DLQ)
- Grafana (observability dashboards)

## Security Baseline

- Do not commit `deploy/env/.env` (already ignored by git).
- Rotate local passwords when sharing screenshots or logs.
- Use the hardening script to generate strong local secrets:

```powershell
powershell -ExecutionPolicy Bypass -File deploy/scripts/harden_env.ps1
```

## Exposed Ports

- ClickHouse HTTP: `8123`
- ClickHouse native: `9000`
- Kafka external listener: `9092`
- Grafana UI: `3000`

## Grafana

- URL: `http://localhost:3000`
- Credentials: from `deploy/env/.env`
  - `GRAFANA_ADMIN_USER`
  - `GRAFANA_ADMIN_PASSWORD`
- Provisioned datasource: ClickHouse (`aegis-clickhouse`)
- Provisioned dashboard: `Aegis SIEM Overview`

## Stop and Cleanup

```bash
docker compose --env-file deploy/env/.env -f deploy/docker-compose.yml down
```

Remove all volumes (destructive):

```bash
docker compose --env-file deploy/env/.env -f deploy/docker-compose.yml down -v
```

## ClickHouse Backup and Restore

Create backup archive from ClickHouse volume:

```powershell
powershell -ExecutionPolicy Bypass -File deploy/scripts/backup_clickhouse.ps1
```

Restore from backup archive (destructive operation):

```powershell
powershell -ExecutionPolicy Bypass -File deploy/scripts/restore_clickhouse.ps1 -BackupFile "deploy/backups/clickhouse/clickhouse-backup-YYYYMMDD-HHMMSS.tar.gz"
```

Notes:

- Stop stack before restore to avoid file lock corruption.
- Scripts auto-detect `CLICKHOUSE_VOLUME_NAME` from `deploy/env/.env`.
- If not set, default volume name is `deploy_clickhouse_data`.

## One-Command Smoke Test

Run all core checks (compose config, running containers, health, Kafka topics, ClickHouse tables, Grafana health):

```powershell
powershell -ExecutionPolicy Bypass -File deploy/scripts/smoke_test.ps1
```

Optional: auto-start stack before running checks:

```powershell
powershell -ExecutionPolicy Bypass -File deploy/scripts/smoke_test.ps1 -AutoStart
```

## Produce a Sample Event

Send one sample `process_start` event to Kafka topic `KAFKA_TOPIC_EVENTS`:

```powershell
powershell -ExecutionPolicy Bypass -File deploy/scripts/produce_sample_event.ps1
```

Send + verify consumer can read from topic:

```powershell
powershell -ExecutionPolicy Bypass -File deploy/scripts/produce_sample_event.ps1 -VerifyConsumer
```
