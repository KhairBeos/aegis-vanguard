# Phase 1 Elastic Stack

## Architecture

The host runs one Elasticsearch node and one Kibana instance through Docker Compose. Both services use official Elastic images pinned to `9.4.2`, share a dedicated Docker network, and publish only on the VirtualBox host-only address `192.168.56.1`.

Elasticsearch stores data in the named `elasticsearch-data` volume. Kibana does not use a separate volume because its saved objects are stored in Elasticsearch.

## Resource allocation

| Service | Heap | Memory limit |
| --- | --- | --- |
| Elasticsearch | 2 GiB | 4 GiB |
| Kibana | Image default | 2 GiB |

## Lab security boundary

`xpack.security.enabled=false` is intentional only for this isolated personal lab. The deployment is not suitable for production or any public or untrusted network.

Published ports:

- `192.168.56.1:9200` for Elasticsearch
- `192.168.56.1:5601` for Kibana

Port `9300` is not published. The Compose file does not use privileged mode, host networking, or the Docker socket.

## Files

| File | Purpose |
| --- | --- |
| `infra/elastic/docker-compose.yml` | Elasticsearch and Kibana services |
| `infra/elastic/.env.example` | Tracked non-secret configuration template |
| `infra/elastic/.env` | Local ignored Compose values |
| `scripts/verify-elastic.ps1` | Host health, API, and binding validation |

## Start and stop

Run from `infra/elastic`:

```powershell
docker compose --env-file .env config
docker compose --env-file .env pull
docker compose --env-file .env up -d
docker compose --env-file .env ps
```

Stop without deleting data:

```powershell
docker compose --env-file .env down
```

Do not use `down -v` unless intentionally resetting all Elasticsearch data.

## Verification

Run from `infra/elastic`:

```powershell
powershell -ExecutionPolicy Bypass -File ..\..\scripts\verify-elastic.ps1
```

The script validates the Docker engine, both container health states, the Elasticsearch root and cluster-health APIs, Kibana status, and the expected host-only port bindings.

## Healthcheck results

Host validation completed at `2026-07-29T03:26:49.1846858Z`.

| Service | Version | Container state | Health/API state |
| --- | --- | --- | --- |
| Elasticsearch | 9.4.2 | running | healthy; cluster green |
| Kibana | 9.4.2 | running | healthy; overall available |

Validation results:

- Elasticsearch root API: PASS
- Elasticsearch `_cluster/health`: PASS; one node, one data node, no timeout
- Kibana `/api/status`: PASS
- Docker port mappings: PASS; only `192.168.56.1:9200` and `192.168.56.1:5601`
- Windows listener addresses: PASS; both ports reported only on `192.168.56.1`
- `scripts/verify-elastic.ps1`: PASS; exit code `0`

## VM connectivity checkpoint

The user completed the manual checkpoint from `victim-win-01`:

- VM TCP access to `192.168.56.1:9200`: PASS
- VM TCP access to `192.168.56.1:5601`: PASS
- Kibana UI at `http://192.168.56.1:5601`: PASS

Overall state: `ELASTIC STACK AND VM ACCESS VERIFIED`.

## Known gaps

- Elastic Agent is not installed.
- Telemetry ingestion and ECS normalization are not verified.
- Detection rules are not deployed.

## Troubleshooting

1. Confirm Docker Desktop is already running with `docker info`.
2. Inspect current state with `docker compose --env-file .env ps`.
3. Inspect a short service log with `docker compose --env-file .env logs --tail 100 elasticsearch` or `kibana`.
4. Confirm `192.168.56.1` still exists on the host and ports `9200` and `5601` are not owned by another process.
5. Do not reset Docker Desktop or delete the named volume as an automatic recovery step.
