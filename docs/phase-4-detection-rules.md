# Phase 4 Sigma conversion and detection rules

Executor decision: see `docs/adr-001-detection-executor.md`.

## Pipeline

```text
rules/windows/*.yml                  Sigma source (authored here)
  └─ sigma-cli
       ├─ pipeline ecs_windows       log source -> winlog.channel + event.code, ECS field names
       └─ pipeline sigma/pipelines/aegis-lab.yml
                                     widens process fields to raw winlog names
  └─ format siem_rule_ndjson
rules/generated/*.ndjson             Elastic detection rules (gitignored)
  └─ Kibana detection engine API
.alerts-security.alerts-default      alerts
```

## Why a custom pipeline exists

`ecs_windows` is written for data that has passed through the Windows integration ingest
pipelines. It maps Sigma's `Image` to `process.executable`.

This lab runs a standalone Elastic Agent writing raw `winlog` documents into custom datasets
(`logs-windows.sysmon-aegis_lab` and siblings) with **no integration package installed**, so
`process.executable` does not exist in those documents - only `winlog.event_data.Image` does.
A rule converted with `ecs_windows` alone would import cleanly and never match anything.

`sigma/pipelines/aegis-lab.yml` runs at priority 30 (after `ecs_windows` at 20) and maps the
affected fields to **both** names, which pySigma renders as an `OR`:

```text
(process.executable:(*\\powershell.exe OR *\\pwsh.exe)) OR (winlog.event_data.Image:(...))
```

The rule therefore matches raw winlog documents today, and keeps matching if the integration
assets are installed later. ECS normalization stays an open gap rather than a silent breakage.

`event.code` and `winlog.channel` are left as-is: the Agent's `winlog` input produces both
natively, without any ingest pipeline.

## Initial rule

| Field | Value |
| --- | --- |
| File | `rules/windows/powershell_encoded_command.yml` |
| Rule ID | `1131fb39-a497-4a09-b051-4e4c89066f5f` |
| Technique | T1059.001 - Command and Scripting Interpreter: PowerShell |
| Log source | Sysmon Event ID 1, `Microsoft-Windows-Sysmon/Operational` |
| Severity / risk | `high` / `73` |
| Schedule | every `5m`, window `now-5m` to `now`, additional look-back `1m` |

It was chosen because Sysmon Event ID 1 is telemetry `infra/sysmon/sysmon-aegis.xml` is already
configured to emit, and because Atomic Red Team T1059.001 exercises the behaviour, which keeps
the Phase 3 scenario-alignment gate satisfiable with the telemetry the lab actually collects.

Event ID 1 is written explicitly in the rule rather than relying on a `category:
process_creation` pipeline mapping, so the rule matches exactly what the Sysmon config emits.

## Commands

Set up the conversion environment once:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Convert, then deploy:

```powershell
.\scripts\convert-sigma.ps1
.\scripts\deploy-detection-rules.ps1 -KibanaUrl "http://192.168.56.1:5601"
```

`convert-sigma.ps1` normalises `index` to an array; `sigma-cli` emits a bare string when only
one index pattern is supplied, which the import API rejects.

## Credentials

Host scripts resolve Elasticsearch credentials in this order:

1. `$env:AEGIS_ES_USER` / `$env:AEGIS_ES_PASSWORD`
2. `ELASTIC_PASSWORD` from `infra/elastic/.env` (username defaults to `elastic`)

`infra/elastic/.env` is gitignored. No credential is written back into the repository, and
`scripts/new-agent-api-key.ps1` prints the Agent API key once without storing it.

## Known gaps

- Rule import, rule execution, alert generation, and deduplication behaviour: **not verified at runtime**.
- Advanced telemetry ingestion is still `PENDING` in the VM, so the rule has no data to match yet.
- ECS normalization and integration-package ingest pipelines: still not installed or verified.
- TLS: deliberately not enabled. See ADR-001.
- Atomic Red Team: not installed or run. No `Live verified` claim is possible yet.
