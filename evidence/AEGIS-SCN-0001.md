# Scenario evidence bundle: AEGIS-SCN-0001

> REDACTION REVIEW REQUIRED before committing. Command lines, script blocks, user
> names, and host names can carry credentials or personal data. Check the fields
> listed under Source events and the raw export at `AEGIS-SCN-0001-raw.json`.

## MVP checkpoint fields

| Field | Value |
| --- | --- |
| Scenario ID | `AEGIS-SCN-0001` |
| Lab session ID | `AEGIS-LAB-20260802` |
| MITRE technique ID | `T1059.001` |
| Atomic test number | not applicable - benign marker run |
| Rule identity | `1131fb39-a497-4a09-b051-4e4c89066f5f` version `1` |
| Rule name | SIGMA - PowerShell Encoded Command Execution |
| Attack execution start (UTC) | `2026-08-02T05:30:38.8396468Z` |
| Attack execution end (UTC) | `2026-08-02T05:30:41.6983440Z` |
| Alert timestamp (UTC) | `2026-08-02T05:32:43.753Z` |
| Time to detect (seconds) | 124.9 |
| Rule execution result | succeeded at 2026-08-02T05:52:43.636Z: Rule execution completed successfully |
| Query time window | `now-5m` to `now`, every `5m` |
| Alert deduplication | Detection engine derives a deterministic alert id from the source document and rule identity |
| Alert count | 1 |
| Source document count | 1 |
| Evidence artifact path | `evidence/AEGIS-SCN-0001-raw.json` |
| Evidence hash (SHA-256) | `0659A28275751F9737D8F5F465083B647E41978036F54CA63C80457ED4D29CA3` |
| Detection result | **detected** |
| Marker ID | `AEGIS-20260802T053038839Z-984f587b` |

## Alerts

| Alert UUID | Alert @timestamp | Original event time |
| --- | --- | --- |
| `799d17f1677425c3d556402c5172f195408255d60cb6b8da36a006c4e1ef9db5` | `2026-08-02T05:32:43.753Z` | `2026-08-02T05:30:40.101Z` |

## Source events

- `.ds-logs-windows.sysmon-aegis_lab-2026.08.02-000001` / `AZ_A9F8hvJGjv-sIwfNs`

## Analyst triage note

`powershell.exe` started at `05:30:40.101Z` with `-EncodedCommand`. Since TUNE-001 the
payload is decoded at ingest, and it reads `Write-Output 'AEGIS-20260802T053038839Z-984f587b'`:
the lab marker id and nothing else.

Pivot: the same rule execution emitted two sibling alerts, at `05:28:55.434Z` and
`05:28:56.749Z`. Both are this project's own tooling. `VBoxManage guestcontrol` drives the
VM by invoking `powershell.exe -EncodedCommand`, so the diagnostic scripts run during setup
are indistinguishable from this scenario on every command-line field.

Verdict: **true positive by rule logic, benign in fact.** The rule did exactly what it says
it does. It detects encoding, and encoding is not malice. Being unable to separate the two
is what motivated TUNE-001 and the decode pipeline.

## Gap category

`rule logic gap`. The discriminating information sat inside a base64 blob the query could
not read. Closed by decoding at ingest and adding rule
`8c1d2f4a-5b6e-47c8-9a03-2e7f81d4b6c5`; see `docs/detection-tuning-log.md`.

