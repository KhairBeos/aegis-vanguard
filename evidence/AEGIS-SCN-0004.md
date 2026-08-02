# Scenario evidence bundle: AEGIS-SCN-0004

> REDACTION REVIEW REQUIRED before committing. Command lines, script blocks, user
> names, and host names can carry credentials or personal data. Check the fields
> listed under Source events and the raw export at `AEGIS-SCN-0004-raw.json`.

## MVP checkpoint fields

| Field | Value |
| --- | --- |
| Scenario ID | `AEGIS-SCN-0004` |
| Lab session ID | `AEGIS-LAB-20260802` |
| MITRE technique ID | `T1027` |
| Atomic test number | not applicable - benign marker run |
| Rule identity | `8c1d2f4a-5b6e-47c8-9a03-2e7f81d4b6c5` version `1` |
| Rule name | SIGMA - PowerShell Encoded Download Cradle |
| Attack execution start (UTC) | `2026-08-02T06:19:06.5071424Z` |
| Attack execution end (UTC) | `2026-08-02T06:19:10.1165242Z` |
| Alert timestamp (UTC) | `2026-08-02T06:23:19.719Z` |
| Time to detect (seconds) | 253.2 |
| Rule execution result | succeeded at 2026-08-02T06:23:19.635Z: Rule execution completed successfully |
| Query time window | `now-5m` to `now`, every `5m` |
| Alert deduplication | Detection engine derives a deterministic alert id from the source document and rule identity |
| Alert count | 1 |
| Source document count | 1 |
| Evidence artifact path | `evidence/AEGIS-SCN-0004-raw.json` |
| Evidence hash (SHA-256) | `245A5D8D868EE3402EE89ECEDED346D6896DA5B53950A629FD2CC8424FC099ED` |
| Detection result | **detected** |
| Marker ID | `AEGIS-20260802T061907464Z-015b4cb7` |

## Alerts

| Alert UUID | Alert @timestamp | Original event time |
| --- | --- | --- |
| `2f46b4c87f120669c4b7632bea3f343aa3bf8e9292efd17c7fa8375319f6d85f` | `2026-08-02T06:23:19.719Z` | `2026-08-02T06:19:07.571Z` |

## Source events

- `.ds-logs-windows.sysmon-aegis_lab-2026.08.02-000002` / `AZ_BIF8hvJGjv-tuy3kE`

## Analyst triage note

`powershell.exe` ran an encoded command at `06:19:07.571Z`. The ingest pipeline decoded it
to a payload containing `IEX`, `New-Object Net.WebClient` and `DownloadString` pointed at
`http://192.168.56.1/<marker>` - textbook download-cradle shape.

Pivot: Sysmon Event ID 3 for the surrounding minute shows five network connections, all
from `elastic-otel-collector.exe` to `192.168.56.1:9200`, which is the Elastic Agent
shipping its own logs. **There is no network connection from `powershell.exe`.** The cradle
string was assigned and echoed, never executed.

Verdict: **true positive by rule logic, benign in fact.** The rule matched intent expressed
in text, and the absence of a corresponding Event ID 3 is what separates that from
execution. In a real incident this pivot decides whether the case is "staged but did not
run" or "ran and pulled a second stage", which changes the response entirely.

## Gap category

`rule logic gap`. The rule alerts on the presence of cradle vocabulary in a decoded
payload and cannot tell whether the payload executed. Improvement to make: correlate the
Event ID 1 alert with a following Event ID 3 from the same `ProcessGuid`, and raise
severity only when the network connection actually occurred.

