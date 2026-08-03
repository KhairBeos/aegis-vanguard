# Scenario evidence bundle: AEGIS-SCN-0013

> REDACTION REVIEW REQUIRED before committing. Command lines, script blocks, user
> names, and host names can carry credentials or personal data. Check the fields
> listed under Source events and the raw export at `AEGIS-SCN-0013-raw.json`.

## MVP checkpoint fields

| Field | Value |
| --- | --- |
| Scenario ID | `AEGIS-SCN-0013` |
| Lab session ID | `AEGIS-LAB-20260803` |
| MITRE technique ID | `T1059.001` |
| Atomic test number | #17 (a538de64) - PowerShell Command Execution via -e base64 (obfuscated Write-Host), faithful run from a transferred .ps1 |
| Rule identity | `1131fb39-a497-4a09-b051-4e4c89066f5f` version `1` |
| Rule name | SIGMA - PowerShell Encoded Command Execution |
| Attack execution start (UTC) | `2026-08-03T03:16:22.0000000Z` |
| Attack execution end (UTC) | `2026-08-03T03:16:45.0000000Z` |
| Alert timestamp (UTC) | `2026-08-03T03:20:44.142Z` |
| Time to detect (seconds) | 262.1 |
| Rule execution result | succeeded at 2026-08-03T03:35:44.023Z: Rule execution completed successfully |
| Query time window | `now-5m` to `now`, every `5m` |
| Alert deduplication | Detection engine derives a deterministic alert id from the source document and rule identity |
| Alert count | 1 |
| Source document count | 1 |
| Evidence artifact path | `evidence/AEGIS-SCN-0013-raw.json` |
| Evidence hash (SHA-256) | `27708B9885ACF51239AAAF9BBEE0F077C974B49E8DF80B64AC7EA78915FE29DC` |
| Detection result | **detected** |

## Alerts

| Alert UUID | Alert @timestamp | Original event time |
| --- | --- | --- |
| `01b3fc9bd376484e348e786408ba3ad167ebdf04262bfe22c7342ce0c9349dbd` | `2026-08-03T03:20:44.142Z` | `2026-08-03T03:16:33.483Z` |

## Source events

- `.ds-logs-windows.sysmon-aegis_lab-2026.08.02-000002` / `AZ_Fn2ZyveKuiCmOCrPE`

## Analyst triage note

<!-- Written by a human. Describe what happened, what the alert showed, which
     events you pivoted to, and whether this is a true or false positive. -->

One alert, a true positive. The Encoded Command rule fired on a child
`powershell.exe -e <base64>` launched by Atomic T1059.001 #17. The ingest decoder decoded the
payload into `aegis.powershell.decoded_command`:
`& (gcm ('ie{0}' -f 'x')) ("Wr"+"it"+"e-H"+"ost 'Hel"+"lo, from PowerShell!'")` — a string-format
and concatenation obfuscation of `IEX (Write-Host 'Hello, from PowerShell!')`. Benign, but a
real external obfuscation procedure.

Only the Encoded Command rule (`medium`) fired; the cradle rule (`high`) correctly did **not**,
because the decoded text carries no literal download/`IEX` primitive — `iex` itself is hidden as
`('ie{0}' -f 'x')`. That is the medium/high split from TUNE-001 behaving exactly as designed:
encoding is surfaced as hunting context, and only a recognisable payload escalates to an
alerting rule. This converts `AEGIS-SCN-0001` (a benign marker) into an externally validated pair.

(Drafted from the evidence; rewrite in the author's own words before using as portfolio.)

## Gap category

<!-- One of: telemetry gap, normalization gap, rule logic gap, scenario limitation.
     Leave as not applicable only when the result is detected and nothing was missed. -->

Not applicable — detected. Converts the Encoded Command rule from a benign-marker detection
(`AEGIS-SCN-0001`) to an Atomic-backed `Live verified` pair.

