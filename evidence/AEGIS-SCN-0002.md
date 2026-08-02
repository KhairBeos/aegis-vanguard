# Scenario evidence bundle: AEGIS-SCN-0002

> REDACTION REVIEW REQUIRED before committing. Command lines, script blocks, user
> names, and host names can carry credentials or personal data. Check the fields
> listed under Source events and the raw export at `AEGIS-SCN-0002-raw.json`.

## MVP checkpoint fields

| Field | Value |
| --- | --- |
| Scenario ID | `AEGIS-SCN-0002` |
| Lab session ID | `AEGIS-LAB-20260802` |
| MITRE technique ID | `T1059.005` |
| Atomic test number | not applicable - benign marker run |
| Rule identity | `a41ef4b6-efa6-42c0-80d6-3d4ccd1b2aa9` version `1` |
| Rule name | SIGMA - Script Host Spawning a Command Shell |
| Attack execution start (UTC) | `2026-08-02T05:47:04.5678231Z` |
| Attack execution end (UTC) | `2026-08-02T05:47:08.6794128Z` |
| Alert timestamp (UTC) | `2026-08-02T05:51:43.738Z` |
| Time to detect (seconds) | 279.2 |
| Rule execution result | succeeded at 2026-08-02T05:51:43.643Z: Rule execution completed successfully |
| Query time window | `now-5m` to `now`, every `5m` |
| Alert deduplication | Detection engine derives a deterministic alert id from the source document and rule identity |
| Alert count | 1 |
| Source document count | 1 |
| Evidence artifact path | `evidence/AEGIS-SCN-0002-raw.json` |
| Evidence hash (SHA-256) | `36888B186241D5F2E888A8E5362F7648A9B7EDD77DFECDC59A2E024E02CA9F55` |
| Detection result | **detected** |
| Marker ID | `AEGIS-20260802T054705567Z-17be202a` |

## Alerts

| Alert UUID | Alert @timestamp | Original event time |
| --- | --- | --- |
| `366153afe6f12e4666790b3a4517c4442a6456b4ede7c41146e6940190800ab3` | `2026-08-02T05:51:43.738Z` | `2026-08-02T05:47:05.955Z` |

## Source events

- `.ds-logs-windows.sysmon-aegis_lab-2026.08.02-000001` / `AZ_BA18hvJGjv-sWw4uM`

## Analyst triage note

`wscript.exe` launched `powershell.exe` at `05:47:05Z`. The child command line is
`Write-Output '<marker>'` - completely innocuous. No keyword or command-line rule would
have fired on it, and no analyst scanning command lines would have looked twice.

The entire signal is the parent. A script host has almost no legitimate reason to launch a
shell on a workstation, which is why this pairing is worth an alert even when the child
looks harmless.

Pivot: parent `wscript.exe` was itself started by the lab scenario driver, and the `.vbs`
it executed was written and deleted by that driver in the same run.

Verdict: **true positive by rule logic, benign in fact.** In a real environment this exact
pair, with this exact innocuous child command line, is the shape of a macro or scriptlet
first stage and would warrant a full investigation.

## Gap category

`scenario limitation`. The trigger was synthetic and the parent chain was known-good in
advance. The rule has not been tested against a script host whose origin is genuinely
unknown, which is the case that matters.

