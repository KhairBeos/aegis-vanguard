# Scenario evidence bundle: AEGIS-SCN-0003

> REDACTION REVIEW REQUIRED before committing. Command lines, script blocks, user
> names, and host names can carry credentials or personal data. Check the fields
> listed under Source events and the raw export at `AEGIS-SCN-0003-raw.json`.

## MVP checkpoint fields

| Field | Value |
| --- | --- |
| Scenario ID | `AEGIS-SCN-0003` |
| Lab session ID | `AEGIS-LAB-20260802` |
| MITRE technique ID | `T1547.001` |
| Atomic test number | not applicable - benign marker run |
| Rule identity | `0630c267-9ba0-40b2-95d9-670996d404c8` version `1` |
| Rule name | SIGMA - Registry Run Key Persistence |
| Attack execution start (UTC) | `2026-08-02T05:47:06.6815739Z` |
| Attack execution end (UTC) | `2026-08-02T05:47:10.7367104Z` |
| Alert timestamp (UTC) | `2026-08-02T05:51:43.748Z` |
| Time to detect (seconds) | 277.1 |
| Rule execution result | failed at 2026-08-02T08:56:33.355Z: 2 hours (7489700ms) were not queried between this rule execution and the last execution, so signals may have been missed. Consider increasing your look behind time or adding more Kibana instances |
| Query time window | `now-5m` to `now`, every `5m` |
| Alert deduplication | Detection engine derives a deterministic alert id from the source document and rule identity |
| Alert count | 1 |
| Source document count | 1 |
| Evidence artifact path | `evidence/AEGIS-SCN-0003-raw.json` |
| Evidence hash (SHA-256) | `EA9406B5DBBD9E507B73AB0DEFA5BE9F5022DDC63354A7F37F701ECEBC4EDC39` |
| Detection result | **detected** |
| Marker ID | `AEGIS-20260802T054707681Z-523fd21d` |

## Alerts

| Alert UUID | Alert @timestamp | Original event time |
| --- | --- | --- |
| `12140350b96cb742db14ad51c408e33612af1662389185fe5ebfbc2bc56041f2` | `2026-08-02T05:51:43.748Z` | `2026-08-02T05:47:07.708Z` |

## Source events

- `.ds-logs-windows.sysmon-aegis_lab-2026.08.02-000001` / `AZ_BA18hvJGjv-sWw4uY`

## Analyst triage note

A value was written to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` at
`05:47:07.708Z`, captured as Sysmon Event ID 13 (`SetValue`).

Pivot, and the important part of this triage: Sysmon **also** recorded Event ID 12
(`DeleteValue`) for the same value at `05:47:09.722Z`, 2.0 seconds later. The persistence
never survived. The autorun entry did not exist by the time the alert was even created.

That fact is invisible in the alert. This rule watches Event ID 13 only, so an analyst who
stops at the alert would report live persistence on the host and be wrong. The telemetry
to correct that is already being collected; nothing surfaces it.

Verdict: **true positive by rule logic, benign in fact**, and a demonstration that an alert
describing a moment is not the same as a description of the current state of the host.

## Gap category

`rule logic gap`. The rule reports that persistence was created and says nothing about
whether it still exists. Improvement to make: pair the Event ID 13 alert with a lookup of
Event ID 12 for the same `TargetObject`, or enrich the alert with the current registry
value, so the analyst is told the lifetime rather than having to think to ask.

