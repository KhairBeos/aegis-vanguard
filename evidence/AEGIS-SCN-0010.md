# Scenario evidence bundle: AEGIS-SCN-0010

> REDACTION REVIEW REQUIRED before committing. Command lines, script blocks, user
> names, and host names can carry credentials or personal data. Check the fields
> listed under Source events and the raw export at `AEGIS-SCN-0010-raw.json`.

## MVP checkpoint fields

| Field | Value |
| --- | --- |
| Scenario ID | `AEGIS-SCN-0010` |
| Lab session ID | `AEGIS-LAB-20260803` |
| MITRE technique ID | `T1027` |
| Atomic test number | #11 (6683baf0) - char-array obfuscated Start-Process, faithful re-run from a transferred .ps1 |
| Rule identity | `d4e91a72-3c85-4f6b-9e2a-7b1c0d5f8a34` version `1` |
| Rule name | SIGMA - PowerShell Character-Array Obfuscated Execution |
| Attack execution start (UTC) | `2026-08-03T02:12:26.0000000Z` |
| Attack execution end (UTC) | `2026-08-03T02:12:42.0000000Z` |
| Alert timestamp (UTC) | `2026-08-03T02:15:17.205Z` |
| Time to detect (seconds) | 171.2 |
| Rule execution result | succeeded at 2026-08-03T02:15:17.090Z: Rule execution completed successfully |
| Query time window | `now-5m` to `now`, every `5m` |
| Alert deduplication | Detection engine derives a deterministic alert id from the source document and rule identity |
| Alert count | 1 |
| Source document count | 1 |
| Evidence artifact path | `evidence/AEGIS-SCN-0010-raw.json` |
| Evidence hash (SHA-256) | `6D3079DCA0A9256CF0D177F2ED7CDD7A71D86B5079DB07985D31D7C5CE7F67DD` |
| Detection result | **detected** |

## Alerts

| Alert UUID | Alert @timestamp | Original event time |
| --- | --- | --- |
| `2c23e7faa979cec6bb8fecfefbb671564542fdcfb08730fd30bf8798cf80712d` | `2026-08-03T02:15:17.205Z` | `2026-08-03T02:12:31.003Z` |

## Source events

- `.ds-logs-windows.sysmon-aegis_lab-2026.08.02-000002` / `AZ_FZWZyveKuiCkNBcSC`

## Analyst triage note

<!-- Written by a human. Describe what happened, what the alert showed, which
     events you pivoted to, and whether this is a true or false positive. -->

The alert fired on a powershell.exe process whose command line assembled its interpreter
name and its argument from decimal `[char[]]` arrays and rejoined them with `-join`. The
decimal codes decode to `powershell` and `Start-Process calc.exe`; pivoting on the process
tree for the surrounding seconds shows the expected chain — the obfuscated launcher (`02:12:31`)
spawned `powershell.exe -Command "Start-Process calc.exe"` at `02:12:32`, which started
`calc.exe`/`CalculatorApp.exe` at `02:12:33`, and the driver killed the calculator at
`02:12:36`. No network connection and no file write accompanied it. This is a true positive: benign in
intent because it is an Atomic Red Team procedure, but exactly the obfuscation shape the
rule is meant to catch, and it fired on the first scheduled execution after the event.

The finding that made this rule exist: the identical procedure ran on `2026-08-02` and every
one of the five rules then deployed returned zero hits against its telemetry. See
`docs/atomic-validation-gap-analysis.md` and `TUNE-002`.

(Drafted from the evidence; rewrite in the author's own words before using as portfolio.)

## Gap category

<!-- One of: telemetry gap, normalization gap, rule logic gap, scenario limitation.
     Leave as not applicable only when the result is detected and nothing was missed. -->

Not applicable — detected. This bundle is the "after" of a closed rule-logic gap: the
char-array obfuscation was undetectable by the pack until this rule was added.

