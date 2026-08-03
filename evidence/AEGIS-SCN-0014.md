# Scenario evidence bundle: AEGIS-SCN-0014

> REDACTION REVIEW REQUIRED before committing. Command lines, script blocks, user
> names, and host names can carry credentials or personal data. Check the fields
> listed under Source events and the raw export at `AEGIS-SCN-0014-raw.json`.

## MVP checkpoint fields

| Field | Value |
| --- | --- |
| Scenario ID | `AEGIS-SCN-0014` |
| Lab session ID | `AEGIS-LAB-20260803` |
| MITRE technique ID | `T1218.005` |
| Atomic test number | #10 (8707a805) - mshta executes PowerShell via inline HTA/VBScript Wscript.Shell.Run |
| Rule identity | `a41ef4b6-efa6-42c0-80d6-3d4ccd1b2aa9` version `1` |
| Rule name | SIGMA - Script Host Spawning a Command Shell |
| Attack execution start (UTC) | `2026-08-03T03:31:44.0000000Z` |
| Attack execution end (UTC) | `2026-08-03T03:31:55.0000000Z` |
| Alert timestamp (UTC) | `2026-08-03T03:35:50.101Z` |
| Time to detect (seconds) | 246.1 |
| Rule execution result | succeeded at 2026-08-03T03:35:50.024Z: Rule execution completed successfully |
| Query time window | `now-5m` to `now`, every `5m` |
| Alert deduplication | Detection engine derives a deterministic alert id from the source document and rule identity |
| Alert count | 1 |
| Source document count | 1 |
| Evidence artifact path | `evidence/AEGIS-SCN-0014-raw.json` |
| Evidence hash (SHA-256) | `747C59EF63C7BCEFA2C7B423FB65E590FCE5EDEE01C18092379205A52F14D0A8` |
| Detection result | **detected** |

## Alerts

| Alert UUID | Alert @timestamp | Original event time |
| --- | --- | --- |
| `b48f7bc10fe36ec905d081b108efdf123d6a1280d6a8c689cede9eecdf0a78aa` | `2026-08-03T03:35:50.101Z` | `2026-08-03T03:31:46.557Z` |

## Source events

- `.ds-logs-windows.sysmon-aegis_lab-2026.08.02-000002` / `AZ_FrWZyveKuiCmYDpf4`

## Analyst triage note

<!-- Written by a human. Describe what happened, what the alert showed, which
     events you pivoted to, and whether this is a true or false positive. -->

One alert, a true positive, on a parent-child relationship rather than a payload. Atomic
T1218.005 #10 ran an inline `mshta.exe "about:<hta:application>..."` whose VBScript called
`CreateObject("Wscript.Shell").Run "powershell.exe -nop -Command Write-Host Hello, MSHTA!; Start-Sleep -Seconds 5"`.
Sysmon recorded `powershell.exe` at `03:31:46.557` with **ParentImage `mshta.exe`**, which is
exactly what the Script Host rule keys on. The child command line is innocuous — the rule fires
on who launched it, not what it does — so no keyword rule would have caught this. This is the
mshta (`T1218.005`) path of the rule, a genuinely different technique from the `T1059.005`
cscript marker that first exercised it (`AEGIS-SCN-0002`), so it both externally validates the
rule and broadens its evidence to a second technique.

Harness note: `%20` inside the `.bat` had to be escaped as `%%20`, because cmd reads `%2` as a
batch parameter; the first attempt passed `powershell.exe0-nop0...` to mshta, which spawned no
child at all. Faithful reproduction of an mshta/HTA procedure is quoting-sensitive.

(Drafted from the evidence; rewrite in the author's own words before using as portfolio.)

## Gap category

<!-- One of: telemetry gap, normalization gap, rule logic gap, scenario limitation.
     Leave as not applicable only when the result is detected and nothing was missed. -->

Not applicable — detected. Converts the Script Host rule from a benign-marker detection
(`AEGIS-SCN-0002`) to an Atomic-backed `Live verified` pair, via the mshta (`T1218.005`) path.

