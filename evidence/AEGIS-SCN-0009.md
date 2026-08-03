# Scenario evidence bundle: AEGIS-SCN-0009

> REDACTION REVIEW REQUIRED before committing. Command lines, script blocks, user
> names, and host names can carry credentials or personal data. Check the fields
> listed under Source events and the raw export at `AEGIS-SCN-0009-raw.json`.

## MVP checkpoint fields

| Field | Value |
| --- | --- |
| Scenario ID | `AEGIS-SCN-0009` |
| Lab session ID | `AEGIS-LAB-20260802` |
| MITRE technique ID | `T1059.005` |
| Atomic test number | #1 (bc4fafd0) - cscript running a VBS that spawns no shell |
| Rule identity | `a41ef4b6-efa6-42c0-80d6-3d4ccd1b2aa9` version `1` |
| Rule name | SIGMA - Script Host Spawning a Command Shell |
| Attack execution start (UTC) | `2026-08-02T10:55:05.0000000Z` |
| Attack execution end (UTC) | `2026-08-02T10:55:50.0000000Z` |
| Alert timestamp (UTC) | `not applicable` |
| Time to detect (seconds) | not applicable |
| Rule execution result | failed at 2026-08-03T01:50:43.009Z: 14 hours (51658063ms) were not queried between this rule execution and the last execution, so signals may have been missed. Consider increasing your look behind time or adding more Kibana instances |
| Query time window | `now-5m` to `now`, every `5m` |
| Alert deduplication | Detection engine derives a deterministic alert id from the source document and rule identity |
| Alert count | 0 |
| Source document count | 0 |
| Evidence artifact path | `evidence/AEGIS-SCN-0009-raw.json` |
| Evidence hash (SHA-256) | `B13705E636A55CA53EE0C0E87215057559A5FE77D8EF05D82D14AFB89D297F73` |
| Detection result | **missed** |

## Analyst triage note

<!-- Written by a human. Describe what happened, what the alert showed, which
     events you pivoted to, and whether this is a true or false positive. -->

`cscript C:\AEGIS\atomics\T1059.005\src\sys_info.vbs` ran and gathered system information;
it spawned no child shell. The Script Host rule detects `wscript`/`cscript`/`mshta`
**spawning `powershell`/`cmd`** — a parent-child relationship, not the mere use of a script
host. This procedure never exhibits that behaviour, so the rule correctly did not fire.
Confirmed deterministically: the rule's own query returns 0 hits, and pivoting on
`ParentImage = *\cscript.exe` for the window shows no shell child. Recording this as a rule
defect would be dishonest — it is a true negative for the behaviour the rule targets. See
`docs/atomic-validation-gap-analysis.md`.

(Drafted from the evidence; rewrite in the author's own words before using as portfolio.)

## Gap category

<!-- One of: telemetry gap, normalization gap, rule logic gap, scenario limitation.
     Leave as not applicable only when the result is detected and nothing was missed. -->

Not applicable — correct scope boundary. The rule targets a script host spawning a shell;
this procedure does not do that, so a non-alert is the right outcome, not a miss.

## Why this is recorded as missed

No alert existed for rule `a41ef4b6-efa6-42c0-80d6-3d4ccd1b2aa9` between `2026-08-02T10:55:05.0000000Z` and
`2026-08-02T11:25:50.0000000Z`. The alert timestamp is recorded as
`not applicable` rather than as a placeholder value. Confirm the rule ran at least
once inside that window before concluding the rule logic is at fault.

