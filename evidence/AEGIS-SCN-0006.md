# Scenario evidence bundle: AEGIS-SCN-0006

> REDACTION REVIEW REQUIRED before committing. Command lines, script blocks, user
> names, and host names can carry credentials or personal data. Check the fields
> listed under Source events and the raw export at `AEGIS-SCN-0006-raw.json`.

## MVP checkpoint fields

| Field | Value |
| --- | --- |
| Scenario ID | `AEGIS-SCN-0006` |
| Lab session ID | `AEGIS-LAB-20260802` |
| MITRE technique ID | `T1218.010` |
| Atomic test number | #4 (2408973b) - regsvr32 registering a renamed local DLL, no scrobj/URL |
| Rule identity | `6b5da61b-8454-449f-b33c-99f2335025c9` version `1` |
| Rule name | SIGMA - Regsvr32 Remote Scriptlet Execution |
| Attack execution start (UTC) | `2026-08-02T10:55:05.0000000Z` |
| Attack execution end (UTC) | `2026-08-02T10:55:50.0000000Z` |
| Alert timestamp (UTC) | `not applicable` |
| Time to detect (seconds) | not applicable |
| Rule execution result | failed at 2026-08-03T01:50:43.010Z: 14 hours (51658063ms) were not queried between this rule execution and the last execution, so signals may have been missed. Consider increasing your look behind time or adding more Kibana instances |
| Query time window | `now-5m` to `now`, every `5m` |
| Alert deduplication | Detection engine derives a deterministic alert id from the source document and rule identity |
| Alert count | 0 |
| Source document count | 0 |
| Evidence artifact path | `evidence/AEGIS-SCN-0006-raw.json` |
| Evidence hash (SHA-256) | `A262D5CD13429991190855BCF13E48B09DBB76C4764B14A03E0B02EA3EE753BB` |
| Detection result | **missed** |

## Analyst triage note

<!-- Written by a human. Describe what happened, what the alert showed, which
     events you pivoted to, and whether this is a true or false positive. -->

`regsvr32.exe /s shell32.jpg` ran and was captured intact in Sysmon Event ID 1 — this is a
**local, renamed** DLL, not a remote scriptlet. The rule matches the Squiblydoo form:
`scrobj.dll` or a URL. The miss was confirmed deterministically: the rule's own generated
query returns 0 hits against this exact telemetry (the `failed / 14 hours were not queried`
line above is only the executor's first run after overnight downtime, not proof the window
went unscanned — the direct query settles it). A true miss, but of a different sub-technique
than the rule targets, not a bug in the rule. See `docs/atomic-validation-gap-analysis.md`.

(Drafted from the evidence; rewrite in the author's own words before using as portfolio.)

## Gap category

<!-- One of: telemetry gap, normalization gap, rule logic gap, scenario limitation.
     Leave as not applicable only when the result is detected and nothing was missed. -->

Rule logic gap — a renamed local-DLL regsvr32 variant is out of the remote-scriptlet rule's
scope. Recorded as future work, not closed: covering it needs its own rule matching
regsvr32 loading a non-`.dll`/`.ocx` file, with its own false-positive measurement.

## Why this is recorded as missed

No alert existed for rule `6b5da61b-8454-449f-b33c-99f2335025c9` between `2026-08-02T10:55:05.0000000Z` and
`2026-08-02T11:25:50.0000000Z`. The alert timestamp is recorded as
`not applicable` rather than as a placeholder value. Confirm the rule ran at least
once inside that window before concluding the rule logic is at fault.

