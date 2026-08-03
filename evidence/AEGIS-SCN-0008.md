# Scenario evidence bundle: AEGIS-SCN-0008

> REDACTION REVIEW REQUIRED before committing. Command lines, script blocks, user
> names, and host names can carry credentials or personal data. Check the fields
> listed under Source events and the raw export at `AEGIS-SCN-0008-raw.json`.

## MVP checkpoint fields

| Field | Value |
| --- | --- |
| Scenario ID | `AEGIS-SCN-0008` |
| Lab session ID | `AEGIS-LAB-20260802` |
| MITRE technique ID | `T1027` |
| Atomic test number | #11 (6683baf0) - char-array obfuscated Start-Process, no -EncodedCommand |
| Rule identity | `1131fb39-a497-4a09-b051-4e4c89066f5f` version `1` |
| Rule name | SIGMA - PowerShell Encoded Command Execution |
| Attack execution start (UTC) | `2026-08-02T10:55:05.0000000Z` |
| Attack execution end (UTC) | `2026-08-02T10:55:50.0000000Z` |
| Alert timestamp (UTC) | `not applicable` |
| Time to detect (seconds) | not applicable |
| Rule execution result | failed at 2026-08-03T01:50:42.390Z: 14 hours (51663353ms) were not queried between this rule execution and the last execution, so signals may have been missed. Consider increasing your look behind time or adding more Kibana instances |
| Query time window | `now-5m` to `now`, every `5m` |
| Alert deduplication | Detection engine derives a deterministic alert id from the source document and rule identity |
| Alert count | 0 |
| Source document count | 0 |
| Evidence artifact path | `evidence/AEGIS-SCN-0008-raw.json` |
| Evidence hash (SHA-256) | `C1228CE0B824D421BA895375D4C73677485CC84117B06579FA679B6D0DF11E65` |
| Detection result | **missed** |

## Analyst triage note

<!-- Written by a human. Describe what happened, what the alert showed, which
     events you pivoted to, and whether this is a true or false positive. -->

This is the miss that mattered. The procedure built `powershell` and `Start-Process
calc.exe` from decimal `[char[]]` arrays and invoked them with `& (-join ...)`; the command
line was captured intact. It carries no `-EncodedCommand`, no download vocabulary, and no
scriptlet, so every rule in the pack missed it — confirmed deterministically, all five
rules' own queries returned 0 hits against this document. This was recorded here as a
**rule logic gap and then closed**: a new rule, `d4e91a72-3c85-4f6b-9e2a-7b1c0d5f8a34`,
matches the `[char[]](` + `-join` idiom, went 0→1 on this exact document, matches nothing
else in the lab's history, and fired live on a faithful re-run (`AEGIS-SCN-0010`, 171.2 s).
See `TUNE-002` and `docs/atomic-validation-gap-analysis.md`.

(Drafted from the evidence; rewrite in the author's own words before using as portfolio.)

## Gap category

<!-- One of: telemetry gap, normalization gap, rule logic gap, scenario limitation.
     Leave as not applicable only when the result is detected and nothing was missed. -->

Rule logic gap — **closed**. The obfuscation was undetectable by the pack until the
char-array rule was added; this bundle is the "before", `AEGIS-SCN-0010` is the "after".

## Why this is recorded as missed

No alert existed for rule `1131fb39-a497-4a09-b051-4e4c89066f5f` between `2026-08-02T10:55:05.0000000Z` and
`2026-08-02T11:25:50.0000000Z`. The alert timestamp is recorded as
`not applicable` rather than as a placeholder value. Confirm the rule ran at least
once inside that window before concluding the rule logic is at fault.

