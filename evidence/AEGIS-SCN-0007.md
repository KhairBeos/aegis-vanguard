# Scenario evidence bundle: AEGIS-SCN-0007

> REDACTION REVIEW REQUIRED before committing. Command lines, script blocks, user
> names, and host names can carry credentials or personal data. Check the fields
> listed under Source events and the raw export at `AEGIS-SCN-0007-raw.json`.

## MVP checkpoint fields

| Field | Value |
| --- | --- |
| Scenario ID | `AEGIS-SCN-0007` |
| Lab session ID | `AEGIS-LAB-20260802` |
| MITRE technique ID | `T1027` |
| Atomic test number | #3 (450e7218) - base64 payload in registry, inline IEX+FromBase64String (no -EncodedCommand) |
| Rule identity | `8c1d2f4a-5b6e-47c8-9a03-2e7f81d4b6c5` version `1` |
| Rule name | SIGMA - PowerShell Encoded Download Cradle |
| Attack execution start (UTC) | `2026-08-02T10:55:05.0000000Z` |
| Attack execution end (UTC) | `2026-08-02T10:55:50.0000000Z` |
| Alert timestamp (UTC) | `not applicable` |
| Time to detect (seconds) | not applicable |
| Rule execution result | failed at 2026-08-03T01:50:42.392Z: 14 hours (51663353ms) were not queried between this rule execution and the last execution, so signals may have been missed. Consider increasing your look behind time or adding more Kibana instances |
| Query time window | `now-5m` to `now`, every `5m` |
| Alert deduplication | Detection engine derives a deterministic alert id from the source document and rule identity |
| Alert count | 0 |
| Source document count | 0 |
| Evidence artifact path | `evidence/AEGIS-SCN-0007-raw.json` |
| Evidence hash (SHA-256) | `DE7884D4658D7264F6FE5793D4B16FD9B85B8AD5662B00175BFDEE786BACECF5` |
| Detection result | **missed** |

## Analyst triage note

<!-- Written by a human. Describe what happened, what the alert showed, which
     events you pivoted to, and whether this is a true or false positive. -->

This procedure did **not** execute faithfully, so its miss is confounded and not usable to
judge the rule. It should run an inline `IEX ([Convert]::FromBase64String(...))` read from
the registry, but passed through the guest-control layer its nested double quotes were
mangled: the inner runner was recorded as `powershell.exe -Command \IEX \`, with the
`FromBase64String` deobfuscation stripped off before it reached the command line. The
registry value was set, but the deobfuscate-and-execute step the cradle rule keys on never
appeared in the telemetry, so both the decoded-payload field and the raw command line lack
it. The rule's own query returns 0 hits — correctly, because the artifact is not there. Not
a rule finding. See `docs/atomic-validation-gap-analysis.md`.

(Drafted from the evidence; rewrite in the author's own words before using as portfolio.)

## Gap category

<!-- One of: telemetry gap, normalization gap, rule logic gap, scenario limitation.
     Leave as not applicable only when the result is detected and nothing was missed. -->

Scenario limitation — test-harness quoting corrupted the procedure. Re-running it faithfully
(correct escaping or a transferred script file, as was done for T1027 #11) is future work.

## Why this is recorded as missed

No alert existed for rule `8c1d2f4a-5b6e-47c8-9a03-2e7f81d4b6c5` between `2026-08-02T10:55:05.0000000Z` and
`2026-08-02T11:25:50.0000000Z`. The alert timestamp is recorded as
`not applicable` rather than as a placeholder value. Confirm the rule ran at least
once inside that window before concluding the rule logic is at fault.

