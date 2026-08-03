# Scenario evidence bundle: AEGIS-SCN-0012

> REDACTION REVIEW REQUIRED before committing. Command lines, script blocks, user
> names, and host names can carry credentials or personal data. Check the fields
> listed under Source events and the raw export at `AEGIS-SCN-0012-raw.json`.

## MVP checkpoint fields

| Field | Value |
| --- | --- |
| Scenario ID | `AEGIS-SCN-0012` |
| Lab session ID | `AEGIS-LAB-20260803` |
| MITRE technique ID | `T1027` |
| Atomic test number | #3 (450e7218) - inline IEX + FromBase64String from registry, faithful re-run (raw command line arm) |
| Rule identity | `8c1d2f4a-5b6e-47c8-9a03-2e7f81d4b6c5` version `1` |
| Rule name | SIGMA - PowerShell Encoded Download Cradle |
| Attack execution start (UTC) | `2026-08-03T02:42:10.0000000Z` |
| Attack execution end (UTC) | `2026-08-03T02:42:20.0000000Z` |
| Alert timestamp (UTC) | `2026-08-03T02:45:44.148Z` |
| Time to detect (seconds) | 214.1 |
| Rule execution result | succeeded at 2026-08-03T02:45:44.060Z: Rule execution completed successfully |
| Query time window | `now-5m` to `now`, every `5m` |
| Alert deduplication | Detection engine derives a deterministic alert id from the source document and rule identity |
| Alert count | 1 |
| Source document count | 1 |
| Evidence artifact path | `evidence/AEGIS-SCN-0012-raw.json` |
| Evidence hash (SHA-256) | `CB0108B255B9D08DBF91B075FD0E16161E5809F61C9C445AC861277B3ABF9811` |
| Detection result | **detected** |

## Alerts

| Alert UUID | Alert @timestamp | Original event time |
| --- | --- | --- |
| `3e70ba00035860a2fc5fdd6201757ce1956111f270bfbef0c5c327982ae16b06` | `2026-08-03T02:45:44.148Z` | `2026-08-03T02:42:12.323Z` |

## Source events

- `.ds-logs-windows.sysmon-aegis_lab-2026.08.02-000002` / `AZ_FgGZyveKuiCkwBzBX`

## Analyst triage note

<!-- Written by a human. Describe what happened, what the alert showed, which
     events you pivoted to, and whether this is a true or false positive. -->

One alert, a true positive. The command line staged a base64 blob in
`HKCU:\...\CurrentVersion\Debug`, then a child powershell deobfuscated and ran it inline
with `IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp ...).Debug)))`
at `02:42:12`. Because there is no `-EncodedCommand`, the ingest decoder never ran and
`decoded_command` is empty — the alert fired on the plaintext `frombase64string`/`iex (`
primitives on the raw command line, which is the new arm added to the cradle rule. The
payload itself only writes a marker string, so no download or further child process
followed. This is the faithful re-run of `AEGIS-SCN-0007`, whose first attempt was mangled
by guest-control quoting; the deobfuscate-and-run behaviour is now visible and detected.

(Drafted from the evidence; rewrite in the author's own words before using as portfolio.)

## Gap category

<!-- One of: telemetry gap, normalization gap, rule logic gap, scenario limitation.
     Leave as not applicable only when the result is detected and nothing was missed. -->

Not applicable — detected. Closes the inline-deobfuscation gap: the cradle rule now matches
the same primitives on the raw command line, not only in the decoded `-EncodedCommand`
payload. See `TUNE-003` and `AEGIS-SCN-0007`.

