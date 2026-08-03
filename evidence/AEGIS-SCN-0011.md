# Scenario evidence bundle: AEGIS-SCN-0011

> REDACTION REVIEW REQUIRED before committing. Command lines, script blocks, user
> names, and host names can carry credentials or personal data. Check the fields
> listed under Source events and the raw export at `AEGIS-SCN-0011-raw.json`.

## MVP checkpoint fields

| Field | Value |
| --- | --- |
| Scenario ID | `AEGIS-SCN-0011` |
| Lab session ID | `AEGIS-LAB-20260803` |
| MITRE technique ID | `T1218.010` |
| Atomic test number | #4 (2408973b) - regsvr32 registering a renamed local DLL (shell32.jpg), faithful re-run from a transferred .ps1 |
| Rule identity | `f7a3c9e1-2b8d-4e6f-a1c5-9d0e3f7b2a48` version `1` |
| Rule name | SIGMA - Regsvr32 Loading a Non-Registrable File |
| Attack execution start (UTC) | `2026-08-03T02:41:56.0000000Z` |
| Attack execution end (UTC) | `2026-08-03T02:42:09.0000000Z` |
| Alert timestamp (UTC) | `2026-08-03T02:46:05.124Z` |
| Time to detect (seconds) | 249.1 |
| Rule execution result | succeeded at 2026-08-03T02:46:05.058Z: Rule execution completed successfully |
| Query time window | `now-5m` to `now`, every `5m` |
| Alert deduplication | Detection engine derives a deterministic alert id from the source document and rule identity |
| Alert count | 2 |
| Source document count | 2 |
| Evidence artifact path | `evidence/AEGIS-SCN-0011-raw.json` |
| Evidence hash (SHA-256) | `75B0213B524962EABCCED0F06C32D4079692056F4D49E504395EA5F62DDFFD98` |
| Detection result | **detected** |

## Alerts

| Alert UUID | Alert @timestamp | Original event time |
| --- | --- | --- |
| `522a07150956411030b8856058555174b263e95b215220002b67d47082906824` | `2026-08-03T02:46:05.124Z` | `2026-08-03T02:42:01.688Z` |
| `53cddd8c27b315ab29027b96b652da3c98197c8b550874e5f76104dd2a9c0d7c` | `2026-08-03T02:46:05.125Z` | `2026-08-03T02:42:02.911Z` |

## Source events

- `.ds-logs-windows.sysmon-aegis_lab-2026.08.02-000002` / `AZ_FgGZyveKuiCkIB0oY`
- `.ds-logs-windows.sysmon-aegis_lab-2026.08.02-000002` / `AZ_FgGZyveKuiCkIB0of`

## Analyst triage note

<!-- Written by a human. Describe what happened, what the alert showed, which
     events you pivoted to, and whether this is a true or false positive. -->

Two alerts, both true positives, from the register and unregister calls of the same
procedure. `regsvr32.exe /s ...\shell32.jpg` (`02:42:01`) and its `/u /s` cleanup
(`02:42:02`) each loaded a file with a `.jpg` extension — a real signed `shell32.dll`
copied to a renamed path — which regsvr32 cannot legitimately register. The rule fired on
the extension, not on any payload, so it catches the masquerade regardless of what the
renamed library contains. The remote-scriptlet rule (`6b5da61b`) stayed silent, correctly:
there is no `scrobj.dll` and no URL here. This is the same procedure (`AEGIS-SCN-0006`) that
the pack missed on 2026-08-02; the new rule closes it.

(Drafted from the evidence; rewrite in the author's own words before using as portfolio.)

## Gap category

<!-- One of: telemetry gap, normalization gap, rule logic gap, scenario limitation.
     Leave as not applicable only when the result is detected and nothing was missed. -->

Not applicable — detected. This closes the renamed-local-DLL variant gap recorded in
`AEGIS-SCN-0006`; the new rule `f7a3c9e1` covers the form the remote-scriptlet rule does not.

