# Scenario evidence bundle: AEGIS-SCN-0005

> REDACTION REVIEW REQUIRED before committing. Command lines, script blocks, user
> names, and host names can carry credentials or personal data. Check the fields
> listed under Source events and the raw export at `AEGIS-SCN-0005-raw.json`.

## MVP checkpoint fields

| Field | Value |
| --- | --- |
| Scenario ID | `AEGIS-SCN-0005` |
| Lab session ID | `AEGIS-LAB-20260802` |
| MITRE technique ID | `T1547.001` |
| Atomic test number | T1547.001 test #1 'Reg Key Run', GUID e55be3fd-3521-4610-9d1a-e210e42dcf05 |
| Rule identity | `0630c267-9ba0-40b2-95d9-670996d404c8` version `1` |
| Rule name | SIGMA - Registry Run Key Persistence |
| Attack execution start (UTC) | `2026-08-02T09:42:11.7450929Z` |
| Attack execution end (UTC) | `2026-08-02T09:42:17.0261114Z` |
| Alert timestamp (UTC) | `2026-08-02T09:44:43.369Z` |
| Time to detect (seconds) | 151.6 |
| Rule execution result | succeeded at 2026-08-02T09:44:43.253Z: Rule execution completed successfully |
| Query time window | `now-5m` to `now`, every `5m` |
| Alert deduplication | Detection engine derives a deterministic alert id from the source document and rule identity |
| Alert count | 1 |
| Source document count | 1 |
| Evidence artifact path | `evidence/AEGIS-SCN-0005-raw.json` |
| Evidence hash (SHA-256) | `7A0AD588E34C19567C4ADE7BD1858FBBB04E27AF6471B628D62412E7BFA9B705` |
| Detection result | **detected** |

## Alerts

| Alert UUID | Alert @timestamp | Original event time |
| --- | --- | --- |
| `750bee7eb80b3d3c6d6f17a2468d873814e2824e2f2704702ee909b06988651b` | `2026-08-02T09:44:43.369Z` | `2026-08-02T09:42:13.487Z` |

## Source events

- `.ds-logs-windows.sysmon-aegis_lab-2026.08.02-000002` / `AZ_B2n0KPV5zHPxHLnnJ`

## Analyst triage note

Atomic Red Team T1547.001 test #1, "Reg Key Run", executed against `victim-win-01` with
approval for this exact run. The two commands were taken verbatim from the official
definition, whose SHA-256 is recorded in `docs/scenario-alignment-t1547-001.md`. The
`Invoke-AtomicRedTeam` framework was **not** installed; the commands were run directly, and
that distinction is stated here rather than left for a reader to assume.

Sysmon captured the full lifecycle:

| Time (UTC) | Event | Detail |
| --- | --- | --- |
| `09:42:13.487Z` | EID 13 `SetValue` | `...\CurrentVersion\Run\Atomic Red Team` = `C:\Path\AtomicRedTeam.exe` |
| `09:42:16.567Z` | EID 12 `DeleteValue` | same target, 3.1 seconds later |

Pivots performed:

1. **Did the persistence survive?** No. The Event ID 12 delete is present, and a direct
   registry read afterwards returned only `MicrosoftEdgeAutoLaunch` and `OneDrive`. Cleanup
   was confirmed two independent ways rather than trusted from an exit code.
2. **Would the payload have run?** No. `Details` is `C:\Path\AtomicRedTeam.exe`, a path that
   does not exist on the host. Even had the value survived to next logon, Windows would have
   failed to launch it. This is by design in the atomic and is worth stating, because an
   analyst who reports "persistence established" without reading `Details` overstates the
   finding.

Verdict: **true positive.** The rule detected a real, externally-defined persistence
technique, not a bespoke marker written to match it. This is the first scenario in the lab
where the activity was specified by someone other than the rule author, which is the whole
point of using Atomic Red Team.

Note the same limitation seen in `AEGIS-SCN-0003`: the alert reports the moment of creation
and says nothing about the deletion three seconds later. An analyst working from the alert
alone would report live persistence on a host that has none.

## Gap category

`rule logic gap`, unchanged from `AEGIS-SCN-0003` and now confirmed against an
externally-defined test rather than a self-written marker.

The rule alerts on Event ID 13 and cannot express lifetime. Two improvements are indicated:

1. Correlate the Event ID 13 alert with any Event ID 12 `DeleteValue` for the same
   `TargetObject`, so the analyst is told whether the persistence still exists.
2. Enrich the alert with the `Details` value and flag when the referenced path does not
   resolve, which separates a working autorun from an inert one.

Neither is a scenario limitation: the telemetry to do both is already being collected and
is already in this bundle's source data.

