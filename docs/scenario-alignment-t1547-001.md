# Scenario alignment record: T1547.001

This is the Phase 3 gate artifact required by `PROJECT_PLAN.md` before any Atomic Red Team
run. It is a proposal. **No approval has been given and nothing here has been executed.**

Prepared `2026-08-02`.

## Why this technique was chosen first

Three deployed rules already have evidence-backed detections, so any of them could be the
first Atomic-backed scenario. `T1547.001` is proposed because it is the only candidate that
satisfies every constraint at once:

| Constraint | T1547.001 Run key | T1059.001 encoded command | T1218.010 regsvr32 |
| --- | --- | --- | --- |
| Runs with no network egress | yes | yes | **no** - needs a remote scriptlet |
| Official Atomic has a cleanup command | yes | varies by test | yes |
| Change is reversible and user-scoped | yes | n/a | yes |
| Already detected by a deployed rule with evidence | yes, `AEGIS-SCN-0003` | yes, `AEGIS-SCN-0001` | never detected |
| Does not touch credentials or security controls | yes | yes | yes |

`T1059.001` is a reasonable second scenario. Several of its atomics fetch remote content,
so each test number must be read before selection rather than assumed safe.

## Proposed run

| Field | Value |
| --- | --- |
| MITRE technique | `T1547.001` - Boot or Logon Autostart Execution: Registry Run Keys |
| Atomic test | **To be confirmed against the installed atomics before approval.** The intended test is the plain "Reg Key Run" case that writes a value under `HKCU\...\CurrentVersion\Run` and removes it in cleanup. The exact test number must be read from the transferred `atomics/T1547.001/T1547.001.yaml`, not assumed from memory. |
| Target host | `victim-win-01`, VirtualBox host-only `192.168.56.10` |
| Detecting rule | `0630c267-9ba0-40b2-95d9-670996d404c8` - Registry Run Key Persistence |
| Rule version at run time | To be recorded by `scripts/collect-evidence.ps1` |
| Scenario ID | `AEGIS-SCN-0005` |

## Expected telemetry

| Item | Expectation |
| --- | --- |
| Source | Sysmon, `Microsoft-Windows-Sysmon/Operational`, into `logs-windows.sysmon-aegis_lab` |
| Primary event | Event ID 13, `SetValue`, `TargetObject` ending in `\CurrentVersion\Run\<value name>` |
| Secondary event | Event ID 12, `DeleteValue`, produced by the Atomic cleanup command |
| Fields relied on | `winlog.event_data.TargetObject`, lowercased at index time by `logs@custom` |
| Not relied on | `registry.path`; the integration ingest pipelines are not installed |

The Event ID 12 expectation comes from `AEGIS-SCN-0003`, where Sysmon captured both the set
and the delete. The alert will report only the set, which is a known and documented rule
logic gap rather than a surprise.

## Detection expectation

| Item | Value |
| --- | --- |
| Query window | `from: now-5m` to `now`, plus 1 minute additional lookback |
| Schedule | every 5 minutes |
| Expected latency | 0 to 5 minutes; observed range so far is 124 to 279 seconds |
| Expected result | `detected`, one alert, one source document |
| Deduplication | Not verified. If the run produces more than one alert for one source document, that is the finding, not a defect in the scenario |

## Cleanup

1. The Atomic test's own cleanup command removes the Run value. It must be run and its
   output captured, not assumed to have worked.
2. Independently confirm removal by reading the key, because the cleanup command's exit
   code is not proof of state.
3. Confirm the Event ID 12 delete event reached `logs-windows.sysmon-aegis_lab`.
4. `scripts/windows/rollback-advanced-telemetry.ps1` remains available but is not expected
   to be needed; this scenario changes no service, policy, or security control.

## Safety boundaries for this run

- No security control is disabled. Defender and the firewall stay as they are.
- No credential material is touched.
- The value written is user-scoped (`HKCU`) and removed by cleanup.
- Network isolation is preserved. The atomics are downloaded on the host and transferred
  through the same controlled path already used for `Sysmon64.exe`; the VM does not get
  egress for this.
- The run is a single test, executed once.

## Approval

`PROJECT_PLAN.md` requires explicit approval for the exact run. No documentation approval
authorises execution, including approval of this record.

| Item | Status |
| --- | --- |
| Exact Atomic test number confirmed from the transferred atomics | **not done** |
| User approval for this exact run | **not given** |
| Executed | **no** |

Until all three read otherwise, this file is a plan and nothing more.
