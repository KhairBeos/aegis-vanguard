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

### Why test #1 specifically

The technique has 20 atomic tests. The definition was parsed rather than skimmed, and only
five run without elevation, which matters because `VBoxManage guestcontrol` cannot obtain an
elevated token on this VM:

| Test | Elevation | Why it was or was not chosen |
| --- | --- | --- |
| #1 Reg Key Run | not required | **Chosen.** `HKCU` only, no dependencies, cleanup defined, payload path does not exist so nothing executes |
| #8 Add persistence via Recycle bin | not required | Rejected: writes to `HKCR` and hijacks a shell-open verb, a wider blast radius for no extra detection value |
| #9 SystemBC Malware-as-a-Service Registry | not required | Rejected for a first run: writes a Run value whose payload is a real `powershell.exe` command line |
| #11 Change Startup Folder | not required | Rejected: copies a binary and repoints the user's Startup folder, so cleanup has more to undo |
| #2-#7, #10, #12-#20 | required | Not runnable unattended here |

### Exact commands that would run

Taken verbatim from the definition above, not paraphrased:

```bat
REM execute
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"

REM cleanup
REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /f
```

`C:\Path\AtomicRedTeam.exe` does not exist on the host, so the value is inert: Windows would
try to launch it at next logon and fail. Cleanup removes it well before that.

Note on method: the `Invoke-AtomicRedTeam` framework would not be installed. The two commands
above would be executed directly, with the definition's SHA-256 recorded so a reviewer can
confirm they match the official test. This should be stated plainly in any resulting evidence
bundle rather than implying the framework was used.

## Proposed run

| Field | Value |
| --- | --- |
| MITRE technique | `T1547.001` - Boot or Logon Autostart Execution: Registry Run Keys |
| Atomic test | **#1, "Reg Key Run"**, confirmed by reading the official definition rather than from memory |
| Atomic test GUID | `e55be3fd-3521-4610-9d1a-e210e42dcf05` |
| Source definition | `atomics/T1547.001/T1547.001.yaml`, SHA-256 `9F8ADD4DC6C94E68A4053F970439219E9D91D4A4EFFFDE2B77B576E57007240D` |
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
| Exact Atomic test number confirmed from the official definition | **done** - test #1, GUID `e55be3fd-3521-4610-9d1a-e210e42dcf05` |
| User approval for this exact run | **given** `2026-08-02` |
| Executed | **yes**, `2026-08-02T09:42:11Z` to `09:42:17Z` |

## Outcome

| Item | Result |
| --- | --- |
| Scenario | `AEGIS-SCN-0005` |
| Detection result | `detected`, 1 alert, 1 source document |
| Time to detect | 151.6 seconds |
| Evidence | `evidence/AEGIS-SCN-0005.md` |

Telemetry captured the full lifecycle: Event ID 13 `SetValue` at `09:42:13.487Z` with
`Details` of `C:\Path\AtomicRedTeam.exe`, and Event ID 12 `DeleteValue` at `09:42:16.567Z`.

Cleanup was confirmed two independent ways, not trusted from an exit code:

1. A direct registry read afterwards returned only `MicrosoftEdgeAutoLaunch` and `OneDrive`.
2. The Event ID 12 delete event is present in `logs-windows.sysmon-aegis_lab`.

An earlier attempt at this run was prepared and **stopped at the user's instruction**. The
registry was checked at that point and carried no trace, so the run recorded above is the
only execution that took place.

The `Invoke-AtomicRedTeam` framework was not installed. The two commands above were executed
directly, and the SHA-256 of the official definition is recorded so a reviewer can confirm
they match. Any claim made from this bundle should say so rather than imply framework use.
