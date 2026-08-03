# Atomic Red Team validation — gap analysis

The rule pack was validated against real Atomic Red Team procedures rather than the
benign marker scenarios it was written alongside. The point of the exercise was to find
out where the rules are narrow, and it did. Four of five procedures that produced
telemetry went undetected. This document records each result honestly, separates genuine
detection gaps from a test-harness artifact and from a correct scope boundary, and closes
every gap that was both real and reproducible — three rules added or extended, each
re-verified live. The one remaining non-detection (T1059.005 #1) is a correct scope
boundary, not a defect.

## The run

Five Windows procedures were run verbatim from their official definitions inside
`victim-win-01` on `2026-08-02`, window `10:55:05Z`–`10:55:50Z`. Every one is a benign,
self-cleaning, non-elevated, no-egress subset; the driver is preserved out of tree.

| Atomic | GUID | Ran faithfully? | Rule expected to catch it | Result |
| --- | --- | --- | --- | --- |
| T1218.010 #4 | `2408973b` | yes | Regsvr32 Remote Scriptlet (`6b5da61b`) | missed → **closed** by new rule `f7a3c9e1` (`AEGIS-SCN-0011`) |
| T1027 #3 | `450e7218` | first run mangled; re-run faithful | Encoded Download Cradle (`8c1d2f4a`) | missed → **closed** by cradle plaintext arm (`AEGIS-SCN-0012`) |
| T1027 #11 | `6683baf0` | yes | none existed | missed → **closed** by new rule `d4e91a72` (`AEGIS-SCN-0010`) |
| T1059.001 #10 | `fa050f5e` | no — failed to execute (quoting) | Encoded Command (`1131fb39`) | not evaluated |
| T1059.005 #1 | `bc4fafd0` | yes | Script Host Spawns Shell (`a41ef4b6`) | **missed** — correct scope boundary, not a defect |

## The miss was proven deterministically, not inferred from a quiet alert feed

Zero alerts can mean "the rule ran and matched nothing" or "the rule never queried the
window". The stack was also down overnight, so the executor's own history carried a
14-hour gap warning that muddies the second reading. To remove all doubt, each deployed
rule's own generated Lucene query was run directly against the persisted Sysmon telemetry
for the window:

| Atomic | Rule query hits against its own telemetry |
| --- | --- |
| T1218.010 #4 | 0 |
| T1027 #3 | 0 |
| T1027 #11 | 0 |
| T1059.005 #1 | 0 |

The telemetry is present — every procedure's Event ID 1 is in the index — and every rule
returns zero. The misses are rule logic, not scheduler timing.

## What each miss actually means

### T1027 #11 — a real gap, and the one worth closing

The procedure builds both the interpreter name and its argument from decimal `[char[]]`
arrays and invokes them with `& (-join $ps) '-Command' (-join $cmd)`. It carries no
`-EncodedCommand`, no download vocabulary, and no scriptlet, so every rule in the pack
misses it by construction. Its command line was captured intact:

```
powershell.exe -NoProfile -Command "$ps=[char[]](112,111,119,101,114,115,104,101,108,108); $cmd=[char[]](83,116,97,114,116,45,80,114,111,99,101,115,115,32,99,97,108,99,46,101,120,101); & (-join $ps) '-Command' (-join $cmd)"
```

This is a clean, generic obfuscation signal on faithful telemetry, so it became the target
of the tuning loop below (`TUNE-002`).

### T1218.010 #4 — a variant gap, now closed

`regsvr32.exe /s shell32.jpg` loads a **local, renamed** DLL. The original rule matched only
the remote scriptlet form (Squiblydoo): `scrobj.dll` or a URL. This is a different
sub-technique — a renamed-extension local library, not a remote script. Rather than blur the
remote-scriptlet rule, a **new** rule (`f7a3c9e1-2b8d-4e6f-a1c5-9d0e3f7b2a48` — Regsvr32
Loading a Non-Registrable File) matches regsvr32 whose command line carries no registrable
extension (`.dll`/`.ocx`/`.cpl`/`.ax`), excluding bare launches. Only two regsvr32 events
exist in all lab history — both this atomic — so it measured 0 false positives, and a
`scrobj.dll` Squiblydoo command line is filtered out and left to the remote rule. Re-verified
live: `AEGIS-SCN-0011`, detected, 2 alerts (register + unregister), MTTD 249.1s. See `TUNE-004`.

### T1027 #3 — confounded by the test harness, then re-run faithfully and closed

The intended command runs an inline `IEX ([Convert]::FromBase64String(...))` read from the
registry. On the first attempt, passed through the guest-control layer, its nested double
quotes were mangled: the inner runner was recorded as `powershell.exe -Command \IEX \`, with
the `FromBase64String` deobfuscation stripped off before it reached the command line. Tuning
to that broken artifact would have been dishonest, so it was not used.

The faithful re-run spawns the deobfuscation as a child with `-Command`, so the plaintext
`IEX (...FromBase64String...)` lands on the command line as the real procedure does. This
exposed a genuine gap: the cradle rule matched only the decoded `-EncodedCommand` field, which
is empty when base64 is deobfuscated inline. The rule was extended to match the same
vocabulary on the raw command line too (0 false positives across all lab history). Re-verified
live: `AEGIS-SCN-0012`, detected, MTTD 214.1s, with `decoded_command` empty. See `TUNE-003`.

### T1059.005 #1 — a correct scope boundary, not a defect

`cscript sys_info.vbs` gathers system information and spawns no child shell. The Script
Host rule detects `wscript`/`cscript`/`mshta` **spawning `powershell`/`cmd`** — a
parent-child relationship, not the mere use of a script host. This procedure never
exhibits that behaviour, so the rule correctly did not fire. Recording this as a "gap"
would be dishonest; it is the rule behaving exactly as designed. The bundle records it as
a true negative for the rule's specific behaviour.

## The loop: T1027 #11 missed → detected — see TUNE-002

A new rule, `d4e91a72-3c85-4f6b-9e2a-7b1c0d5f8a34` — PowerShell Character-Array Obfuscated
Execution — matches a `[char[]](` cast paired with `-join`, the idiom that turns a decimal
code array back into runnable text. Both markers are required together so the rule stays
tight. Full before/after measurement is in `docs/detection-tuning-log.md` (`TUNE-002`);
the closed evidence bundle is `evidence/AEGIS-SCN-0010.md`.
