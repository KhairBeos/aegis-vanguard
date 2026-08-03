# Detection tuning log

One entry per tuning decision, each with the measurement that motivated it and the
measurement that followed. A tuning change with no before-and-after is an opinion.

---

## TUNE-001 - PowerShell encoded command, `T1059.001`

**Rule:** `1131fb39-a497-4a09-b051-4e4c89066f5f` - PowerShell Encoded Command Execution
**Date:** `2026-08-02`

### What was observed

The rule fired 4 times in its first hour of life. Two of those alerts were this project's
own tooling: `VBoxManage guestcontrol` drives the VM by invoking
`powershell.exe -EncodedCommand`, so every diagnostic script run during setup produced an
alert. The rule's own `falsepositives` field had predicted exactly this, and was right
within minutes.

Alerts grouped by parent process:

| Parent | Alerts |
| --- | --- |
| `C:\Windows\System32\VBoxService.exe` | 1 |
| `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | 3 |

### The obvious fix was measured and rejected

Excluding `VBoxService.exe` as a parent is the reflex answer. It does not work here:

- It removes only **1 of the 2** false positives.
- The surviving false positive shares its parent process, its image, and its command-line
  shape with the true positives. On every field visible in the command line they are
  identical.

They differ only in the base64 payload, which Lucene cannot inspect. Any exclusion narrow
enough to remove the false positive would also remove the true positives, and any
exclusion loose enough to keep the true positives leaves the false positive. Parent-based
allowlisting would also have handed an attacker a trivial evasion: spawn from the
allowlisted parent.

### What was done instead

The payload was made visible rather than guessed at.

1. `infra/elastic/ingest-pipelines/aegis-powershell-decode.json` decodes the
   `-EncodedCommand` base64 into `aegis.powershell.decoded_command` at ingest time. It is
   attached as `index.final_pipeline` so it runs after any integration pipeline rather
   than replacing one.
2. A new alerting rule, `8c1d2f4a-5b6e-47c8-9a03-2e7f81d4b6c5` - PowerShell Encoded
   Download Cradle - matches the decoded text for download and in-memory execution
   primitives.
3. The original rule was **kept** and downgraded from `high` to `medium`. Encoding is
   still worth seeing; it is context for hunting, not an incident.

### After

Both rules were run against the same live activity: one benign marker
(`Write-Output '<marker>'`) and two cradle payloads, all encoded identically.

| Source event, decoded | Encoded rule (`medium`) | Cradle rule (`high`) |
| --- | --- | --- |
| `Write-Output 'AEGIS-...'` | alerted - **false positive** | no alert |
| `... IEX (New-Object Net.WebClient).DownloadString(...)` | alerted | alerted |
| `$simulated = 'IEX (New-Object Net.WebClient).DownloadString(...)'` | alerted | alerted |
| **Totals** | 3 alerts, 1 false positive | 2 alerts, 0 false positives |

Recall was preserved: every cradle event is still detected. The benign event no longer
reaches the alerting rule.

### What this does not establish

The sample is three events on one host in one lab. That is enough to show the tuning
changed the outcome in the intended direction, and nowhere near enough to state a false
positive rate. Per `PROJECT_PLAN.md`, the false-positive-rate metric stays
`Not measured yet` until a documented benign-activity window of meaningful size exists.

### Residual risk

- An attacker who encodes a payload using none of the matched primitives evades the
  cradle rule entirely. It detects a common shape, not the technique.
- The decoder takes the last valid base64 token of at least 16 characters. A command line
  with a decoy trailing token could hide the real payload.
- Non-UTF-16LE or nested encodings are not handled.
- The encoded rule at `medium` still needs someone to actually look at it, or downgrading
  it merely hides the noise instead of resolving it.

---

## TUNE-002 - Character-array obfuscation, `T1027`

**Rule:** `d4e91a72-3c85-4f6b-9e2a-7b1c0d5f8a34` - PowerShell Character-Array Obfuscated Execution (new)
**Date:** `2026-08-03`

### What was observed

Atomic Red Team T1027 #11 was run against the pack and detected nothing. It builds both
the interpreter name and its argument from decimal `[char[]]` arrays and rejoins them:

```
$ps=[char[]](112,111,119,101,114,115,104,101,108,108); $cmd=[char[]](83,116,...); & (-join $ps) '-Command' (-join $cmd)
```

There is no `-EncodedCommand`, no download vocabulary, and no scriptlet, so the encoded
rule, the cradle rule, and both LOLBin rules miss it by construction. The miss was proven
deterministically: each of the five deployed rules' own generated queries returned **0
hits** against the procedure's own persisted Sysmon Event ID 1.

### What was done

A new rule matches the obfuscation idiom itself rather than any specific payload: a
`[char[]](` cast **and** a `-join`, both required together. `-join` alone is common and
`[char[]]` casts appear in benign string work, but assembling a command name from a decimal
code array and rejoining it for execution is not something legitimate automation does. A new
rule was chosen over widening an existing one so each rule keeps a single clear meaning.

### After

Measured on the lab's real telemetry, then confirmed live:

| Measure | Value |
| --- | --- |
| Deployed-rule hits on the procedure, before | 0 (all five rules) |
| New-rule hits on the same document, after | 1 |
| New-rule matches across **all** Sysmon history | 1 — the atomic only, 0 false positives |
| Live detection | `AEGIS-SCN-0010`, faithful re-run, **detected**, 1 alert |
| Time to detect | 171.2 s (source `02:12:31.003Z`, alert `02:15:17.205Z`) |

Missed became detected on the identical document, and the same rule fired end to end on a
fresh faithful re-run through the real detection engine on its normal 5-minute schedule.

### A test-harness lesson, recorded because it nearly corrupted the evidence

The first re-run attempt put the `[char[]]` line directly in a script file and ran it with
`-File`. That executes the array **in process**: the only child it spawns is the already
decoded `powershell -Command "Start-Process calc.exe"`, and `[char[]](` never appears on any
command line. The detection depends on the obfuscation being visible on a process command
line, which only happens when powershell is invoked with `-Command "...[char[]]..."`. The
faithful re-run therefore spawns a child carrying the array as its `-Command` argument,
matching how the original atomic — and Sysmon — record it. Reproducing an obfuscation
technique is not the same as reproducing the artifact the rule keys on.

### What this does not establish

The rule detects one obfuscation idiom, not obfuscation in general. `[string]::Join`,
format-operator rebuilds, and other reassembly methods evade it. The zero-false-positive
figure is over one lab's history, not a rate. Per `PROJECT_PLAN.md` the false-positive-rate
metric stays `Not measured yet`.

---

## TUNE-003 - Cradle rule, plaintext arm, `T1027` / `T1140`

**Rule:** `8c1d2f4a-5b6e-47c8-9a03-2e7f81d4b6c5` - PowerShell Encoded Download Cradle
**Date:** `2026-08-03`

### What was observed

Atomic T1027 #3 deobfuscates a base64 blob read from the registry and runs it inline with
`IEX ([Convert]::FromBase64String(...))`. It uses no `-EncodedCommand`, so the ingest decoder
never runs and `decoded_command` is empty. The cradle rule matched only `decoded_command`, so
it missed the procedure entirely even though the very primitives it looks for — `frombase64string`,
`iex (` — were sitting in plaintext on the command line.

### What was done

The same vocabulary is now matched on the raw command line as a second arm:
`condition: selection_event and (selection_decoded or selection_cmdline)`. When base64 is
hidden in `-EncodedCommand`, the decoded arm still catches it; when it is deobfuscated inline,
the plaintext arm does. The list is duplicated deliberately rather than abstracted — a Sigma
rule is clearer with both field checks spelled out.

### After

| Measure | Value |
| --- | --- |
| Raw-command-line vocab across all Sysmon history, before the re-run | 0 events — the plaintext arm adds 0 false positives |
| Faithful re-run detection | `AEGIS-SCN-0012`, **detected**, 1 alert, `decoded_command` empty |
| Time to detect | 214.1 s (source `02:42:12.323Z`, alert `02:45:44.148Z`) |
| Decoded-arm regression | preserved — the 4 decoded fixture positives still match |

The first attempt at this procedure was mangled by guest-control quote handling
(`AEGIS-SCN-0007`), stripping `FromBase64String` off the command line; the faithful re-run
spawns the deobfuscation as a child with `-Command` so the plaintext primitives are recorded.

### Residual risk

Matching `iex(` / `invoke-expression` / `downloadstring` on the raw command line is noisier in
a real estate than in this lab, where it measured zero. Bare `IEX` is common in admin scripts;
here it only alerts alongside the other cradle verbs, but a production rollout should re-measure
before trusting the plaintext arm at `high`.

---

## TUNE-004 - Regsvr32 non-registrable file, `T1218.010`

**Rule:** `f7a3c9e1-2b8d-4e6f-a1c5-9d0e3f7b2a48` - Regsvr32 Loading a Non-Registrable File (new)
**Date:** `2026-08-03`

### What was observed

Atomic T1218.010 #4 runs `regsvr32 /s shell32.jpg` — a renamed **local** DLL. The existing
Regsvr32 rule (`6b5da61b`) targets the remote-scriptlet form (`scrobj.dll` or a URL) and
returned 0 hits (`AEGIS-SCN-0006`). The abuse is real but structurally different.

### What was done

A new rule matches regsvr32 whose command line does **not** carry a registrable extension
(`.dll`, `.ocx`, `.cpl`, `.ax`), excluding bare flag-only launches. A separate rule was chosen
over widening the remote-scriptlet rule so each keeps one meaning; a `scrobj.dll` Squiblydoo
command line carries `.dll` and is therefore filtered here and left to `6b5da61b`.

### After

| Measure | Value |
| --- | --- |
| regsvr32 events across all Sysmon history | 2 — both this atomic (register + `/u` cleanup), 0 legitimate |
| New-rule false positives | 0 |
| Faithful re-run detection | `AEGIS-SCN-0011`, **detected**, 2 alerts (register and unregister), 2 source docs |
| Time to detect | 249.1 s (first source `02:42:01.688Z`, alert `02:46:05.124Z`) |

### Residual risk

The negative-extension approach flags any non-`.dll`/`.ocx` target, including a bare
`regsvr32 /?`-style call if it ever carried a stray token; the bare-launch filter covers the
no-target case but not every benign flag combination. A real environment with legitimate
regsvr32 usage should measure the alert volume before enabling at `high`.

---

## Specificity smoke test - the pack against a benign workload

**Date:** `2026-08-03`

A benign administrator workload (18 read-only diagnostics: `hostname`, `whoami /all`,
`ipconfig /all`, `Get-Process`, `tasklist`, `systeminfo`, `netstat`, `nslookup`, and similar)
was run in `victim-win-01`, producing **50 Sysmon Event ID 1** process-creation events in the
window `03:44:25Z`-`03:44:59Z`. Every deployed rule's own generated query was then run
against that window.

| Rule | Matches |
| --- | --- |
| all seven | **0** |
| **Total false positives** | **0 over 50 benign events** |

This is a specificity check, not a false-positive **rate**. Fifty events on one host in half a
minute is nowhere near the scale a rate would need, so per `PROJECT_PLAN.md` the
false-positive-rate metric stays `Not measured yet`. What it does show, deterministically, is
that ordinary admin activity trips none of the seven rules - the pack is not obviously noisy.
The one rule that has ever produced an operational false positive, the `medium` encoded-command
rule, only does so against `-EncodedCommand` automation (TUNE-001), none of which appears in a
normal diagnostic session.
