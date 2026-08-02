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
