# ECS normalization

Status as of `2026-08-02`: **partially achieved, and the remainder is blocked upstream.**

## What was found

The lab's custom dataset names were compared against the real integration data streams. Four
of six already matched, which was not planned - it happened because the earlier phases chose
names close to the official ones.

| Lab dataset | Integration dataset | Match |
| --- | --- | --- |
| `system.application` | `system.application` | yes |
| `system.system` | `system.system` | yes |
| `system.security` | `system.security` | yes |
| `windows.powershell` | `windows.powershell` | yes |
| `windows.sysmon` | `windows.sysmon_operational` | no |
| `windows.defender` | `windows.windows_defender` | no |

## What was installed

The **System integration `2.22.1`** installed cleanly, 137 assets. Its ingest pipeline is now
attached to the three `logs-system.*-aegis_lab` data streams, which were rolled over so new
documents pass through it.

Confirmed on a real document afterwards: `event.kind` and `event.outcome` are present. Raw
`winlog` input does not produce `event.outcome`, so those fields come from the integration
pipeline. No ingest failure tags or `error.message` values appeared.

## What is blocked, and why it is not a configuration mistake

The **Windows integration `3.9.0` cannot be installed** on Elasticsearch `9.4.2`:

```
mapper_parsing_exception
  illegal_argument_exception: analyzer [powershell_script_analyzer] has not been configured in mappings
```

The obvious suspect was this project's own `logs@custom` component template, which defines an
`analysis.normalizer` block that could plausibly clobber the package's `analysis.analyzer`
block during composition. That hypothesis was **tested, not assumed**: `logs@custom` was
temporarily blanked and the install retried. It failed identically. The incompatibility is in
the package against this stack version, not in the lab's configuration.

## The renames were deliberately NOT done

Renaming `windows.sysmon` to `windows.sysmon_operational` would only pay off if the Windows
integration could then attach its pipeline. It cannot. Doing the rename anyway would mean
editing the Agent policy, an elevated re-apply inside the VM, and updating every rule's index
patterns - all to end up with the same raw `winlog.*` documents under a different name, plus a
window where the deployed rules point at data streams that no longer exist.

`windows.sysmon` and `windows.defender` therefore stay as they are, and this is recorded as a
blocked dependency rather than an outstanding task.

## Interaction with this project's own templates

Installing an integration replaces the governing index template for its data streams, which
raised the risk that the lab's customisations would silently disappear. Checked directly
rather than assumed:

| Concern | Result |
| --- | --- |
| Does `logs@custom` still apply? | **Yes.** Elastic's integration templates compose `logs@custom` alongside their own `@package` and `@custom` templates |
| Is the lowercase normalizer still on the new backing index? | **Yes**, `winlog.event_data.CommandLine` is `keyword` with `normalizer: aegis_lowercase` |
| Is `aegis-powershell-decode` still running? | **On `windows.sysmon` and `windows.powershell`, yes.** On `system.*` it was replaced by `.fleet_final_pipeline-1` |

The last row matters and is fine: the decode pipeline only ever targeted PowerShell process
creation events, which arrive on the Sysmon stream. It was never needed on `system.*`.

Regression after all of this: 32 of 32 rule fixtures pass, all 5 rules deployed and executing
without error.

## Honest status

- ECS normalization for `system.*`: **`Runtime verified`**, pipeline attached and enrichment
  confirmed on a real document.
- ECS normalization for Sysmon, PowerShell Operational, and Defender: **`Future`**, blocked by
  the Windows integration package incompatibility.
- Detections are unaffected either way, because `sigma/pipelines/aegis-lab.yml` matches both
  the ECS field names and the raw `winlog.event_data.*` names. That decision, made earlier when
  it looked like over-caution, is what makes this partial state survivable.
