# Phase 3 advanced Windows telemetry

## Architecture

```text
victim-win-01
  ├─ Sysmon 15.21
  ├─ PowerShell Script Block Logging
  ├─ Security Process Creation auditing
  ├─ Microsoft Defender Operational log
  └─ Elastic Agent 9.4.2 standalone
       → http://192.168.56.1:9200
       → Elasticsearch 9.4.2
       → Kibana 9.4.2
```

All VM actions remain manual. The repository prepares configuration, setup, rollback, benign markers, and host-side verification; it does not install or run Sysmon.

## Sysmon version lock

Target version: `15.21`, published by Microsoft Sysinternals on `2026-06-17`.

Official references:

- [Sysmon v15.21 download and documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Sysmon command-line reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sysmon)
- [Get-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature)
- [Windows PowerShell Script Block Logging policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowspowershell)
- [Audit Process Creation command-line policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-auditsettings)
- [auditpol command reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol)

The setup script requires an Authenticode status of `Valid`, a Microsoft Corporation signer, and file version `15.21`. The XML uses the official documentation sample schema version `4.82`. Exact runtime schema acceptance remains pending until the user runs the real binary in the VM.

## Telemetry contract

| Source | Windows channel | Dataset | Expected data stream |
| --- | --- | --- | --- |
| Sysmon | `Microsoft-Windows-Sysmon/Operational` | `windows.sysmon` | `logs-windows.sysmon-aegis_lab` |
| PowerShell | `Microsoft-Windows-PowerShell/Operational` | `windows.powershell` | `logs-windows.powershell-aegis_lab` |
| Defender | `Microsoft-Windows-Windows Defender/Operational` | `windows.defender` | `logs-windows.defender-aegis_lab` |

The custom dataset names above are the milestone contract. Installation-package pipelines and ECS normalization for these streams are not yet verified.

Sysmon collection is limited to:

- Event ID 1: Process Create
- Event ID 3: Network Connect
- Event ID 11: File Create for `.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`, `.exe`, and `.dll`
- Event IDs 12 and 13: registry activity around `Run`, `RunOnce`, and Windows PowerShell policy paths
- Event ID 22: DNS Query

Image Load is intentionally not enabled.

## Files

| File | Purpose |
| --- | --- |
| `infra/sysmon/sysmon-aegis.xml` | Minimal reviewable Sysmon configuration |
| `infra/elastic-agent/windows/elastic-agent.yml` | Existing standalone policy extended with three advanced streams |
| `scripts/windows/setup-advanced-telemetry.ps1` | VM-side validation, backup, policy enablement, Sysmon install/config update, and Agent restart |
| `scripts/windows/rollback-advanced-telemetry.ps1` | Restore saved registry, audit, and Agent state; optionally uninstall Sysmon |
| `scripts/windows/generate-advanced-telemetry-markers.ps1` | Generate benign correlated activity |
| `scripts/verify-advanced-windows-telemetry.ps1` | Host-side data-stream and recent-event verification |

## Manual workflow

### 1. Acquire and verify Sysmon

Download Sysmon 15.21 only from the official Microsoft Sysinternals page. Record a SHA-256 hash after download and verify the binary's Authenticode signature before transfer. The setup script repeats the signature and version checks inside the VM.

```powershell
Get-FileHash -LiteralPath ".\Sysmon64.exe" -Algorithm SHA256
Get-AuthenticodeSignature -LiteralPath ".\Sysmon64.exe" |
  Select-Object Status, @{Name='Signer'; Expression={$_.SignerCertificate.Subject}}
```

### 2. Transfer into the VM

Transfer these files through the existing controlled method:

- Official `Sysmon64.exe`
- `infra/sysmon/sysmon-aegis.xml`
- `infra/elastic-agent/windows/elastic-agent.yml`
- `scripts/windows/setup-advanced-telemetry.ps1`
- `scripts/windows/rollback-advanced-telemetry.ps1`
- `scripts/windows/generate-advanced-telemetry-markers.ps1`

Keep `scripts/verify-advanced-windows-telemetry.ps1` on the host.

### 3. Run setup as Administrator

From an Administrator PowerShell session in the transfer directory:

```powershell
.\setup-advanced-telemetry.ps1 `
  -SysmonBinaryPath ".\Sysmon64.exe" `
  -SysmonConfigPath ".\sysmon-aegis.xml" `
  -ElasticAgentConfigPath ".\elastic-agent.yml"
```

Original state is retained under `C:\AEGIS\telemetry-state`. Re-running setup preserves that first backup, updates an existing matching Sysmon 15.21 configuration with the official `-c` command, and does not create another Elastic Agent service.

### 4. Generate benign markers

```powershell
.\generate-advanced-telemetry-markers.ps1
```

To request a Defender custom scan of the marker directory:

```powershell
.\generate-advanced-telemetry-markers.ps1 -RunDefenderScan
```

Record the printed `MarkerId`.

### 5. Verify from the host

```powershell
.\scripts\verify-advanced-windows-telemetry.ps1 `
  -ElasticsearchUrl "http://192.168.56.1:9200" `
  -ExpectedHostName "DESKTOP-EVVU9LS" `
  -LookbackMinutes 30 `
  -MarkerId "AEGIS-..."
```

Before VM setup, a non-zero result reporting missing advanced data streams is expected. Do not call advanced ingestion verified until all three sources return recent data.

### 6. Roll back

Run from an Administrator PowerShell session:

```powershell
.\rollback-advanced-telemetry.ps1
```

This restores the saved registry values, Process Creation audit state, and previous Elastic Agent config, then restarts the Agent. Sysmon is retained unless explicitly requested:

```powershell
.\rollback-advanced-telemetry.ps1 -RemoveSysmon
```

The rollback does not delete Windows Event Logs, Elasticsearch data, indices, or Docker volumes.

## Security boundaries

- No Defender or Firewall disablement.
- No Defender exclusions or EICAR content.
- No downloads from the scripts.
- No WinRM, network-adapter, global execution-policy, or reboot changes.
- No Event Log reset or deletion.
- Process command lines can contain sensitive values; the host verifier never prints full command lines or complete events.
- No credential, certificate, API key, or TLS material is stored in the Agent policy.

## Known gaps

- VM runtime apply: `PENDING`.
- Advanced Sysmon, PowerShell, and Defender ingestion: `PENDING`.
- Advanced ECS normalization and integration-package pipelines: not verified.
- Detection rules: not implemented.
- Atomic Red Team: not installed or run.

## Next milestone

After all three advanced streams contain recent VM telemetry:

1. Verify representative ECS and Windows fields.
2. Select and create the initial Sigma detections from proven telemetry.
