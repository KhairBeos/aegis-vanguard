# Phase 2 Windows Elastic Agent onboarding

## Architecture

```text
victim-win-01
  → Elastic Agent 9.4.2 standalone
  → http://192.168.56.1:9200
  → Elasticsearch 9.4.2
  → Kibana 9.4.2
```

The Agent uses local standalone management and sends directly to Elasticsearch. Fleet enrollment, Fleet Server, authentication credentials, TLS material, metrics, and detection rules remain outside this baseline milestone.

The baseline configuration collects the Windows Application, System, and Security event logs. The Security log requires Elastic Agent to run with Administrator/System privileges. Advanced Sysmon, PowerShell, and Defender channels are prepared separately in Phase 3 and do not change the baseline verification claim.

## Files

| File | Purpose |
| --- | --- |
| `infra/elastic-agent/windows/elastic-agent.yml` | Standalone Windows event-log policy; baseline streams plus Phase 3 advanced streams |
| `scripts/verify-windows-ingestion.ps1` | Host-side data-stream and recent-event verification |

## Configuration validation boundary

The policy structure was checked against the official `elastic-agent.reference.yml` from the Elastic Agent `v9.4.2` source tag and the official Elastic System integration `winlog` stream definitions. The exact `9.4.2` Windows ZIP and SHA-512 files are available from Elastic's artifact registry.

Codex did not download the Agent package solely for validation or control the VM. The user subsequently installed the standalone Agent manually and completed the runtime baseline verification described below.

## Baseline ingestion verification

Runtime verification completed on `2026-07-29` for Windows host `desktop-evvu9ls`.

- `logs-system.application-aegis_lab`: PASS
- `logs-system.system-aegis_lab`: PASS
- `logs-system.security-aegis_lab`: PASS
- Uppercase verifier input `DESKTOP-EVVU9LS` is normalized before querying: PASS
- `scripts/verify-windows-ingestion.ps1`: PASS; exit code `0`

This result verifies recent Application, System, and Security ingestion only. It does not verify ECS normalization, a detection rule, alert generation, or any advanced Phase 3 channel.

## Manual installation boundary

Codex did not download, install, start, stop, or control Elastic Agent or the Windows VM. The following remains the manual onboarding and recovery procedure:

1. Download the official `elastic-agent-9.4.2-windows-x86_64.zip` and its `.sha512` file from:
   - `https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.4.2-windows-x86_64.zip`
   - `https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.4.2-windows-x86_64.zip.sha512`
2. Verify the ZIP SHA-512 value, then transfer the ZIP and the prepared `elastic-agent.yml` into the isolated VM using the existing controlled transfer method.
3. Extract the ZIP. Replace the extracted `elastic-agent.yml` with `infra/elastic-agent/windows/elastic-agent.yml`.
4. Open PowerShell as Administrator and change to the extracted Agent directory.
5. Install the standalone service with the official command:

   ```powershell
   .\elastic-agent.exe install
   ```

6. Check the Windows service and Agent status:

   ```powershell
   Get-Service "Elastic Agent"
   & "C:\Program Files\Elastic\Agent\elastic-agent.exe" status
   ```

7. If recent Application or System events are needed, create harmless verification entries:

   ```powershell
   eventcreate.exe /T INFORMATION /ID 100 /L APPLICATION /D "AEGIS ingestion verification"
   eventcreate.exe /T INFORMATION /ID 101 /L SYSTEM /D "AEGIS ingestion verification"
   ```

8. From the host, run:

   ```powershell
   .\scripts\verify-windows-ingestion.ps1 `
     -ElasticsearchUrl "http://192.168.56.1:9200" `
     -ExpectedHostName "<WINDOWS_HOSTNAME>"
   ```

The verifier uses a 15-minute lookback by default. It prints only data-stream names and the newest timestamp for each channel, not complete events.

Before treating ECS normalization as verified, install and review the matching System integration assets in Kibana. This does not require Fleet Server or Fleet enrollment, but it is a separate manual gate.

## Rollback

Run PowerShell as Administrator.

Stop the service:

```powershell
Stop-Service "Elastic Agent"
```

To uninstall, change to a directory outside `C:\Program Files\Elastic\Agent`, then run:

```powershell
Set-Location $env:TEMP
& "C:\Program Files\Elastic\Agent\elastic-agent.exe" uninstall
```

Rollback must not delete Windows Event Logs or the Elasticsearch Docker volume.

## Known gaps

- Required System integration assets and ECS field behavior are not verified.
- Phase 3 Sysmon, PowerShell, and Defender runtime application and ingestion are pending.
- Detection rules are not created.
- Elastic security remains disabled only because this is an isolated personal lab; this configuration is not suitable for production.
