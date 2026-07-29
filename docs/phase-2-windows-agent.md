# Phase 2 Windows Elastic Agent onboarding

## Architecture

```text
victim-win-01
  → Elastic Agent 9.4.2 standalone
  → http://192.168.56.1:9200
  → Elasticsearch 9.4.2
  → Kibana 9.4.2
```

The Agent uses local standalone management and sends directly to Elasticsearch. Fleet enrollment, Fleet Server, authentication credentials, TLS material, metrics, Sysmon, and detection rules are outside this milestone.

The configuration collects only the Windows Application, System, and Security event logs. The Security log requires Elastic Agent to run with Administrator/System privileges.

## Files

| File | Purpose |
| --- | --- |
| `infra/elastic-agent/windows/elastic-agent.yml` | Standalone Windows event-log policy |
| `scripts/verify-windows-ingestion.ps1` | Host-side data-stream and recent-event verification |

## Configuration validation boundary

The policy structure was checked against the official `elastic-agent.reference.yml` from the Elastic Agent `v9.4.2` source tag and the official Elastic System integration `winlog` stream definitions. The exact `9.4.2` Windows ZIP and SHA-512 files are available from Elastic's artifact registry.

Elastic Agent tooling is not installed on the host, and Codex did not download the 247 MB package solely for validation. Binary policy validation and runtime ingestion remain pending until the user performs the manual installation.

## Manual installation boundary

Codex did not download, install, start, stop, or control Elastic Agent or the Windows VM. Perform these steps manually inside `victim-win-01`:

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

- Elastic Agent has not been installed by the user.
- Windows event ingestion is not verified.
- Required System integration assets and ECS field behavior are not verified.
- Sysmon is not installed.
- Detection rules are not created.
- Elastic security remains disabled only because this is an isolated personal lab; this configuration is not suitable for production.
