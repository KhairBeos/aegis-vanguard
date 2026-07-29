# Working Context

`CONTEXT.md` is non-authoritative working memory. `README.md` and `PROJECT_PLAN.md` remain the trusted sources for project scope, roadmap, and claim status.

## Current working state

- Evidence timestamp: `2026-07-29T05:04:44.8040053Z`.
- Milestone result: `ADVANCED WINDOWS TELEMETRY PREPARED — VM APPLY PENDING`.
- Phase 0 manual setup and runtime environment are complete.
- Elasticsearch `9.4.2` is running and healthy; the single-node cluster currently reports yellow because replica shards are unassigned.
- Kibana `9.4.2` is running, healthy, and available.
- Both services remain bound only to the VirtualBox host-only address `192.168.56.1`.
- From `victim-win-01`, TCP access to ports `9200` and `5601` and Kibana UI access passed.
- Overall connectivity checkpoint: `ELASTIC STACK AND VM ACCESS VERIFIED`.

## Baseline Windows ingestion

- Elastic Agent `9.4.2` standalone on `victim-win-01`: HEALTHY.
- Fleet and Agent monitoring remain disabled; output remains direct to `http://192.168.56.1:9200`.
- Verified host identity: `desktop-evvu9ls`; verifier input is normalized with `Trim().ToLowerInvariant()`.
- Verified data streams:
  - `logs-system.application-aegis_lab`
  - `logs-system.system-aegis_lab`
  - `logs-system.security-aegis_lab`
- Recent Application, System, and Security ingestion: PASS.
- Status: `WINDOWS INGESTION VERIFIED`.
- ECS normalization remains unverified.

## Baseline verifier fix

- Root cause: PowerShell parsed `$namespace?` as a variable name in the data-stream discovery path.
- Minimal fix: delimit the variable as `${namespace}`.
- Parser validation and uppercase-host runtime regression: PASS.
- Verifier exit code: `0`.
- Commit: `203a9f408af721f14a0a3357a0eab864063a48ee` (`fix: correct baseline data stream query`).

## Advanced Windows telemetry preparation

- Sysmon target version: `15.21`, officially published by Microsoft Sysinternals on `2026-06-17`.
- Official lifecycle contract verified: `-i` install, `-c` configuration update, `-s` schema display, and `-u` uninstall.
- Sysmon XML uses the official documentation sample schema version `4.82`; real-binary schema validation remains pending in the VM.
- Prepared advanced streams:
  - `Microsoft-Windows-Sysmon/Operational` → `windows.sysmon`
  - `Microsoft-Windows-PowerShell/Operational` → `windows.powershell`
  - `Microsoft-Windows-Windows Defender/Operational` → `windows.defender`
- Namespace remains `aegis_lab`; baseline streams are unchanged.
- Setup, rollback, benign marker, and host verifier scripts are prepared.
- VM runtime apply: `PENDING`.
- Advanced ingestion: `PENDING`.
- Advanced ECS normalization: not verified.

## Advanced validation

- PowerShell parser validation for all four new scripts: PASS.
- Sysmon XML parse and static event/filter assertions: PASS.
- Agent channel, dataset, stable-ID, direct-output, local-management, and safety assertions: PASS.
- Baseline verifier regression: PASS; exit code `0`.
- Advanced verifier reached Elasticsearch and reported the three not-yet-created data streams separately: expected exit code `1`.
- Elasticsearch-unreachable path reports a distinct HTTP error and separate skipped-source failures: PASS.
- No Sysmon binary was downloaded or run, and no VM, service, registry, audit, Defender, Firewall, Docker, or network state was changed by Codex.

## Files changed for advanced preparation

- `infra/sysmon/sysmon-aegis.xml`
- `infra/elastic-agent/windows/elastic-agent.yml`
- `scripts/windows/setup-advanced-telemetry.ps1`
- `scripts/windows/rollback-advanced-telemetry.ps1`
- `scripts/windows/generate-advanced-telemetry-markers.ps1`
- `scripts/verify-advanced-windows-telemetry.ps1`
- `docs/phase-2-windows-agent.md`
- `docs/phase-3-advanced-telemetry.md`
- `CONTEXT.md`

## Git result

- Part 1 commit: `203a9f408af721f14a0a3357a0eab864063a48ee`.
- Requested Part 2 commit: `feat: prepare advanced Windows telemetry`.
- The Part 2 commit hash is reported in the task output because a commit cannot contain its own hash.
- No push is authorized or performed.

## Decisions that remain in force

- Do not call Sysmon, PowerShell, or Defender ingestion verified before manual VM setup and host verification pass.
- Required integration assets and representative events must be reviewed before advanced ECS behavior can be called verified.
- The initial Sigma rule remains unselected and depends on proven telemetry.
- The detection executor decision gate and exact Atomic-run approval remain unresolved.
- No detection, alert-generation, MITRE coverage, or metric claim is upgraded.
- All metrics remain `Not measured yet`.

## Next manual step

1. Download Sysmon `15.21` from Microsoft Sysinternals and record its SHA-256 hash.
2. Transfer `Sysmon64.exe`, `sysmon-aegis.xml`, the updated `elastic-agent.yml`, and the three VM-side scripts listed in `docs/phase-3-advanced-telemetry.md` to `victim-win-01`.
3. From an Administrator PowerShell session in the transfer directory, run:

   ```powershell
   .\setup-advanced-telemetry.ps1 `
     -SysmonBinaryPath ".\Sysmon64.exe" `
     -SysmonConfigPath ".\sysmon-aegis.xml" `
     -ElasticAgentConfigPath ".\elastic-agent.yml"
   ```

4. Generate a benign marker, then run `scripts/verify-advanced-windows-telemetry.ps1` from the host.

