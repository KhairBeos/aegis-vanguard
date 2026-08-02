# Working Context

`CONTEXT.md` is non-authoritative working memory. `README.md` and `PROJECT_PLAN.md` remain the trusted sources for project scope, roadmap, and claim status.

## Current working state

- Evidence timestamp: `2026-08-02T05:54Z`.
- Milestone result: `RULE PACK AND EVIDENCE-DRIVEN COVERAGE BUILT — ATOMIC VALIDATION STILL PENDING`.
- Four rules deployed; three have evidence-backed detections across three MITRE techniques.
- `mitre/coverage.md` is generated from evidence bundles by `scripts/build-coverage.ps1`.

## Tuning cycle TUNE-001 — measured, not guessed

Full write-up in `docs/detection-tuning-log.md`.

The obvious tune was **measured and rejected**. Excluding `VBoxService.exe` as a parent
removed only 1 of 2 false positives, and the survivor was identical to the true positives
on parent, image, and command-line shape. They differ only in the base64 payload. Any
exclusion tight enough to kill the false positive also kills the true positives, and
parent allowlisting would have handed an attacker a one-line evasion.

Instead the payload was made visible:
`infra/elastic/ingest-pipelines/aegis-powershell-decode.json` decodes `-EncodedCommand`
into `aegis.powershell.decoded_command` at ingest, attached as `index.final_pipeline` so
it runs after any integration pipeline rather than replacing one. Painless has no
`StandardCharsets` in its allowlist, so UTF-16LE is decoded arithmetically from the byte
array.

Measured result on identical live activity:

| Decoded source event | Encoded rule (`medium`) | Cradle rule (`high`) |
| --- | --- | --- |
| `Write-Output 'AEGIS-...'` | alerted - false positive | no alert |
| two `DownloadString` cradles | alerted | alerted |
| **Totals** | 3 alerts, 1 false positive | 2 alerts, 0 false positives |

Recall preserved, false positive removed. The original rule was kept and downgraded from
`high` to `medium` rather than deleted: encoding is worth seeing as hunting context.

The sample is three events on one host. That is enough to show direction and nowhere near
enough to state a rate, so the false-positive-rate metric stays `Not measured yet`.

## Rule pack

| Rule | Technique | Kind of logic | Evidence |
| --- | --- | --- | --- |
| PowerShell Encoded Command Execution | `T1059.001` | command-line string match | `AEGIS-SCN-0001`, detected, MTTD 124.9s |
| Script Host Spawning a Command Shell | `T1059.005` | parent-child relationship | `AEGIS-SCN-0002`, detected, MTTD 279.2s |
| Registry Run Key Persistence | `T1547.001` | registry state change, Sysmon EID 13 | `AEGIS-SCN-0003`, detected, MTTD 277.1s |
| Regsvr32 Remote Scriptlet Execution | `T1218.010` | LOLBin invocation pattern | none - fixtures only |

The parent-child rule is deliberately not a keyword rule: its child command line is
completely innocuous, so no string match would catch it. What makes it suspicious is the
parent. The Run key rule watches a state change rather than a process launch, and matches
on the small closed set of autorun paths rather than on unbounded payload contents.

Regsvr32 has no evidence on purpose. Triggering it requires fetching a remote scriptlet,
and the host-only lab correctly has no egress. That is recorded as a scenario limitation
in `mitre/coverage.md`, not hidden.

## Live scenario driver

`scripts/windows/run-detection-scenarios.ps1` triggers benign activity matching the rules
and emits machine-readable scenario windows. Every action is harmless and self-cleaning:
payloads only echo a marker id, the HKCU Run value is removed in the same run, nothing is
downloaded, and no security control is touched. It is detection validation, not attack
emulation; the approved Atomic Red Team run remains separate and still unauthorised.

## Coverage generation

`scripts/build-coverage.ps1` derives `mitre/coverage.md` from evidence bundles alone. A
technique is listed as covered only because a bundle recorded `detected`, never because a
rule exists. Rules that have never matched real telemetry are listed separately with the
reason. Coverage is reported as counts, not a percentage, because a percentage would imply
a denominator this lab cannot justify.
- The VM is fully applied: Sysmon `15.21` installed, advanced telemetry flowing, Agent authenticating.
- The first alert in the project's history was produced and captured in `evidence/AEGIS-SCN-0001.md`.

## First closed detection loop

| Field | Value |
| --- | --- |
| Scenario | `AEGIS-SCN-0001` (benign marker, **not** an Atomic Red Team run) |
| Marker | `AEGIS-20260802T053038839Z-984f587b` |
| Source event | Sysmon EID 1 at `2026-08-02T05:30:40.101Z` |
| Alert | `2026-08-02T05:32:43.753Z` |
| Time to detect | `124.9` seconds |
| Result | `detected`, 1 alert, 1 source document |
| Evidence hash | `3B9FE24B45027C77783C46A53919C856102701E59813395DD6732725EF6F8BEF` |

Sysmon accepted the repository configuration at runtime: `Loading configuration file with
schema version 4.82 / Sysmon schema version: 4.91 / Configuration file validated`. This closes
the previously open "real-binary schema validation pending" gap.

Ingestion under authentication is confirmed across all six data streams.

## First false-positive finding

The rule's own `falsepositives` field predicted "management agents that legitimately pass
encoded payloads to PowerShell". That was proven correct within minutes, by this project's own
tooling: `VBoxManage guestcontrol` invokes `powershell.exe -EncodedCommand`, so two alerts fired
for the diagnostic scripts run during setup.

This is a true positive by rule logic and a false positive operationally. It is the concrete
input for the rule-tuning work, and it is recorded rather than tuned away silently, because the
before/after evidence is the point.

## Clock skew note (required by the evidence model)

Guest and host clocks agree to within 3 seconds. Guest timezone is `Pacific Standard Time`.

A bounded set of historical documents carries timestamps roughly 13 hours in the future,
logged before the guest clock synchronised: 59 of 5193 in `logs-system.security-aegis_lab` and
1 of 227 in `logs-system.application-aegis_lab`.

`logs-windows.sysmon-aegis_lab` has **0 of 78** future-dated documents, so the stream this
detection depends on is unaffected. No evidence timestamp in `AEGIS-SCN-0001` is derived from a
skewed document.

## Fourth and fifth bugs, both caught by the rule fixture harness

**Registry rule never matched.** `ecs_windows` maps `TargetObject` to `registry.path`, an
ECS field this lab does not produce, exactly like the earlier `Image` case. Three fixture
cases failed immediately. `sigma/pipelines/aegis-lab.yml` now dual-maps `registry.path`,
`file.path`, `dns.question.name`, and `user.name` as well.

**The lowercase normalizer created an invisible trap.** Because `logs@custom` lowercases
values at index time, any rule written with natural casing, such as `\CurrentVersion\Run\`,
would parse, convert, import, execute, and silently never match. Relying on a convention
that rule authors must write lowercase is exactly the sort of hidden coupling that produces
dead detections. Fixed properly with a pySigma `case: lower` transformation scoped to the
normalized fields, so rule authors write natural casing and the pipeline handles it.

## Sixth bug: PowerShell 5.1 JSON array unrolling

`@(Get-Content ... | ConvertFrom-Json)` produces a single-element array containing the
array, because 5.1 emits a parsed JSON array as one pipeline item. With one test suite this
was invisible; with four it made every suite fail to resolve. Now normalised explicitly.

## Third bug found and fixed: alert attribution in evidence bundles

The first run of `collect-evidence.ps1` reported **3 alerts** for a scenario that caused one.

One rule execution stamps every alert it emits with the same `@timestamp`, so filtering alerts
by `@timestamp` swept in two alerts about activity from before the scenario window and credited
them to it. Evidence that attributes the wrong events to a scenario is worse than no evidence.

Fix: attribution now filters on `kibana.alert.original_time`, the time of the source event that
actually triggered the alert, with `@timestamp` used only to bound the search. Re-running the
same scenario then correctly reported 1 alert and 1 source document.
- Elasticsearch `9.4.2` and Kibana `9.4.2` are running healthy **with authentication enforced**, bound only to `192.168.56.1`.
- The first Sigma-derived rule is deployed, enabled, and executing successfully in Elastic Security.
- No alert has ever been produced, and no detection claim is made.
- Advanced telemetry (Sysmon, PowerShell, Defender) remains prepared but not applied in the VM.
- The Phase 2 executor decision gate is now **resolved**; see `docs/adr-001-detection-executor.md`.

## BLOCKER — Elastic Agent will fail until re-applied

Elasticsearch now rejects unauthenticated writes. The Elastic Agent config currently on
`victim-win-01` has no `api_key`, so **the moment the VM boots, every ingest attempt will fail
with HTTP 401**. Baseline ingestion is not broken yet only because the VM is powered off.

A least-privilege API key was created for it:

- Key name: `aegis-agent-victim-win-01`
- Privileges: cluster `monitor`; `auto_configure` + `create_doc` on `logs-system.*-aegis_lab` and `logs-windows.*-aegis_lab`
- Both the key id and its secret were printed once by `scripts/new-agent-api-key.ps1` and are deliberately not stored in this repository.

To list or revoke it, query `GET /_security/api_key?name=aegis-agent-victim-win-01` for the
current id, then `DELETE /_security/api_key` with that id in the body.

## Approved decisions from this session

1. Build the codebase forward assuming the VM infrastructure behaves as intended, while keeping every capability status honest. No status is upgraded without linked evidence.
2. Detection executor: **Elastic Security detection engine**, not a custom scheduled executor.
3. Python tooling installs into a project-local `.venv`.
4. Claude may restart the Elastic Stack once the user has added the new `.env` variables.

## Elastic Stack security

Enabling authentication was a prerequisite for the detection engine, not optional hardening.

- `infra/elastic/docker-compose.yml` now sets `xpack.security.enabled=true`.
- A one-shot `setup` service sets the `kibana_system` password, because the `ELASTIC_PASSWORD` bootstrap only creates the `elastic` user.
- Kibana receives `xpack.encryptedSavedObjects.encryptionKey`, required by the detection engine.
- TLS is deliberately **not** enabled. Elastic removed the TLS requirement for API keys and alerting, and the lab is host-only. This is a recorded gap, not an oversight.
- `docker compose config` passes; three new variables are required in `infra/elastic/.env`: `ELASTIC_PASSWORD`, `KIBANA_SYSTEM_PASSWORD`, `KIBANA_ENCRYPTION_KEY`.

## Verified findings that drove the design

- `sigma-cli` target `lucene` provides the `siem_rule_ndjson` output format (confirmed by `sigma list formats lucene`).
- Custom detection rules and rule import/export are available on the **Basic** licence. Only actions/notifications and ML rules need a higher tier; neither is used.
- `ecs_windows` maps Sigma `Image` to `process.executable`, an ECS field produced by integration ingest pipelines that this lab has not installed. A rule converted with `ecs_windows` alone would import cleanly and never match.
- Mitigation: `sigma/pipelines/aegis-lab.yml` maps the affected process fields to both the ECS name and the raw `winlog.event_data.*` name, so rules work before and after integration assets exist.
- `sigma-cli` emits `index` as a bare string when one index pattern is supplied; the import API requires an array. `convert-sigma.ps1` normalises this.

## Validation results

Static checks:

- `scripts/lib/aegis-elastic.test.ps1`: 14/14 assertions PASS, exit code `0`.
- PowerShell parser validation across all 12 scripts: PASS.
- `docker compose config`: exit code `0`.
- `scripts/convert-sigma.ps1`: converted 1 rule, exit code `0`; `index` is an array, `interval 5m`, window `now-5m` to `now`, severity `high`, risk `73`, technique `T1059.001`.
- `git check-ignore` confirms `rules/generated/`, `*.test.*`, `.venv/`, and `infra/elastic/.env` are excluded.

Runtime checks against the live stack:

- `scripts/verify-elastic.ps1`: 18/18 PASS, exit code `0`. Includes the new assertion that Elasticsearch answers an unauthenticated request with **HTTP 401**, which proves security is enforcing rather than merely configured.
- Elasticsearch and Kibana containers report `healthy`; the `setup` container exited `0`, confirming the `kibana_system` password was set.
- The Elasticsearch healthcheck authenticates as `elastic`, so its passing state also proves the `ELASTIC_PASSWORD` bootstrap took effect on the pre-existing volume. The risk that the bootstrap would be skipped on an already-initialised data path did not materialise.
- `scripts/deploy-detection-rules.ps1`: imported 1 rule, exit code `0`.
- `scripts/verify-detection-rules.ps1`: exit code `0`. Rule is deployed, `enabled=True`, and `last execution = succeeded` at `2026-08-02T04:42:43.645Z`.
- Existing data survived the restart: `logs-system.application-aegis_lab` (197 docs), `logs-system.system-aegis_lab` (696), `logs-system.security-aegis_lab` (3552).

## Critical bug found and fixed: case-sensitive rule matching

The deployed rule could never have matched anything, and nothing would have reported an error.

Sigma matches string values **case-insensitively**. Elasticsearch `keyword` fields do **not**.
`winlog.event_data.CommandLine` is dynamically mapped as `keyword`, so the converted query
`*\ \-encodedcommand*` did not match a real command line containing `-EncodedCommand`.

Proven, not assumed: a synthetic document in a throwaway data stream returned `0` hits for the
rule query while a control query with the real casing returned `1`.

The rule would have kept reporting `succeeded` on every run forever, and zero alerts would have
looked exactly like "no attacks happened". This is the most dangerous class of detection bug.

Fix: `infra/elastic/component-templates/logs@custom.json` adds a lowercase normalizer to the
Sysmon `winlog.event_data.*` fields. `logs@custom` is the extension point the built-in `logs`
index template already composes, so no competing index template is needed. `_source` keeps the
original casing, so evidence value is preserved.

Verified after the fix: 8/8 rule query cases pass, including three casing variants an attacker
could use to evade (`-enc`, `-EnCoDeDcOmMaNd`, `pwsh.exe`) and four negative controls
(`-ExecutionPolicy Bypass` must not match the `-e` prefix, ordinary commands, non-PowerShell
image, wrong event ID).

The harness was verified to actually catch the regression: removing the normalizer makes
`scripts/test-detection-rules.ps1` fail 3 cases with exit code `1` and print the fix command.

## Second bug found and fixed: timestamp corruption in evidence bundles

`collect-evidence.ps1` originally took `[datetime]` parameters. Passed through `-File`, a
`DateTime` loses its `Kind`, is re-parsed as local time, and is then shifted again by
`ToUniversalTime()`. A value of `04:43Z` was recorded as `21:41Z` the previous day, a 7-hour
error, and the time-to-detect figure was derived from it.

Fix: timestamps are accepted as strings and parsed with `AdjustToUniversal | AssumeUniversal`,
so an offset is honoured when present and a missing offset means UTC rather than local time.
Invalid input is rejected with exit code `1` instead of silently producing a wrong bundle.

## What the rule execution does and does not prove

Proven: the converted Lucene query is syntactically valid, Elastic Security accepts the
generated rule format, the rule is scheduled, and it runs to completion against real indices
containing 3552 real Security events.

Not proven: that the rule detects the behaviour it describes. It has never matched a document.
Its Sysmon data streams do not exist yet, and no encoded-PowerShell event has ever been
ingested. Zero alerts is the correct result at this stage, not evidence of anything.

## Files changed

- `infra/elastic/docker-compose.yml`
- `infra/elastic-agent/windows/elastic-agent.yml`
- `scripts/lib/aegis-elastic.ps1`
- `scripts/new-agent-api-key.ps1`
- `scripts/convert-sigma.ps1`
- `scripts/deploy-detection-rules.ps1`
- `scripts/verify-elastic.ps1`
- `scripts/verify-windows-ingestion.ps1`
- `scripts/verify-advanced-windows-telemetry.ps1`
- `scripts/windows/setup-advanced-telemetry.ps1`
- `rules/windows/powershell_encoded_command.yml`
- `sigma/pipelines/aegis-lab.yml`
- `requirements.txt`
- `.gitignore`
- `docs/adr-001-detection-executor.md`
- `docs/phase-4-detection-rules.md`
- `CONTEXT.md`

## Capability status

| Area | Status | Reason |
| --- | --- | --- |
| Elastic Stack authentication | `Runtime verified` | Stack runs with security enforced; unauthenticated requests are rejected with HTTP 401 |
| Sigma conversion | `Unit tested` | Conversion produces a well-formed rule; syntax and conversion only |
| Detection rule deployment | `Runtime verified` | Rule imported into Elastic Security and confirmed enabled |
| Detection rule execution | `Runtime verified` | Rule executed successfully against real indices |
| Detection of real activity | `Runtime verified` | One real Sysmon event produced one correctly attributed alert with a complete evidence bundle |
| Advanced Windows telemetry ingestion | `Runtime verified` | Sysmon, PowerShell, and Defender streams all receiving data under authentication |
| Sysmon configuration | `Runtime verified` | The real 15.21 binary validated the repository config against schema 4.91 |
| ECS normalization | `Future` | Integration assets not installed |
| Atomic-backed rule-scenario validation | `Future` | `AEGIS-SCN-0001` is a benign marker, not an approved Atomic Red Team run |

`Runtime verified` here covers ingestion-side and executor-side plumbing only. Per
`PROJECT_PLAN.md`, no rule-scenario pair may reach `Live verified` without an approved Atomic
Red Team run and a complete evidence bundle. None exists.

All metrics remain `Not measured yet`.

## README.md is now stale

`README.md` still states the repository "contains no source code, runtime configuration, tests,
phase deliverables, or evidence artifacts" and lists every phase as `Future`. That was already
inaccurate before this session and is more so now. `README.md` is a trusted source, so it was
deliberately **not** rewritten without the user's approval. It needs a sync pass.

## Decisions that remain in force

- Do not call Sysmon, PowerShell, or Defender ingestion verified before manual VM setup and host verification pass.
- The detection engine's deduplication, alert persistence, and error handling are claimed only as `Implemented`; all three need runtime confirmation.
- No detection, alert-generation, MITRE coverage, or metric claim is upgraded.
- The exact Atomic Red Team run still requires separate explicit approval.

## Environment incident resolved this session

The VirtualBox host-only adapter had lost its static address and fallen back to the APIPA
address `169.254.217.242`, so Docker could not bind `192.168.56.1:9200` and the stack failed to
start. Restored with `VBoxManage hostonlyif ipconfig ... --ip 192.168.56.1 --netmask
255.255.255.0`. Worth re-checking first whenever the stack fails to bind.

## Evidence bundle machinery

`scripts/collect-evidence.ps1` produces the MVP checkpoint artifact from a scenario window:
rule identity and version, execution result, query window, alert and source document IDs,
attack/alert timestamps, time to detect, SHA-256 of the raw export, and a `detected`/`missed`
result. It never invents an alert timestamp; `missed` records `not applicable` and explains why.
The report leaves the analyst triage note and gap category as `TODO` for a human, and prints a
redaction-review banner because command lines can carry credentials.

`generate-advanced-telemetry-markers.ps1` gained `-TriggerEncodedCommandRule`, which runs a
benign encoded command (the payload only echoes the marker id) so the rule has something to
match. It is opt-in so plain ingestion verification does not manufacture alerts.

## Next steps

1. **Claude (already done, before the VM writes anything)**: `scripts/apply-index-templates.ps1` has been applied, so the Sysmon data stream will be created with the correct mapping the first time.
2. **User**: paste `api_key: "<the key>"` into the `outputs.default` block of `elastic-agent.yml` on `victim-win-01`. `setup-advanced-telemetry.ps1` refuses a config still holding the `REPLACE_WITH_AGENT_API_KEY` placeholder.
3. **User**: run the advanced telemetry setup in the VM (Sysmon 15.21 + the three advanced streams), per `docs/phase-3-advanced-telemetry.md`.
4. **User**: run `.\generate-advanced-telemetry-markers.ps1 -TriggerEncodedCommandRule` and record the printed `MarkerId`, `StartUtc`, and `EndUtc`.
5. **Claude**: wait one rule interval, then run `scripts/collect-evidence.ps1` to produce the first real bundle. This is the step that moves detection from `Future` toward evidence.
6. **Human**: write the triage note and gap category, redact, and commit the bundle.
7. Only after that loop closes: the scenario-alignment gate and the approved Atomic Red Team run.

All seven steps above are now **done**, except the Atomic run.

## Analyst triage notes

All four bundles carry a triage note and a gap category; no `TODO` remains. Each note
records a pivot that was checked against telemetry rather than assumed:

- `AEGIS-SCN-0004`: Sysmon Event ID 3 for the surrounding minute shows five connections, all
  from `elastic-otel-collector.exe` to `192.168.56.1:9200`. **No connection from
  `powershell.exe`**, so the decoded cradle was echoed and never executed.
- `AEGIS-SCN-0003`: Sysmon captured **both** Event ID 13 `SetValue` at `05:47:07.708Z` and
  Event ID 12 `DeleteValue` at `05:47:09.722Z`. The persistence did not survive, yet the
  alert cannot convey that because the rule watches Event ID 13 only. Recorded as a rule
  logic gap with the specific improvement to make.

These notes were drafted by Claude from the evidence. If this repository is used as a job
portfolio, rewrite them in the author's own words: an interviewer will ask the analyst to
walk through this reasoning out loud, and borrowed prose does not survive that.

`collect-evidence.ps1` now preserves an existing triage note and gap category when a bundle
is regenerated, because analyst prose is the one part of a bundle a machine cannot rebuild.
Verified by regenerating `AEGIS-SCN-0003` and confirming the note survived.

## Trusted sources synchronised

`README.md` and `PROJECT_PLAN.md` are both current as of `2026-08-02`. A scan for the old
documentation-only claims returns nothing.

## Alert deduplication — proven

First observation: across all alerts there were as many distinct `(rule_id, source document)`
pairs as alerts, and zero pairs with more than one alert. That was consistent with dedup
working and equally consistent with dedup never having been exercised, so it proved nothing
on its own.

Decisive test, run `2026-08-02T09:13Z` to `09:28Z`: a **temporary copy** of the encoded-command
rule was imported under its own `rule_id` with `lookback: 25m` against a `5m` interval, giving
a 30-minute query window. No deployed rule was modified. One event was generated at
`09:13:08.299Z` and left alone.

| Measure | Value |
| --- | --- |
| Temp rule executions covering the event | 3 (`~09:18:32`, `~09:23:32`, `09:28:32`) |
| Times the source document was queried | 3 |
| Alerts produced | **1** |
| Distinct source documents | 1 |
| Maximum alerts for any one document | **1** |

The same source document was queried three times across three separate rule executions and
produced exactly one alert. Deduplication is **verified**. The temporary rule was deleted and
the five production rules are unchanged.

## Remaining work

1. **Open verification item**: alert deduplication, as above. The clean way to close it without touching a deployed rule is to add a second rule that is a copy with a deliberately wide lookback, run one scenario, count alerts, then delete that rule.
2. **ECS normalization** is still `Future`. Closing it means installing the Windows integration assets, which requires renaming the custom datasets so the integration ingest pipelines actually attach.
3. **Atomic Red Team** is the only thing between the current results and any `Live verified` claim, and it needs approval for an exact test. The atomics can be downloaded on the host and transferred through the same controlled path already used for Sysmon, so the lab's isolation does **not** need to be broken to run one.
4. Nothing has been committed. The working tree is ready.
