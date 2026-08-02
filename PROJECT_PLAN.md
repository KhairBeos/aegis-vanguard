# AEGIS-VANGUARD Project Plan

## Why This Plan Exists

An earlier concept relied on hand-crafted fixture events to "verify" detection logic. Fixtures can check syntax, parsing, conversion, and isolated logic, but they cannot prove that a real telemetry and alert path works. This plan therefore separates implementation, runtime validation, evidence-backed detection validation, and metrics.

## Current position against this plan

Last synchronised `2026-08-02`. `CONTEXT.md` holds the detail; `README.md` holds the
capability table. This section exists so the roadmap below is read against reality.

| Phase | Status | Note |
| --- | --- | --- |
| Phase 0 - local lab foundation | **Complete** | `docs/phase-0-environment.md` |
| Phase 1 - ingestion and ECS verification | **Partly complete** | Six data streams ingest under authentication. ECS normalization is verified for `system.*`; for Sysmon, PowerShell, and Defender it is blocked by a Windows integration package incompatibility, not by configuration. See `docs/ecs-normalization.md` |
| Phase 2 - Sigma conversion, execution, alert persistence | **Complete** | Executor gate resolved in `docs/adr-001-detection-executor.md`. All five executor requirements verified, including deduplication and error handling. Five rules deployed, one tuning cycle with before/after measurement |
| Phase 3 - Atomic-backed validation | **Complete for one pair** | Atomic T1547.001 test #1 executed with approval. `evidence/AEGIS-SCN-0005.md` is the first `Live verified` rule-scenario pair |
| Phase 4 - MITRE coverage and gap analysis | **Complete for the current evidence** | `mitre/coverage.md` is generated from bundles and separates Atomic-backed scenarios from benign marker runs |
| Phase 5 - Suricata | **Built, partially verified** | Pipeline `PCAP -> Suricata -> Elasticsearch` verified end to end. Live capture from the VM needs one elevated `pktmon` run. `docs/phase-5-7-additional-sources.md` |
| Phase 6 - Wazuh | **Built, partially verified** | Manager running with 11 components. Its current alerts describe the container itself and were deliberately not ingested. Agent on the victim VM needs an elevated install |
| Phase 7 - Kafka | **Built and verified** | 15 real alerts crossed the broker byte-identical, compared per record by SHA-256 rather than by count |
| Phase 8 - portfolio packaging | **Complete** | `docs/portfolio-report.md`: claim-to-evidence table, the four bugs worth discussing, a demo runbook, and a list of what a reviewer should push back on |

**The MVP checkpoint below is met, 10 of 10.**

What that does and does not mean: one rule-scenario pair is `Live verified`, and four of the
five scenarios are still benign markers where the same author wrote both the rule and the
thing meant to trigger it. `T1547.001` alone has 20 defined atomic tests and this lab has run
one. The honest next move is more Atomic tests against the existing rules, not Suricata,
Wazuh, or Kafka. Adding components to a lab with one externally validated detection would make
the project look broader and be worth less.

All metrics remain `Not measured yet`. The false-positive-rate metric in particular has a
documented method and a real before/after in `docs/detection-tuning-log.md`, but a sample of
three events on one host is not a rate.

## Goal

Build a fully local, isolated, portfolio-scale SIEM-like SOC lab that can trace one separately approved Atomic Red Team execution through telemetry collection, ECS verification, Sigma-based detection, alert persistence, triage, MITRE ATT&CK mapping, coverage reporting, and gap analysis.

The project does not target production, commercial, or enterprise-scale capability.

## Design Principles

1. **Real telemetry without invented claims.** Fixtures and unit tests may support engineering checks but never detection evidence.
2. **Evidence levels remain distinct.** Implementation, unit validation, runtime validation, Atomic-backed live validation, and metric measurement are separate claims.
3. **Standards over invented formats.** ECS is the planned data model, Sigma the detection rule format, and MITRE ATT&CK the mapping vocabulary.
4. **Fully local and isolated.** The target environment is a Windows victim VM on a VirtualBox host-only network plus staged local Docker services.
5. **Resource-staged.** Only the components needed for an approved phase or session should run.
6. **MVP before breadth.** One complete rule-scenario evidence loop precedes 3-5 rules, additional telemetry sources, and optional UI work.
7. **No invented metrics.** Metrics remain `Not measured yet` until their method, sample scope, and evidence exist.

## Status and Evidence Taxonomy

Capability status and metric status must not be mixed.

### Capability statuses

| Status | Required meaning |
| --- | --- |
| `Future` | No implementation artifact exists. |
| `Implemented` | An artifact or configuration exists and is reviewable; runtime behavior is not proven. |
| `Unit tested` | Syntax, parsing, conversion, or isolated logic has been checked; this is not runtime or detection evidence. |
| `Runtime verified` | A controlled runtime smoke or manual validation has run on real telemetry; this is not evidence-backed detection coverage. |
| `Live verified` | One specific rule-scenario pair has been exercised by an approved Atomic Red Team test and has a complete evidence bundle. |

`Live verified` must never be generalized from one scenario to an entire phase, platform, rule collection, or MITRE technique.

### Metric statuses

| Status | Required meaning |
| --- | --- |
| `Not measured yet` | No sufficient evidence set exists for the metric. |
| `Measured` | The metric has a documented method, sample scope, and linked evidence. |

## Target Environment

All items in this section are planned and require evidence before any status upgrade.

- **Victim VM**: a supported Windows version in VirtualBox, using a host-only adapter for all lab/scenario traffic.
- **Docker host**: the same local laptop, with future staged service profiles or equivalent manual startup boundaries.
- **Phase 1 Agent**: one standalone Elastic Agent for Application, Security, and System; an exact mutually compatible Elastic Stack and Elastic Agent version is selected at the Phase 1 version gate.
- **Network boundary**: Elasticsearch reachable only over the required host-only path; Kibana bound only to host loopback; no public service exposure.
- **Deferred management**: Fleet-managed Elastic Agent and Fleet Server.
- **Deferred telemetry/detection**: Sysmon, PowerShell, Defender, Sigma execution, Atomic Red Team, Suricata, Wazuh, and Kafka.

Future Docker Compose profiles may reflect the resource modes in README, but no Compose configuration currently exists.

## Phase Roadmap

### Phase 0: Local Lab Foundation

| Item | Detail |
| --- | --- |
| Goal | Prepare an isolated Windows victim VM and local Docker host, then document the isolation and resource baseline before any Phase 1 service or attack emulation. |
| Planned prerequisites | Supported VirtualBox host/guest setup, host-only adapter design, guest isolation procedure, Docker host prerequisites, and resource-budget assumptions. |
| Planned deliverables | Isolated victim VM, scoped host firewall baseline, Docker host readiness record, measured CPU/RAM/disk baseline, cleanup notes, and planned `docs/phase-0-environment.md` with linked evidence. |
| Success criteria | Bidirectional host-only communication and intended guest isolation are demonstrated; resource measurements are recorded; no service is publicly exposed; no Phase 1 service is required to be running. |
| Status | `Runtime verified` |
| Evidence | `docs/phase-0-environment.md`: `PHASE 0 RUNTIME ENVIRONMENT COMPLETE`, bidirectional host-only ping passed |
| Evidence rule | Do not upgrade the status until the planned artifact exists and its linked evidence has been reviewed. |

Current RAM figures in README are planning estimates, not preflight measurements.

### Phase 1: Live Telemetry Ingestion and ECS Verification

| Item | Detail |
| --- | --- |
| Goal | Ingest real Application, Security, and System events through one standalone Elastic Agent; verify required integration assets and ingest behavior; store events in Elasticsearch; and verify searchability and planned ECS field groups in Kibana. |
| Planned deliverables | An exact mutually compatible Elastic Stack and Elastic Agent version selected at the Phase 1 version gate, reviewed standalone policy, asset/version verification notes, planned `normalization/ecs_mapping.md`, and planned `docs/phase-1-verification.md`. |
| Success criteria | Recent events from all three planned channels are searchable with consistent host/Agent identity and source timestamps; required assets are present; mapping results and gaps are documented. |
| Status | `Future` |
| Claim boundary | Phase 1 may reach `Runtime verified` only for telemetry ingestion and ECS verification after all relevant readiness gates pass, real events from all three planned channels are collected, source timestamps, host/Agent identity, and planned ECS field groups are checked, and the evidence artifact is reviewed. It makes no detection, alert-generation, MITRE coverage, or `Live verified` claim; ingestion verification does not prove a detection rule works. |

#### Phase 1 pre-implementation gates

Most gates below are now passed. Elastic `9.4.2` is deployed and authenticating, Sysmon
`15.21` is installed with its signature and version verified inside the VM, the Agent uses
a least-privilege API key, and both services publish only on the host-only address.

Two gates remain deliberately open and are recorded rather than quietly dropped:

- **TLS identity.** Not enabled. Elastic no longer requires TLS for API keys or alerting
  and the lab is host-only, so this was accepted as a known gap in `docs/adr-001-detection-executor.md`.
  It must be closed before any transport-security claim.
- **Data stream naming vs integration assets.** The lab writes custom datasets
  (`windows.sysmon`) that do not match the real integration data streams, so no integration
  ingest pipeline runs. This is why ECS normalization is still `Future`.

Any gate that is not passed blocks artifact acquisition, configuration generation, service startup, firewall changes, Agent installation, and live ingestion. It does not block separately approved documentation work.

| Gate | Required record before implementation |
| --- | --- |
| Supported Windows version | Record the exact victim edition/build and confirm official support for the selected Elastic Agent artifact. |
| Exact artifact availability | Confirm official Elasticsearch, Kibana, and Windows Elastic Agent artifacts exist for each exact selected version and platform. |
| Version compatibility | Confirm Elasticsearch, Kibana, Elastic Agent, and required integration-package compatibility for the exact versions selected. |
| Checksum verification | Record the official checksum source and verify each acquired artifact before use. |
| Signature verification | Use signature verification only when Elastic provides an official mechanism for that exact artifact; otherwise record that no official mechanism was identified. |
| CPU/RAM/disk preflight | Measure available host and guest resources and compare them with the planned resource mode before startup. |
| Docker host limits | Record Docker engine/desktop limits and ensure they leave enough capacity for the selected VM mode. |
| Elasticsearch binding | Restrict the listener to the required host-only path; no wildcard/public bind is acceptable. |
| Kibana binding | Restrict Kibana to host loopback. |
| Firewall scope | Limit the allow rule to the victim VM source and only the required Elasticsearch port. |
| TLS identity | Ensure certificate SANs match the hostname or host-only IP the Agent uses. |
| API key and secrets | Define least-privilege credentials, storage, rotation/revocation, and redaction handling. |
| Repository secret safety | Confirm no password, token, API key, private key, or machine-sensitive value is committed. |
| Artifact transfer | Define controlled or offline transfer into the isolated VM and record artifact provenance. |
| Data stream/index naming | Record the expected integration data streams/index patterns before writing verification queries. |
| Timestamp and clock | Verify UTC handling, Windows source timezone, host/guest clocks, and any observed skew. |
| Windows logging prerequisites | Record enabled channels and required audit/logging policy before expecting events. |
| Rollback and cleanup | Define Agent/service removal, credential revocation, firewall rollback, artifact cleanup, and evidence retention steps. |

Version-dependent standalone policy, integration-package, and Fleet UI behavior must be verified for the exact versions selected at this gate rather than inferred from another release or an integration-package version.

#### Standalone Agent and Fleet boundary

- Phase 1 uses one standalone Elastic Agent with manual policy and binary lifecycle management.
- Fleet-managed Agent enrollment and Fleet Server are deferred. Fleet Server is not a prerequisite for this standalone path.
- Kibana Integrations/Fleet UI may be used to install integration package assets, create a policy, and export a standalone policy without enrolling the Agent in Fleet Server.
- Required ingest pipelines, index templates, and other integration assets must exist before ingestion is accepted as valid.
- The exact workflow remains subject to the version gate.

#### Planned telemetry contract

This contract defines what Phase 1 must verify; it does not claim exact ECS mappings or Event IDs before official documentation and live events are reviewed.

| Source | Windows channel | Planned prerequisite | Expected events | Planned ECS field groups to verify | Verification method | Allowed conclusion if absent |
| --- | --- | --- | --- | --- | --- | --- |
| Application | `Application` | Channel enabled; relevant application/provider logging active | Application/provider event categories; exact IDs recorded only when justified by official documentation and the selected verification activity | `@timestamp`, `event.*`, `host.*`, `agent.*`, and applicable Windows event fields such as `winlog.*` | Query the planned data stream over a recorded UTC window; filter by host, channel, provider/category, and inspect the source document | Record a logging prerequisite, collection, or normalization gap; do not call it a detection miss |
| Security | `Security` | Channel accessible to the Agent; required Windows audit subcategories enabled | Security audit categories relevant to the approved verification activity; exact IDs require official support and enabled-policy evidence | `@timestamp`, `event.*`, `host.*`, `agent.*`, user/process fields when applicable, and applicable `winlog.*` fields | Query by host/channel over a recorded UTC window and compare enabled audit policy with returned source documents | Record an audit prerequisite, permission, collection, or normalization gap; do not call it a detection miss |
| System | `System` | Channel enabled; relevant OS/service/provider logging active | Operating-system, service, driver, or provider categories; exact IDs require official support for the selected verification activity | `@timestamp`, `event.*`, `host.*`, `agent.*`, and applicable `winlog.*` fields | Query by host/channel/provider over a recorded UTC window and inspect representative source documents | Record a logging prerequisite, collection, or normalization gap; do not call it a detection miss |

All unresolved source-to-ECS mappings are planned verification work for `normalization/ecs_mapping.md`.

### Phase 2: Sigma Conversion, Detection Execution, and Alert Persistence

| Item | Detail |
| --- | --- |
| Goal | Implement one initial Sigma rule, convert it into a target query or deployable format, run it through a separately selected executor, and persist minimal alerts from live Elasticsearch events. |
| Planned deliverables before MVP | One initial rule in planned `rules/`, conversion command/config, executor decision record and implementation, query-window and deduplication behavior, minimal alert store/index, unit checks for rule syntax/conversion, and planned `docs/phase-2-verification.md`. |
| Success criteria | The conversion output is reviewable; the selected executor runs a controlled query window, applies documented deduplication, and persists an alert during approved runtime smoke/manual validation. |
| Maximum phase status | `Runtime verified` |
| Claim boundary | Manual behavior validation in Phase 2 must not receive `Live verified`, even when it produces real telemetry and an alert. |

Sigma is the detection rule format. `pySigma`/`sigma-cli` and a compatible backend perform conversion. They do not by themselves monitor Elasticsearch, schedule detections, suppress duplicate matches, or create alert records.

#### Phase 2 initial-rule selection gate

No initial Sigma rule may be selected until reviewed Phase 1 telemetry evidence confirms:

- The required Windows channel or data stream exists.
- The required event category and Event IDs, when applicable, actually appear.
- The required ECS/source fields exist and contain usable values.
- The Sigma `logsource`, field names, and processing pipeline align with the observed telemetry.
- The rule does not depend on Sysmon, PowerShell Operational, or other deferred telemetry unless the user approves a roadmap change.

The initial rule must be selected from telemetry proven available; this plan does not select that rule.

#### Phase 2 architecture decision gate

**Resolved on `2026-08-02`.** The preferred path was taken: the Elastic Security detection
engine is the executor, with Sigma converted by `sigma-cli` into `siem_rule_ndjson` and
imported through the Kibana API. The decision, the four checks that justified it, and the
rejected custom-executor alternative are recorded in `docs/adr-001-detection-executor.md`.

Deduplication, alert persistence, and error handling are provided by the detection engine
rather than by this project's code. Deployment and execution are `Runtime verified`; the
deduplication behaviour itself has still not been directly exercised by a repeat scenario
and remains an open verification item.

The original gate text follows for reference.

| Path | Condition | Trade-off |
| --- | --- | --- |
| Preferred: Elastic Security detection rules generated/imported from compatible Sigma output | Use only if the Phase 1 selected-version gate confirms a supported and suitable conversion/import workflow | Reuses native scheduling and alert lifecycle, but depends on exact-version compatibility and supported rule semantics |
| Fallback: custom scheduled executor | Use if the preferred path is unsupported or unsuitable and the additional implementation scope is approved | Makes query windows, deduplication, and alert persistence explicit, but adds code, tests, security handling, and operational ownership |

Whichever path is approved must:

1. Run converted detection logic on a documented schedule or invocation.
2. Record the query time window.
3. Define an alert deduplication method/key.
4. Persist the rule ID, source document IDs, timestamps, and execution context.
5. Handle errors without silently losing or fabricating alert records.

Only after the complete Phase 3 MVP loop succeeds may the rule set expand from one initial rule to 3-5 rules.

### Phase 3: First Atomic-Backed Rule-Scenario Validation

| Item | Detail |
| --- | --- |
| Goal | Run one separately approved Atomic Red Team test in the isolated victim VM, exercise the Phase 2 path, and produce the first complete evidence bundle. |
| Planned deliverables | Scenario runbook with technique ID and Atomic test number, planned `docs/phase-3-scenario-log.md`, linked source events, alert record when detected, analyst note, MITRE mapping, first coverage entry, and gap/validation note. |
| Success criteria | The scenario has a stable ID and lab session ID; attack and telemetry times are recorded in UTC; alert timestamp semantics match the detection result; the exact rule version and query window are known; the result is `detected`, `missed`, or `partial`; evidence is redacted and reviewable. |
| Status | `Future` |
| Claim boundary | This is the first phase in which one specific rule-scenario pair may become `Live verified`. The phase, platform, rule collection, and MITRE technique remain unverified as broader claims. |

#### Phase 3 scenario-alignment gate

Before Phase 3 begins, a reviewed alignment record must link:

- The Atomic test number and expected behavior.
- The required telemetry source and expected source events/fields.
- The Sigma rule ID/version.
- The converted query or deployable rule format.
- The detection query window and expected alert behavior.
- The cleanup procedure.
- Explicit approval for the exact run.

Only after the telemetry-rule-scenario alignment is reviewed may the exact Atomic Red Team run proceed. No documentation approval authorizes attack execution.

## MVP Checkpoint

MVP is reached only when one approved Atomic Red Team test has:

- A stable scenario ID and lab session ID.
- MITRE technique ID and Atomic test number.
- Attack execution, telemetry arrival, and alert timestamps when detected.
- One linked Sigma rule ID and rule version/hash.
- Source event/document IDs and query time window.
- Documented deduplication behavior.
- An analyst triage note.
- A `detected`, `missed`, or `partial` result.
- One evidence-backed coverage entry.
- One documented gap or validation note.

This checkpoint must succeed before expanding to 3-5 rules, Suricata, Wazuh, Kafka, or the optional API/dashboard workstream.

## Evidence Model

Each Phase 3 scenario must use one portfolio-scale evidence bundle.

| Field | Convention |
| --- | --- |
| Scenario ID | Stable identifier for the scenario run and related files |
| Lab session ID | Stable identifier connecting the VM/session/date and environment notes |
| MITRE technique ID | Technique exercised by the approved scenario |
| Atomic test number | Exact Atomic Red Team test selected for the approved run |
| Rule identity | Sigma rule ID plus version or content hash |
| Attack execution timestamp | UTC ISO 8601 |
| Telemetry arrival timestamp | UTC ISO 8601 |
| Alert timestamp | Required UTC ISO 8601 for `detected`; `not applicable` for `missed`; for `partial`, recorded only when an alert exists |
| Rule execution result | Executor/rule outcome for the query window, including the absence of an alert for `missed` |
| Source time context | Source host timezone and a clock-skew note |
| Query time window | Explicit start/end or equivalent lookback interval used by the executor |
| Alert deduplication | Documented method and key |
| Source references | Elasticsearch document IDs and applicable source event IDs |
| Evidence artifact path | Repository-relative path to the scenario log, query export, alert note, or supporting screenshot |
| Evidence hash | Optional SHA-256 for important exported evidence |
| Analyst triage note | Short assessment tied to the scenario, alert, and supporting events |
| Detection result | `detected`, `missed`, or `partial` |
| Gap category | `telemetry gap`, `normalization gap`, `rule logic gap`, or `scenario limitation` |
| Redaction | Remove credentials, tokens, personal data, and sensitive machine identifiers before committing evidence |

A `detected` result requires an alert timestamp. A `missed` result records the alert timestamp as `not applicable` and includes the query window, rule execution result, and confirmation that no alert existed in that window. A `partial` result records the alert timestamp when an alert exists; otherwise it identifies which expected path was observed and which part was missing. Never use a fabricated or placeholder alert timestamp.

A screenshot is supporting evidence only. It is not standalone proof unless it links to the corresponding query, source event/document, and scenario run.

Phase 3 produces the first evidence bundle and evidence-backed coverage entry; Phase 4 expands them into a coverage and gap-analysis workflow.

### Phase 4: MITRE Coverage and Gap Analysis

| Item | Detail |
| --- | --- |
| Goal | Turn complete scenario evidence bundles into a small, honest MITRE ATT&CK coverage matrix and gap-analysis workflow. |
| Planned deliverables | Planned `mitre/coverage.md`, evidence-linked gap notes, and rule-improvement entries with before/after evidence. |
| Success criteria | Every coverage entry links to a complete scenario bundle; every gap explains whether it comes from telemetry, normalization, rule logic, or scenario limitations. |
| Status | `Future` |
| Metric boundary | Coverage metrics remain `Not measured yet` until the documented sample is sufficient for the stated measurement. |

### Optional Post-MVP Workstream: Alert-Triage API and Dashboard

| Item | Detail |
| --- | --- |
| Goal | Add a minimal local API and SOC-style dashboard for reviewing persisted alerts and evidence after the core MVP is complete. |
| Planned deliverables | Minimal alert-reading API, local-only dashboard, and evidence links; exact stack remains undecided. |
| Entry gate | Complete the Phase 3 MVP evidence loop first. |
| Status | `Future` (optional) |
| Scope boundary | This workstream does not block the first evidence-backed detection loop and must never be publicly exposed. |

### Phase 5: Suricata Network Telemetry

| Item | Detail |
| --- | --- |
| Goal | Add Suricata as a second real telemetry source for a scenario that needs network visibility. |
| Planned deliverables | EVE JSON ingestion/ECS verification, one relevant rule-scenario pairing, and linked evidence. |
| Success criteria | A scenario run with separate explicit approval for that exact run produces reviewable network telemetry and an evidence-linked result. |
| Status | `Future` |
| Entry gate | Do not start before the MVP checkpoint; validate actual resource use before deciding whether Suricata may share an Elastic session. |

### Phase 6: Wazuh Host Log / FIM Telemetry

| Item | Detail |
| --- | --- |
| Goal | Evaluate Wazuh as a complementary host-log/FIM source in a separately staged session. |
| Planned deliverables | Wazuh deployment decision, host integration, ECS adapter or correlation notes, and one relevant evidence-linked scenario. |
| Success criteria | A scenario run with separate explicit approval for that exact run produces a reviewable Wazuh result linked to the common evidence format. |
| Status | `Future` |
| Entry gate | Do not start before MVP; validate resources before deciding the final service-switching procedure. |

### Phase 7: Kafka Event Streaming Layer

| Item | Detail |
| --- | --- |
| Goal | Optionally evaluate Kafka as a transport layer after the detection loop is evidence-backed. |
| Planned deliverables | If approved, minimal topics and producer/consumer flow for an existing event path. |
| Success criteria | A previously evidence-backed event path crosses Kafka without an unsupported data-loss claim. |
| Status | `Future` (optional) |
| Entry gate | Post-MVP only; skip unless architecture breadth is worth the additional operational scope. |

### Phase 8: Portfolio Packaging

| Item | Detail |
| --- | --- |
| Goal | Package evidence-backed work into an interview-ready demo without overstating scope. |
| Planned deliverables | Demo runbook, recordings when available, planned `docs/portfolio-report.md`, and interview notes. |
| Success criteria | A reviewer can trace every published capability and metric claim to repository evidence. |
| Status | `Future` |
| Entry gate | Requires MVP and enough additional evidence to support the claims included. |

## Metrics

Metric rows remain separate from phase capability statuses.

| Metric | Status | Planned measurement method |
| --- | --- | --- |
| MITRE technique coverage | `Not measured yet` | Distinct MITRE techniques executed with at least one evidence-backed `detected` rule-scenario result divided by all distinct MITRE techniques executed in the declared sample |
| Scenario detection rate | `Not measured yet` | Approved scenarios with result `detected` divided by all approved scenarios executed in the declared sample |
| False positive rate | `Not measured yet` | Analyst-reviewed alerts confirmed as false positives divided by all analyst-reviewed alerts in the same declared benign-activity window |
| MTTD | `Not measured yet` | Alert timestamp minus attack execution timestamp for `detected` scenarios only, with sample scope and timezone convention recorded |
| Gaps found/closed | `Not measured yet` | Evidence-linked gap count and before/after closure count |

Use `Measured` only after the method, sample, and evidence links are present.

## Primary Technical References

- Elastic release/download and platform support: [Elastic past releases](https://www.elastic.co/downloads/past-releases) and [Elastic Support Matrix](https://www.elastic.co/support/matrix).
- Standalone Agent policy and integration assets: [Create a standalone Elastic Agent policy](https://www.elastic.co/docs/reference/fleet/create-standalone-agent-policy) and [Best practices for integration assets](https://www.elastic.co/docs/reference/fleet/integrations-assets-best-practices).
- Elastic Security rule execution and import: [Create a detection rule](https://www.elastic.co/guide/en/security/current/rules-ui-create.html/) and [Manage detection rules](https://www.elastic.co/docs/solutions/security/detect-and-alert/manage-detection-rules).
- Sigma/pySigma conversion: [Sigma documentation](https://sigmahq.io/docs/), [Backends](https://sigmahq.io/docs/digging-deeper/backends), and [Processing Pipelines](https://sigmahq.io/docs/digging-deeper/pipelines.html).
- Atomic Red Team test metadata, prerequisites, permissions, and cleanup: [Atomic Red Team documentation](https://www.atomicredteam.io/docs/atomic-red-team), [Check Prerequisites](https://www.atomicredteam.io/docs/invoke-atomicredteam/check-prereqs), and [Cleanup](https://www.atomicredteam.io/docs/invoke-atomicredteam/cleanup).
- MITRE ATT&CK identifiers: [Enterprise Techniques](https://attack.mitre.org/techniques/).

These sources establish the baseline workflow but do not prove behavior for an unselected exact version. Version-specific behavior must be verified at the Phase 1 version gate.

## Risks and Planned Controls

| Risk | Planned control |
| --- | --- |
| Unsupported capability claims | Require the taxonomy and linked evidence before any status upgrade |
| Fixture results presented as detection evidence | Limit fixtures/unit tests to engineering checks and keep them out of coverage claims |
| Unsafe attack emulation | Require explicit approval for the exact Atomic run and host-only isolation |
| Public exposure | Restrict Elasticsearch to the required host-only path and Kibana/API/dashboard to host loopback |
| Resource exhaustion | Measure resources during preflight and later implement staged startup; no current Compose enforcement is claimed |
| Secret disclosure | Define least-privilege secret handling and redact repository artifacts |
| Scope creep | Require the MVP checkpoint before 3-5 rules, additional telemetry, Kafka, or optional UI work |
| Metric fabrication | Keep metrics `Not measured yet` until method, sample, and linked evidence exist |

## Next Project Gates

1. Complete a final trust review of this documentation baseline.
2. After separate approval, plan Phase 0 evidence collection without starting Phase 1 services.
3. Complete and review the Phase 0 deliverable before any capability status upgrade.
4. Select exact mutually compatible Elastic Stack and Elastic Agent versions and pass all Phase 1 pre-implementation gates before acquiring artifacts or changing runtime state.
5. Use reviewed Phase 1 telemetry evidence to pass the initial-rule selection gate, then resolve the Phase 2 executor architecture gate before implementing detection execution.
6. Review the telemetry-rule-scenario alignment and obtain exact-run approval before Phase 3 execution.

No item in this plan authorizes VM, Docker, service, firewall, network, artifact, or Atomic Red Team changes.

## Documentation Ownership

- `README.md`: project identity, current repository state, target architecture summary, status model, resource modes, safety boundaries, and roadmap link.
- `PROJECT_PLAN.md`: roadmap, gates, dependencies, success criteria, evidence requirements, and future work.
- `AGENTS.local.md`: project-specific agent behavior and safety boundaries.
- `CONTEXT.md`: non-authoritative working state, approved decisions, unresolved gates, changed files, validation results, and next approved step.
