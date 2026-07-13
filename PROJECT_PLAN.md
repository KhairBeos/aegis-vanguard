# AEGIS-VANGUARD Project Plan

## Why This Plan Exists

The first version of this project relied on hand-crafted fixture events labeled `Offline verified`, which created the appearance of detection capability without ever proving it against real telemetry. This plan removes that failure mode by making **live, real telemetry the only source of truth from Phase 1 onward**, and by running the lab entirely on local infrastructure (VirtualBox + Docker) instead of a promotional cloud credit with an uncertain expiry.

## Goal

Build a fully local SIEM-like SOC lab that proves, with real timestamped evidence, the path from controlled attack execution to SOC-style detection and review: collect telemetry, normalize to ECS, apply Sigma rules, generate alerts, triage evidence, investigate related events, map detections to MITRE ATT&CK, produce evidence-backed coverage notes, and document detection gaps.

The goal is portfolio-scale evidence, not enterprise-scale coverage.

## Design Principles

1. **Real telemetry from day one.** Fixtures/unit tests exist only to check parsing and rule syntax, and are explicitly never cited as detection evidence.
2. **Standards over invented formats.** ECS for data, Sigma for detection logic, MITRE ATT&CK for mapping.
3. **Fully local, fully isolated.** Windows victim VM on a VirtualBox host-only network; no cloud hosting, no public IP ever involved in attack emulation.
4. **Resource-staged, not resource-parallel.** Only the components needed for the current phase/session run at once (see Resource Modes in README).
5. **No invented metrics.** Coverage %, false positive rate, and MTTD are `Not measured yet` until real scenario logs with timestamps exist.
6. **SOC workflow without production claims.** Triage, investigation, coverage, and gap analysis are modeled honestly as a local learning lab, not as a production SIEM, commercial SIEM, commercial EDR, or enterprise SOC platform.

## Core Story

> Given a specific MITRE ATT&CK technique, executed for real against an isolated Windows VM, can this local SIEM-like pipeline collect the telemetry, normalize it, alert on it, support triage and investigation, and explain what was detected or missed?

## Environment Setup (Phase 0 detail)

- **Victim VM**: Windows 10/11, VirtualBox, host-only adapter (no bridged/NAT to the internet during scenario sessions). Install Sysmon with a documented community config and Elastic Agent enrolled to a local Fleet server.
- **Docker host**: same laptop, Docker Desktop or Docker Engine. Services brought up via `docker compose --profile <name>` so only the needed group runs.
- **Networking**: Elastic Agent on the victim VM reaches the Fleet server/Elasticsearch container via a host-only or NAT network route reachable only from the VM and host, never exposed to the internet.

Recommended future `docker-compose.yml` profile groups:

```yaml
# profile: elastic   -> elasticsearch, kibana, fleet-server
# profile: wazuh     -> wazuh-manager, wazuh-indexer, wazuh-dashboard
# profile: suricata  -> suricata (lightweight, can join "elastic" sessions)
# profile: kafka     -> kafka, zookeeper (stretch goal, own session)
```

## Phase Roadmap

### Phase 0: Local SIEM Lab Foundation / Environment Setup

| Item | Detail |
| --- | --- |
| Goal | Stand up the isolated Windows victim VM and local Docker host, with networking verified before any attack emulation. |
| Deliverables | VirtualBox VM (host-only network), Sysmon installed, Docker Compose skeleton with profiles, `docs/phase-0-environment.md` recording exact versions and network config. |
| Success check | Victim VM can reach the Docker host's Elasticsearch/Fleet endpoint and nothing attack-related is exposed to the public internet. |
| Status | `Future` |
| Gaps | Not started. |

### Phase 1: Live Telemetry Ingestion + ECS Normalization

| Item | Detail |
| --- | --- |
| Goal | Get real Sysmon telemetry from the victim VM into Elasticsearch and document ECS field mapping decisions with no fixture involved. |
| Deliverables | Elastic Agent enrolled and shipping data; `normalization/ecs_mapping.md` documenting field mapping decisions, deviations, and source fields. |
| Success check | Manually trigger a benign action on the victim VM, such as launching `cmd.exe`, and confirm the resulting ECS event appears in Elasticsearch with a logged timestamp in `docs/phase-1-verification.md`. |
| Status | `Future` |
| Gaps | Not started. This replaces the old fixture-based `Offline verified` claim entirely; the first proof point must be a real, manually triggered event. |

### Phase 2: Sigma Detection + Alert Generation

| Item | Detail |
| --- | --- |
| Goal | Write Sigma rules, compile with `pySigma`, and generate alerts from live Elasticsearch events rather than fixture files. |
| Deliverables | 3-5 Sigma rules in `rules/*.yml` covering common techniques such as encoded PowerShell, suspicious parent-child process behavior, and LOLBin abuse; unit tests for rule YAML syntax only. |
| Success check | Manually trigger the exact behavior a rule targets on the victim VM and confirm a real alert fires against the live index, timestamped in `docs/phase-2-verification.md`. |
| Status | `Future` |
| Gaps | Not started. Unit tests here are labeled `Unit tested`, never `Live verified`; that label is reserved for the manual trigger + real alert step. Start with one rule for the first live-verified loop, then expand to 3-5 rules after the first alert path works. |

### Phase 3: SOC Triage Workflow + Atomic Red Team Validation

| Item | Detail |
| --- | --- |
| Goal | Run a controlled Atomic Red Team test for at least one technique, generate a real alert, and record the evidence needed for SOC-style triage and investigation. |
| Deliverables | `scenarios/` runbook per technique (technique id, atomic test number, expected telemetry, expected rule), `docs/phase-3-scenario-log.md` with attack/telemetry/alert timestamps per run, and triage notes linking alert context to supporting events. |
| Success check | For each executed technique: attack execution timestamp, telemetry arrival timestamp, alert timestamp, linked Sigma rule, MITRE technique id, and triage note are all recorded. |
| Status | `Future` |
| Gaps | This is the first complete live detection loop and must happen before Suricata, Wazuh, or Kafka work starts. |

## MVP Checkpoint

MVP is done when one Atomic Red Team technique has all of the following:

- Attack execution timestamp.
- Telemetry arrival timestamp.
- Alert timestamp.
- Linked Sigma rule.
- MITRE technique mapping.
- One `coverage.md` entry.
- One documented gap or validation note.

This checkpoint is the minimum evidence needed before expanding telemetry sources or claiming any coverage value.

## Evidence Model

Every live scenario should produce one evidence bundle:

| Field | Purpose |
| --- | --- |
| Scenario id | Stable id for the scenario run and related notes |
| Lab session id | Identifier for the VM/session/date used to connect timestamps and environment notes |
| MITRE technique id | ATT&CK technique being tested |
| Atomic test number | Atomic Red Team test executed inside the isolated lab |
| Attack execution timestamp | When the technique was executed |
| Telemetry arrival timestamp | When matching source telemetry reached the pipeline |
| Alert timestamp, if detected | When the Sigma detection workflow generated an alert |
| Sigma rule id | Rule expected to match or explain the miss |
| Source event ids | Event ids or document ids used as supporting evidence |
| Evidence file path | Path to the scenario log, alert note, screenshot, or exported query result used as proof |
| Analyst triage note | Short SOC-style assessment of what happened |
| Detection result | `detected`, `missed`, or `partial` |
| Gap reason | `telemetry gap`, `normalization gap`, `rule logic gap`, or `scenario limitation` |

Phase 3 produces the evidence bundle; Phase 4 turns those evidence bundles into coverage and gap-analysis reports.

### Phase 4: MITRE Coverage + Gap Analysis

| Item | Detail |
| --- | --- |
| Goal | Turn live scenario results into a small, honest MITRE ATT&CK coverage matrix and gap-analysis workflow. |
| Deliverables | `mitre/coverage.md` populated from scenario logs, gap notes for missed telemetry or weak rules, and rule-improvement entries tied to before/after evidence. |
| Success check | Every coverage entry links back to a real scenario log and every gap entry explains whether the miss came from telemetry, normalization, rule logic, or scenario limitations. |
| Status | `Not measured yet` |
| Gaps | Waits on Phase 3's first complete live scenario log. No percentage is allowed until enough real runs exist to support it. |

### Phase 5: Suricata Network Telemetry

| Item | Detail |
| --- | --- |
| Goal | Add Suricata as a second real telemetry source after the first host-based live detection loop is proven. |
| Deliverables | Suricata EVE JSON to ECS pipeline, plus a rule/scenario pairing that specifically needs network visibility, such as a controlled C2/beaconing-style pattern. |
| Success check | A real Suricata alert for a manually triggered network pattern appears in the same evidence workflow and links to a scenario log. |
| Status | `Future` |
| Gaps | Do not start before the MVP checkpoint. Suricata can run alongside the Elastic stack because it is lightweight enough for the resource budget. |

### Phase 6: Wazuh Host Log / FIM Telemetry

| Item | Detail |
| --- | --- |
| Goal | Add Wazuh for host-based log collection and file integrity monitoring as a complementary, real telemetry source. |
| Deliverables | Wazuh agent on the victim VM, Wazuh-to-ECS adapter or direct correlation notes, and a scenario pairing that benefits from FIM, such as persistence via scheduled task or registry run key. |
| Success check | A real Wazuh alert for a manually triggered FIM-relevant change is recorded and linked to the same scenario log format used in Phase 3. |
| Status | `Future` |
| Gaps | **Run in its own Docker session**; do not run Wazuh's indexer alongside the Elasticsearch stack. Sequence: stop `elastic` profile, start `wazuh` profile, test, then switch back. |

### Phase 7: Kafka Event Streaming Layer (Stretch)

| Item | Detail |
| --- | --- |
| Goal | Insert Kafka as an optional transport layer between telemetry sources and storage to demonstrate event-streaming architecture skill. |
| Deliverables | Kafka topics for raw, normalized, and alert events; producer/consumer workers. |
| Success check | A real event from a completed earlier phase flows through Kafka into storage with no data loss, logged. |
| Status | `Future` (optional) |
| Gaps | Only attempt after the first SIEM/SOC loop is evidence-backed. This adds architecture breadth, not detection-engineering depth; treat it as a bonus, not a blocker for portfolio readiness. |

### Phase 8: Portfolio Packaging

| Item | Detail |
| --- | --- |
| Goal | Package the lab into an interview-ready demo without overstating scope. |
| Deliverables | Demo runbook, screen recordings of 2-3 full scenario runs when available, final `docs/portfolio-report.md` with real MITRE coverage numbers and honest gaps, interview talking points. |
| Success check | A reviewer can watch a recording or follow the runbook and independently trace every claim to linked evidence files. |
| Status | `Future` |
| Gaps | Waits on MVP plus enough additional live scenario runs to support the report. |

## Metrics (populate only from real scenario logs)

| Metric | Status | Measurement method |
| --- | --- | --- |
| MITRE technique coverage | `Not measured yet` | Detected techniques divided by techniques executed via real Atomic Red Team runs |
| False positive rate | `Not measured yet` | Alerts fired during a defined benign-activity window on the live victim VM |
| MTTD | `Not measured yet` | Alert timestamp minus attack execution timestamp, averaged across scenario runs |
| Gaps found / closed | `Not measured yet` | Count of scenario misses, then count resolved by a rule/telemetry change, each with a before/after log |

## Interview Story Template

- **Situation**: My first version of this lab used fixture data to "verify" detection, which I recognized did not actually prove detection capability.
- **Task**: Rebuild it as a local SIEM-like SOC lab that proves each detection claim with real telemetry and timestamped evidence.
- **Action**: Build an isolated Windows VM lab with Sysmon + Elastic Agent, normalize events to ECS, write Sigma rules, run Atomic Red Team tests, and record the alert triage and investigation trail.
- **Result**: Fill in only with the actual current phase, such as: "One technique is live-verified with attack, telemetry, and alert timestamps; the next gap is documented in `coverage.md`."

## Risks and Controls

| Risk | Control |
| --- | --- |
| Silent regression to fixture-based claims | Any status label of `Live verified` must link to a scenario log file with three timestamps: attack, telemetry, alert. PR/commit review checklist includes this. |
| RAM exhaustion from running everything at once | Docker Compose profiles enforce staged startup; README resource table is the reference budget. |
| Unsafe attack emulation | Victim VM network is host-only, never bridged to the internet during scenario sessions. |
| Scope creep before core loop works | Suricata, Wazuh, and Kafka are explicitly gated behind the MVP checkpoint and first live-verified detection loop. |
| Metric fabrication | Metrics table stays `Not measured yet` until scenario logs exist; no percentage is written without a linked file. |
| Overstating SOC maturity | Documentation must say SIEM-like/SOC-style lab, not production SIEM, commercial EDR, or enterprise SOC platform. |

## Next Immediate Actions

1. Create Phase 0 documentation and evidence templates.
2. Set up the VirtualBox victim VM and confirm network isolation (Phase 0).
3. Enroll Elastic Agent and get the first real ECS event flowing (Phase 1).
4. Write and live-verify the first Sigma alert against manually triggered behavior (Phase 2).
5. Run one Atomic Red Team scenario and produce the first scenario log, triage note, MITRE mapping, coverage entry, and documented gap or validation note (Phase 3 MVP).
6. Only after the MVP checkpoint: expand MITRE coverage/gap analysis, then add Suricata, Wazuh, and optionally Kafka.
