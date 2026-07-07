# AEGIS-VANGUARD Project Plan (v2 — Real-First, Full Local)

## Why v2 Exists

The first version of this project relied on hand-crafted fixture events labeled `Offline verified`, which created the appearance of detection capability without ever proving it against real telemetry. v2 removes that failure mode by making **live, real telemetry the only source of truth from Phase 1 onward**, and by running entirely on local infrastructure (VirtualBox + Docker) instead of a promotional cloud credit with an uncertain expiry.

## Goal

Prove, with real timestamped evidence, the full path from a controlled MITRE ATT&CK technique to a validated detection — using the same building blocks a real SOC uses (ECS, Sigma, MITRE ATT&CK, Atomic Red Team) — sized to run entirely on a 16GB laptop.

## Design Principles

1. **Real telemetry from day one.** Fixtures/unit tests exist only to check parsing and rule syntax, and are explicitly never cited as detection evidence.
2. **Standards over invented formats.** ECS for data, Sigma for detection logic, MITRE ATT&CK for mapping.
3. **Fully local, fully isolated.** Windows victim VM on a VirtualBox host-only network; no cloud hosting, no public IP ever involved in attack emulation.
4. **Resource-staged, not resource-parallel.** Only the components needed for the current phase/session run at once (see Resource Modes in README).
5. **No invented metrics.** Coverage %, false positive rate, and MTTD are `Not measured yet` until a real scenario log with timestamps exists.

## Core Story

> Given a specific MITRE ATT&CK technique, executed for real against an isolated Windows VM, what does my pipeline detect, what does it miss, and what do I change to close the gap?

## Environment Setup (Phase 0 detail)

- **Victim VM**: Windows 10/11, VirtualBox, host-only adapter (no bridged/NAT to the internet during scenario sessions). Install Sysmon (with a well-known community config, e.g. SwiftOnSecurity's, documented as a dependency) and Elastic Agent enrolled to a local Fleet server.
- **Docker host**: same laptop, Docker Desktop or Docker Engine. Services brought up via `docker compose --profile <name>` so only the needed group runs (see profiles below).
- **Networking**: Elastic Agent on the victim VM reaches the Fleet server/Elasticsearch container via a host-only or NAT network route reachable only from the VM and host — never exposed to the internet.

Recommended `docker-compose.yml` profile groups:

```yaml
# profile: elastic  -> elasticsearch, kibana, fleet-server
# profile: wazuh     -> wazuh-manager, wazuh-indexer, wazuh-dashboard
# profile: suricata  -> suricata (lightweight, can join "elastic" sessions)
# profile: kafka      -> kafka, zookeeper (stretch goal, own session)
```

## Phase Roadmap

### Phase 0: Environment Setup

| Item | Detail |
| --- | --- |
| Goal | Stand up the isolated Windows victim VM and the local Docker host, with networking verified. |
| Deliverables | VirtualBox VM (host-only network), Sysmon installed, Docker Compose skeleton with profiles, `docs/phase-0-environment.md` recording exact versions and network config. |
| Success check | Victim VM can reach the Docker host's Elasticsearch container port and nothing else; host cannot reach the internet from the VM during a scenario session. |
| Status | `Future` |
| Gaps | Not started. |

### Phase 1: Live ECS Telemetry Ingestion

| Item | Detail |
| --- | --- |
| Goal | Get real Sysmon telemetry from the victim VM into Elasticsearch, ECS-mapped, with no fixture involved. |
| Deliverables | Elastic Agent enrolled and shipping data; `normalization/ecs_mapping.md` documenting field mapping decisions and any deviations. |
| Success check | Manually trigger a benign action on the victim VM (e.g. launch `cmd.exe`) and confirm the resulting ECS event appears in Elasticsearch within seconds, with a logged timestamp in `docs/phase-1-verification.md`. |
| Status | `Future` |
| Gaps | Not started. This replaces the old fixture-based "Offline verified" claim entirely — first proof point must be a real, manually-triggered event. |

### Phase 2: Sigma Detection Against Live Data

| Item | Detail |
| --- | --- |
| Goal | Write Sigma rules, compile with `pySigma`, and run them against the live Elasticsearch index — not against fixture files. |
| Deliverables | 3–5 Sigma rules in `rules/*.yml` covering common techniques (e.g. encoded PowerShell, suspicious parent-child process, LOLBin abuse). Unit tests for rule YAML syntax only. |
| Success check | Manually trigger the exact behavior a rule targets (e.g. run `powershell -enc ...` on the victim) and confirm a real alert fires against the live index, timestamped in `docs/phase-2-verification.md`. |
| Status | `Future` |
| Gaps | Not started. Unit tests here are labeled `Unit tested`, never `Live verified` — that label is reserved for the manual trigger + real alert step. |

### Phase 3: Controlled Atomic Red Team Scenarios + First Coverage Numbers

| Item | Detail |
| --- | --- |
| Goal | Run real Atomic Red Team tests for a small set of MITRE techniques matching the rules already written, and record what's detected vs. missed. |
| Deliverables | `scenarios/` runbook per technique (technique id, atomic test number, expected telemetry, expected rule), `docs/phase-3-scenario-log.md` with attack/telemetry/alert timestamps per run, first entries in `mitre/coverage.md`. |
| Success check | For each executed technique: attack execution timestamp, telemetry arrival timestamp, and alert timestamp (if detected) are all linked in the scenario log. |
| Status | `Future` |
| Gaps | This is the highest-value phase for interview credibility — prioritize it right after Phase 2, don't defer it to "later." |

### Phase 4: Suricata (Network Telemetry)

| Item | Detail |
| --- | --- |
| Goal | Add Suricata as a second real telemetry source (network layer), ECS-mapped into the same Elasticsearch index. |
| Deliverables | Suricata EVE JSON → ECS pipeline, a rule/scenario pairing that specifically needs network visibility (e.g. C2 beaconing pattern via Atomic Red Team's network tests). |
| Success check | A real Suricata alert for a manually-triggered network pattern appears in the same index, alongside host-based events. |
| Status | `Future` |
| Gaps | Runs in the same Docker session as the Elastic stack (lightweight enough, per resource budget). Do not start before Phase 3 has at least one full scenario log. |

### Phase 5: Wazuh (Host Log / FIM)

| Item | Detail |
| --- | --- |
| Goal | Add Wazuh for host-based log collection and file integrity monitoring as a complementary, real telemetry source. |
| Deliverables | Wazuh agent on the victim VM, Wazuh → ECS adapter or direct correlation notes, a scenario pairing that benefits from FIM (e.g. persistence via scheduled task or registry run key). |
| Success check | A real Wazuh alert for a manually-triggered FIM-relevant change is recorded, linked to the same scenario log format used in Phase 3. |
| Status | `Future` |
| Gaps | **Run in its own Docker session** — do not run Wazuh's indexer alongside the Elasticsearch stack (RAM budget, see README). Sequence: stop `elastic` profile, start `wazuh` profile, test, then switch back. |

### Phase 6: Kafka Event-Streaming Layer (Stretch Goal)

| Item | Detail |
| --- | --- |
| Goal | Insert Kafka as a transport layer between telemetry sources and storage, to demonstrate event-streaming architecture skill. |
| Deliverables | Kafka topics for raw/normalized/alert events, producer/consumer workers. |
| Success check | A real event from any Phase 1–5 source flows through Kafka into storage with no data loss, logged. |
| Status | `Future` (optional) |
| Gaps | Only attempt after Phases 1–5 form a working, evidence-backed loop. This phase adds architecture breadth, not detection-engineering depth — treat it as a bonus, not a blocker for portfolio readiness. |

### Phase 7: Portfolio Packaging

| Item | Detail |
| --- | --- |
| Goal | Package the lab into an interview-ready demo. |
| Deliverables | Demo runbook, screen recordings of at least 2–3 full scenario runs (attack → telemetry → alert, shown live), final `docs/portfolio-report.md` with real MITRE coverage numbers and honest gaps, interview talking points. |
| Success check | A reviewer can watch a recording or follow the runbook and independently verify every claim against a linked evidence file. |
| Status | `Future` |
| Gaps | Waits on Phases 1–5 at minimum. |

## Metrics (populate only from real scenario logs)

| Metric | Status | Measurement method |
| --- | --- | --- |
| MITRE technique coverage | `Not measured yet` | Detected techniques ÷ techniques executed via real Atomic Red Team runs |
| False positive rate | `Not measured yet` | Alerts fired during a defined benign-activity window on the live victim VM |
| MTTD | `Not measured yet` | Alert timestamp − attack execution timestamp, averaged across scenario runs |
| Gaps found / closed | `Not measured yet` | Count of scenario misses, then count resolved by a rule/telemetry change, each with a before/after log |

## Interview Story Template

- **Situation**: My first version of this lab used fixture data to "verify" detection, which I recognized didn't actually prove anything. I rebuilt it around real telemetry only.
- **Task**: Prove, with timestamped evidence, that a written Sigma rule detects a real, executed MITRE ATT&CK technique.
- **Action**: Built an isolated Windows VM lab with Sysmon + Elastic Agent, wrote ECS-mapped Sigma rules, and ran Atomic Red Team tests against it, logging every run.
- **Result**: [Fill in with actual current phase — e.g. "3 of 5 written rules are live-verified against real Atomic Red Team executions; the other 2 are known gaps with a documented plan to close them."]

## Risks and Controls

| Risk | Control |
| --- | --- |
| Silent regression to fixture-based claims | Any status label of `Live verified` must link to a scenario log file with three timestamps (attack, telemetry, alert). PR/commit review checklist includes this. |
| RAM exhaustion from running everything at once | Docker Compose profiles enforce staged startup; README resource table is the reference budget. |
| Unsafe attack emulation | Victim VM network is host-only, never bridged to the internet during scenario sessions. |
| Scope creep before core loop works | Suricata (Phase 4), Wazuh (Phase 5), and Kafka (Phase 6) are explicitly gated behind a working Phase 3 scenario log. |
| Metric fabrication | Metrics table stays `Not measured yet` until scenario logs exist; no percentage is written without a linked file. |

## Next Immediate Actions

1. Set up the VirtualBox victim VM and confirm network isolation (Phase 0).
2. Enroll Elastic Agent and get the first real ECS event flowing (Phase 1).
3. Write and live-verify 3–5 Sigma rules against manually-triggered behavior (Phase 2).
4. Run the first Atomic Red Team scenario and produce the first real scenario log + coverage entry (Phase 3) — this is the single most important milestone for interview credibility.
5. Only after Phase 3 has at least one full logged scenario: add Suricata, then Wazuh, then (optionally) Kafka.