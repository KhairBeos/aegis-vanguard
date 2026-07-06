# AEGIS-VANGUARD - SOC Detection Lab

AEGIS-VANGUARD is a personal security lab for learning and demonstrating SOC detection engineering, adversary simulation, and security platform engineering. The goal is to build a small but real end-to-end lab that can collect telemetry, normalize events, run detection rules, show alerts, and measure detection coverage against controlled attack scenarios.

This is a lab project for internship/fresher portfolio work. It is not presented as a production SIEM or enterprise EDR product.

## What This Project Shows

- Detection engineering with Sigma-like rules, MITRE ATT&CK mapping, and measurable coverage.
- Adversary simulation using controlled lab scenarios, Atomic Red Team-style tests, and later an Active Directory range.
- Platform/backend engineering with event pipelines, storage, APIs, and dashboard views.
- Honest validation through metrics such as detection coverage, false positives, MTTD, and gap analysis.

## Architecture

```text
Range / Datasets / Simulators
        |
        v
Collection + Adapters
        |
        v
Normalization
        |
        v
Kafka event bus
        |
        v
Detection + Correlation
        |
        +--> Storage
        +--> Alert stream
        |
        v
Dashboard + Reports
```

## Planned Layers

| Layer | Purpose |
| --- | --- |
| Range Layer | Active Directory lab, victim host, attacker host, and controlled attack scenarios |
| Collection Layer | AEGIS telemetry adapters, Sysmon logs, Suricata EVE JSON, Wazuh alerts, and dataset replay |
| Normalization Layer | Convert source-specific logs into one canonical event format |
| Detection Layer | Sigma-like rules, YARA/ML experiments, MITRE ATT&CK metadata, severity and risk scoring |
| Correlation Layer | Link process, file, auth, and network events into higher-confidence findings |
| Response / Reporting Layer | Dashboard, MITRE coverage heatmap, gap analysis, and demo-ready reports |

## Current Direction

The project is being rebuilt around a clear lab-first workflow:

1. Generate or replay telemetry.
2. Normalize events into a shared schema.
3. Publish events into Kafka.
4. Run detection rules and correlation logic.
5. Store events and alerts.
6. Display alerts and coverage in the dashboard.
7. Measure what was detected, missed, and improved.

The first useful milestone is a vertical slice:

```text
sample event -> normalize -> Kafka -> detection -> storage -> API/dashboard
```

## Repository Status During Rebuild

`README.md`, `PROJECT_PLAN.md`, and `AGENTS.md` are the approved source of truth for the rebuild direction.

The current near-term work is Phase 0/Phase 1 alignment. Earlier prototype runtime code has been removed from the tracked repo so the lab can rebuild around the approved small vertical slice.

See `docs/repository-classification.md` for the current baseline folder classification.

## Tech Stack

The stack is intentionally practical for a personal machine with limited RAM.

| Area | Technology |
| --- | --- |
| Event pipeline | Kafka single broker |
| Event analytics | ClickHouse |
| App metadata | PostgreSQL, only where relational app data is needed |
| Detection / tooling | Python, YAML rules, MITRE ATT&CK metadata |
| Dashboard | Next.js / TypeScript |
| Lab tooling | Docker Compose, VMware, optional cloud burst |
| Security tools | Suricata, Wazuh, Sysmon, Atomic Red Team-style tests |

## Repository Structure

Target structure:

```text
aegis-vanguard/
├── backend/              # API layer for dashboard, reports, and lab metadata
├── worker/               # Pipeline workers: consume, normalize, detect, store
├── normalization/        # Source adapters and canonical schema mapping
├── detection/            # Rule engine, rule metadata, scoring, MITRE mapping
├── correlation/          # Multi-event correlation and provenance experiments
├── dashboard/            # Analyst-facing web UI
├── deploy/               # Docker Compose and local infra setup
├── rules/                # Detection rules and validation fixtures
├── datasets/             # Small local fixtures or pointers to external datasets
├── range/                # AD lab topology and setup notes
├── scenarios/            # Attack scenario timeline and replay scripts
├── mitre/                # Coverage heatmap and gap analysis outputs
├── docs/                 # Architecture notes and runbooks
└── PROJECT_PLAN.md       # Development roadmap and portfolio metrics
```

Some folders may be created gradually as the lab is rebuilt.

## Minimum Demo Goal

The first demo should prove the pipeline works end to end:

- Ingest three event types: `process_start`, `network_connect`, `auth_failure`.
- Run three rules: suspicious shell, brute-force authentication, rare port egress.
- Store raw events and alerts.
- Show alerts in the dashboard.
- Explain each alert with MITRE technique metadata.

Example normalized event shape:

```json
{
  "schema": "lab-event",
  "event_id": "evt-001",
  "timestamp": "2026-07-06T10:00:00Z",
  "host": "victim-01",
  "source": "sysmon",
  "event_type": "process_start",
  "severity": "info",
  "tenant_id": "lab",
  "trace_id": "trace-001",
  "event": {
    "process": {
      "pid": 4321,
      "ppid": 1000,
      "user_name": "lab\\alice",
      "image": "powershell.exe",
      "command_line": "powershell -enc ..."
    }
  }
}
```

## Metrics

Do not publish guessed numbers. Fill these only after running real scenarios.

| Metric | How to measure |
| --- | --- |
| MITRE ATT&CK coverage | Detected techniques / total techniques in the scenario |
| False positive rate | Alerts fired during baseline benign activity |
| MTTD | Alert timestamp minus attack-step timestamp |
| Gap closed | Detection gaps fixed / detection gaps found |

## Roadmap

- [ ] Align README, project plan, and folder structure with the lab direction.
- [ ] Build the minimum event schema and normalization adapters.
- [ ] Implement the first detection rules with MITRE metadata.
- [ ] Wire the event pipeline through Kafka and storage.
- [ ] Build dashboard views for alerts, timeline, and rule coverage.
- [ ] Add Suricata and Wazuh as comparison sources.
- [ ] Add AD range and controlled attack scenarios.
- [ ] Produce MITRE gap analysis and portfolio demo material.

## Ethics

All attack simulation must run only in an isolated lab that you own or are explicitly authorized to test. Do not target third-party systems. The project is for learning, research, and portfolio demonstration.
