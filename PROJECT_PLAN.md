# AEGIS-VANGUARD - Development Plan

## Goal

AEGIS-VANGUARD is a personal SOC detection lab for internship/fresher portfolio work. The project focuses on three practical skills:

1. Detection Engineering
2. Adversary Simulation
3. Platform / Backend Engineering

The project should stay honest and demoable. Every major feature should be backed by a runnable scenario, visible alert, or measurable metric.

## Design Constraints

- Personal machine with about 16 GB RAM.
- Prefer local-first setup.
- Do not require enterprise-grade HA, multi-region deployment, or production hardening.
- Avoid running every lab component at the same time.
- Build small vertical slices before adding more tools.

## Core Story

The lab answers one question:

> If I simulate an attack in a controlled environment, what does my detection pipeline catch, what does it miss, and how do I improve it?

This is stronger than only showing a dashboard. The project should demonstrate the full loop:

```text
attack / dataset replay
        -> telemetry
        -> normalization
        -> detection
        -> alert
        -> MITRE mapping
        -> gap analysis
        -> rule improvement
```

## Target Architecture

```text
Range / Datasets / Simulators
        |
        v
Collection Sources
  - Sysmon
  - Suricata EVE JSON
  - Wazuh alerts
  - Atomic Red Team-style logs
  - Security dataset replay
        |
        v
Normalization Adapters
        |
        v
Kafka Topics
  - raw.telemetry
  - normalized.events
  - security.alerts
        |
        v
Detection + Correlation
  - Sigma-like rules
  - MITRE metadata
  - threshold rules
  - multi-event correlation
        |
        v
Storage + Dashboard
  - ClickHouse for events and alerts
  - PostgreSQL only for app metadata if needed
  - Dashboard for alerts, timeline, coverage, and gaps
```

## Canonical Event Direction

All sources should map into one canonical event shape before detection. Keep the schema small at first.

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

Initial event types:

- `process_start`
- `network_connect`
- `auth_failure`

Later event types:

- `file_write`
- `dns_query`
- `security_alert`
- `process_access`

## Initial Rule Set

Start with a small rule set that is easy to test and explain.

| Rule | Event source | MITRE example | Purpose |
| --- | --- | --- | --- |
| Suspicious shell / encoded command | process_start | T1059 | Detect suspicious interpreter execution |
| Authentication brute force | auth_failure | T1110 | Detect repeated failed logins |
| Rare port egress | network_connect | T1071 / T1571 | Detect uncommon outbound network activity |
| Sensitive file access | file event | T1005 | Detect suspicious access to sensitive files |
| Download then execute | process + network/file | T1105 + T1059 | Correlate payload download and execution |

Rule metadata should include:

```yaml
id: suspicious-shell-encoded-command
name: Suspicious encoded PowerShell command
severity: high
risk_score: 80
mitre:
  tactics:
    - execution
  techniques:
    - T1059.001
tags:
  - windows
  - powershell
```

## Resource Plan

Do not run all components at once.

### Mode A - Daily Detection Stack

Use this while developing the pipeline.

| Component | Expected role |
| --- | --- |
| Kafka single broker | Event bus |
| ClickHouse | Event and alert analytics |
| Backend/API | Dashboard data and reports |
| Dashboard | Analyst view |
| Worker/detection engine | Normalize, detect, store |

### Mode B - Attack Simulation Session

Use this only when validating scenarios.

| Component | Expected role |
| --- | --- |
| Windows victim | Sysmon / Wazuh agent telemetry |
| Optional domain controller | Active Directory scenario |
| Attacker VM or controlled tools | Atomic-style tests / later C2 scenario |
| Suricata | Network telemetry |

If local RAM is not enough, use a short cloud burst for the range and shut it down after testing.

## Development Phases

### Phase 0 - Documentation and Repo Alignment

Goal: make the repo match the lab direction.

Deliverables:

- Standard `README.md`
- Updated `PROJECT_PLAN.md`
- Clear folder structure
- Removed confusing draft docs

### Phase 1 - Minimal Event Pipeline

Goal: prove the pipeline with local sample events.

Deliverables:

- Canonical event schema
- Sample events for `process_start`, `network_connect`, `auth_failure`
- Normalization code
- Kafka topic setup
- Storage table for raw events

Success check:

```text
sample event -> normalized event -> Kafka -> stored raw event
```

### Phase 2 - Detection Rules

Goal: generate real alerts from normalized events.

Deliverables:

- Rule format with MITRE metadata
- First three detection rules
- Alert schema
- Alert storage
- Rule validation script

Success check:

```text
known suspicious event -> matching rule -> alert with risk_score and MITRE technique
```

### Phase 3 - Dashboard

Goal: show useful SOC views, not just raw tables.

Deliverables:

- Alert list
- Severity and risk summary
- Timeline
- Rule coverage section
- Empty/loading/error states

Success check:

```text
run sample scenario -> open dashboard -> see alert timeline and rule metadata
```

### Phase 4 - Suricata and Wazuh Integration

Goal: compare custom detection with existing security tools.

Deliverables:

- Suricata EVE JSON adapter
- Wazuh alert adapter
- Source comparison view
- Mapping from external alerts to canonical event/alert format

Success check:

```text
same scenario -> AEGIS alert + Suricata/Wazuh observation -> comparison report
```

### Phase 5 - Lab Range and Attack Scenarios

Goal: validate detection against controlled attack flows.

Deliverables:

- `range/README.md`
- One Windows victim setup
- Optional AD setup
- Scenario timeline
- Atomic Red Team-style tests or equivalent safe commands

Success check:

```text
scenario step timestamp -> telemetry timestamp -> alert timestamp -> MTTD
```

### Phase 6 - Gap Analysis and Portfolio Report

Goal: make the project explainable in interviews.

Deliverables:

- MITRE coverage matrix
- Gap analysis report
- Before/after rule improvement notes
- Demo script
- Short STAR story for interview

Success check:

```text
scenario techniques -> detected / missed / fixed -> final report
```

## Metrics

Only fill these after running real scenarios.

| Metric | How to measure | Why it matters |
| --- | --- | --- |
| Detection coverage | Detected MITRE techniques / total techniques in scenario | Shows rule effectiveness |
| False positive rate | Alerts during benign baseline activity | Shows alert quality |
| MTTD | Alert time - attack step time | Shows detection latency |
| Gap closed | Fixed gaps / found gaps | Shows iteration and engineering maturity |

## Interview Story

Use this structure when explaining the project:

- Situation: I wanted a lab that tests whether my detection logic works against realistic attack behavior.
- Task: Build a pipeline that collects telemetry, detects suspicious behavior, and measures detection gaps.
- Action: Implement normalization, rules, MITRE mapping, dashboard views, and controlled scenarios.
- Result: Show measured coverage, false positives, MTTD, and improvements after adding rules.

## Risks

- Scope creep: AD, Suricata, Wazuh, C2, graph correlation, and dashboard can become too much if done together.
- Overclaiming: do not say a capability exists until it has a runnable demo or test.
- Resource limits: keep heavy range components off by default.
- Data contract drift: every adapter must map into the same canonical event schema.
- Unsafe simulation: keep all attack testing inside isolated, authorized lab networks.

## Best Practice

Build one vertical slice first. A small pipeline that runs correctly is better than a large architecture that only exists in docs.
