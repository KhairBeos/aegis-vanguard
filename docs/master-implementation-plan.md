# AEGIS-VANGUARD Master Implementation Plan

This document is the long-term implementation guide for rebuilding AEGIS-VANGUARD from the current Phase 0/Phase 1 baseline into an honest, local-first SOC detection lab portfolio project.

## 1. Approved project direction

AEGIS-VANGUARD is a personal SOC detection lab for internship/fresher portfolio work. It is a learning and demo project, not a production SIEM or enterprise EDR product.

The approved project story is:

```text
attack or dataset replay
  -> telemetry
  -> normalization
  -> detection
  -> alert
  -> MITRE ATT&CK mapping
  -> gap analysis
  -> rule improvement
```

The first useful vertical slice remains:

```text
sample event -> normalize -> Kafka -> detection -> storage -> API/dashboard
```

The project must stay:

- honest: no capability is claimed before it has a runnable demo or test
- demoable: every major feature has a small local verification path
- local-first: personal machine friendly, with optional short cloud/range bursts later
- resource-conscious: no enterprise HA, no unnecessary heavy services, no all-components-at-once requirement

Approved source-of-truth documents:

- `AGENTS.md`
- `README.md`
- `PROJECT_PLAN.md`
- `docs/repository-classification.md`
- Phase-specific docs under `normalization/`, `datasets/`, `worker/`, `deploy/`, and `docs/`

## 2. Current baseline

Phase 0 cleaned the tracked repository around the approved lab direction. Earlier C++ collector/engine, eBPF, Mordor/demo replay, old protobuf/API schema, old dashboard, old rules, old CMake, and old CI material are no longer part of the tracked baseline.

Current tracked folder intent:

| Path | Current role |
| --- | --- |
| `normalization/` | Current Phase 1 schema, adapter, and stdlib CLI |
| `datasets/` | Current Phase 1 raw and normalized fixtures |
| `worker/` | Pipeline plan and future worker boundary |
| `deploy/` | Safe env example, Kafka topic plan, storage plan |
| `docs/` | Repository classification, verification, master planning |
| `rules/` | Reserved for Phase 2 rules |
| `detection/` | Reserved for future detection engine code |
| `backend/` | Reserved for API layer |
| `dashboard/` | Reserved for analyst UI |
| `correlation/` | Reserved for multi-event correlation experiments |
| `range/` | Reserved for isolated lab range notes |
| `scenarios/` | Reserved for controlled scenario timelines |
| `mitre/` | Reserved for coverage and gap analysis outputs |

Phase 1 currently provides:

- canonical event schema: `normalization/schema/canonical_event.schema.json`
- raw fixtures for `process_start`, `network_connect`, and `auth_failure`
- expected normalized fixtures for the same three event types
- stdlib normalizer and check mode:

```powershell
py normalization/normalize.py --check
```

Current Phase 1 proof:

```text
3 raw samples -> 3 canonical lab-event records matching expected fixtures
```

Current Phase 1 does not prove:

- Kafka publish/consume
- ClickHouse table creation
- detection alerts
- API/dashboard behavior
- external telemetry integrations

Local untracked or ignored leftovers may still exist on disk on a Windows machine. Future agents must treat tracked files and approved docs as the source of truth.

## 3. Final target output

The final portfolio output should be a small, repeatable SOC detection lab demo:

1. Run a local fixture or controlled lab scenario.
2. Normalize telemetry into `lab-event`.
3. Move events through approved Kafka topics.
4. Run a small Sigma-like rule set.
5. Store raw events, normalized events, and alerts.
6. Serve alert and coverage data through a minimal API.
7. Show a dashboard with alerts, timeline, rule metadata, and MITRE coverage.
8. Produce a concise portfolio report explaining detections, misses, false positives, MTTD, and gaps closed.

Final demo evidence should include:

- one command or short runbook for the local fixture demo
- screenshots or saved dashboard output
- MITRE ATT&CK coverage table
- sample alert JSON with rule metadata and risk score
- gap analysis report with measured, not guessed, metrics
- clear statement of what is implemented and what remains future work

## 4. Non-goals

Do not build or claim:

- production SIEM or enterprise EDR readiness
- high availability Kafka, ClickHouse, or backend deployment
- multi-tenant enterprise access control beyond a simple `tenant_id` field
- heavy Active Directory range before the local fixture pipeline works
- Suricata, Wazuh, Sysmon, Mordor, AD, or eBPF integration before their approved phase
- offensive tooling outside isolated, authorized lab scenarios
- detection coverage numbers that were not measured from a real scenario or fixture run
- complex ML, graph correlation, SOAR, or response automation before the basic pipeline is stable

## 5. Phase roadmap

### Phase 0 - Repository alignment

Status: complete for the tracked baseline.

Purpose:

- align docs and folders with the approved lab direction
- remove confusing prototype direction from tracked files
- preserve only useful current/future folders

Verification:

```powershell
git status --short
```

Expected outcome:

- approved docs are clear
- no tracked prototype code drives future work
- folder classification is documented

### Phase 1 - Normalization foundation

Status: complete for local fixture normalization.

Purpose:

- define the first canonical event contract
- normalize three sample event types
- prove deterministic output with checked-in fixtures

Verification:

```powershell
py normalization/normalize.py --check
```

Expected outcome:

```text
OK process_start
OK network_connect
OK auth_failure
Phase 1 normalization check passed.
```

### Phase 2 - Detection rules and alert contract

Status: current for offline fixture-based detection.

Purpose:

- create the minimal rule format
- define the alert schema
- implement offline detection over normalized fixtures
- create the first three rules:
  - suspicious shell / encoded command
  - brute-force authentication
  - rare port egress

Current files:

- `rules/*.json`
- `rules/README.md`
- `detection/README.md`
- `detection/alert_schema.json`
- `detection/rule_loader.py`
- `detection/detect.py`
- `datasets/alerts/*.json`
- `docs/phase-2-verification.md`

Success check:

```text
known suspicious normalized event -> matching rule -> alert with severity, risk_score, and MITRE technique
```

Phase 2 must not require Kafka, ClickHouse, API, or dashboard yet. Use local JSON fixtures first.

### Phase 3 - Local event bus and storage slice

Purpose:

- add the minimal local Kafka and ClickHouse setup
- publish raw fixtures to `raw.telemetry`
- normalize into `normalized.events`
- store raw and normalized evidence
- keep `security.alerts` ready for Phase 2 alerts

Expected files:

- `deploy/docker-compose.yml`
- `deploy/clickhouse/init/*.sql`
- `worker/README.md`
- `worker/producer.py`
- `worker/normalizer_worker.py`
- `worker/storage_writer.py`
- `docs/phase-3-verification.md`

Success check:

```text
sample raw event -> raw.telemetry -> normalized.events -> raw_telemetry storage row
```

Phase 3 should use a single Kafka broker, one ClickHouse node, and short-lived local runs only.

### Phase 4 - API and dashboard

Purpose:

- expose stored alerts and event evidence through a minimal backend API
- build a dashboard that shows useful SOC views, not a marketing page

Expected views:

- alert list
- severity and risk summary
- alert timeline
- rule detail with MITRE metadata
- fixture/demo status panel
- empty, loading, and error states

Expected files:

- `backend/README.md`
- backend source files for read-only alert/event APIs
- `dashboard/README.md`
- dashboard source files for the analyst UI
- `docs/phase-4-verification.md`

Success check:

```text
run sample scenario -> open dashboard -> see alert timeline and rule metadata
```

Phase 4 must not invent metrics. It may show counts from stored demo data only.

### Phase 5 - Controlled scenarios and source adapters

Purpose:

- add safe, controlled scenario timelines
- add external source adapters one at a time only after the fixture pipeline works
- compare AEGIS-generated alerts with external observations when relevant

Candidate order:

1. scenario timeline from checked-in JSON fixtures
2. Sysmon-style sample adapter
3. Suricata EVE JSON adapter
4. Wazuh alert adapter
5. optional Windows victim notes
6. optional AD range notes

Expected files:

- `scenarios/README.md`
- `scenarios/<scenario-name>/timeline.md`
- `scenarios/<scenario-name>/events/*.json`
- `range/README.md`
- source-specific adapter docs under `normalization/`

Success check:

```text
scenario step timestamp -> telemetry timestamp -> alert timestamp -> measured MTTD
```

Any attack simulation must stay inside an isolated, authorized lab.

### Phase 6 - MITRE coverage and gap analysis

Purpose:

- map rules and scenarios to MITRE ATT&CK techniques
- record detected, missed, and improved coverage
- show measured false positives and MTTD when data exists

Expected files:

- `mitre/README.md`
- `mitre/coverage.json`
- `mitre/coverage.md`
- `docs/gap-analysis.md`
- `docs/demo-runbook.md`

Success check:

```text
scenario techniques -> detected / missed / fixed -> final gap analysis report
```

Metrics must remain blank or marked not measured until real demo data exists.

### Phase 7 - Portfolio packaging

Purpose:

- create a clean final reviewer/interviewer experience
- make the project easy to run, explain, and defend

Expected output:

- updated `README.md` with a verified quickstart
- final demo runbook
- screenshots or saved dashboard evidence
- short architecture diagram
- concise portfolio report
- interview explanation using Situation, Task, Action, Result

Success check:

```text
fresh clone -> run documented demo -> view alerts/report -> explain detected and missed behavior
```

## 6. Data contracts

### Canonical event

The current canonical schema is `lab-event`.

Required top-level fields:

- `schema`
- `event_id`
- `timestamp`
- `host`
- `source`
- `event_type`
- `severity`
- `tenant_id`
- `trace_id`
- `event`

Current event types:

- `process_start`
- `network_connect`
- `auth_failure`

Allowed severities:

- `info`
- `low`
- `medium`
- `high`
- `critical`

Contract rule:

- Adapters may accept source-specific raw shapes.
- Detection must consume only canonical `lab-event` records.
- Field renames require a schema update, fixture update, and verification doc update in the same phase.

### Kafka topics

Approved topic names:

| Topic | Purpose |
| --- | --- |
| `raw.telemetry` | Raw source events before normalization |
| `normalized.events` | Canonical `lab-event` records |
| `security.alerts` | Detection alerts, reserved until Phase 2+ |

Local lab defaults:

- partitions: `1`
- replication factor: `1`
- single broker

### Storage

Phase 1 storage design keeps raw and normalized evidence together:

```sql
CREATE TABLE raw_telemetry (
  event_id String,
  ingested_at DateTime,
  source LowCardinality(String),
  event_type LowCardinality(String),
  host LowCardinality(String),
  raw_json String,
  normalized_json String
)
ENGINE = MergeTree
ORDER BY (host, ingested_at, event_type);
```

Phase 2+ should add alert storage only after alert schema and offline detection fixtures are stable.

### Alert contract

Phase 2 should define a small explicit alert contract before writing detection code. Minimum fields:

- `alert_id`
- `timestamp`
- `rule_id`
- `rule_name`
- `severity`
- `risk_score`
- `tenant_id`
- `trace_id`
- `event_id`
- `host`
- `event_type`
- `mitre`
- `evidence`

`mitre` should include tactics and techniques. `evidence` should explain which fields caused the match.

### Rule metadata

Each rule should include:

- stable rule id
- readable name
- description
- severity
- risk score
- event type
- match criteria
- MITRE tactics and techniques
- tags
- test fixture references

## 7. Demo milestones

| Milestone | Demo proof | Command or output |
| --- | --- | --- |
| M1 normalization | Three samples normalize deterministically | `py normalization/normalize.py --check` |
| M2 offline detection | Suspicious fixtures create alerts | future `py detection/detect.py --check` |
| M3 local pipeline | Events move through Kafka and storage | future worker verification doc |
| M4 dashboard | Alerts and rule metadata visible | future dashboard runbook |
| M5 scenario validation | Scenario produces measured alert timing | future scenario runbook |
| M6 portfolio report | Detected/missed/fixed gaps explained | final report and demo script |

Each milestone must have:

- exact command
- expected output
- files used
- what the check proves
- what the check does not prove

## 8. Verification strategy

Use layered verification. Do not start with Docker if a fixture check can prove the contract.

### Fixture checks

Use for schema, normalization, rule matching, alert shape, and MITRE metadata.

Current command:

```powershell
py normalization/normalize.py --check
```

Fallbacks:

```powershell
python normalization/normalize.py --check
```

or the available Python interpreter path in the current environment.

### Integration checks

Use only after local fixture checks pass.

Future examples:

- Kafka topic creation check
- publish one raw event
- consume one normalized event
- query one ClickHouse row
- query one backend endpoint

### Dashboard checks

Use only after API fixtures or stored demo data exist.

Required dashboard states:

- data loaded
- empty state
- error state
- loading state

### Reporting checks

Every measured metric must link back to:

- scenario input
- event timestamp
- alert timestamp
- rule id
- MITRE technique
- command or runbook used

## 9. Resource strategy for a 16 GB RAM personal machine

Run the lab in modes, not all at once.

### Mode A - Fixture development

Run only:

- Python stdlib scripts
- JSON/YAML fixtures
- docs checks

Use this for Phase 1 and most of Phase 2.

### Mode B - Local pipeline

Run only:

- Kafka single broker
- ClickHouse single node
- worker scripts
- optional backend

Use this for Phase 3 and focused pipeline demos.

### Mode C - Dashboard demo

Run only:

- stored fixture/demo data
- backend API
- dashboard

Kafka and range services do not need to run if data is already stored.

### Mode D - Attack simulation session

Run only when validating a scenario:

- Windows victim or local replay source
- optional Suricata/Wazuh later
- optional AD only after simpler scenarios work

Shut down heavy services after the session. Use Docker Compose profiles or separate runbooks so future agents do not start everything by default.

## 10. Risk control

### Scope creep

Risk: AD, Suricata, Wazuh, dashboard, correlation, and reports can expand together.

Control:

- one phase, one proof
- fixture-first implementation
- no new integration until current phase verification passes

### Resource limits

Risk: Kafka, ClickHouse, dashboard, backend, Windows VM, AD, and sensors exceed 16 GB RAM.

Control:

- keep single-node services
- use profiles or separate commands
- avoid running range and dashboard stack together unless needed

### Data contract drift

Risk: adapters, rules, storage, and dashboard silently disagree about field names.

Control:

- update schema, fixtures, docs, and checks together
- detection reads canonical events only
- dashboard reads alert/API contracts only

### Overclaiming

Risk: docs imply detection or integration exists before a runnable check exists.

Control:

- every capability needs a command, fixture, or screenshot-backed demo
- mark planned capabilities as future or reserved

### Unsafe simulation

Risk: attack tooling or scenario commands escape the intended lab context.

Control:

- only isolated, authorized lab scenarios
- prefer fixture replay before live attack simulation
- write scenario safety notes before adding executable scripts

### Generated and local files

Risk: local `.tmp/`, logs, VM outputs, or generated data pollute commits.

Control:

- keep generated output ignored
- commit small fixtures only
- document large external datasets as pointers, not checked-in blobs

## 11. Prompting strategy for Codex

Before each future phase, Codex must:

- read `AGENTS.md`
- inspect `.agents/skills/`
- read `README.md`
- read `PROJECT_PLAN.md`
- read `docs/master-implementation-plan.md`
- summarize current state
- select relevant skills/workflow
- propose a phase plan
- wait for approval before editing

Future prompts should include:

- exact phase number
- allowed files or folders
- hard limits
- expected verification command
- whether Docker is allowed
- whether new libraries are allowed
- whether docs-only, code-only, or code-plus-docs work is expected

Recommended phase workflow:

1. Plan only.
2. User approval.
3. Implement smallest runnable slice.
4. Run phase verification.
5. Report changed files, commands, output, gaps, and next step.

Do not ask Codex to implement multiple major phases in one prompt.

## 12. Next immediate step

After Phase 2 is committed, the next immediate step is Phase 3 planning only.

Phase 3 planning should define:

- minimal local Kafka setup
- minimal ClickHouse setup
- raw event publish path
- normalized event publish path
- raw and normalized storage path
- local verification command
- resource-safe run/stop workflow

Phase 3 implementation should wait until the Phase 3 plan is approved.

Suggested Phase 3 success check:

```text
sample raw event -> raw.telemetry -> normalized.events -> raw_telemetry storage row
```

Phase 3 planning must choose the exact verification command before implementation.
