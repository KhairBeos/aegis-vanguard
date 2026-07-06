# Repository Classification

`README.md`, `PROJECT_PLAN.md`, and `AGENTS.md` are the approved source of truth.

Phase 0 cleanup removed the earlier C++/eBPF/Mordor prototype stack from the tracked repo. Rebuild new functionality in small vertical slices only.

## Current Baseline

| Path | Status | Purpose |
| --- | --- | --- |
| `backend/` | placeholder | API layer when storage/API contracts are ready. |
| `worker/` | near-term | Phase 1 pipeline worker code. |
| `normalization/` | near-term | Canonical schema and source adapters. |
| `datasets/` | near-term | Small local sample events and dataset pointers. |
| `dashboard/` | placeholder | Analyst UI after API/fixtures are stable. |
| `deploy/` | placeholder | Local-first Kafka/ClickHouse setup notes and env examples. |
| `rules/` | placeholder | Small Phase 2 rule set and validation fixtures. |
| `detection/` | future | Rule engine and alert generation code. |
| `correlation/` | future | Multi-event correlation experiments. |
| `range/` | future | Isolated lab range notes. |
| `scenarios/` | future | Controlled scenario timelines. |
| `mitre/` | future | ATT&CK coverage and gap analysis outputs. |
| `docs/` | current | Architecture notes and runbooks. |

## Removed From Tracked Repo

- C++ collector and engine prototype.
- eBPF loader and integration docs.
- Mordor/demo replay scripts and generated artifacts.
- Legacy protobuf/API schema.
- Old rule pack and old dashboard implementation.
- Old CMake and CI workflow.

## Cleanup Rule

If a capability is not backed by a current runnable demo or test, keep it out of the tracked repo until the phase that needs it.
