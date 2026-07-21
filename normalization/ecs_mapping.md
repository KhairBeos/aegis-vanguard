# Phase 1 ECS Mapping Record

- **Scope:** Windows Application, Security, and System event logs through one standalone Elastic Agent `9.4.3`.
- **Current state:** `Unverified`.
- **Recording rule:** Populate rows only from live, timestamped ingestion evidence after all runtime gates pass.

| Windows channel | Source fields observed | ECS fields verified | Data stream | Ingest pipeline | System package version | Kibana query | Evidence path | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Application | — | — | — | — | — | — | — | `Unverified` |
| Security | — | — | — | — | — | — | — | `Unverified` |
| System | — | — | — | — | — | — | — | `Unverified` |

## Identity and timestamp checks

| Check | Observed value | Evidence path | Verdict |
| --- | --- | --- | --- |
| `host.name` matches `AEGIS-WIN-VICTIM-01` | — | — | `Unverified` |
| `agent.id` remains stable across restarts | — | — | `Unverified` |
| Original event timestamp is preserved and distinguishable from ingest time | — | — | `Unverified` |
| Source channel is queryable for each approved stream | — | — | `Unverified` |

No row is evidence of detection, alerting, coverage, or a measured metric.
