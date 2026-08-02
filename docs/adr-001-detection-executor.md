# ADR-001: Detection executor

- Date: `2026-08-02`
- Status: Accepted
- Resolves: the Phase 2 architecture decision gate in `PROJECT_PLAN.md`

## Decision

Use the **Elastic Security detection engine** as the detection executor. Sigma rules are
converted with `sigma-cli` into Elastic Security detection rules and imported through the
Kibana detection engine API. No custom scheduler is written.

This is the "Preferred" path already described in `PROJECT_PLAN.md`; the fallback custom
scheduled executor is rejected.

## Context

The gate required confirming that a supported conversion and import workflow exists for the
selected versions before choosing this path. Four things were checked.

| Question | Finding | Evidence |
| --- | --- | --- |
| Does a Sigma-to-Elastic-rule conversion exist? | Yes. `pySigma-backend-elasticsearch` target `lucene` offers the `siem_rule_ndjson` output format. | `sigma list formats lucene` |
| Does the detection engine need a paid licence? | No. Custom detection rules and rule import/export are available on Basic. Only rule *actions/notifications* and ML rules need a higher tier, and this lab uses neither. | [Manage detection rules](https://www.elastic.co/docs/solutions/security/detect-and-alert/manage-detection-rules) |
| What must the stack enable? | `xpack.security.enabled=true` in Elasticsearch and `xpack.encryptedSavedObjects.encryptionKey` (32+ chars) in Kibana. | [Troubleshoot detection rules](https://www.elastic.co/docs/troubleshoot/security/detection-rules) |
| Is TLS between Elasticsearch and Kibana required? | No longer. Elasticsearch dropped the TLS requirement for API keys, and the alerting framework's enforcement check was removed. | [kibana#111721](https://github.com/elastic/kibana/issues/111721) |

The lab previously ran with `xpack.security.enabled=false`, which by itself blocked this path.
Enabling security was therefore a prerequisite, not an optional hardening step.

## How this satisfies the executor requirements

`PROJECT_PLAN.md` lists five obligations for whichever executor is approved.

| Requirement | How the detection engine meets it | Verified? |
| --- | --- | --- |
| Run on a documented schedule | Rule `interval: 5m`, set from the `schedule_interval` backend option | `Implemented` |
| Record the query time window | Rule carries `from: now-5m`, `to: now`, plus an additional look-back of `1m` | `Implemented` |
| Define an alert deduplication method | The detection engine derives a deterministic alert ID from the source document and rule identity, so one source event yields one alert across overlapping windows | `Runtime verified` - one document queried by three consecutive executions produced exactly one alert |
| Persist rule ID, source document IDs, timestamps, execution context | Alerts-as-data documents in the `.alerts-security.alerts-*` indices | `Runtime verified` - every field in the evidence bundles is read back from these documents |
| Handle errors without losing or fabricating alerts | Rule execution status and failure history are kept by the alerting framework | **Not verified** - no rule has yet been made to fail, so the failure path is untested |

Deduplication was proven with a temporary rule imported under its own `rule_id` with a
25-minute lookback against a 5-minute interval, so a single source event sat inside three
consecutive query windows. It produced one alert. No deployed rule was modified, and the
temporary rule was deleted afterwards. Details in `CONTEXT.md`.

Error handling remains unverified and is the reason this ADR still does not claim the
executor is fully validated.

## Consequences

Accepted:

- The stack now requires authentication. Every host script and the Elastic Agent output need
  credentials; the Agent uses a least-privilege API key created by `scripts/new-agent-api-key.ps1`.
- Alert lifecycle, scheduling, and deduplication are Elastic's implementation, not ours. That
  removes code but also removes the ability to demonstrate that engineering directly.
- The lab depends on the `siem_rule_ndjson` output contract of `pySigma-backend-elasticsearch`.

Rejected alternative - custom scheduled executor:

- Would have worked against the security-disabled stack with no infrastructure change.
- Rejected because it re-implements scheduling, query windows, deduplication, and alert
  persistence that the target platform already provides, and because detection engineers are
  expected to work with the platform's native rule lifecycle.

Deliberately not done:

- **TLS is not enabled.** The lab is confined to a VirtualBox host-only network and no service
  is publicly exposed. This is a known, accepted gap, not an oversight; it must be revisited
  before any claim about transport security.
