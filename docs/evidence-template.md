# Live scenario evidence bundle template

> Use this template for real scenario evidence only. `Live verified` requires real telemetry, linked timestamps, source evidence, and an evidence verdict of `sufficient`. Screenshots alone are not enough unless they are tied to the scenario id, timestamps, source events, verification query, and rule evidence.

## Scenario identity

| Field | Value |
| --- | --- |
| Scenario id | `<scenario-id>` |
| Lab session id | `<lab-session-id>` |
| Date/time | `<YYYY-MM-DD HH:mm:ss timezone>` |
| Operator | `<name or handle>` |
| MITRE technique id | `<Txxxx or Txxxx.xxx>` |
| Atomic Red Team test number | `<test number>` |

## Timestamp linkage

| Timestamp | Value | Evidence file path | Notes |
| --- | --- | --- | --- |
| Attack execution timestamp | `<YYYY-MM-DD HH:mm:ss timezone>` | `<path>` | Time the controlled scenario was executed |
| Telemetry arrival timestamp | `<YYYY-MM-DD HH:mm:ss timezone>` | `<path>` | Time matching real telemetry reached the pipeline |
| Alert timestamp, if detected | `<YYYY-MM-DD HH:mm:ss timezone or not detected>` | `<path>` | Time the alert was generated, if any |

## Detection and source evidence

| Field | Value |
| --- | --- |
| Sigma rule id | `<rule id>` |
| Telemetry source | `<Sysmon / Suricata / Wazuh / other>` |
| Index / data stream | `<Elasticsearch index or data stream>` |
| Verification query | `<KQL / Lucene / Elasticsearch query used to find the event or alert>` |
| Source event ids | `<event ids / document ids>` |
| Evidence file paths | `<paths to logs, exports, notes, screenshots>` |
| Screenshots / exports | `<paths and short descriptions>` |
| Analyst triage note | `<short SOC-style assessment>` |

## Result classification

| Field | Allowed values | Selected value | Notes |
| --- | --- | --- | --- |
| Detection result | `detected` / `missed` / `partial` | `<value>` | `<notes>` |
| Gap reason | `telemetry gap` / `normalization gap` / `rule logic gap` / `scenario limitation` | `<value>` | Required for missed or partial results |
| Evidence verdict | `sufficient` / `insufficient` / `needs review` | `<value>` | `sufficient` is required before any `Live verified` claim |
| Status label | `Not measured yet` / `Unit tested` / `Live verified` | `Not measured yet` | Use `Live verified` only after real telemetry, linked timestamps, source evidence, and a `sufficient` evidence verdict exist |

## Validation notes

`<Record what was checked, what matched, what did not match, and whether the evidence is sufficient to support the selected result.>`

## Follow-up action

`<Next rule, telemetry, normalization, triage, or documentation action.>`

## Evidence quality checklist

- [ ] Scenario id and lab session id are present.
- [ ] Attack execution timestamp is recorded from the controlled scenario run.
- [ ] Telemetry arrival timestamp is recorded from real telemetry.
- [ ] Alert timestamp is recorded if detection occurred.
- [ ] Sigma rule id is linked when a rule is expected or evaluated.
- [ ] Telemetry source is recorded.
- [ ] Index/data stream is recorded.
- [ ] Verification query is recorded.
- [ ] Source event ids or document ids are linked.
- [ ] Screenshots or exports are linked to the scenario and timestamps.
- [ ] Detection result is one of `detected`, `missed`, or `partial`.
- [ ] Gap reason is selected for missed or partial results.
- [ ] Evidence verdict is selected.
- [ ] `Live verified` is not used unless the evidence proves a real live run with real telemetry, linked timestamps, source evidence, and a `sufficient` evidence verdict.
