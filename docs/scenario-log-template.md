# Controlled Atomic Red Team scenario log template

> Use this template only for controlled, isolated lab runs. Do not paste real attack commands here until the exact test is approved for the local victim VM and isolation is confirmed.

## Scenario metadata

| Field | Value |
| --- | --- |
| Scenario id | `<scenario-id>` |
| Lab session id | `<lab-session-id>` |
| Date/time | `<YYYY-MM-DD HH:mm:ss timezone>` |
| Operator | `<name or handle>` |
| Scenario objective | `<what this run is meant to prove or test>` |
| Approved by | `<name or handle>` |
| Approval timestamp | `<YYYY-MM-DD HH:mm:ss timezone>` |
| Detection expectation | `<expected detection / expected miss / exploratory gap test>` |
| MITRE technique id | `<Txxxx or Txxxx.xxx>` |
| Technique name | `<technique name>` |
| Atomic Red Team test number | `<test number>` |
| Status label | `Not measured yet` |

## Preconditions

- [ ] Phase 0 environment evidence is filled in and reviewed.
- [ ] Victim VM baseline snapshot exists.
- [ ] Host-only network is active.
- [ ] Public exposure is not present.
- [ ] Required telemetry source for this scenario is installed and ready.
- [ ] Expected Sigma rule is identified or the scenario is explicitly marked as a gap test.

## Safety/isolation confirmation

| Check | Expected value | Actual value | Evidence file path |
| --- | --- | --- | --- |
| Victim VM network mode | `Host-only` | `<value>` | `<path>` |
| Bridged adapter | `Disabled` | `<value>` | `<path>` |
| Public target involved | `No` | `<value>` | `<path>` |
| Temporary NAT/internet access | `Disabled before scenario` | `<value>` | `<path>` |
| Snapshot available | `Yes` | `<value>` | `<path>` |

## Atomic command/test reference

| Field | Value |
| --- | --- |
| Atomic test reference | `<link or local reference>` |
| Command placeholder | `<approved command goes here during real run>` |
| Executor | `<PowerShell / cmd / other>` |
| Required privileges | `<user / administrator>` |
| Safety notes | `<notes>` |

## Expected telemetry

| Source | Expected event | Expected fields | Notes |
| --- | --- | --- | --- |
| Sysmon | `<event id / event type>` | `<fields>` | `<notes>` |
| Elastic Agent / Elasticsearch | `<index or dataset>` | `<ECS fields>` | `<notes>` |
| Other source | `<future source>` | `<fields>` | Suricata, Wazuh, and Kafka remain gated behind MVP checkpoint |

## Expected Sigma rule

| Field | Value |
| --- | --- |
| Rule id | `<rule id>` |
| Rule file | `<path>` |
| Expected match fields | `<fields>` |
| Expected severity | `<value>` |
| MITRE mapping | `<technique id>` |

## Execution log

| Step | Timestamp | Action | Evidence path | Notes |
| --- | --- | --- | --- | --- |
| 1 | `<timestamp>` | `<prepare scenario>` | `<path>` | `<notes>` |
| 2 | `<timestamp>` | `<execute approved Atomic test>` | `<path>` | `<notes>` |
| 3 | `<timestamp>` | `<record immediate result>` | `<path>` | `<notes>` |

## Telemetry verification

| Check | Result | Timestamp | Verification query | Evidence path | Notes |
| --- | --- | --- | --- | --- | --- |
| Source telemetry present | `<yes/no/partial>` | `<timestamp>` | `<KQL / Lucene / Elasticsearch query>` | `<path>` | `<notes>` |
| ECS fields present | `<yes/no/partial>` | `<timestamp>` | `<KQL / Lucene / Elasticsearch query>` | `<path>` | `<notes>` |
| Source event ids recorded | `<yes/no>` | `<timestamp>` | `<KQL / Lucene / Elasticsearch query>` | `<path>` | `<notes>` |

## Alert verification

| Check | Result | Timestamp | Verification query | Evidence path | Notes |
| --- | --- | --- | --- | --- | --- |
| Expected rule evaluated | `<yes/no>` | `<timestamp>` | `<KQL / Lucene / Elasticsearch query>` | `<path>` | `<notes>` |
| Alert generated | `<yes/no/partial>` | `<timestamp or not detected>` | `<KQL / Lucene / Elasticsearch query>` | `<path>` | `<notes>` |
| Alert links to source event ids | `<yes/no/partial>` | `<timestamp>` | `<KQL / Lucene / Elasticsearch query>` | `<path>` | `<notes>` |

## Triage summary

`<Short SOC-style summary of what happened, why the alert matters or why it missed, and what evidence supports the conclusion.>`

## MITRE coverage update

| Field | Value |
| --- | --- |
| Technique id | `<Txxxx or Txxxx.xxx>` |
| Coverage result | `<detected / missed / partial / Not measured yet>` |
| Evidence bundle path | `<path>` |
| Coverage note | `<note>` |

## Gap analysis

| Gap reason | Applies? | Evidence | Follow-up |
| --- | --- | --- | --- |
| Telemetry gap | `<yes/no>` | `<path>` | `<action>` |
| Normalization gap | `<yes/no>` | `<path>` | `<action>` |
| Rule logic gap | `<yes/no>` | `<path>` | `<action>` |
| Scenario limitation | `<yes/no>` | `<path>` | `<action>` |

## Cleanup steps

- [ ] Stop or revert the tested behavior as required by the approved Atomic test.
- [ ] Restore victim VM baseline if needed.
- [ ] Confirm no unintended network exposure remains.
- [ ] Save evidence files under the scenario id.
- [ ] Record unresolved cleanup issues here: `<notes>`.

## Final result

| Field | Value |
| --- | --- |
| Detection result | `<detected / missed / partial>` |
| Gap reason | `<telemetry gap / normalization gap / rule logic gap / scenario limitation / none>` |
| Evidence bundle path | `<path>` |
| Status label | `Not measured yet` |
| Evidence sufficient for `Live verified`? | `<yes/no>` |
| Final notes | `<notes>` |
