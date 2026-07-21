# Phase 1 Runtime Verification Record

- **Current state:** `Unverified`.
- **Runtime executed during scaffolding:** No.
- **Evidence rule:** Leave every item unchecked until the exact command or UI check is run and its timestamped evidence path is recorded.

## Resource and artifact gates

- [ ] Available host RAM meets the approved threshold with the victim VM running.
- [ ] Docker backing storage meets the approved free-space threshold.
- [ ] `vm.max_map_count` is at least `1048576`.
- [ ] Docker data is on the separately approved storage location.
- [ ] Elasticsearch and Kibana images are exactly `9.4.3` and were acquired through an approved action.
- [ ] The Elastic Agent `9.4.3` artifact matches the official SHA-512 file and any official signature mechanism published for that exact artifact.

## Network, TLS, and readiness

- [ ] Elasticsearch is listening only on host address `192.168.15.1`, TCP `9200`.
- [ ] Kibana is listening only on loopback address `127.0.0.1`, TCP `5601`.
- [ ] No host listener exists for Elasticsearch transport or Fleet Server.
- [ ] The Elasticsearch certificate contains DNS SAN `elasticsearch` and IP SAN `192.168.15.1` and chains to the one local CA.
- [ ] TLS generation completes as one validated transaction before promotion.
- [ ] Generated private keys retain restrictive non-inherited ACLs after promotion.
- [ ] No run-specific TLS staging material remains after success or failure.
- [ ] The CA-verified unauthenticated probe returns HTTP `401` and is recorded as listener-only.
- [ ] Authenticated cluster health returns `yellow` or `green` with `timed_out=false`.
- [ ] Docker reports Elasticsearch health as `healthy` only after the authenticated check.
- [ ] Kibana `/api/status` returns HTTP `200`.
- [ ] Kibana `status.overall.level` equals `available`.
- [ ] Kibana health runs successfully through the bundled Node path `/usr/share/kibana/node/bin/node`.

## Integration assets and egress

- [ ] Kibana's only package-registry session is the approved System integration installation over outbound HTTPS.
- [ ] The exact installed System package version and installation timestamp are recorded.
- [ ] The installed package version matches the recorded version before policy download.
- [ ] The installed package version matches the recorded version before each scenario session.
- [ ] No unofficial mirror, copied package asset, or invented package policy was used.
- [ ] The victim VM remained host-only without Internet access.

## Firewall

- [ ] Exactly one Phase 1 rule exists and is inbound Allow, TCP `9200`.
- [ ] The rule local address is exactly `192.168.15.1` and remote address exactly `192.168.15.6`.
- [ ] The rule is bound to the uniquely discovered VirtualBox host-only interface and its applicable profile.
- [ ] No firewall profile was disabled and no Kibana or deferred port was opened.

## Standalone Agent and telemetry

- [ ] The Agent runs standalone without enrollment or Fleet Server.
- [ ] The protected live policy trusts the local CA with full verification and contains no repository-sourced credential.
- [ ] Only Windows Application, Security, and System streams are enabled; metrics and unrelated streams are disabled.
- [ ] Recent events from each approved channel are searchable in Kibana.
- [ ] `host.name` identifies `AEGIS-WIN-VICTIM-01` consistently.
- [ ] `agent.id` remains stable across the recorded restart check.
- [ ] Source timestamps, ingest timestamps, source channels, data streams, ingest pipelines, and applicable ECS fields are recorded.

## Evidence record

| Check group | Timestamp | Evidence path | Verdict |
| --- | --- | --- | --- |
| Resource and artifact gates | — | — | `Unverified` |
| Network, TLS, and readiness | — | — | `Unverified` |
| Integration assets and egress | — | — | `Unverified` |
| Firewall | — | — | `Unverified` |
| Standalone Agent and telemetry | — | — | `Unverified` |

This record cannot establish detection, alerting, coverage, or measured-performance capability.
