# Phases 5-7: Suricata, Wazuh, Kafka

Built `2026-08-02`. Each phase is recorded with what it actually demonstrates, which in every
case is less than "we have Suricata / Wazuh / Kafka".

The honest framing up front: none of these three improves detection in this lab today. They
were built because the roadmap lists them and because each answers a narrow, checkable
question. Where a phase stops short, that is stated rather than papered over.

---

## Phase 5 - Suricata network telemetry

### What was built

| Piece | File |
| --- | --- |
| Offline analysis and ingestion | `scripts/analyze-network-telemetry.ps1` |
| Capture inside the VM | `scripts/windows/capture-network-telemetry.ps1` |
| Data stream | `logs-suricata.eve-aegis_lab` |

`PCAP -> Suricata 8.0.6 -> EVE JSON -> Elasticsearch`, verified end to end. Three records
(`dns`, `flow` x2) were parsed and ingested, and are queryable.

The ET Open ruleset fetches on demand: 68,097 rules, 52,158 enabled.

### Why it reads a file instead of an interface

Docker Desktop containers sit behind the WSL2 network namespace and cannot see the VirtualBox
host-only adapter, so a container cannot sniff the lab network. Capture therefore happens
inside the victim VM with `pktmon`, which ships with Windows.

`pktmon` talks to a kernel driver and returns `Access is denied` without elevation, and
`VBoxManage guestcontrol` cannot obtain an elevated token on this VM. That single step is the
one thing in this phase a human has to start.

### What this is not

The verification above used a **synthetic PCAP crafted for the purpose**. It proves the
pipeline moves records; it is not network telemetry from the victim VM and is not evidence of
network detection. `analyze-network-telemetry.ps1` prints that caveat on every run.

An early version of the fixture produced three `SURICATA TCPv4 invalid checksum` alerts. Those
looked like findings and were not - they were an artefact of hand-computed packets with no TCP
checksum. Fixing the checksums removed them. Worth remembering: a synthetic input can
manufacture alerts that mean nothing.

Status: pipeline `Runtime verified`; network telemetry from the victim VM `Future`.

---

## Phase 6 - Wazuh host log and FIM source

### What was built

`infra/wazuh/docker-compose.yml` runs the **manager only**, at `wazuh/wazuh-manager:4.9.2`.

The full `wazuh-docker` stack ships its own OpenSearch indexer and dashboard, which would
duplicate the Elasticsearch and Kibana this lab already runs. The question the roadmap asks is
whether Wazuh is useful as a complementary host-log and FIM source, not whether a second SIEM
can be installed next to the first. The manager alone answers that.

Verified running: 11 components including `analysisd`, `syscheckd` (FIM), `logcollector`,
`remoted`, and `authd`. Ports `1514`, `1515`, and `55000` are bound to `192.168.56.1` only.

### The alerts it is producing are about itself

The manager had generated 187 alerts within minutes - CIS benchmark and SCA findings against
the **container's own Amazon Linux base image**. They say nothing about `victim-win-01`.

Those alerts were deliberately **not** ingested into Elasticsearch. Putting them in the lab's
evidence store would inflate the alert count with records that describe a container nobody is
defending, and every downstream count in `mitre/coverage.md` would become harder to trust.

To get Wazuh telemetry from the victim VM, a Wazuh agent has to be installed there. That is an
elevated MSI install, blocked by the same UAC constraint as `pktmon`.

Status: deployment `Runtime verified`; Wazuh as a source of victim-VM telemetry `Future`.

---

## Phase 7 - Kafka event streaming

### What was built

`infra/kafka/docker-compose.yml` runs a single broker, `apache/kafka:3.9.0` in KRaft mode, no
ZooKeeper. `scripts/verify-kafka-transport.ps1` answers the roadmap's exact question: can an
event path that already has evidence behind it cross Kafka without losing records?

Result: **15 real detection alerts** read from Elasticsearch, produced to `aegis.alerts`,
consumed back, and compared by SHA-256 per record.

| Check | Result |
| --- | --- |
| Count in / out | 15 / 15 |
| Records byte-identical after the round trip | all 15 |

Comparing counts alone would not have answered the question, because a broker that reordered
or truncated payloads would still pass a count check. Hence the per-record hash.

### Two configuration traps worth recording

**`0.0.0.0` in `KAFKA_LISTENERS`.** Kafka refuses to start with
`advertised.listeners cannot use the nonroutable meta-address 0.0.0.0`, even when
`KAFKA_ADVERTISED_LISTENERS` is set correctly to a routable address - which it was, and which
was confirmed inside the container before the real cause was found. Kafka derives an
advertised address for the `CONTROLLER` listener from `listeners`, and the error never
mentions the controller. Using an empty host, `PLAINTEXT://:9092`, fixes it.

**Native stderr under `$ErrorActionPreference = 'Stop'`.** `kafka-console-consumer.sh` writes
`Processed a total of N messages` to stderr on success. Windows PowerShell 5.1 wraps native
stderr in an `ErrorRecord`, which aborted the verification script on a run that had actually
succeeded.

### What this does not mean

At this lab's volume a message broker earns nothing operationally. Kafka is here as an
architecture demonstration and the verification script says so on every successful run.

Status: transport `Runtime verified`; operational value `none at this scale`, by design.

---

## Combined honest summary

| Phase | Deployed | Verified | Still missing |
| --- | --- | --- | --- |
| 5 Suricata | yes | pipeline moves records end to end | real capture from the victim VM, needs one elevated `pktmon` run |
| 6 Wazuh | manager only | 11 components running, ports host-only | agent on the victim VM, needs an elevated install |
| 7 Kafka | yes | 15 real alerts round-trip byte-identical | nothing; it works and is still not useful here |

All three share one gap: **none of them has produced a detection**. The lab's five detections
still come entirely from Sysmon via Elastic. Adding these components made the architecture
diagram wider without making the detection story deeper, which is exactly the trade
`docs/portfolio-report.md` warns a reviewer about.
