# Phase 0 environment setup and evidence record

> Status: Phase 0 is complete. Current evidence proves host `192.168.15.1/24` and guest `192.168.15.6/24`, two 0%-loss final validation sets in each direction, enabled guest firewall profiles with default inbound `Block` and outbound `Allow`, the exact narrow host and guest ICMP rules, no guest IPv4 default route, failed guest external ping and public-IP retrieval, absent NAT/bridged VM adapters, and the available `clean-windows-baseline` snapshot. The earlier failed host-to-guest attempts remain preserved as historical evidence; they were not reproduced after guest readiness and current interface/firewall validation, and no more specific root cause is claimed. Evidence: `evidence/phase-0/phase0-20260708-khai/20260714-host-to-guest-final-validation.txt`, `evidence/phase-0/phase0-20260708-khai/20260714-phase0-guest-connectivity-revalidation.txt`, `evidence/phase-0/phase0-20260708-khai/20260714-1118-phase0-connectivity-firewall-revalidation.txt`, `evidence/phase-0/phase0-20260708-khai/20260714-1023-phase0-vm-resource-amendment.txt`.

## Purpose

Record and verify the isolated local lab foundation for AEGIS-VANGUARD before Elastic, Fleet, Sigma, or Atomic Red Team implementation work begins.

Phase 0 proves that the lab can be set up safely, consistently, and with evidence that future detection claims can reference.

## Lab session identity

| Field | Value | Evidence path |
| --- | --- | --- |
| Lab session id | `phase0-20260708-khai` | `evidence/phase-0/phase0-20260708-khai/20260708-1029-host-user-session.txt` |
| Setup date | `2026-07-08` | `evidence/phase-0/phase0-20260708-khai/20260708-1029-host-user-session.txt` |
| Operator | `Khai` | `evidence/phase-0/phase0-20260708-khai/20260708-1029-host-user-session.txt` |
| Host machine | `KhaiPC` | `evidence/phase-0/phase0-20260708-khai/20260708-1027-host-os-registry-hostname.txt` |

## Scope

In scope:

- Record host laptop, virtualization, Docker, and planned Elastic stack details.
- Confirm network isolation for the Windows victim VM.
- Capture version and configuration evidence before live telemetry work starts.
- Define the minimum success criteria for moving to Phase 1.

Out of scope:

- Running Atomic Red Team tests.
- Creating detection rules.
- Creating Docker Compose files or Elastic/Fleet configuration.
- Claiming detection, alerting, coverage, or dashboard capability.
- Marking any metric as measured.

## Safety rules

- Use a fully local SIEM-like SOC lab only.
- Do not expose victim VM services or attack emulation traffic to a public network.
- Do not use bridged networking during scenario sessions.
- Do not target third-party systems.
- Do not record fake evidence, fake screenshots, fake timestamps, or fake metrics.
- Do not mark any scenario `Live verified` without real telemetry, linked timestamps, source evidence, and a sufficient evidence verdict.
- Keep Suricata, Wazuh, and Kafka gated behind the MVP checkpoint.

## Required local components

| Component | Required for Phase 0 | Planned role | Current value | Evidence path | Notes |
| --- | --- | --- | --- | --- | --- |
| Host laptop | Yes | Runs local tools, VirtualBox, and Docker | `KhaiPC / Windows 10 Home Single Language 25H2 build 26200.8655 / ~15.69 GiB RAM` | `evidence/phase-0/phase0-20260708-khai/20260708-1027-host-os-registry-hostname.txt`, `evidence/phase-0/phase0-20260708-khai/20260708-1027-host-cpu-ram-env-dotnet.txt` | Host model could not be read through CIM due access denial; CPU/RAM captured through environment/.NET fallback |
| VirtualBox | Yes | Hosts isolated Windows victim VM | `7.2.4r170995` | `evidence/phase-0/phase0-20260708-khai/20260708-1026-virtualbox-version.txt` | VBoxManage is available |
| Windows 10/11 victim VM | Yes | Generates real endpoint telemetry in later phases | `AEGIS-WIN-VICTIM-01 / running / Windows 10 build 10.0.19045.3803 / 3 CPU / 4096 MiB RAM / 61440 MiB disk` | `evidence/phase-0/phase0-20260708-khai/20260714-1023-phase0-vm-resource-amendment.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1413-victim-guest-properties-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1504-post-firewall-remediation-host-vm-docker-recheck.txt` | Current 4096 MiB/3-vCPU configuration is operator-approved and historical 6144 MiB evidence remains linked; current host-to-guest connectivity/firewall validation passes |
| Host-only network | Yes | Isolates victim VM from public networks | `VirtualBox Host-Only Ethernet Adapter #2 / 192.168.15.1 / 255.255.255.0` | `evidence/phase-0/phase0-20260708-khai/20260714-1118-phase0-connectivity-firewall-revalidation.txt`, `evidence/phase-0/phase0-20260708-khai/20260714-host-to-guest-final-validation.txt`, `evidence/phase-0/phase0-20260708-khai/20260714-phase0-guest-connectivity-revalidation.txt` | Current host and guest addressing, routing, firewall, bidirectional connectivity, and isolation checks pass |
| Docker Desktop or Docker Engine | Yes | Runs future local SIEM services | `Docker Desktop 4.79.0 / Engine 29.5.3 / context desktop-linux / 0 running containers` | `evidence/phase-0/phase0-20260708-khai/20260713-1504-post-firewall-remediation-host-vm-docker-recheck.txt` | Docker daemon is reachable; no SIEM services or other containers are running |
| Future Elastic/Kibana/Fleet containers | No, planned | Later telemetry ingestion and review stack | `Not created yet` | `<future path>` | Do not create in Phase 0 |

## Network isolation checklist

- [x] Host-only adapter exists in VirtualBox at `192.168.15.1/24`. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1412-host-network-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-network-snapshot-final.txt`
- [x] Victim VM uses host-only networking for lab traffic. Adapter 1 is `hostonly` on `VirtualBox Host-Only Ethernet Adapter #2`. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt`
- [x] Victim VM is not configured with bridged networking. Adapter 1 is host-only and adapters 2-8 are disabled. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt`
- [x] NAT is absent from the current VM configuration. Adapter 1 is host-only, adapters 2-8 are disabled, and no VirtualBox NAT network is listed. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-network-snapshot-final.txt`
- [x] Victim VM has no active internet route. No `0.0.0.0/0` route exists and persistent routes are `None`. Evidence: `evidence/phase-0/phase0-20260708-khai/20260714-phase0-guest-connectivity-revalidation.txt`
- [x] Public IP check from the victim VM returns no public IP. The IPv4 request fails with `Could not resolve host` and exit code 6. Evidence: `evidence/phase-0/phase0-20260708-khai/20260714-phase0-guest-connectivity-revalidation.txt`
- [x] Bidirectional reachability is current: both host-to-guest final validation sets and both guest-to-host validation sets received 4/4 replies with 0% loss. The earlier failed host-to-guest attempts remain preserved and were not reproduced after guest readiness and current interface/firewall validation. Evidence: `evidence/phase-0/phase0-20260708-khai/20260714-host-to-guest-final-validation.txt`, `evidence/phase-0/phase0-20260708-khai/20260714-phase0-guest-connectivity-revalidation.txt`; historical failure: `evidence/phase-0/phase0-20260708-khai/20260714-1023-phase0-vm-resource-amendment.txt`
- [x] On 2026-07-13, the victim VM reached `192.168.15.1` and could not reach `8.8.8.8` or retrieve a public IP after remediation. Host ping received 4/4 replies; internet ping lost 4/4 packets; the public-IP request returned no address. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt`
- [x] Domain, Private, and Public guest firewall profiles are enabled with default inbound `Block` and outbound `Allow`. Evidence: `evidence/phase-0/phase0-20260708-khai/20260714-phase0-guest-connectivity-revalidation.txt`
- [x] The guest ICMP exception is a narrow lab-only rule: enabled inbound `Allow`, Public profile, ICMPv4 type 8, remote `192.168.15.0/24`, local `192.168.15.6`, and the discovered guest interface. Evidence: `evidence/phase-0/phase0-20260708-khai/20260714-phase0-guest-connectivity-revalidation.txt`
- [x] The host ICMP rule is limited to inbound ICMPv4 Echo Request from `192.168.15.0/24` on the discovered VirtualBox host-only interface; the firewall is not globally disabled. Evidence: `evidence/phase-0/phase0-20260708-khai/20260714-1118-phase0-connectivity-firewall-revalidation.txt`
- [x] No SIEM lab service is exposed on a public interface because Docker reports zero running containers. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1414-docker-final.txt`
- [x] Export captured for VM network adapter settings. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt`
- [x] Export captured for host-only network settings. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1412-host-network-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-network-snapshot-final.txt`

Final isolation verification is `Complete`. Current host and guest evidence proves the required addressing, exact firewall rules, bidirectional validation pings, absent guest IPv4 default route, failed external ping and public-IP retrieval, and absent NAT/bridged VM adapters. The earlier failures were not reproduced after guest readiness and current interface/firewall validation; no more specific root cause is proven. Evidence: `evidence/phase-0/phase0-20260708-khai/20260714-host-to-guest-final-validation.txt`, `evidence/phase-0/phase0-20260708-khai/20260714-phase0-guest-connectivity-revalidation.txt`, `evidence/phase-0/phase0-20260708-khai/20260714-1118-phase0-connectivity-firewall-revalidation.txt`.

## Version inventory table

| Item | Version / build | How recorded | Evidence file path | Status | Notes |
| --- | --- | --- | --- | --- | --- |
| Host OS | `Windows 10 Home Single Language 25H2 build 26200.8655` | Registry export plus hostname fallback | `evidence/phase-0/phase0-20260708-khai/20260708-1027-host-os-registry-hostname.txt` | `Recorded` | CIM systeminfo access was denied; registry fallback succeeded |
| Host RAM | `~15.69 GiB total; ~3.26 GiB available at capture time` | Environment/.NET fallback | `evidence/phase-0/phase0-20260708-khai/20260708-1027-host-cpu-ram-env-dotnet.txt` | `Recorded` | Also recorded 16 logical processors |
| VirtualBox | `7.2.4r170995` | `VBoxManage --version` | `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt` | `Recorded` | Version refreshed during the final review |
| Windows victim VM OS | `Windows 10 build 10.0.19045.3803` | VirtualBox guest properties | `evidence/phase-0/phase0-20260708-khai/20260713-1413-victim-guest-properties-final.txt` | `Recorded` | Guest Additions reported the product and release; current guest-local network evidence is recorded separately |
| Docker Desktop / Docker Engine | `Docker Desktop 4.79.0; Engine 29.5.3` | `docker version`; `docker context ls`; `docker info`; `docker ps --no-trunc` | `evidence/phase-0/phase0-20260708-khai/20260713-1414-docker-final.txt` | `Recorded` | Active context is `desktop-linux`; daemon is reachable; running containers: 0 |
| Elastic image tag | `<future value>` | `<future source>` | `<future path>` | `Future` | Record only when planned containers are created |
| Kibana image tag | `<future value>` | `<future source>` | `<future path>` | `Future` | Record only when planned containers are created |
| Fleet image/tag or integration version | `<future value>` | `<future source>` | `<future path>` | `Future` | Record only when planned Fleet work starts |

## VM configuration table

| Setting | Planned value | Actual value | Evidence file path | Notes |
| --- | --- | --- | --- | --- |
| VM name | `AEGIS-WIN-VICTIM-01` | `AEGIS-WIN-VICTIM-01` (`running`) | `evidence/phase-0/phase0-20260708-khai/20260714-1023-phase0-vm-resource-amendment.txt` | Registered and running during the resource-amendment capture |
| VM state | `Running for evidence capture` | `running` | `evidence/phase-0/phase0-20260708-khai/20260714-1023-phase0-vm-resource-amendment.txt` | Read-only checks did not start, stop, or modify the VM |
| Windows version | `Windows 10/11` | `Windows 10 build 10.0.19045.3803` | `evidence/phase-0/phase0-20260708-khai/20260713-1413-victim-guest-properties-final.txt` | Reported by VirtualBox Guest Additions; guest `systeminfo` was not recorded |
| CPU allocation | `3` | `3 vCPU` | `evidence/phase-0/phase0-20260708-khai/20260714-1023-phase0-vm-resource-amendment.txt` | Unchanged |
| RAM allocation | Original 4 GiB lab target | `4096 MiB` | `evidence/phase-0/phase0-20260708-khai/20260714-1023-phase0-vm-resource-amendment.txt`; historical: `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt` | Operator-approved adjustment back to the original target; the prior `6144 MB` state remains historically traceable |
| Disk size | `61440 MiB` | `61440 MiB` capacity; `4959 MiB` on disk at capture | `evidence/phase-0/phase0-20260708-khai/20260714-1023-phase0-vm-resource-amendment.txt` | Normal differencing VDI; no disk change was made |
| Network adapter 1 | `Host-only adapter` | `Host-only / VirtualBox Host-Only Ethernet Adapter #2 / cable connected` | `evidence/phase-0/phase0-20260708-khai/20260714-1023-phase0-vm-resource-amendment.txt` | Host-only configuration is unchanged; linked isolation evidence remains authoritative for connectivity |
| Network adapters 2-8 | `Disabled unless temporarily needed` | `Disabled` | `evidence/phase-0/phase0-20260708-khai/20260714-1023-phase0-vm-resource-amendment.txt` | NAT and bridged networking remain absent from the current VM configuration |
| Snapshot baseline | `clean-windows-baseline` | `clean-windows-baseline` exists and is current | `evidence/phase-0/phase0-20260708-khai/20260714-1023-phase0-vm-resource-amendment.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-network-snapshot-final.txt` | Historical snapshot description and current-name evidence are preserved |

## Network configuration table

| Item | Planned value | Actual value | Evidence file path | Notes |
| --- | --- | --- | --- | --- |
| Host-only adapter name | `VirtualBox Host-Only Ethernet Adapter #2` | `VirtualBox Host-Only Ethernet Adapter #2` | `evidence/phase-0/phase0-20260708-khai/20260713-1412-host-network-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-network-snapshot-final.txt` | GUID and MAC match the target; adapter status: Up |
| Host-only subnet | `Host and guest on the same isolated subnet` | `192.168.15.0/24` | `evidence/phase-0/phase0-20260708-khai/20260713-1412-host-network-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1413-victim-guest-properties-final.txt` | One connected lab route exists; other active host and Docker networks do not overlap |
| Host IP on lab network | `Same subnet as victim VM` | `192.168.15.1/24` | `evidence/phase-0/phase0-20260708-khai/20260714-1118-phase0-connectivity-firewall-revalidation.txt` | Manual IPv4; no default gateway or DNS |
| Victim VM IP | `Same subnet as host-only adapter` | `192.168.15.6/24` | `evidence/phase-0/phase0-20260708-khai/20260714-phase0-guest-connectivity-revalidation.txt` | Current authoritative guest-local address is Preferred on the discovered Up interface |
| Host route to victim VM | `Reachable over host-only network` | One alive on-link `192.168.15.0/24` route through discovered interface index 9; no competing matching route | `evidence/phase-0/phase0-20260708-khai/20260714-1118-phase0-connectivity-firewall-revalidation.txt` | Host route/interface correlation and final host-to-guest validation pass |
| Host ICMP firewall rule | `Scoped lab rule only` | `Inbound ICMPv4 Echo Request / remote 192.168.15.0/24 / discovered host-only interface` | `evidence/phase-0/phase0-20260708-khai/20260714-1118-phase0-connectivity-firewall-revalidation.txt` | Interface filter maps to the discovered VirtualBox host-only adapter; no global firewall disablement |
| Victim guest `ipconfig /all` | `Recorded` | `192.168.15.6 / 255.255.255.0 / DHCP enabled` | `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt` | Guest NIC MAC and DHCP server `192.168.15.2` match the VirtualBox lease evidence |
| Default gateway in victim VM | `<none or controlled value>` | `None` | `evidence/phase-0/phase0-20260708-khai/20260714-phase0-guest-connectivity-revalidation.txt` | The current IPv4 route table has no `0.0.0.0/0` entry and persistent routes are `None` |
| DNS in victim VM | `<none or controlled value>` | `No IPv4 DNS server addresses` | `evidence/phase-0/phase0-20260708-khai/20260713-guest-isolation-evidence.txt` | `Get-DnsClientServerAddress` reports `{}` for Ethernet; `ipconfig /all` lists only IPv6 site-local placeholder addresses |
| Guest network profile | `Host-only lab interface` | `Unidentified network / Ethernet / Public / IPv4Connectivity NoTraffic` | `evidence/phase-0/phase0-20260708-khai/20260714-phase0-guest-connectivity-revalidation.txt` | The discovered host-only guest adapter is classified as Public |
| Guest-to-host reachability | `Reachable over host-only network` | `Two validation sets: 4/4 replies; 0% loss` | `evidence/phase-0/phase0-20260708-khai/20260714-phase0-guest-connectivity-revalidation.txt` | Current guest-to-host validation passes |
| Guest internet reachability | `Unavailable` | `8.8.8.8: 0/4 replies; 100% loss; exit code 1` | `evidence/phase-0/phase0-20260708-khai/20260714-phase0-guest-connectivity-revalidation.txt` | Current route evidence contains no internet-capable default route |
| Guest firewall profiles | `Recorded` | `Domain enabled / Private enabled / Public enabled; default inbound Block; default outbound Allow` | `evidence/phase-0/phase0-20260708-khai/20260714-phase0-guest-connectivity-revalidation.txt` | Current profile state is verified |
| Guest ICMP exception | `Narrow lab-only rule` | `AEGIS Guest Host-Only ICMPv4 In / enabled / inbound allow / Public / ICMPv4 type 8 / remote 192.168.15.0/24 / local 192.168.15.6 / discovered interface` | `evidence/phase-0/phase0-20260708-khai/20260714-phase0-guest-connectivity-revalidation.txt` | Allows only lab-subnet Echo Requests on the discovered guest host-only interface; no global firewall disablement |
| Guest public-IP check | `No public IP returned` | `IPv4 request failed: Could not resolve host; exit code 6` | `evidence/phase-0/phase0-20260708-khai/20260714-phase0-guest-connectivity-revalidation.txt` | Current evidence confirms no public IP was retrieved |
| Public exposure check | `No public exposure` | `No listeners on 9200/5601/8220; NAT and bridged VM adapters absent` | `evidence/phase-0/phase0-20260708-khai/20260714-1118-phase0-connectivity-firewall-revalidation.txt` | Current host listener and VM adapter state pass; current guest Internet isolation also passes |

## Temporary internet access log

Use this table only for installation or update windows that require temporary access. Disable internet access again before any scenario session.

| Date/time | Reason | Network mode used | Disabled after? | Evidence path | Notes |
| --- | --- | --- | --- | --- | --- |
| `2026-07-08 10:26 +07:00` | `No temporary victim VM internet access recorded during this task` | `Not applicable` | `Not applicable` | `evidence/phase-0/phase0-20260708-khai/20260708-1026-host-network-routes.txt` | Host routes were captured; no victim VM NAT/internet session was enabled by this task |

## Evidence to capture

- Host OS and hardware/RAM evidence.
- Host network route evidence.
- VirtualBox version evidence.
- Victim VM Windows version evidence.
- VirtualBox host-only adapter settings screenshot or export.
- Host-only adapter configuration export.
- Victim VM network adapter settings screenshot or export.
- Victim VM `ipconfig /all` or equivalent screenshot/export.
- Docker Desktop or Docker Engine version evidence.
- Notes showing Suricata, Wazuh, and Kafka were not started in Phase 0.
- Any temporary internet/NAT use during installation, with a note confirming it was disabled before scenario sessions.

## Success criteria

Phase 0 is ready to close only when:

- [x] Required component versions are recorded. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1413-victim-guest-properties-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1414-docker-final.txt`
- [x] VM configuration is recorded. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-network-snapshot-final.txt`
- [x] Host-only network configuration is recorded. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1412-host-network-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-network-snapshot-final.txt`
- [x] Evidence paths are linked for each required setup fact. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1412-host-network-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1414-docker-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-guest-isolation-evidence.txt`
- [x] Current guest-local firewall, connectivity, route, and Internet-isolation evidence is captured, and both final host-to-guest validation sets have 0% loss. Evidence: `evidence/phase-0/phase0-20260708-khai/20260714-phase0-guest-connectivity-revalidation.txt`, `evidence/phase-0/phase0-20260708-khai/20260714-host-to-guest-final-validation.txt`
- [x] No implementation code, Docker Compose file, Elastic config, Sigma rule, or Atomic Red Team script was created as part of Phase 0. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1236-remediation-guardrails-postchange.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1414-docker-final.txt`
- [x] Current status remains Phase 0 environment setup/evidence only; no Phase 1 services are running. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1414-docker-final.txt`

## Known gaps / pending items

| Gap / pending item | Owner | Needed before | Notes |
| --- | --- | --- | --- |
| Elastic/Kibana/Fleet container plan | `<name>` | Phase 1 planning | Do not create containers in Phase 0 |
| First real telemetry path | `<name>` | Phase 1 | Requires live Sysmon/Elastic Agent evidence |
| First `Live verified` scenario | `<name>` | Phase 3 | Requires real telemetry, linked timestamps, source evidence, and a sufficient evidence verdict |

## Phase 0 completion checklist

- [x] This document is filled with real local values. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1412-host-network-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1414-docker-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-guest-isolation-evidence.txt`
- [x] Every linked evidence path points to a real file created or supplied during setup and verification. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-guest-isolation-evidence.txt`
- [x] Network isolation and firewall completion have current authoritative guest-local output and successful bidirectional validation. Evidence: `evidence/phase-0/phase0-20260708-khai/20260714-phase0-guest-connectivity-revalidation.txt`, `evidence/phase-0/phase0-20260708-khai/20260714-host-to-guest-final-validation.txt`, `evidence/phase-0/phase0-20260708-khai/20260714-1118-phase0-connectivity-firewall-revalidation.txt`
- [x] No detection claim is made from Phase 0 setup evidence; Docker reports zero running containers. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1414-docker-final.txt`
- [x] Metrics remain `Not measured yet`; Phase 0 evidence records environment and isolation facts only. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1236-remediation-guardrails-postchange.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-guest-isolation-evidence.txt`

## Phase 1 transition gates

- [x] Phase 1 architecture and preflight decisions are reviewed before non-runtime implementation begins.
- [ ] Runtime startup remains gated until the resource prerequisites are satisfied and reverified, including adequate storage and `vm.max_map_count >= 1048576`.
