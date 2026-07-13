# Phase 0 environment setup and evidence record

> Status: Phase 0 is complete. Raw post-firewall guest evidence proves all three Windows Firewall profiles are enabled with default inbound `Block` and outbound `Allow`, the host-only Ethernet network profile is `Public`, the guest ICMPv4 Echo Request exception is limited to the lab subnet/interface, bidirectional host-only communication succeeds, and the guest has no internet-capable default route, cannot reach `8.8.8.8`, and cannot retrieve a public IP. VM host-only/NAT isolation, the current baseline snapshot, and Docker readiness with zero containers remain verified. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1504-post-firewall-remediation-host-vm-docker-recheck.txt`.

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
| Windows 10/11 victim VM | Yes | Generates real endpoint telemetry in later phases | `AEGIS-WIN-VICTIM-01 / running / Windows 10 build 10.0.19045.3803 / 3 CPU / 6144 MB RAM / 61440 MB disk` | `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1413-victim-guest-properties-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1504-post-firewall-remediation-host-vm-docker-recheck.txt` | VM configuration, running state, current guest address, firewall state, and isolation are recorded |
| Host-only network | Yes | Isolates victim VM from public networks | `VirtualBox Host-Only Ethernet Adapter #2 / 192.168.15.1 / 255.255.255.0` | `evidence/phase-0/phase0-20260708-khai/20260713-1412-host-network-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1504-post-firewall-remediation-host-vm-docker-recheck.txt` | Bidirectional host-only communication and continued guest internet isolation are verified |
| Docker Desktop or Docker Engine | Yes | Runs future local SIEM services | `Docker Desktop 4.79.0 / Engine 29.5.3 / context desktop-linux / 0 running containers` | `evidence/phase-0/phase0-20260708-khai/20260713-1504-post-firewall-remediation-host-vm-docker-recheck.txt` | Docker daemon is reachable; no SIEM services or other containers are running |
| Future Elastic/Kibana/Fleet containers | No, planned | Later telemetry ingestion and review stack | `Not created yet` | `<future path>` | Do not create in Phase 0 |

## Network isolation checklist

- [x] Host-only adapter exists in VirtualBox at `192.168.15.1/24`. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1412-host-network-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-network-snapshot-final.txt`
- [x] Victim VM uses host-only networking for lab traffic. Adapter 1 is `hostonly` on `VirtualBox Host-Only Ethernet Adapter #2`. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt`
- [x] Victim VM is not configured with bridged networking. Adapter 1 is host-only and adapters 2-8 are disabled. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt`
- [x] NAT is absent from the current VM configuration. Adapter 1 is host-only, adapters 2-8 are disabled, and no VirtualBox NAT network is listed. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-network-snapshot-final.txt`
- [x] Victim VM has no active internet route after guest firewall remediation. The default gateway is blank, no `0.0.0.0/0` route exists, and persistent routes are `None`. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt`
- [x] Public IP check from the victim VM returns no public IP after guest firewall remediation. The request fails with `Could not resolve host` and returns no address. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt`
- [x] Host can reach the victim VM on the host-only network after guest firewall remediation. Four ICMP replies were received with 0% loss. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1504-post-firewall-remediation-host-vm-docker-recheck.txt`
- [x] Victim VM can reach `192.168.15.1` and remains unable to reach `8.8.8.8` or retrieve a public IP after remediation. Host ping receives 4/4 replies; internet ping loses 4/4 packets; the public-IP request returns no address. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt`
- [x] Domain, Private, and Public guest firewall profiles are enabled with default inbound `Block` and outbound `Allow`. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt`
- [x] The guest ICMP exception is a narrow lab-only rule: enabled inbound `Allow`, Public profile, ICMPv4 type 8, remote `192.168.15.0/24`, local `192.168.15.6`, and interface Ethernet. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt`
- [x] The host ICMP rule is limited to inbound ICMPv4 Echo Request from `192.168.15.0/24` on the VirtualBox host-only interface; the firewall is not globally disabled. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1412-host-firewall-rule-final.txt`
- [x] No SIEM lab service is exposed on a public interface because Docker reports zero running containers. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1414-docker-final.txt`
- [x] Export captured for VM network adapter settings. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt`
- [x] Export captured for host-only network settings. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1412-host-network-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-network-snapshot-final.txt`

Final isolation verification is `Complete` after guest firewall remediation: the guest firewall remains enabled with a narrow lab-only ICMP exception, bidirectional host-only ping succeeds, the guest has no internet-capable default route, `8.8.8.8` is unreachable, no public IP is returned, VM adapter 1 remains host-only, adapters 2-8 remain disabled, and NAT/bridged networking remains absent. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1504-post-firewall-remediation-host-vm-docker-recheck.txt`.

## Version inventory table

| Item | Version / build | How recorded | Evidence file path | Status | Notes |
| --- | --- | --- | --- | --- | --- |
| Host OS | `Windows 10 Home Single Language 25H2 build 26200.8655` | Registry export plus hostname fallback | `evidence/phase-0/phase0-20260708-khai/20260708-1027-host-os-registry-hostname.txt` | `Recorded` | CIM systeminfo access was denied; registry fallback succeeded |
| Host RAM | `~15.69 GiB total; ~3.26 GiB available at capture time` | Environment/.NET fallback | `evidence/phase-0/phase0-20260708-khai/20260708-1027-host-cpu-ram-env-dotnet.txt` | `Recorded` | Also recorded 16 logical processors |
| VirtualBox | `7.2.4r170995` | `VBoxManage --version` | `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt` | `Recorded` | Version refreshed during the final review |
| Windows victim VM OS | `Windows 10 build 10.0.19045.3803` | VirtualBox guest properties | `evidence/phase-0/phase0-20260708-khai/20260713-1413-victim-guest-properties-final.txt` | `Recorded` | Guest Additions reported the product, release, and guest NIC address; authenticated guest command output remains unavailable |
| Docker Desktop / Docker Engine | `Docker Desktop 4.79.0; Engine 29.5.3` | `docker version`; `docker context ls`; `docker info`; `docker ps --no-trunc` | `evidence/phase-0/phase0-20260708-khai/20260713-1414-docker-final.txt` | `Recorded` | Active context is `desktop-linux`; daemon is reachable; running containers: 0 |
| Elastic image tag | `<future value>` | `<future source>` | `<future path>` | `Future` | Record only when planned containers are created |
| Kibana image tag | `<future value>` | `<future source>` | `<future path>` | `Future` | Record only when planned containers are created |
| Fleet image/tag or integration version | `<future value>` | `<future source>` | `<future path>` | `Future` | Record only when planned Fleet work starts |

## VM configuration table

| Setting | Planned value | Actual value | Evidence file path | Notes |
| --- | --- | --- | --- | --- |
| VM name | `AEGIS-WIN-VICTIM-01` | `AEGIS-WIN-VICTIM-01` (`running`) | `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt` | Registered and running during final capture |
| VM state | `Running for evidence capture` | `running` | `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt` | Read-only checks did not start, stop, or modify the VM |
| Windows version | `Windows 10/11` | `Windows 10 build 10.0.19045.3803` | `evidence/phase-0/phase0-20260708-khai/20260713-1413-victim-guest-properties-final.txt` | Reported by VirtualBox Guest Additions; guest `systeminfo` was not recorded |
| CPU allocation | `3` | `3 vCPU` | `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt` | `cpus=3` |
| RAM allocation | `6144 MB` | `6144 MB` | `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt` | `memory=6144` |
| Disk size | `61440 MB` | `61440 MB` | `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt` | VDI differencing medium; capacity recorded separately from current allocated file size |
| Network adapter 1 | `Host-only adapter` | `Host-only / VirtualBox Host-Only Ethernet Adapter #2 / cable connected` | `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt` | Host and guest are aligned on `192.168.15.0/24`; host-to-guest ping succeeds |
| Network adapters 2-8 | `Disabled unless temporarily needed` | `Disabled` | `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt` | NAT and bridged networking are absent from the current VM configuration |
| Snapshot baseline | `clean-windows-baseline` | `clean-windows-baseline` exists and is current | `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-network-snapshot-final.txt` | Snapshot description states no Sysmon, Elastic Agent, or Atomic Red Team is installed |

## Network configuration table

| Item | Planned value | Actual value | Evidence file path | Notes |
| --- | --- | --- | --- | --- |
| Host-only adapter name | `VirtualBox Host-Only Ethernet Adapter #2` | `VirtualBox Host-Only Ethernet Adapter #2` | `evidence/phase-0/phase0-20260708-khai/20260713-1412-host-network-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-network-snapshot-final.txt` | GUID and MAC match the target; adapter status: Up |
| Host-only subnet | `Host and guest on the same isolated subnet` | `192.168.15.0/24` | `evidence/phase-0/phase0-20260708-khai/20260713-1412-host-network-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1413-victim-guest-properties-final.txt` | One connected lab route exists; other active host and Docker networks do not overlap |
| Host IP on lab network | `Same subnet as victim VM` | `192.168.15.1/24` | `evidence/phase-0/phase0-20260708-khai/20260713-1412-host-network-final.txt` | Manual IPv4; no default gateway or DNS |
| Victim VM IP | `Same subnet as host-only adapter` | `192.168.15.6/24` (DHCP lease) | `evidence/phase-0/phase0-20260708-khai/20260713-1413-victim-guest-properties-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1414-virtualbox-guest-lease-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt` | Guest Additions, the active DHCP lease, and current raw guest `ipconfig /all` agree |
| Host route to victim VM | `Reachable over host-only network` | `Connected route; fresh post-remediation ping succeeds with 0% loss` | `evidence/phase-0/phase0-20260708-khai/20260713-1412-host-network-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1504-post-firewall-remediation-host-vm-docker-recheck.txt` | Host-to-guest reachability is verified after the user-performed firewall remediation |
| Host ICMP firewall rule | `Scoped lab rule only` | `Inbound ICMPv4 Echo Request / remote 192.168.15.0/24 / interface Ethernet` | `evidence/phase-0/phase0-20260708-khai/20260713-1412-host-firewall-rule-final.txt` | Interface alias maps to the target VirtualBox host-only adapter; no global firewall disablement |
| Victim guest `ipconfig /all` | `Recorded` | `192.168.15.6 / 255.255.255.0 / DHCP enabled` | `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt` | Guest NIC MAC and DHCP server `192.168.15.2` match the VirtualBox lease evidence |
| Default gateway in victim VM | `<none or controlled value>` | `None` | `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt` | Default Gateway is blank; the IPv4 route table has no `0.0.0.0/0` entry and persistent routes are `None` |
| DNS in victim VM | `<none or controlled value>` | `No IPv4 DNS server addresses` | `evidence/phase-0/phase0-20260708-khai/20260713-guest-isolation-evidence.txt` | `Get-DnsClientServerAddress` reports `{}` for Ethernet; `ipconfig /all` lists only IPv6 site-local placeholder addresses |
| Guest network profile | `Host-only lab interface` | `Unidentified network / Ethernet / Public / IPv4Connectivity NoTraffic` | `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt` | The host-only guest adapter is classified as Public |
| Guest-to-host reachability | `Reachable over host-only network` | `4/4 replies; 0% loss` | `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt` | Guest-to-host communication remains successful with the firewall enabled |
| Guest internet reachability | `Unavailable` | `8.8.8.8: 0/4 replies; 100% loss; General failure` | `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt` | The route table contains no internet-capable default route |
| Guest firewall profiles | `Recorded` | `Domain enabled / Private enabled / Public enabled; default inbound Block; default outbound Allow` | `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt` | All profiles remain enabled after remediation |
| Guest ICMP exception | `Narrow lab-only rule` | `AEGIS Guest Host-Only ICMPv4 In / enabled / inbound allow / Public / ICMPv4 type 8 / remote 192.168.15.0/24 / local 192.168.15.6 / Ethernet` | `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt` | Allows only lab-subnet Echo Requests on the guest host-only interface; no global firewall disablement |
| Guest public-IP check | `No public IP returned` | `Request failed: Could not resolve host; no address returned` | `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt` | Confirms no public IP was retrieved |
| Public exposure check | `No public exposure` | `0 running Docker containers; NAT and bridged VM adapters absent` | `evidence/phase-0/phase0-20260708-khai/20260713-1413-virtualbox-vm-final.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1414-docker-final.txt` | Confirms current service and VM adapter state only |

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
- [x] Victim VM isolation is confirmed after guest firewall remediation. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1504-post-firewall-remediation-host-vm-docker-recheck.txt`
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
- [x] Network isolation is re-confirmed after guest firewall remediation. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-post-firewall-evidence.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-1504-post-firewall-remediation-host-vm-docker-recheck.txt`
- [x] No detection claim is made from Phase 0 setup evidence; Docker reports zero running containers. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1414-docker-final.txt`
- [x] Metrics remain `Not measured yet`; Phase 0 evidence records environment and isolation facts only. Evidence: `evidence/phase-0/phase0-20260708-khai/20260713-1236-remediation-guardrails-postchange.txt`, `evidence/phase-0/phase0-20260708-khai/20260713-guest-isolation-evidence.txt`

## Phase 1 transition gates

- [ ] Next phase plan is reviewed before implementation begins.
- [ ] Phase 1 plan is reviewed and approved before Elastic/Fleet implementation begins.
