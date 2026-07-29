# Phase 0 environment evidence

## Milestone result

- Result: `PHASE 0 RUNTIME ENVIRONMENT COMPLETE`
- Evidence timestamp: `2026-07-29T03:26:49.1846858Z`
- Guest operating system: Windows 11 Enterprise Evaluation
- VM: `victim-win-01`
- Snapshot: `clean-windows-11-baseline`

## Runtime baseline

- Windows installation is complete.
- VirtualBox Guest Additions is installed.
- The VM has exactly one active Host-only Adapter; no NAT or Bridged Adapter is enabled.
- Host lab address: `192.168.56.1`.
- Guest lab address: `192.168.56.10`.
- The guest has no default gateway or DNS server.
- Host-to-guest ping: PASS.
- Guest-to-host ping: PASS.
- The host firewall has a scoped ICMP rule for the lab.
- The matching VirtualBox DHCP server is disabled.
- A clean snapshot named `clean-windows-11-baseline` exists.

## Read-only host verification

On the host, `VBoxManage` confirmed that:

- `victim-win-01` is running.
- NIC 1 uses the Host-only Adapter.
- NIC 2 through NIC 8 are disabled.
- The matching DHCP server is disabled.
- `clean-windows-11-baseline` is the current snapshot.

No username, hostname, MAC address, machine identifier, or credential is recorded in this evidence.

## Boundary and next gate

Phase 0 manual setup and runtime environment are complete. Elastic Agent, telemetry ingestion, ECS verification, detection execution, and attack simulation remain outside Phase 0.
