# Phase 0 environment evidence

## Milestone result

- Result: `VM START FAILED — REVIEW REQUIRED`
- Evidence timestamp: `2026-07-28T14:08:26.7038661Z`
- Phase 0 status: `Future`
- VirtualBox: `7.2.12r174389`
- VM: `victim-win-01`

## Provisioned state

- Platform: Windows 11 (64-bit), 4 vCPU, 8192 MiB RAM, I/O APIC.
- Firmware security: EFI64, Secure Boot enabled, platform key plus Microsoft `KEK`, `db`, and `dbx` enrolled, TPM 2.0.
- Boot order: DVD, then disk; remaining boot devices disabled.
- Storage: one dynamically allocated 80 GiB VDI on SATA port 0 and `D:\Security-SOC\iso\Windows11_Enterprise_Evaluation_x64.iso` on SATA port 1.
- Network: exactly one enabled host-only NIC bound to the sole VirtualBox host-only adapter; cable connected; NIC 2-8 disabled; no NAT or bridged NIC.
- Matching VirtualBox guest DHCP server: `Enabled` before the milestone, `Disabled` afterward. The server and host-only adapter were retained.

## Verification

All pre-start checks passed:

- VM configuration, EFI64, Secure Boot keys, TPM 2.0, boot order, storage attachments, and dynamic disk capacity matched the requested values.
- Exactly one host-only NIC was active; no NAT or bridged NIC was active.
- The matching guest DHCP server remained present and disabled.
- ISO readability, host CPU/RAM/disk capacity, VM/disk registration counts, and clean repository state passed.

First-start evidence:

- GUI start succeeded and the VM entered `running`.
- The first boot loaded `cdboot.efi` twice, timed out after about 3.2 seconds each time, raised non-fatal `VMBootFail`, and displayed the UEFI firmware menu instead of Windows Setup.
- One minimal retry reset the blank VM and sent one Space key within the observed optical-media boot window.
- After that retry, the display remained black and the firmware log stopped progressing after `PciHostBridgeDxe`; Windows Setup was not visible.
- At the evidence timestamp, the VM remained `running`. No further input, configuration change, power action, installer action, or cleanup was performed.

## Known gaps and next gate

- Windows is not installed, and no installer screen was advanced.
- The exact ISO build and checksum have not been verified.
- The UEFI boot stall requires review before another boot attempt.
- Phase 0 remains `Future`; Phase 1 must not start from this state.
