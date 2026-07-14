# Phase 1 Step 1 Preflight Decision

- **Updated:** 2026-07-14
- **Evidence reviewed:** [`00-session-metadata.txt`](00-session-metadata.txt), [`01-windows-identity-support-sanitized.txt`](01-windows-identity-support-sanitized.txt), [`02-host-vm-resources.txt`](02-host-vm-resources.txt), [`03-docker-capacity-kernel.txt`](03-docker-capacity-kernel.txt), [`04-port-bind-check.txt`](04-port-bind-check.txt), [`06-guest-windows-preflight-sanitized.txt`](06-guest-windows-preflight-sanitized.txt), and [`07-host-ram-with-vm-running.txt`](07-host-ram-with-vm-running.txt).

## Official sources

Accessed 2026-07-14:

- [SoftwareLicensingProduct class](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/sppwmi/softwarelicensingproduct)
- [Windows 10 - release information](https://learn.microsoft.com/en-us/windows/release-health/release-information)
- [Windows 10, version 22H2 end of support date updated](https://learn.microsoft.com/en-us/lifecycle/announcements/windows-10-22h2-end-of-support-update)
- [Windows 10 Consumer Extended Security Updates](https://www.microsoft.com/en-us/windows/extended-security-updates)
- [Enable Windows 10 Extended Security Updates (ESU)](https://learn.microsoft.com/en-us/windows/whats-new/enable-extended-security-updates)
- [Support Matrix](https://www.elastic.co/support/matrix)
- [Increase virtual memory](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/vm-max-map-count)

## Detected Windows values

- Product/edition: **Windows 10 Pro**, `Professional`; display version **22H2**.
- Full build: **19045.3803**; build lab identifies an AMD64 free build.
- Architecture: **64-bit**, `Is64BitOperatingSystem=True`.
- Licensing channel: **RETAIL**.
- Ordinary activation state: `LicenseStatus=5`, which Microsoft defines as **Notification**, not `Licensed`; remaining grace is 0.
- ESU: no ESU product or status was returned. Windows 10 Pro 22H2 is eligible in principle for the consumer ESU path, but this evidence proves neither enrollment nor active ESU coverage.
- Servicing: the newest listed cumulative security evidence is `Package_for_RollupFix` **19041.3803.1.3** and **KB5033372**, corresponding to the December 2023 **19045.3803** baseline; the servicing-stack evidence includes **19041.3745.1.0**.

## Support analysis and verdicts

- Microsoft general support for Windows 10 Pro 22H2 ended on **2025-10-14**. Current ESU servicing requires enrollment and current prerequisite updates; neither is evidenced, and build 19045.3803 is substantially behind the current ESU servicing baseline.
- The Elastic support matrix lists Windows 10 for Elastic Agent 9.4.x and excludes 32-bit Windows and Windows on ARM. This x64 platform is not architecture-excluded, but Elastic compatibility does not override the missing Microsoft-supported/ESU state.
- **Windows decision state:** `Unsupported isolated-lab exception approved` — the user explicitly accepted the unsupported Windows 10 Pro 22H2 build 19045.3803 x64 baseline only for this isolated, host-only, non-production lab.
- **Resource verdict:** `Resource remediation approval required` — unchanged and independent of the Windows verdict.

The exception does not establish Microsoft-supported, production-ready, or generally supported status. Active ESU was not evidenced. Elastic Agent installation must stop if platform incompatibility or instability occurs; rebuilding or upgrading to a supported Windows version remains the fallback.

## Unchanged resource gates

- Host available RAM with the running VM: **2.16 GiB**, below **5 GiB**.
- Docker backing-drive free space: **16.69 GiB**, below **20 GiB**.
- `vm.max_map_count`: **262144**, below **1048576**.
- VirtualBox currently reports the operator-approved **4096 MiB RAM and 3 vCPUs**. Phase 0 now links [`20260714-1023-phase0-vm-resource-amendment.txt`](../../phase-0/phase0-20260708-khai/20260714-1023-phase0-vm-resource-amendment.txt), while the earlier 6144 MiB evidence remains preserved.
- Phase 0 is complete. Final host-to-guest validation passed twice with 0% loss, and current guest-local evidence verifies addressing, firewall, guest-to-host connectivity, no IPv4 default route, failed external ping, and failed public-IP retrieval. Evidence: [`20260714-host-to-guest-final-validation.txt`](../../phase-0/phase0-20260708-khai/20260714-host-to-guest-final-validation.txt), [`20260714-phase0-guest-connectivity-revalidation.txt`](../../phase-0/phase0-20260708-khai/20260714-phase0-guest-connectivity-revalidation.txt), and [`20260714-1118-phase0-connectivity-firewall-revalidation.txt`](../../phase-0/phase0-20260708-khai/20260714-1118-phase0-connectivity-firewall-revalidation.txt).

## Decisions requiring approval

1. Satisfy and reverify the resource prerequisites before runtime startup; no remediation is authorized by this decision update.

## Conclusion and limitations

The Windows exception and current VM allocation are approved and recorded, and Phase 0 is complete. Resource shortcomings do not block non-runtime Phase 1 work such as repository scaffolding, Compose/configuration authoring, TLS design, or secret-handling design. Actual `docker compose up`, Elasticsearch startup, and live Agent ingestion remain blocked until runtime prerequisites are satisfied and reverified, including adequate RAM and storage and `vm.max_map_count >= 1048576`; the resource gate is not passed. No repository scaffolding, image, container, certificate, secret, firewall rule, Agent, detection, alerting, coverage, or `Live verified` artifact was created, and no system or configuration state was changed by this review.
