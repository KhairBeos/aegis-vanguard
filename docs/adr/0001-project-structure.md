# ADR 0001: SIEM Project Structure

## Status

Accepted

## Date

2026-03-10

## Owner

Aegis-Vanguard Core Team

## Context

The platform combines multiple domains with different runtime and toolchain requirements:

- Endpoint telemetry collection (low-level, host-bound, eBPF/system code)
- Stream processing and detection (high-throughput C++ pipeline)
- Analyst-facing web UI (Next.js/TypeScript)
- Local infrastructure and operations assets (Docker, Kafka, ClickHouse)

Late-stage restructuring would be expensive because each domain has different dependency lifecycles, CI requirements, and release cadence.

## Decision Drivers

- Clear module boundaries and ownership
- Low coupling between runtime stacks
- Faster onboarding for contributors
- CI and testing isolation by component
- Minimized future refactor risk as project scope grows

## Considered Options

1. Single monolithic source tree with shared build and mixed concerns
2. Multi-repository split by module
3. Modular monorepo with domain folders and shared contracts

## Decision

Adopt a modular monorepo layout:

- `collector/` for endpoint collection logic
- `engine/` for detection and enrichment pipeline
- `dashboard/` for UI and analyst workflows
- `deploy/` for infrastructure definitions and bootstrap scripts
- `config/` for environment-scoped runtime configuration
- `rules/` for detection rules and validation assets
- `shared/` for common contracts (for example protobuf schemas)
- `tests/` for cross-module integration and end-to-end tests

## Rationale

The modular monorepo model balances local developer convenience with clear separation of concerns. It avoids operational overhead of multi-repo coordination while preserving independent evolution of major components.

## Trade-offs

- Pros: clearer boundaries, simpler local setup, better CI targeting, easier architecture traceability
- Cons: more initial scaffolding work, stricter contract discipline required across modules

## Consequences

- Architecture decisions can be documented and versioned per module with ADRs
- Teams can iterate on collector, engine, and dashboard in parallel
- Shared contracts become explicit integration points and must be versioned carefully
- Future additions (multi-tenant, new data sources, new engines) can be added with limited structural churn

## Migration Impact

For current project state, no migration is required because this ADR defines the baseline structure. Future structural changes must reference this ADR and include migration steps.

## Implementation Notes

- Use root-level build orchestration for native modules (`CMakeLists.txt`, `CMakePresets.json`)
- Keep infrastructure bootstrap assets under `deploy/`
- Keep integration and e2e tests in top-level `tests/`
- Keep API and storage contracts synchronized with `docs/api_spec.md`

## Related Artifacts

- `README.md`
- `docs/api_spec.md`
- `deploy/docker-compose.yml`
- `deploy/clickhouse/init/001_create_events.sql`

## Follow-up ADRs

- ADR 0002: Data contract versioning policy (`v1.1+`)
- ADR 0003: ClickHouse hot-column schema strategy
- ADR 0004: Risk scoring model and calibration
