# ADR 0002: Data Contract Versioning Policy

## Status

Accepted

## Date

2026-03-10

## Owner

Aegis-Vanguard Core Team

## Context

The SIEM pipeline has multiple producers and consumers:

- collectors publish events
- engine consumes events and produces alerts
- storage and dashboard consume persisted output

Without explicit versioning policy, independent module changes can break compatibility and create hard-to-debug runtime failures.

## Decision Drivers

- Backward compatibility for distributed components
- Controlled rollout of schema changes
- Clear migration path for breaking changes
- Predictable validation behavior in CI

## Considered Options

1. No explicit versioning; rely on code conventions
2. Date-based contract tags only
3. Semantic-style contract versioning with compatibility rules

## Decision

Adopt semantic-style contract versioning:

- Current active version: `v1.1`
- Minor updates (`v1.x`) allow additive, backward-compatible fields
- Major updates (`v2.0+`) are required for breaking schema changes

All events and alerts MUST carry `schema_version`.

## Compatibility Rules

- Producers may add optional fields in same major line.
- Consumers must ignore unknown fields within same major line.
- Removing or renaming required fields is a breaking change.
- Type changes of existing fields are breaking changes.

## Validation and Enforcement

- CI must validate schema examples in `docs/api_spec.md`.
- Runtime consumers must log version mismatch with event ID and host.
- Events with unsupported major versions must be routed to a quarantine/dead-letter path.

## Consequences

- Safer independent deployment of collector, engine, and dashboard.
- Slightly higher governance overhead when proposing field changes.
- Better auditability of data-contract evolution.

## Related Artifacts

- `docs/api_spec.md`
- `scripts/validate_rules.py`
- `deploy/kafka/init/create-topics.sh`
