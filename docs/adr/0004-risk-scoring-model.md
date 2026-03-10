# ADR 0004: Risk Scoring Model and Calibration

## Status

Accepted

## Date

2026-03-10

## Owner

Aegis-Vanguard Core Team

## Context

String-based severity labels (`low`, `medium`, `high`, `critical`) are useful for readability but not sufficient for quantitative analytics. SOC workflows require sorting, thresholding, trend analysis, and host-level aggregation.

## Decision Drivers

- Numeric ranking of alerts
- Statistical calculations in dashboard and reporting
- Consistent behavior across rules and data sources
- Ability to calibrate scoring logic over time

## Considered Options

1. Keep severity string only
2. Static integer per severity level
3. Base severity score with rule/context modifiers

## Decision

Adopt numeric `risk_score` with range `0..100` in alert contract.

Initial baseline mapping:

- `low` -> 25
- `medium` -> 50
- `high` -> 75
- `critical` -> 90

Engine may apply bounded modifiers (for example, +0..10) based on context confidence, repetition, or threat intelligence weight, but final score must remain in `0..100`.

## Scoring Governance

- Each detection rule should define default severity and base score intent.
- Calibration changes must be recorded in ADR or rule changelog.
- Dashboard and APIs must use `risk_score` for ranking and threshold filters.

## Validation Rules

- `risk_score` must be an integer.
- Value must be between `0` and `100` inclusive.
- Missing `risk_score` in alerts is invalid for `v1.1` contract.

## Consequences

- Enables quantitative dashboards and host risk rollups.
- Improves triage prioritization consistency.
- Requires periodic score calibration to avoid drift and alert fatigue.

## Related Artifacts

- `docs/api_spec.md`
- `deploy/clickhouse/init/001_create_events.sql`
- `dashboard/src/` (alert ranking and aggregation views)
