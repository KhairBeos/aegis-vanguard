# Normalization

Phase 1 will use this folder for canonical event schema work and source adapters.

Near-term purpose:

- Define the approved `lab-event` shape from `PROJECT_PLAN.md`.
- Map sample source events into canonical events.
- Keep adapters small and testable.

Out of scope for Phase 0A:

- No normalization code yet.
- No new Python packages.
- No Kafka producer or storage logic changes.

Planned Phase 1 success check:

```text
sample event -> normalized event -> Kafka -> stored raw event
```
