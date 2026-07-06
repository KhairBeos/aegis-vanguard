# Worker

This folder documents worker boundaries for the local pipeline.

Phase 3A does not implement real Kafka producer/consumer workers yet. It defines the responsibilities that Phase 3B should implement after dependency approval.

Near-term boundaries:

- fixture producer: read local raw fixtures and publish to `raw.telemetry`
- normalizer worker: consume `raw.telemetry`, normalize to `lab-event`, publish to `normalized.events`
- storage writer: persist raw and normalized evidence to ClickHouse
- future alert publisher: consume `normalized.events`, reuse Phase 2 detection, publish to `security.alerts`

Keep this local-first and lightweight.

Current executable behavior still lives in:

- `normalization/normalize.py`
- `detection/detect.py`

See `worker/phase-3-pipeline-plan.md` for the Phase 3A worker contract.
