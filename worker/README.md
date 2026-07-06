# Worker

This folder is reserved for Phase 1 pipeline workers.

Near-term responsibilities:

- read sample/raw events
- normalize into the canonical `lab-event` shape
- document the approved Kafka topic flow
- document raw event storage

Keep this local-first and lightweight.

Current Phase 1 implementation lives in `normalization/` until a worker process is actually needed.
