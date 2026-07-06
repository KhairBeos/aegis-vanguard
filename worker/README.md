# Worker

This folder is reserved for Phase 1 pipeline workers.

Near-term worker responsibilities:

- read sample/raw events
- normalize into the canonical `lab-event` shape
- publish to approved Kafka topics
- store raw event evidence

Keep this local-first and lightweight.
