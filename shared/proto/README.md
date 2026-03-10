# Shared Protobuf

Canonical SIEM machine-readable contracts used across collector, engine, and downstream consumers.

Current files:

- `event.proto`: canonical event envelope and payload variants.
- `alert.proto`: detection output contract with numeric risk scoring.

Contract source of truth:

- `docs/api_spec.md` (version `v1.1`)

Example generation command:

```bash
protoc -I . --cpp_out=. shared/proto/event.proto shared/proto/alert.proto
```
