# End-to-End Tests

Use this directory for full-system scenarios with docker-compose.

Primary harness:

- `deploy/scripts/engine_e2e.ps1` starts the stack, runs the engine, sends 5 `auth_failure` events, and verifies both `aegis.raw_events` and `aegis.alerts`.

Recommended cases:

- brute force simulation triggers alert
- suspicious process tree triggers alert
- network beacon pattern triggers alert
