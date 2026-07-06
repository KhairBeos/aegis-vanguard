# Rules

Phase 2 keeps rules as small JSON files so detection can run with Python stdlib only.

## Current Rule Set

- `suspicious_shell_encoded_command.json`
- `authentication_bruteforce.json`
- `rare_port_egress.json`

## Supported Rule Types

Phase 2 supports only:

- `field_contains_any`
- `threshold_count`
- `port_not_in`

Do not add YAML or large rule packs until the local JSON rule contract is stable.

## Required Metadata

Each rule must include:

- `id`
- `name`
- `description`
- `enabled`
- `event_type`
- `severity`
- `risk_score`
- `mitre`
- `tags`
- `detection`

Rules are lab fixtures for local validation. They are not claims of real-world detection coverage.
