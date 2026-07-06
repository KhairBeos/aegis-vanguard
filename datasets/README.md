# Datasets

Phase 1 uses this folder for small local fixtures.

## Raw Samples

`datasets/raw/` contains source-shaped sample events:

- `process_start`
- `network_connect`
- `auth_failure`

These are intentionally simple local events, not Sysmon/Wazuh/Suricata records.

## Normalized Fixtures

`datasets/normalized/` contains expected canonical `lab-event` output for each raw sample.

`py normalization/normalize.py --check` compares adapter output against these fixtures on Windows. Use `python` or the available Python interpreter path if `py` is not available.

## Rules

- Keep checked-in fixtures small.
- Do not commit large generated replay outputs.
- Do not commit real sensitive telemetry.
- Do not add attack tooling here.
