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

## Detection Fixtures

`datasets/detection/` contains suspicious normalized events used by Phase 2 offline detection checks:

- `process_suspicious_shell.json`
- `auth_failure_burst.json`
- `network_rare_port.json`

These fixtures are local lab data only.

## Alert Fixtures

`datasets/alerts/` contains expected `lab-alert` outputs for Phase 2 detection checks:

- `process_suspicious_shell.json`
- `auth_bruteforce.json`
- `network_rare_port.json`

`py detection/detect.py --check` compares detector output against these fixtures.

## Rules

- Keep checked-in fixtures small.
- Do not commit large generated replay outputs.
- Do not commit real sensitive telemetry.
- Do not add attack tooling here.
