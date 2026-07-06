# Phase 2 Verification

Phase 2 verification is local and stdlib-only.

## Check Fixtures

On Windows, prefer the Python Launcher when it is available:

```powershell
py detection/detect.py --check
```

If `py` is not available, use `python` or the available Python interpreter path in the current environment:

```powershell
python detection/detect.py --check
```

Expected result:

```text
OK suspicious-shell-encoded-command
OK authentication-bruteforce
OK rare-port-egress
Phase 2 detection check passed.
```

## Run One Fixture

```powershell
py detection/detect.py datasets/detection/process_suspicious_shell.json --out .tmp/alerts.json
```

`.tmp/` is ignored by git.

## What This Proves

- JSON rules are readable and validated.
- Local normalized fixtures can generate deterministic `lab-alert` records.
- The first three rules copy MITRE metadata into alerts.
- Alert output matches checked-in fixtures.

## What This Does Not Prove

- No Kafka messages are published yet.
- No ClickHouse alert table is created yet.
- No backend/API exists yet.
- No dashboard exists yet.
- No real-world detection coverage is claimed.
