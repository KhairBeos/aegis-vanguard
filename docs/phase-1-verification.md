# Phase 1 Verification

Phase 1 verification is local and stdlib-only.

## Check Fixtures

On Windows, prefer the Python Launcher when it is available:

```powershell
py normalization/normalize.py --check
```

If `py` is not available, use `python` or the available Python interpreter path in the current environment:

```powershell
python normalization/normalize.py --check
```

Expected result:

```text
OK process_start
OK network_connect
OK auth_failure
Phase 1 normalization check passed.
```

## Normalize One Sample

```powershell
py normalization/normalize.py datasets/raw/process_start.json --out .tmp/process_start.normalized.json
```

`.tmp/` is ignored by git.

## What This Proves

- Raw samples are readable.
- Required raw fields are validated.
- Each sample maps into the canonical `lab-event` shape.
- Output is deterministic and matches checked-in fixtures.

## What This Does Not Prove

- No Kafka messages are published yet.
- No ClickHouse table is created yet.
- No detection rules or alerts exist yet.
- `security.alerts` is reserved for Phase 2.
