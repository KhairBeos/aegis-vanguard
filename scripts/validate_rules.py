#!/usr/bin/env python3
"""Basic syntax validator for YAML-based detection rules."""

from pathlib import Path
import sys

try:
    import yaml
except ImportError:
    print("Missing dependency: pyyaml")
    print("Install with: pip install pyyaml")
    sys.exit(2)


def iter_rule_files(root: Path):
    for ext in ("*.yml", "*.yaml"):
        yield from root.rglob(ext)


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    rules_dir = repo_root / "rules"
    failures = []

    for file_path in iter_rule_files(rules_dir):
        try:
            yaml.safe_load(file_path.read_text(encoding="utf-8"))
        except Exception as exc:
            failures.append((file_path, str(exc)))

    if failures:
        print("Rule validation failed:")
        for file_path, err in failures:
            print(f"- {file_path}: {err}")
        return 1

    print("Rule validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
