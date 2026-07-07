from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class FixtureReadResult:
    data: list[dict[str, Any]]
    warnings: list[str]


def read_rules(repo_root: Path) -> FixtureReadResult:
    return _read_json_objects(repo_root / "rules", "*.json", repo_root)


def read_alert_fixtures(repo_root: Path) -> FixtureReadResult:
    return _read_json_objects(repo_root / "datasets" / "alerts", "*.json", repo_root)


def _read_json_objects(directory: Path, pattern: str, repo_root: Path) -> FixtureReadResult:
    warnings: list[str] = []
    records: list[dict[str, Any]] = []
    if not directory.exists():
        return FixtureReadResult([], [f"fixture directory missing: {_display_path(directory, repo_root)}"])

    for path in sorted(directory.glob(pattern)):
        try:
            with path.open("r", encoding="utf-8") as handle:
                value = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            warnings.append(f"failed to read {_display_path(path, repo_root)}: {exc}")
            continue
        if not isinstance(value, dict):
            warnings.append(f"fixture root must be an object: {_display_path(path, repo_root)}")
            continue
        value = dict(value)
        value["_fixture_file"] = _display_path(path, repo_root)
        records.append(value)

    if not records:
        warnings.append(f"no fixture files matched {pattern} in {_display_path(directory, repo_root)}")
    return FixtureReadResult(records, warnings)


def _display_path(path: Path, repo_root: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return path.as_posix()
