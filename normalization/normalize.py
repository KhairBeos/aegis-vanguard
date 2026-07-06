from __future__ import annotations

import argparse
import difflib
import json
import sys
from pathlib import Path
from typing import Any

from adapters.sample_adapter import NormalizationError, normalize


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ("process_start", "network_connect", "auth_failure")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Normalize AEGIS-VANGUARD sample events.")
    parser.add_argument("input", nargs="?", help="Path to one raw sample JSON file.")
    parser.add_argument("--out", help="Optional output path for normalized JSON.")
    parser.add_argument("--check", action="store_true", help="Verify all raw samples against fixtures.")
    args = parser.parse_args(argv)

    try:
        if args.check:
            return _check_all()
        if not args.input:
            parser.error("input is required unless --check is used")
        normalized = normalize(_read_json(Path(args.input)))
        _write_or_print(normalized, args.out)
        return 0
    except (OSError, json.JSONDecodeError, NormalizationError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def _check_all() -> int:
    for sample in SAMPLES:
        raw_path = ROOT / "datasets" / "raw" / f"{sample}.json"
        expected_path = ROOT / "datasets" / "normalized" / f"{sample}.json"
        actual = normalize(_read_json(raw_path))
        expected = _read_json(expected_path)
        if actual != expected:
            print(f"FAIL {sample}", file=sys.stderr)
            print(_diff(expected, actual), file=sys.stderr)
            return 1
        print(f"OK {sample}")
    print("Phase 1 normalization check passed.")
    return 0


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise NormalizationError(f"JSON root must be an object: {path}")
    return data


def _write_or_print(data: dict[str, Any], out: str | None) -> None:
    text = _format_json(data)
    if out is None:
        print(text)
        return
    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text + "\n", encoding="utf-8")


def _diff(expected: dict[str, Any], actual: dict[str, Any]) -> str:
    expected_lines = _format_json(expected).splitlines()
    actual_lines = _format_json(actual).splitlines()
    return "\n".join(
        difflib.unified_diff(
            expected_lines,
            actual_lines,
            fromfile="expected",
            tofile="actual",
            lineterm="",
        )
    )


def _format_json(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    raise SystemExit(main())
