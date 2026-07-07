from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


VALID_SOURCE_TYPES = {"stored", "fixture", "metadata"}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def response_envelope(
    data: Any,
    source_type: str,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    if source_type not in VALID_SOURCE_TYPES:
        raise ValueError(f"unsupported source_type: {source_type}")
    return {
        "data": data,
        "source_type": source_type,
        "generated_at": utc_now(),
        "warnings": warnings or [],
    }


def error_envelope(message: str, warnings: list[str] | None = None) -> dict[str, Any]:
    all_warnings = [message]
    if warnings:
        all_warnings.extend(warnings)
    return {
        "data": None,
        "source_type": "metadata",
        "generated_at": utc_now(),
        "warnings": all_warnings,
        "error": message,
    }
