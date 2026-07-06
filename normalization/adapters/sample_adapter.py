from __future__ import annotations

from datetime import datetime
from typing import Any


ALLOWED_KINDS = {"process_start", "network_connect", "auth_failure"}
ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}


class NormalizationError(ValueError):
    """Raised when a raw sample event cannot be normalized."""


def normalize(raw_event: dict[str, Any]) -> dict[str, Any]:
    """Convert one local sample raw event into the canonical lab-event shape."""
    if not isinstance(raw_event, dict):
        raise NormalizationError("raw event must be a JSON object")

    kind = _require_str(raw_event, "kind")
    if kind not in ALLOWED_KINDS:
        raise NormalizationError(f"unsupported kind: {kind}")

    raw_event_id = _require_str(raw_event, "raw_event_id")
    data = _require_object(raw_event, "data")
    timestamp = _require_timestamp(raw_event, "observed_at")
    severity = _require_str(raw_event, "severity")
    if severity not in ALLOWED_SEVERITIES:
        raise NormalizationError(f"unsupported severity: {severity}")

    event = {
        "schema": "lab-event",
        "event_id": _event_id_from_raw(raw_event_id),
        "timestamp": timestamp,
        "host": _require_str(raw_event, "host"),
        "source": _require_str(raw_event, "source"),
        "event_type": kind,
        "severity": severity,
        "tenant_id": _require_str(raw_event, "tenant_id"),
        "trace_id": _require_str(raw_event, "trace_id"),
        "event": _normalize_payload(kind, data),
    }
    _validate_canonical_event(event)
    return event


def _normalize_payload(kind: str, data: dict[str, Any]) -> dict[str, Any]:
    if kind == "process_start":
        return {
            "process": {
                "pid": _require_int(data, "pid"),
                "ppid": _require_int(data, "ppid"),
                "user_name": _require_str(data, "user"),
                "image": _require_str(data, "image"),
                "command_line": _require_str(data, "cmd"),
            }
        }

    if kind == "network_connect":
        return {
            "network": {
                "pid": _require_int(data, "pid"),
                "process_image": _require_str(data, "process_image"),
                "src_ip": _require_str(data, "src_ip"),
                "src_port": _require_port(data, "src_port"),
                "dst_ip": _require_str(data, "dst_ip"),
                "dst_port": _require_port(data, "dst_port"),
                "protocol": _require_enum(data, "protocol", {"tcp", "udp"}),
                "direction": _require_enum(data, "direction", {"inbound", "outbound"}),
            }
        }

    if kind == "auth_failure":
        return {
            "auth": {
                "user_name": _require_str(data, "user"),
                "src_ip": _require_str(data, "src_ip"),
                "auth_method": _require_str(data, "method"),
                "failure_reason": _require_str(data, "reason"),
            }
        }

    raise NormalizationError(f"unsupported kind: {kind}")


def _validate_canonical_event(event: dict[str, Any]) -> None:
    required = [
        "schema",
        "event_id",
        "timestamp",
        "host",
        "source",
        "event_type",
        "severity",
        "tenant_id",
        "trace_id",
        "event",
    ]
    for field in required:
        if field not in event:
            raise NormalizationError(f"canonical event missing field: {field}")

    if event["schema"] != "lab-event":
        raise NormalizationError("canonical schema must be lab-event")
    if event["event_type"] not in ALLOWED_KINDS:
        raise NormalizationError(f"unsupported canonical event_type: {event['event_type']}")
    if event["severity"] not in ALLOWED_SEVERITIES:
        raise NormalizationError(f"unsupported canonical severity: {event['severity']}")
    if not isinstance(event["event"], dict) or not event["event"]:
        raise NormalizationError("canonical event payload must be a non-empty object")


def _event_id_from_raw(raw_event_id: str) -> str:
    if not raw_event_id.startswith("raw-"):
        raise NormalizationError("raw_event_id must start with raw-")
    return "evt-" + raw_event_id.removeprefix("raw-")


def _require_object(obj: dict[str, Any], field: str) -> dict[str, Any]:
    value = obj.get(field)
    if not isinstance(value, dict):
        raise NormalizationError(f"missing object field: {field}")
    return value


def _require_str(obj: dict[str, Any], field: str) -> str:
    value = obj.get(field)
    if not isinstance(value, str) or value == "":
        raise NormalizationError(f"missing string field: {field}")
    return value


def _require_int(obj: dict[str, Any], field: str) -> int:
    value = obj.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise NormalizationError(f"missing non-negative integer field: {field}")
    return value


def _require_port(obj: dict[str, Any], field: str) -> int:
    value = _require_int(obj, field)
    if value > 65535:
        raise NormalizationError(f"port out of range: {field}")
    return value


def _require_enum(obj: dict[str, Any], field: str, allowed: set[str]) -> str:
    value = _require_str(obj, field)
    if value not in allowed:
        allowed_values = ", ".join(sorted(allowed))
        raise NormalizationError(f"{field} must be one of: {allowed_values}")
    return value


def _require_timestamp(obj: dict[str, Any], field: str) -> str:
    value = _require_str(obj, field)
    if not value.endswith("Z"):
        raise NormalizationError(f"{field} must be UTC and end with Z")
    try:
        datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise NormalizationError(f"{field} must be ISO-8601 UTC") from exc
    return value
