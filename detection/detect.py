"""Offline Phase 2 detection over local normalized fixtures."""

from __future__ import annotations

import argparse
import difflib
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from rule_loader import RuleValidationError, load_rules


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES_DIR = ROOT / "rules"

CHECK_CASES = [
    (
        "suspicious-shell-encoded-command",
        ROOT / "datasets" / "detection" / "process_suspicious_shell.json",
        ROOT / "datasets" / "alerts" / "process_suspicious_shell.json",
    ),
    (
        "authentication-bruteforce",
        ROOT / "datasets" / "detection" / "auth_failure_burst.json",
        ROOT / "datasets" / "alerts" / "auth_bruteforce.json",
    ),
    (
        "rare-port-egress",
        ROOT / "datasets" / "detection" / "network_rare_port.json",
        ROOT / "datasets" / "alerts" / "network_rare_port.json",
    ),
]

ALERT_REQUIRED_FIELDS = {
    "schema",
    "alert_id",
    "timestamp",
    "rule_id",
    "rule_name",
    "severity",
    "risk_score",
    "tenant_id",
    "trace_id",
    "event_id",
    "host",
    "event_type",
    "mitre",
    "evidence",
}


class DetectionError(ValueError):
    """Raised when fixture detection cannot complete."""


def main() -> int:
    parser = argparse.ArgumentParser(description="Run offline AEGIS-VANGUARD Phase 2 detection.")
    parser.add_argument("input", nargs="?", help="Path to a normalized event fixture.")
    parser.add_argument("--check", action="store_true", help="Compare Phase 2 detection fixtures.")
    parser.add_argument("--out", help="Write alert output to this JSON file.")
    parser.add_argument("--rules-dir", default=str(DEFAULT_RULES_DIR), help="Directory containing JSON rules.")
    args = parser.parse_args()

    try:
        rules = load_rules(Path(args.rules_dir))
        if args.check:
            run_check(rules)
            return 0
        if not args.input:
            raise DetectionError("provide an input fixture or use --check")

        alerts = detect_fixture(Path(args.input), rules)
        if args.out:
            write_json(Path(args.out), alerts)
        else:
            print(json.dumps(alerts, indent=2))
        return 0
    except (DetectionError, RuleValidationError, FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def run_check(rules: list[dict[str, Any]]) -> None:
    for rule_id, input_path, expected_path in CHECK_CASES:
        actual = detect_fixture(input_path, rules)
        expected = load_expected_alerts(expected_path)
        if actual != expected:
            diff = "\n".join(
                difflib.unified_diff(
                    format_json(expected).splitlines(),
                    format_json(actual).splitlines(),
                    fromfile=str(expected_path),
                    tofile=f"actual:{input_path.name}",
                    lineterm="",
                )
            )
            raise DetectionError(f"{rule_id} fixture mismatch\n{diff}")
        print(f"OK {rule_id}")
    print("Phase 2 detection check passed.")


def detect_fixture(path: Path, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events = load_events(path)
    alerts = evaluate_rules(events, rules)
    for alert in alerts:
        validate_alert(alert)
    return sorted(alerts, key=lambda alert: alert["alert_id"])


def load_events(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if isinstance(payload, list):
        events = payload
    elif isinstance(payload, dict) and payload.get("schema") == "lab-event":
        events = [payload]
    elif isinstance(payload, dict) and isinstance(payload.get("events"), list):
        events = payload["events"]
    else:
        raise DetectionError(f"{path}: expected a lab-event, a list of lab-events, or an events list")

    for event in events:
        validate_event(event, path)
    return events


def load_expected_alerts(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    alerts = payload if isinstance(payload, list) else [payload]
    for alert in alerts:
        validate_alert(alert)
    return sorted(alerts, key=lambda alert: alert["alert_id"])


def evaluate_rules(events: list[dict[str, Any]], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for rule in rules:
        if not rule["enabled"]:
            continue
        rule_type = rule["detection"]["type"]
        if rule_type == "field_contains_any":
            alerts.extend(evaluate_field_contains_any(rule, events))
        elif rule_type == "threshold_count":
            alerts.extend(evaluate_threshold_count(rule, events))
        elif rule_type == "port_not_in":
            alerts.extend(evaluate_port_not_in(rule, events))
        else:
            raise DetectionError(f"unsupported detection type: {rule_type}")
    return alerts


def evaluate_field_contains_any(
    rule: dict[str, Any], events: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    detection = rule["detection"]
    for event in matching_event_type(rule, events):
        if not requirements_match(event, detection.get("requires", [])):
            continue

        field = detection["field"]
        value = get_field(event, field)
        matched_values = contains_any(value, detection["values"])
        if not matched_values:
            continue

        matched_fields = requirement_fields(event, detection.get("requires", []))
        matched_fields[field] = value
        evidence = {
            "matched_fields": matched_fields,
            "matched_values": matched_values,
            "reason": "process image indicated PowerShell and command line contained an encoded-command indicator",
        }
        alerts.append(build_single_event_alert(rule, event, evidence))
    return alerts


def evaluate_port_not_in(rule: dict[str, Any], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    detection = rule["detection"]
    allowed_ports = detection["allowed_ports"]
    for event in matching_event_type(rule, events):
        if not requirements_match(event, detection.get("requires", [])):
            continue

        field = detection["field"]
        port = get_field(event, field)
        if not isinstance(port, int):
            raise DetectionError(f"{event['event_id']}: {field} must be an integer")
        if port in allowed_ports:
            continue

        matched_fields = requirement_fields(event, detection.get("requires", []))
        matched_fields[field] = port
        evidence = {
            "matched_fields": matched_fields,
            "allowed_ports": allowed_ports,
            "reason": "outbound destination port was not in the common allowed port list",
        }
        alerts.append(build_single_event_alert(rule, event, evidence))
    return alerts


def evaluate_threshold_count(
    rule: dict[str, Any], events: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    detection = rule["detection"]
    threshold = detection["threshold"]
    window = timedelta(seconds=detection["window_seconds"])

    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for event in matching_event_type(rule, events):
        key = tuple(get_field(event, field) for field in detection["group_by"])
        groups[key].append(event)

    alerts: list[dict[str, Any]] = []
    for group_events in groups.values():
        ordered = sorted(group_events, key=lambda event: (parse_timestamp(event["timestamp"]), event["event_id"]))
        matched = first_threshold_window(ordered, threshold, window)
        if matched:
            alerts.append(build_threshold_alert(rule, matched, detection["window_seconds"]))
    return alerts


def first_threshold_window(
    events: list[dict[str, Any]], threshold: int, window: timedelta
) -> list[dict[str, Any]]:
    for index, start_event in enumerate(events):
        start_time = parse_timestamp(start_event["timestamp"])
        matched: list[dict[str, Any]] = []
        for event in events[index:]:
            if parse_timestamp(event["timestamp"]) - start_time <= window:
                matched.append(event)
            if len(matched) == threshold:
                return matched
    return []


def build_single_event_alert(
    rule: dict[str, Any], event: dict[str, Any], evidence: dict[str, Any]
) -> dict[str, Any]:
    return {
        "schema": "lab-alert",
        "alert_id": f"alert-{rule['id']}-{event['event_id']}",
        "timestamp": event["timestamp"],
        "rule_id": rule["id"],
        "rule_name": rule["name"],
        "severity": rule["severity"],
        "risk_score": rule["risk_score"],
        "tenant_id": event["tenant_id"],
        "trace_id": event["trace_id"],
        "event_id": event["event_id"],
        "host": event["host"],
        "event_type": event["event_type"],
        "mitre": rule["mitre"],
        "evidence": evidence,
    }


def build_threshold_alert(
    rule: dict[str, Any], events: list[dict[str, Any]], window_seconds: int
) -> dict[str, Any]:
    first_event = events[0]
    last_event = events[-1]
    evidence = {
        "event_ids": [event["event_id"] for event in events],
        "count": len(events),
        "window_seconds": window_seconds,
        "src_ip": get_field(first_event, "event.auth.src_ip"),
        "user_name": get_field(first_event, "event.auth.user_name"),
        "reason": "three authentication failures matched the same tenant, host, source IP, and user within five minutes",
    }
    return {
        "schema": "lab-alert",
        "alert_id": f"alert-{rule['id']}-{first_event['event_id']}-{last_event['event_id']}",
        "timestamp": last_event["timestamp"],
        "rule_id": rule["id"],
        "rule_name": rule["name"],
        "severity": rule["severity"],
        "risk_score": rule["risk_score"],
        "tenant_id": first_event["tenant_id"],
        "trace_id": first_event["trace_id"],
        "event_id": first_event["event_id"],
        "host": first_event["host"],
        "event_type": first_event["event_type"],
        "mitre": rule["mitre"],
        "evidence": evidence,
    }


def matching_event_type(rule: dict[str, Any], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [event for event in events if event["event_type"] == rule["event_type"]]


def requirements_match(event: dict[str, Any], requirements: list[dict[str, Any]]) -> bool:
    for requirement in requirements:
        value = get_field(event, requirement["field"])
        if "equals" in requirement and value != requirement["equals"]:
            return False
        if "contains_any" in requirement and not contains_any(value, requirement["contains_any"]):
            return False
    return True


def requirement_fields(event: dict[str, Any], requirements: list[dict[str, Any]]) -> dict[str, Any]:
    return {requirement["field"]: get_field(event, requirement["field"]) for requirement in requirements}


def contains_any(value: Any, needles: list[str]) -> list[str]:
    haystack = str(value).lower()
    return [needle for needle in needles if needle.lower() in haystack]


def get_field(event: dict[str, Any], path: str) -> Any:
    value: Any = event
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            raise DetectionError(f"{event.get('event_id', '<unknown>')}: missing field {path}")
        value = value[part]
    return value


def parse_timestamp(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DetectionError(f"invalid timestamp: {value}") from exc


def validate_event(event: Any, path: Path) -> None:
    if not isinstance(event, dict):
        raise DetectionError(f"{path}: each event must be an object")
    required = {
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
    }
    missing = sorted(required - set(event))
    if missing:
        raise DetectionError(f"{path}: event missing fields: {', '.join(missing)}")
    if event["schema"] != "lab-event":
        raise DetectionError(f"{path}: event schema must be lab-event")


def validate_alert(alert: Any) -> None:
    if not isinstance(alert, dict):
        raise DetectionError("alert must be an object")
    missing = sorted(ALERT_REQUIRED_FIELDS - set(alert))
    if missing:
        raise DetectionError(f"{alert.get('alert_id', '<unknown>')}: alert missing fields: {', '.join(missing)}")
    if alert["schema"] != "lab-alert":
        raise DetectionError(f"{alert['alert_id']}: alert schema must be lab-alert")
    if not isinstance(alert["risk_score"], int) or not 0 <= alert["risk_score"] <= 100:
        raise DetectionError(f"{alert['alert_id']}: risk_score must be 0..100")
    mitre = alert["mitre"]
    if not isinstance(mitre, dict) or not mitre.get("tactics") or not mitre.get("techniques"):
        raise DetectionError(f"{alert['alert_id']}: mitre tactics and techniques are required")
    if not isinstance(alert["evidence"], dict) or not alert["evidence"]:
        raise DetectionError(f"{alert['alert_id']}: evidence must be a non-empty object")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(format_json(value) + "\n", encoding="utf-8")


def format_json(value: Any) -> str:
    return json.dumps(value, indent=2)


if __name__ == "__main__":
    raise SystemExit(main())
