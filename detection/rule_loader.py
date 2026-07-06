"""Load and validate Phase 2 JSON detection rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


VALID_EVENT_TYPES = {"process_start", "network_connect", "auth_failure"}
VALID_RULE_TYPES = {"field_contains_any", "threshold_count", "port_not_in"}
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}

REQUIRED_RULE_FIELDS = {
    "id",
    "name",
    "description",
    "enabled",
    "event_type",
    "severity",
    "risk_score",
    "mitre",
    "tags",
    "detection",
}


class RuleValidationError(ValueError):
    """Raised when a rule does not match the Phase 2 rule contract."""


def load_rules(rules_dir: Path) -> list[dict[str, Any]]:
    """Load all JSON rule files from a directory in deterministic order."""

    if not rules_dir.exists():
        raise RuleValidationError(f"rules directory not found: {rules_dir}")

    rules: list[dict[str, Any]] = []
    for path in sorted(rules_dir.glob("*.json")):
        rule = _load_json_object(path)
        validate_rule(rule, path)
        rules.append(rule)

    if not rules:
        raise RuleValidationError(f"no JSON rules found in: {rules_dir}")

    return sorted(rules, key=lambda rule: rule["id"])


def validate_rule(rule: dict[str, Any], path: Path | None = None) -> None:
    location = str(path) if path is not None else "<rule>"
    missing = sorted(REQUIRED_RULE_FIELDS - set(rule))
    if missing:
        raise RuleValidationError(f"{location}: missing required fields: {', '.join(missing)}")

    _expect_string(rule, "id", location)
    _expect_string(rule, "name", location)
    _expect_string(rule, "description", location)

    if not isinstance(rule["enabled"], bool):
        raise RuleValidationError(f"{location}: enabled must be a boolean")

    if rule["event_type"] not in VALID_EVENT_TYPES:
        raise RuleValidationError(f"{location}: unsupported event_type: {rule['event_type']}")

    if rule["severity"] not in VALID_SEVERITIES:
        raise RuleValidationError(f"{location}: unsupported severity: {rule['severity']}")

    risk_score = rule["risk_score"]
    if not isinstance(risk_score, int) or not 0 <= risk_score <= 100:
        raise RuleValidationError(f"{location}: risk_score must be an integer from 0 to 100")

    _validate_mitre(rule["mitre"], location)
    _validate_string_list(rule["tags"], f"{location}: tags")
    _validate_detection(rule["detection"], location)


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except json.JSONDecodeError as exc:
        raise RuleValidationError(f"{path}: invalid JSON: {exc}") from exc

    if not isinstance(value, dict):
        raise RuleValidationError(f"{path}: rule file must contain a JSON object")

    return value


def _validate_mitre(value: Any, location: str) -> None:
    if not isinstance(value, dict):
        raise RuleValidationError(f"{location}: mitre must be an object")

    for key in ("tactics", "techniques"):
        if key not in value:
            raise RuleValidationError(f"{location}: mitre.{key} is required")
        _validate_string_list(value[key], f"{location}: mitre.{key}")


def _validate_detection(value: Any, location: str) -> None:
    if not isinstance(value, dict):
        raise RuleValidationError(f"{location}: detection must be an object")

    rule_type = value.get("type")
    if rule_type not in VALID_RULE_TYPES:
        raise RuleValidationError(f"{location}: unsupported detection.type: {rule_type}")

    if rule_type == "field_contains_any":
        _expect_string(value, "field", location)
        _validate_string_list(value.get("values"), f"{location}: detection.values")
    elif rule_type == "threshold_count":
        _validate_string_list(value.get("group_by"), f"{location}: detection.group_by")
        _expect_positive_int(value, "threshold", location)
        _expect_positive_int(value, "window_seconds", location)
    elif rule_type == "port_not_in":
        _expect_string(value, "field", location)
        _validate_port_list(value.get("allowed_ports"), f"{location}: detection.allowed_ports")

    _validate_requires(value.get("requires", []), location)


def _validate_requires(value: Any, location: str) -> None:
    if not isinstance(value, list):
        raise RuleValidationError(f"{location}: detection.requires must be a list")

    for index, requirement in enumerate(value):
        req_location = f"{location}: detection.requires[{index}]"
        if not isinstance(requirement, dict):
            raise RuleValidationError(f"{req_location} must be an object")
        _expect_string(requirement, "field", req_location)

        has_equals = "equals" in requirement
        has_contains = "contains_any" in requirement
        if has_equals == has_contains:
            raise RuleValidationError(f"{req_location} must define exactly one of equals or contains_any")
        if has_contains:
            _validate_string_list(requirement["contains_any"], f"{req_location}.contains_any")


def _expect_string(value: dict[str, Any], key: str, location: str) -> None:
    if not isinstance(value.get(key), str) or not value[key]:
        raise RuleValidationError(f"{location}: {key} must be a non-empty string")


def _expect_positive_int(value: dict[str, Any], key: str, location: str) -> None:
    if not isinstance(value.get(key), int) or value[key] <= 0:
        raise RuleValidationError(f"{location}: {key} must be a positive integer")


def _validate_string_list(value: Any, location: str) -> None:
    if not isinstance(value, list) or not value:
        raise RuleValidationError(f"{location} must be a non-empty list")
    for item in value:
        if not isinstance(item, str) or not item:
            raise RuleValidationError(f"{location} must contain only non-empty strings")


def _validate_port_list(value: Any, location: str) -> None:
    if not isinstance(value, list) or not value:
        raise RuleValidationError(f"{location} must be a non-empty list")
    for item in value:
        if not isinstance(item, int) or not 0 <= item <= 65535:
            raise RuleValidationError(f"{location} must contain integer ports from 0 to 65535")
