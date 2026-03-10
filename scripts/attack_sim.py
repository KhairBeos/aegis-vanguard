#!/usr/bin/env python3
"""Simple attack simulation scaffold for SIEM pipeline testing."""

from datetime import datetime, timezone
import json


def main() -> None:
	event = {
		"ts": datetime.now(timezone.utc).isoformat(),
		"source": "attack-sim",
		"event_type": "bruteforce_attempt",
		"host": "lab-host",
		"details": {"username": "admin", "attempts": 5},
	}
	print(json.dumps(event))


if __name__ == "__main__":
	main()