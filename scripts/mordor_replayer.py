#!/usr/bin/env python3
"""
mordor_replayer.py – Replay Aegis v1.1 JSONL events into Kafka siem.events
===========================================================================
Reads the JSONL output produced by mordor_mapper.py and publishes each event
to the Kafka broker so the Aegis C++ engine can evaluate the detection rules
in real time.

Flow
----
  mordor_mapper.py
      ↓  (Aegis v1.1 JSONL)
  mordor_replayer.py
      ↓  (Kafka produce)
  siem.events  →  aegis_engine  →  siem.alerts  →  dashboard

Pacing modes
------------
  burst    No delay between messages; good for rule stress-testing.
  fixed    Fixed sleep of --interval seconds between each event (default 0.05 s).
  realtime Scale original timestamp deltas by 1/--speedup. Preserves attack
           cadence while letting you fast-forward (default 100×).

Usage
-----
  python3 mordor_replayer.py <aegis_events.jsonl>
  python3 mordor_replayer.py <aegis_events.jsonl> --mode burst
  python3 mordor_replayer.py <aegis_events.jsonl> --mode realtime --speedup 50
  python3 mordor_replayer.py <aegis_events.jsonl> --broker 192.168.1.10:9092
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    from kafka import KafkaProducer
    from kafka.errors import NoBrokersAvailable, KafkaError
except ImportError:
    sys.exit(
        "[ERROR] kafka-python is not installed.\n"
        "        Run:  pip install kafka-python\n"
    )

DEFAULT_BROKER = "localhost:9092"
DEFAULT_TOPIC = "siem.events"


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

_TS_FMTS = (
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
)


def ts_to_epoch(ts_str: str) -> float:
    """Parse Aegis RFC3339Z timestamp string to UTC epoch float."""
    for fmt in _TS_FMTS:
        try:
            dt = datetime.strptime(ts_str, fmt).replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            pass
    return 0.0


def make_producer(broker: str) -> KafkaProducer:
    return KafkaProducer(
        bootstrap_servers=broker,
        value_serializer=lambda v: json.dumps(v, separators=(",", ":")).encode("utf-8"),
        key_serializer=lambda k: k.encode("utf-8") if k else None,
        acks="all",
        retries=5,
        linger_ms=10,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Core replay logic
# ──────────────────────────────────────────────────────────────────────────────

def replay(
    events: list[dict],
    producer: KafkaProducer,
    topic: str,
    mode: str,
    interval: float,
    speedup: float,
) -> None:
    total = len(events)
    if total == 0:
        print("[WARN] No events to send.")
        return

    sent = 0
    errors = 0
    prev_orig_ts: float = 0.0
    prev_wall_ts: float = 0.0

    print(f"[+] Sending {total} events -> '{topic}'  mode={mode}")
    print(f"    Broker: {producer.config.get('bootstrap_servers')}")
    print()

    for ev in events:
        key = ev.get("host") or "unknown"

        try:
            producer.send(topic, value=ev, key=key)
            sent += 1
        except KafkaError as exc:
            errors += 1
            print(f"\n[WARN] Kafka send error: {exc}")

        # Progress display
        if sent % 50 == 0 or sent == total:
            print(
                f"    {sent:>6}/{total}  errors={errors}  "
                f"event_type={ev.get('event_type','?'):<16} "
                f"host={ev.get('host','?'):<20}",
                end="\r",
                flush=True,
            )

        # Pacing
        if mode == "fixed":
            time.sleep(interval)

        elif mode == "realtime":
            orig_ts = ts_to_epoch(ev.get("ts", ""))
            now = time.time()
            if prev_orig_ts > 0 and orig_ts > prev_orig_ts:
                orig_delta = orig_ts - prev_orig_ts
                wall_elapsed = now - prev_wall_ts
                sleep_for = (orig_delta / speedup) - wall_elapsed
                if sleep_for > 0:
                    time.sleep(min(sleep_for, 30.0))   # cap gap at 30 s
            prev_orig_ts = orig_ts
            prev_wall_ts = time.time()

        # mode == "burst": no sleep

    producer.flush()
    print(f"\n\n[+] Done. {sent} sent, {errors} errors.")


# ──────────────────────────────────────────────────────────────────────────────
# Summary printer
# ──────────────────────────────────────────────────────────────────────────────

def print_summary(events: list[dict]) -> None:
    counts: dict[str, int] = {}
    hosts: set[str] = set()
    for ev in events:
        et = ev.get("event_type", "unknown")
        counts[et] = counts.get(et, 0) + 1
        h = ev.get("host")
        if h:
            hosts.add(h)

    print(f"  Total events     : {len(events):>6,}")
    print(f"  Unique hosts     : {len(hosts):>6,}")
    print(f"  Event type breakdown:")
    for et, cnt in sorted(counts.items()):
        print(f"    {et:<22} {cnt:>6,}")
    print()


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__,
    )
    parser.add_argument(
        "input",
        help="Aegis v1.1 JSONL file produced by mordor_mapper.py",
    )
    parser.add_argument(
        "--broker",
        default=DEFAULT_BROKER,
        help=f"Kafka bootstrap server (default: {DEFAULT_BROKER})",
    )
    parser.add_argument(
        "--topic",
        default=DEFAULT_TOPIC,
        help=f"Target Kafka topic (default: {DEFAULT_TOPIC})",
    )
    parser.add_argument(
        "--mode",
        choices=["burst", "fixed", "realtime"],
        default="fixed",
        help=(
            "Pacing mode – burst: no delay; fixed: constant --interval sleep; "
            "realtime: replay at --speedup× wall-clock speed (default: fixed)"
        ),
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.05,
        help="Seconds between events in 'fixed' mode (default: 0.05)",
    )
    parser.add_argument(
        "--speedup",
        type=float,
        default=100.0,
        help="Speed multiplier for 'realtime' mode (default: 100×)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Send only the first N events (0 = all)",
    )
    args = parser.parse_args()

    in_path = Path(args.input).expanduser().resolve()
    if not in_path.exists():
        sys.exit(f"[ERROR] File not found: {in_path}")

    # ── Load events ───────────────────────────────────────────────────────────
    print(f"[+] Loading events from {in_path} ...")
    events: list[dict] = []
    bad = 0
    with in_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                events.append(ev)
            except json.JSONDecodeError:
                bad += 1
            if args.limit and len(events) >= args.limit:
                break

    if bad:
        print(f"[WARN] {bad} malformed lines skipped.")

    if not events:
        sys.exit("[ERROR] No valid events found in input file.")

    print_summary(events)

    # ── Connect to Kafka ──────────────────────────────────────────────────────
    print(f"[+] Connecting to Kafka @ {args.broker} ...")
    try:
        producer = make_producer(args.broker)
    except NoBrokersAvailable:
        sys.exit(
            f"[ERROR] Cannot reach Kafka at {args.broker}.\n"
            "        Make sure Docker Compose is running:  docker compose up -d\n"
        )

    # ── Replay ────────────────────────────────────────────────────────────────
    try:
        replay(events, producer, args.topic, args.mode, args.interval, args.speedup)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user, flushing ...")
        producer.flush()
    finally:
        producer.close()

    print("[+] Check the dashboard or ClickHouse for alerts:")
    print("    http://localhost:3000               (Next.js dashboard)")
    print("    http://localhost:8123/play          (ClickHouse UI)")


if __name__ == "__main__":
    main()
