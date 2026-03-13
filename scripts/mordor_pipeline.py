#!/usr/bin/env python3
"""Mordor production-line orchestration for Aegis-Vanguard.

Flow covered:
  selection (manifest) -> mapping -> optional collector-fixture replay
  and/or direct Kafka replay -> engine matching -> dashboard forensics.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, Iterator, Optional

from mordor_mapper import map_record

DEFAULT_TOPIC = "siem.events"
DEFAULT_BROKER = "localhost:9092"
DEFAULT_CAMPAIGN_BASENAME = "windows_campaign"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _script_dir() -> Path:
    return Path(__file__).resolve().parent


def load_manifest(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)

    if not isinstance(manifest, dict):
        raise ValueError("Manifest root must be a JSON object")
    if "targets" not in manifest or not isinstance(manifest["targets"], list):
        raise ValueError("Manifest must contain a list field: targets")
    return manifest


def resolve_datasets_root(manifest: dict, override: Optional[Path]) -> Path:
    if override is not None:
        root = override
    else:
        hint = manifest.get("security_datasets_root_hint", "../Security-Datasets")
        root = (_repo_root() / hint).resolve()

    if not root.exists():
        raise FileNotFoundError(f"Security-Datasets root not found: {root}")
    return root


def iter_target_datasets(manifest: dict) -> Iterator[tuple[str, str, list[str]]]:
    for target in manifest["targets"]:
        name = str(target.get("name", "unnamed-target"))
        datasets = target.get("datasets", [])
        if not isinstance(datasets, list) or not datasets:
            raise ValueError(f"Target '{name}' must define a non-empty datasets list")

        rule_ids = target.get("rule_ids", [])
        if not isinstance(rule_ids, list):
            raise ValueError(f"Target '{name}' field rule_ids must be a list")

        if len(datasets) < 2:
            raise ValueError(f"Target '{name}' must have at least 2 datasets to satisfy multi-dataset coverage")

        for dataset in datasets:
            if not isinstance(dataset, str):
                raise ValueError(f"Target '{name}' contains a non-string dataset path")
            yield name, dataset, [str(rule_id) for rule_id in rule_ids]


def parse_json_objects(blob: str, origin: str) -> Iterator[dict]:
    stripped = blob.lstrip()
    if not stripped:
        return

    if stripped[0] == "[":
        try:
            parsed = json.loads(blob)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON array in {origin}: {exc}") from exc

        if not isinstance(parsed, list):
            raise ValueError(f"Expected array payload in {origin}")

        for item in parsed:
            if isinstance(item, dict):
                yield item
        return

    # Try single JSON object first.
    try:
        parsed = json.loads(blob)
    except json.JSONDecodeError:
        parsed = None

    if isinstance(parsed, dict):
        yield parsed
        return

    # Fallback: JSONL.
    for index, line in enumerate(blob.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            yield payload
        else:
            raise ValueError(f"Non-object JSON record at {origin}:{index}")


def iter_dataset_records(dataset_path: Path) -> Iterator[dict]:
    suffix = dataset_path.suffix.lower()
    if suffix == ".zip":
        with zipfile.ZipFile(dataset_path) as archive:
            for entry in sorted(archive.namelist()):
                if entry.endswith("/"):
                    continue
                if not entry.lower().endswith((".json", ".jsonl")):
                    continue
                with archive.open(entry) as handle:
                    content = handle.read().decode("utf-8", errors="replace")
                yield from parse_json_objects(content, f"{dataset_path}!{entry}")
        return

    with dataset_path.open("r", encoding="utf-8", errors="replace") as handle:
        content = handle.read()
    yield from parse_json_objects(content, str(dataset_path))


def to_fixture_record(envelope: dict) -> Optional[dict]:
    event_type = envelope.get("event_type")
    event = envelope.get("event", {}) if isinstance(envelope.get("event"), dict) else {}

    ts = envelope.get("ts", "")
    process_guid = envelope.get("process_guid", "")

    if event_type == "process_start":
        process = event.get("process", {}) if isinstance(event.get("process"), dict) else {}
        return {
            "kind": "process_start",
            "ts": ts,
            "process_guid": process_guid or process.get("process_guid", ""),
            "pid": int(process.get("pid", 0) or 0),
            "ppid": int(process.get("ppid", 0) or 0),
            "uid": int(process.get("uid", 0) or 0),
            "user_name": str(process.get("user_name", "")),
            "name": str(process.get("name", "")),
            "exe": str(process.get("exe", "")),
            "cmdline": str(process.get("cmdline", "")),
            "process_start_time": str(process.get("process_start_time", ts)),
        }

    if event_type == "network_connect":
        network = event.get("network", {}) if isinstance(event.get("network"), dict) else {}
        return {
            "kind": "network_connect",
            "ts": ts,
            "pid": int(network.get("pid", 0) or 0),
            "process_guid": process_guid or str(network.get("process_guid", "")),
            "protocol": str(network.get("protocol", "tcp")),
            "src_ip": str(network.get("src_ip", "")),
            "src_port": int(network.get("src_port", 0) or 0),
            "dst_ip": str(network.get("dst_ip", "")),
            "dst_port": int(network.get("dst_port", 0) or 0),
            "direction": str(network.get("direction", "outbound")),
        }

    if event_type == "file_open":
        file_event = event.get("file", {}) if isinstance(event.get("file"), dict) else {}
        flags = file_event.get("flags", [])
        if not isinstance(flags, list):
            flags = [str(flags)]
        return {
            "kind": "file_open",
            "ts": ts,
            "pid": int(file_event.get("pid", 0) or 0),
            "process_guid": process_guid or str(file_event.get("process_guid", "")),
            "user_name": str(file_event.get("user_name", "")),
            "path": str(file_event.get("path", "")),
            "flags": [str(flag) for flag in flags],
            "result": str(file_event.get("result", "success")),
        }

    if event_type == "auth_failure":
        auth = event.get("auth", {}) if isinstance(event.get("auth"), dict) else {}
        return {
            "kind": "auth_failure",
            "ts": ts,
            "user_name": str(auth.get("user_name", "")),
            "method": str(auth.get("method", "")),
            "src_ip": str(auth.get("src_ip", "")),
            "reason": str(auth.get("reason", "")),
        }

    return None


def prepare_campaign(
    manifest_path: Path,
    datasets_root: Path,
    output_dir: Path,
    campaign_basename: str,
    event_ids: Optional[set[int]],
) -> dict:
    manifest = load_manifest(manifest_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    mapped_dir = output_dir / "mapped"
    mapped_dir.mkdir(parents=True, exist_ok=True)

    canonical_path = output_dir / f"{campaign_basename}.aegis.jsonl"
    fixture_path = output_dir / f"{campaign_basename}.fixture.jsonl"
    report_path = output_dir / f"{campaign_basename}.report.json"

    dataset_to_targets: Dict[str, list[str]] = defaultdict(list)
    dataset_to_rules: Dict[str, list[str]] = defaultdict(list)

    unique_datasets: list[str] = []
    for target_name, dataset, rule_ids in iter_target_datasets(manifest):
        if dataset not in unique_datasets:
            unique_datasets.append(dataset)
        dataset_to_targets[dataset].append(target_name)
        for rule_id in rule_ids:
            if rule_id not in dataset_to_rules[dataset]:
                dataset_to_rules[dataset].append(rule_id)

    summary = {
        "campaign": manifest.get("campaign", campaign_basename),
        "manifest": str(manifest_path),
        "datasets_root": str(datasets_root),
        "outputs": {
            "canonical": str(canonical_path),
            "fixture": str(fixture_path),
        },
        "totals": {
            "records_read": 0,
            "records_mapped": 0,
            "records_skipped": 0,
            "event_type_breakdown": {},
            "fixture_records": 0,
        },
        "datasets": [],
        "targets": manifest.get("targets", []),
    }

    event_type_breakdown: Dict[str, int] = defaultdict(int)

    with canonical_path.open("w", encoding="utf-8") as canonical_out, fixture_path.open("w", encoding="utf-8") as fixture_out:
        for relative in unique_datasets:
            dataset_path = (datasets_root / relative).resolve()
            if not dataset_path.exists():
                raise FileNotFoundError(f"Dataset not found: {dataset_path}")

            dataset_stats = {
                "dataset": relative,
                "path": str(dataset_path),
                "targets": dataset_to_targets[relative],
                "rule_ids": dataset_to_rules[relative],
                "records_read": 0,
                "records_mapped": 0,
                "records_skipped": 0,
                "event_types": {},
            }
            dataset_event_types: Dict[str, int] = defaultdict(int)

            for record in iter_dataset_records(dataset_path):
                dataset_stats["records_read"] += 1
                summary["totals"]["records_read"] += 1

                event_id_raw = record.get("EventID")
                if event_id_raw is None:
                    dataset_stats["records_skipped"] += 1
                    summary["totals"]["records_skipped"] += 1
                    continue

                try:
                    event_id = int(event_id_raw)
                except (TypeError, ValueError):
                    dataset_stats["records_skipped"] += 1
                    summary["totals"]["records_skipped"] += 1
                    continue

                if event_ids is not None and event_id not in event_ids:
                    dataset_stats["records_skipped"] += 1
                    summary["totals"]["records_skipped"] += 1
                    continue

                envelope = map_record(record)
                if envelope is None:
                    dataset_stats["records_skipped"] += 1
                    summary["totals"]["records_skipped"] += 1
                    continue

                canonical_out.write(json.dumps(envelope, separators=(",", ":")) + "\n")
                dataset_stats["records_mapped"] += 1
                summary["totals"]["records_mapped"] += 1

                event_type = str(envelope.get("event_type", "unknown"))
                dataset_event_types[event_type] += 1
                event_type_breakdown[event_type] += 1

                fixture_record = to_fixture_record(envelope)
                if fixture_record is not None:
                    fixture_out.write(json.dumps(fixture_record, separators=(",", ":")) + "\n")
                    summary["totals"]["fixture_records"] += 1

            dataset_stats["event_types"] = dict(sorted(dataset_event_types.items()))
            summary["datasets"].append(dataset_stats)

    summary["totals"]["event_type_breakdown"] = dict(sorted(event_type_breakdown.items()))

    with report_path.open("w", encoding="utf-8") as report_out:
        json.dump(summary, report_out, indent=2)

    return {
        "canonical": canonical_path,
        "fixture": fixture_path,
        "report": report_path,
        "summary": summary,
    }


def default_collector_binary() -> Path:
    """Return the most likely collector binary path for the current platform.

    Probe both repo-local and workspace-level CMake output directories and pick
    the newest existing collector binary. This avoids selecting a stale binary
    when VS Code CMake Tools and manual presets use different build roots.
    """
    root = _repo_root()
    build_roots = [root / "build", root.parent / "build"]
    if os.name == "nt":
        names = [
            ("collector", "src", "aegis_collector_agent.exe"),
            ("debug-collector", "collector", "src", "aegis_collector_agent.exe"),
        ]
    else:
        names = [
            ("debug-collector", "collector", "src", "aegis_collector_agent"),
            ("collector", "src", "aegis_collector_agent"),
        ]

    candidates = [build_root.joinpath(*parts) for build_root in build_roots for parts in names]
    existing = [candidate for candidate in candidates if candidate.exists()]
    if existing:
        return max(existing, key=lambda path: path.stat().st_mtime)
    return candidates[0]


def run_direct_replay(canonical_path: Path, broker: str, topic: str, mode: str, interval: float, speedup: float) -> None:
    replayer = _script_dir() / "mordor_replayer.py"
    command = [
        sys.executable,
        str(replayer),
        str(canonical_path),
        "--broker",
        broker,
        "--topic",
        topic,
        "--mode",
        mode,
        "--interval",
        str(interval),
        "--speedup",
        str(speedup),
    ]
    subprocess.run(command, check=True)


def run_collector_fixture_replay(fixture_path: Path, collector_bin: Path, broker: str, topic: str, tenant_id: str) -> None:
    if not collector_bin.exists():
        raise FileNotFoundError(
            f"Collector binary not found: {collector_bin}. Build it first with cmake --preset debug-collector && cmake --build --preset build-debug-collector"
        )

    host = os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "localhost"
    config_path = fixture_path.parent / "collector_fixture.generated.yaml"

    config_text = "\n".join(
        [
            "agent_id: mordor-fixture-collector",
            f"hostname: {host}",
            "kafka:",
            "  brokers:",
            f"    - {broker}",
            f"  topic: {topic}",
            "collection:",
            "  process_events: true",
            "  network_events: true",
            "  file_events: true",
            "  auth_events: true",
            "runtime:",
            "  source: fixture",
            f"  fixture_path: '{fixture_path}'",
            "  ebpf_input_path: /var/run/aegis/ebpf-events.jsonl",
            "  ebpf_reader_command:",
            "  ebpf_follow: true",
            "  poll_interval_ms: 50",
            "  max_events: 0",
            "  dry_run: false",
            f"  tenant_id: {tenant_id}",
            "  log_level: info",
            "",
        ]
    )
    config_path.write_text(config_text, encoding="utf-8")

    command = [str(collector_bin), str(config_path)]
    subprocess.run(command, check=True)


def parse_event_ids(value: str) -> set[int]:
    event_ids: set[int] = set()
    for token in value.split(","):
        token = token.strip()
        if token:
            event_ids.add(int(token))
    return event_ids


def add_common_prepare_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--manifest",
        default=str(_script_dir() / "mordor_windows_campaign.json"),
        help="Path to campaign manifest JSON",
    )
    parser.add_argument(
        "--datasets-root",
        default=None,
        help="Security-Datasets root path (optional override)",
    )
    parser.add_argument(
        "--output-dir",
        default=str(_repo_root() / "runtime" / "mordor"),
        help="Output directory for merged files and report",
    )
    parser.add_argument(
        "--campaign-basename",
        default=DEFAULT_CAMPAIGN_BASENAME,
        help="Base filename for generated outputs",
    )
    parser.add_argument(
        "--event-ids",
        default=None,
        help="Optional comma-separated EventIDs filter, e.g. 4625,4776,10",
    )


def command_prepare(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest).resolve()
    manifest = load_manifest(manifest_path)
    datasets_root = resolve_datasets_root(manifest, Path(args.datasets_root).resolve() if args.datasets_root else None)
    output_dir = Path(args.output_dir).resolve()
    event_ids = parse_event_ids(args.event_ids) if args.event_ids else None

    result = prepare_campaign(
        manifest_path=manifest_path,
        datasets_root=datasets_root,
        output_dir=output_dir,
        campaign_basename=args.campaign_basename,
        event_ids=event_ids,
    )

    summary = result["summary"]
    print(f"[+] Campaign prepared: {summary['campaign']}")
    print(f"[+] Canonical merged file: {result['canonical']}")
    print(f"[+] Fixture merged file  : {result['fixture']}")
    print(f"[+] Report               : {result['report']}")
    print("[+] Totals")
    print(f"    records_read={summary['totals']['records_read']} mapped={summary['totals']['records_mapped']} skipped={summary['totals']['records_skipped']} fixture={summary['totals']['fixture_records']}")
    for event_type, count in summary["totals"]["event_type_breakdown"].items():
        print(f"    {event_type:<18} {count}")

    return 0


def command_replay_direct(args: argparse.Namespace) -> int:
    canonical_path = Path(args.input).resolve()
    if not canonical_path.exists():
        raise FileNotFoundError(f"Canonical file not found: {canonical_path}")
    run_direct_replay(canonical_path, args.broker, args.topic, args.mode, args.interval, args.speedup)
    return 0


def command_replay_collector(args: argparse.Namespace) -> int:
    fixture_path = Path(args.input).resolve()
    if not fixture_path.exists():
        raise FileNotFoundError(f"Fixture file not found: {fixture_path}")

    collector_bin = Path(args.collector_bin).resolve() if args.collector_bin else default_collector_binary().resolve()
    run_collector_fixture_replay(fixture_path, collector_bin, args.broker, args.topic, args.tenant_id)
    return 0


def command_run(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest).resolve()
    manifest = load_manifest(manifest_path)
    datasets_root = resolve_datasets_root(manifest, Path(args.datasets_root).resolve() if args.datasets_root else None)
    output_dir = Path(args.output_dir).resolve()
    event_ids = parse_event_ids(args.event_ids) if args.event_ids else None

    result = prepare_campaign(
        manifest_path=manifest_path,
        datasets_root=datasets_root,
        output_dir=output_dir,
        campaign_basename=args.campaign_basename,
        event_ids=event_ids,
    )

    route = args.route.lower()
    if route in ("collector", "both"):
        collector_bin = Path(args.collector_bin).resolve() if args.collector_bin else default_collector_binary().resolve()
        run_collector_fixture_replay(result["fixture"], collector_bin, args.broker, args.topic, args.tenant_id)

    if route in ("direct", "both"):
        run_direct_replay(result["canonical"], args.broker, args.topic, args.mode, args.interval, args.speedup)

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Mordor production-line orchestration for Aegis")
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare", help="Map and merge campaign datasets into canonical + fixture JSONL")
    add_common_prepare_args(prepare)
    prepare.set_defaults(handler=command_prepare)

    replay_direct = subparsers.add_parser("replay-direct", help="Replay canonical JSONL directly to Kafka")
    replay_direct.add_argument("--input", required=True, help="Merged canonical JSONL path")
    replay_direct.add_argument("--broker", default=DEFAULT_BROKER, help="Kafka bootstrap server")
    replay_direct.add_argument("--topic", default=DEFAULT_TOPIC, help="Kafka events topic")
    replay_direct.add_argument("--mode", choices=["burst", "fixed", "realtime"], default="realtime")
    replay_direct.add_argument("--interval", type=float, default=0.03)
    replay_direct.add_argument("--speedup", type=float, default=120.0)
    replay_direct.set_defaults(handler=command_replay_direct)

    replay_collector = subparsers.add_parser("replay-collector", help="Replay fixture JSONL through C++ collector")
    replay_collector.add_argument("--input", required=True, help="Merged fixture JSONL path")
    replay_collector.add_argument("--collector-bin", default=None, help="Path to aegis_collector_agent binary")
    replay_collector.add_argument("--broker", default=DEFAULT_BROKER, help="Kafka bootstrap server")
    replay_collector.add_argument("--topic", default=DEFAULT_TOPIC, help="Kafka events topic")
    replay_collector.add_argument("--tenant-id", default="default")
    replay_collector.set_defaults(handler=command_replay_collector)

    run = subparsers.add_parser("run", help="Prepare and replay campaign in one command")
    add_common_prepare_args(run)
    run.add_argument("--route", choices=["direct", "collector", "both"], default="both")
    run.add_argument("--collector-bin", default=None, help="Path to aegis_collector_agent binary")
    run.add_argument("--broker", default=DEFAULT_BROKER, help="Kafka bootstrap server")
    run.add_argument("--topic", default=DEFAULT_TOPIC, help="Kafka events topic")
    run.add_argument("--tenant-id", default="default")
    run.add_argument("--mode", choices=["burst", "fixed", "realtime"], default="realtime")
    run.add_argument("--interval", type=float, default=0.03)
    run.add_argument("--speedup", type=float, default=120.0)
    run.set_defaults(handler=command_run)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.handler(args)
    except subprocess.CalledProcessError as exc:
        print(f"[ERROR] Subprocess failed with exit code {exc.returncode}: {exc.cmd}")
        return exc.returncode or 1
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
