#!/usr/bin/env python3
"""
mordor_mapper.py – OTRF Security-Datasets  →  Aegis-Vanguard v1.1 normalizer
==============================================================================
Reads a Security-Datasets JSONL file (one JSON object per line, exported from
Windows Security/Sysmon event logs) and emits Aegis canonical event envelopes
(v1.1) that can be fed directly to the Kafka replayer or the C++ collector
fixture source.

Supported source EventIDs
--------------------------
  4625        Windows Security – Failed logon          → auth_failure
  4776        Windows Security – NTLM credential valid → auth_failure
  4688        Windows Security – Process created       → process_start
  1  (Sysmon) Process created                         → process_start
  3  (Sysmon) Network connection                      → network_connect
  5156        Windows WFP  – connection permitted      → network_connect
  10 (Sysmon) Process accessed (LSASS dump)           → file_open  *  
  11 (Sysmon) File created                            → file_open
  23 (Sysmon) File deleted                            → file_open
  4663        Windows Security – Object access         → file_open

  * EventID 10 is only mapped when TargetImage contains a sensitive process
    (lsass.exe, sam, ntds, security).

Usage
-----
  python3 mordor_mapper.py <input.json> [-o output.jsonl] [--limit N]
  python3 mordor_mapper.py <input.json> --event-ids 4625,3,5156

Output
------
  JSONL file (one Aegis v1.1 envelope per line), ready for mordor_replayer.py.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

SCHEMA_VERSION = "v1.1"
AGENT_ID = "mordor-replayer"
SOURCE = "security-datasets.windows"
TENANT_ID = "default"

# ──────────────────────────────────────────────────────────────────────────────
# Timestamp helpers
# ──────────────────────────────────────────────────────────────────────────────

_TS_FMTS = (
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S",
)


def normalize_ts(raw: str) -> str:
    """Return RFC3339-UTC timestamp string (seconds precision, trailing Z)."""
    for fmt in _TS_FMTS:
        try:
            dt = datetime.strptime(raw.strip(), fmt)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass
    return raw  # fallback: return as-is


# ──────────────────────────────────────────────────────────────────────────────
# ID generation
# ──────────────────────────────────────────────────────────────────────────────

def make_event_id() -> str:
    return uuid.uuid4().hex


def make_trace_id() -> str:
    return str(uuid.uuid4())


def process_guid(host: str, pid: int, ts: str) -> str:
    """Deterministic process_guid per API spec: sha256(host + pid + ts)."""
    return hashlib.sha256(f"{host}{pid}{ts}".encode()).hexdigest()


# ──────────────────────────────────────────────────────────────────────────────
# Field helpers
# ──────────────────────────────────────────────────────────────────────────────

def parse_pid(val) -> int:
    """Parse PID that may be decimal int or hex string ('0x1d60')."""
    if isinstance(val, int):
        return val
    s = str(val).strip()
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s, 10)
    except (ValueError, TypeError):
        return 0


def clean_host(raw: str) -> str:
    """Return short hostname (strip FQDN suffix, lower-case)."""
    return (raw or "unknown").split(".")[0].lower()


def host_from(rec: dict) -> str:
    """Return the best available hostname field."""
    return rec.get("Hostname") or rec.get("host") or "unknown"


def strip_domain(user: str) -> str:
    """'DOMAIN\\user' → 'user'."""
    return user.split("\\")[-1] if "\\" in user else user


# ──────────────────────────────────────────────────────────────────────────────
# Auth method / reason mapping (Windows → Aegis)
# ──────────────────────────────────────────────────────────────────────────────

_LOGON_TYPE_MAP: dict[str, str] = {
    "2": "interactive",
    "3": "network",
    "4": "batch",
    "5": "service",
    "7": "unlock",
    "8": "network-cleartext",
    "9": "new-credentials",
    "10": "remote-interactive",
    "11": "cached-interactive",
}

_AUTH_PKG_MAP: dict[str, str] = {
    "ntlm": "ntlm",
    "kerberos": "kerberos",
    "microsoft_authentication_package_v1_0": "ntlm",
    "negotiate": "negotiate",
    "credssp": "credssp",
}

_NTSTATUS_MAP: dict[str, str] = {
    "0xc000006d": "bad_credentials",
    "0xc0000064": "no_such_user",
    "0xc000006a": "wrong_password",
    "0xc0000234": "account_locked",
    "0xc0000072": "account_disabled",
    "0xc0000193": "account_expired",
    "0xc000006f": "outside_logon_hours",
    "0xc0000071": "password_expired",
    "0xc000015b": "logon_type_not_granted",
    "0xc0000133": "time_skew",
    "0xc000018d": "trust_failure",
}

_PROTO_MAP: dict[str, str] = {"6": "tcp", "17": "udp", "1": "icmp"}


def map_auth_method(rec: dict) -> str:
    logon_type = str(rec.get("LogonType", "")).strip()
    pkg_raw = (rec.get("AuthenticationPackageName") or "").lower().strip()
    pkg = _AUTH_PKG_MAP.get(pkg_raw, pkg_raw or "unknown")
    logon = _LOGON_TYPE_MAP.get(logon_type, f"type{logon_type}" if logon_type else "unknown")
    return f"{logon}-{pkg}" if pkg not in ("", "unknown") else logon


def map_auth_reason(rec: dict) -> str:
    status = (rec.get("Status") or rec.get("SubStatus") or "").lower().strip()
    return _NTSTATUS_MAP.get(status, f"ntstatus_{status}" if status else "auth_failed")


def map_src_ip(rec: dict) -> str:
    """Resolve best source IP, ignoring loopback / empty / dash placeholders."""
    ip = rec.get("IpAddress") or rec.get("SourceAddress") or ""
    if ip and ip not in ("-", "::", "0.0.0.0", "::1", "127.0.0.1", "0"):
        return ip
    ws = rec.get("WorkstationName") or rec.get("Workstation") or ""
    return ws if ws and ws not in ("-", "") else "unknown"


# ──────────────────────────────────────────────────────────────────────────────
# Envelope builder
# ──────────────────────────────────────────────────────────────────────────────

def build_envelope(
    rec: dict,
    event_type: str,
    severity: str,
    event_payload: dict,
    pg: str = "",
) -> dict:
    ts = normalize_ts(rec.get("@timestamp") or rec.get("EventTime") or "")
    host = clean_host(host_from(rec))
    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": make_event_id(),
        "ts": ts,
        "host": host,
        "agent_id": AGENT_ID,
        "source": SOURCE,
        "event_type": event_type,
        "severity": severity,
        "tenant_id": TENANT_ID,
        "trace_id": make_trace_id(),
        "process_guid": pg,
        "event": event_payload,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Per-EventID handlers
# ──────────────────────────────────────────────────────────────────────────────

def map_4625(rec: dict) -> Optional[dict]:
    """EventID 4625 – failed logon → auth_failure."""
    user = rec.get("TargetUserName") or rec.get("SubjectUserName") or "unknown"
    if user in ("-", " ", ""):
        user = "unknown"
    return build_envelope(
        rec,
        event_type="auth_failure",
        severity="medium",
        event_payload={"auth": {
            "user_name": user,
            "method": map_auth_method(rec),
            "src_ip": map_src_ip(rec),
            "reason": map_auth_reason(rec),
        }},
    )


def map_4776(rec: dict) -> Optional[dict]:
    """EventID 4776 – NTLM credential validation attempt → auth_failure."""
    # 4776 fires on DCs even for successful auths; only map clear failures.
    status = (rec.get("Status") or "").lower().strip()
    if not status or status == "0x0":
        return None  # success — not an auth failure
    user = rec.get("TargetUserName") or "unknown"
    src = rec.get("Workstation") or rec.get("WorkstationName") or "unknown"
    return build_envelope(
        rec,
        event_type="auth_failure",
        severity="medium",
        event_payload={"auth": {
            "user_name": user,
            "method": "domain-ntlm",
            "src_ip": src,
            "reason": map_auth_reason(rec),
        }},
    )


def map_4688(rec: dict) -> Optional[dict]:
    """EventID 4688 – process creation → process_start."""
    exe = rec.get("NewProcessName") or rec.get("ProcessName") or "unknown"
    name = exe.split("\\")[-1] if "\\" in exe else exe
    pid = parse_pid(rec.get("NewProcessId") or 0)
    ppid = parse_pid(rec.get("ProcessId") or 0)
    user = strip_domain(rec.get("SubjectUserName") or rec.get("TargetUserName") or "system")
    cmdline = rec.get("CommandLine") or name
    ts = normalize_ts(rec.get("@timestamp") or "")
    host = clean_host(host_from(rec))
    pg = process_guid(host, pid, ts)
    return build_envelope(
        rec,
        event_type="process_start",
        severity="info",
        pg=pg,
        event_payload={"process": {
            "pid": pid,
            "ppid": ppid,
            "uid": 0,
            "user_name": user,
            "name": name,
            "exe": exe,
            "cmdline": cmdline,
            "process_start_time": ts,
        }},
    )


def map_sysmon_1(rec: dict) -> Optional[dict]:
    """Sysmon EventID 1 – ProcessCreate → process_start."""
    exe = rec.get("Image") or "unknown"
    name = exe.split("\\")[-1] if "\\" in exe else exe
    pid = parse_pid(rec.get("ProcessId") or 0)
    ppid = parse_pid(rec.get("ParentProcessId") or 0)
    user = strip_domain(rec.get("User") or rec.get("AccountName") or "system")
    cmdline = rec.get("CommandLine") or name
    ts = normalize_ts(rec.get("@timestamp") or "")
    host = clean_host(host_from(rec))
    pg = rec.get("ProcessGuid") or process_guid(host, pid, ts)
    return build_envelope(
        rec,
        event_type="process_start",
        severity="info",
        pg=pg,
        event_payload={"process": {
            "pid": pid,
            "ppid": ppid,
            "uid": 0,
            "user_name": user,
            "name": name,
            "exe": exe,
            "cmdline": cmdline,
            "process_start_time": ts,
        }},
    )


def map_sysmon_3(rec: dict) -> Optional[dict]:
    """Sysmon EventID 3 – NetworkConnect → network_connect."""
    pid = parse_pid(rec.get("ProcessId") or 0)
    pg = rec.get("ProcessGuid") or ""
    ts = normalize_ts(rec.get("@timestamp") or "")
    host = clean_host(host_from(rec))
    if not pg:
        pg = process_guid(host, pid, ts)

    direction = "outbound" if str(rec.get("Initiated", "")).lower() == "true" else "inbound"
    proto = (rec.get("Protocol") or "tcp").lower()

    try:
        src_port = int(rec.get("SourcePort") or 0)
    except (ValueError, TypeError):
        src_port = 0
    try:
        dst_port = int(rec.get("DestinationPort") or 0)
    except (ValueError, TypeError):
        dst_port = 0

    return build_envelope(
        rec,
        event_type="network_connect",
        severity="info",
        pg=pg,
        event_payload={"network": {
            "pid": pid,
            "process_guid": pg,
            "protocol": proto,
            "src_ip": rec.get("SourceIp") or "",
            "src_port": src_port,
            "dst_ip": rec.get("DestinationIp") or "",
            "dst_port": dst_port,
            "direction": direction,
        }},
    )


def map_5156(rec: dict) -> Optional[dict]:
    """EventID 5156 – WFP permitted connection → network_connect."""
    pid = parse_pid(rec.get("ProcessId") or 0)
    ts = normalize_ts(rec.get("@timestamp") or "")
    host = clean_host(host_from(rec))
    pg = process_guid(host, pid, ts)

    proto_num = str(rec.get("Protocol") or "6")
    proto = _PROTO_MAP.get(proto_num, "tcp")

    # %%14592 = receive/inbound, %%14593 = connect/outbound
    direction_raw = rec.get("Direction") or ""
    direction = "inbound" if "14592" in direction_raw else "outbound"

    try:
        src_port = int(rec.get("SourcePort") or 0)
    except (ValueError, TypeError):
        src_port = 0
    try:
        dst_port = int(rec.get("DestPort") or 0)
    except (ValueError, TypeError):
        dst_port = 0

    return build_envelope(
        rec,
        event_type="network_connect",
        severity="info",
        pg=pg,
        event_payload={"network": {
            "pid": pid,
            "process_guid": pg,
            "protocol": proto,
            "src_ip": rec.get("SourceAddress") or "",
            "src_port": src_port,
            "dst_ip": rec.get("DestAddress") or "",
            "dst_port": dst_port,
            "direction": direction,
        }},
    )


def map_sysmon_10(rec: dict) -> Optional[dict]:
    """Sysmon EventID 10 – ProcessAccess → file_open (semantics: memory read).

    Only emitted when TargetImage is a sensitive process (LSASS, SAM, NTDS).
    The engine rule 'windows-lsass-dump' looks for event.file.path matching
    lsass.exe to raise a critical credential-dump alert.
    """
    target = rec.get("TargetImage") or ""
    _sensitive = ("lsass.exe", "sam", "ntds", "security")
    if not any(s.lower() in target.lower() for s in _sensitive):
        return None

    pid = parse_pid(rec.get("SourceProcessId") or rec.get("ProcessId") or 0)
    pg = rec.get("SourceProcessGuid") or rec.get("ProcessGuid") or ""
    ts = normalize_ts(rec.get("@timestamp") or "")
    host = clean_host(host_from(rec))
    if not pg:
        pg = process_guid(host, pid, ts)

    user = strip_domain(rec.get("User") or rec.get("AccountName") or "system")
    src_image = rec.get("SourceImage") or "unknown"
    access_mask = rec.get("GrantedAccess") or "0x0"

    return build_envelope(
        rec,
        event_type="file_open",
        severity="high",
        pg=pg,
        event_payload={"file": {
            "pid": pid,
            "process_guid": pg,
            "user_name": user,
            # path carries the target process image so rules can match lsass.exe
            "path": target,
            "flags": [f"PROCESS_VM_READ", f"access={access_mask}"],
            "result": "success",
            # Extra context passed through so alert summaries are richer
            "src_image": src_image,
        }},
    )


def map_sysmon_11(rec: dict) -> Optional[dict]:
    """Sysmon EventID 11 – FileCreate → file_open."""
    pid = parse_pid(rec.get("ProcessId") or 0)
    pg = rec.get("ProcessGuid") or ""
    ts = normalize_ts(rec.get("@timestamp") or "")
    host = clean_host(host_from(rec))
    if not pg:
        pg = process_guid(host, pid, ts)

    user = strip_domain(rec.get("User") or rec.get("AccountName") or "system")
    path = rec.get("TargetFilename") or rec.get("TargetObject") or "unknown"

    return build_envelope(
        rec,
        event_type="file_open",
        severity="info",
        pg=pg,
        event_payload={"file": {
            "pid": pid,
            "process_guid": pg,
            "user_name": user,
            "path": path,
            "flags": ["O_CREAT"],
            "result": "success",
        }},
    )


def map_sysmon_23(rec: dict) -> Optional[dict]:
    """Sysmon EventID 23 – FileDelete → file_open (O_UNLINK)."""
    pid = parse_pid(rec.get("ProcessId") or 0)
    pg = rec.get("ProcessGuid") or ""
    ts = normalize_ts(rec.get("@timestamp") or "")
    host = clean_host(host_from(rec))
    if not pg:
        pg = process_guid(host, pid, ts)

    user = strip_domain(rec.get("User") or "system")
    path = rec.get("TargetFilename") or "unknown"

    return build_envelope(
        rec,
        event_type="file_open",
        severity="info",
        pg=pg,
        event_payload={"file": {
            "pid": pid,
            "process_guid": pg,
            "user_name": user,
            "path": path,
            "flags": ["O_RDWR", "O_UNLINK"],
            "result": "success",
        }},
    )


def map_4663(rec: dict) -> Optional[dict]:
    """EventID 4663 – Object access → file_open."""
    pid = parse_pid(rec.get("ProcessId") or 0)
    ts = normalize_ts(rec.get("@timestamp") or "")
    host = clean_host(host_from(rec))
    pg = process_guid(host, pid, ts)

    user = rec.get("SubjectUserName") or "system"
    path = rec.get("ObjectName") or rec.get("TargetFilename") or "unknown"

    access_raw = (rec.get("AccessMask") or "").upper()
    # Very coarse AccessMask interpretation; real mappings need bitflag parsing
    flags = ["O_RDWR"] if ("2" in access_raw or "40" in access_raw) else ["O_RDONLY"]

    return build_envelope(
        rec,
        event_type="file_open",
        severity="info",
        pg=pg,
        event_payload={"file": {
            "pid": pid,
            "process_guid": pg,
            "user_name": user,
            "path": path,
            "flags": flags,
            "result": "success",
        }},
    )


# ──────────────────────────────────────────────────────────────────────────────
# Dispatcher table
# ──────────────────────────────────────────────────────────────────────────────

_HANDLERS = {
    4625: map_4625,
    4776: map_4776,
    4688: map_4688,
    1:    map_sysmon_1,
    3:    map_sysmon_3,
    5156: map_5156,
    10:   map_sysmon_10,
    11:   map_sysmon_11,
    23:   map_sysmon_23,
    4663: map_4663,
}


def map_record(rec: dict) -> Optional[dict]:
    eid = rec.get("EventID")
    if eid is None:
        return None
    try:
        eid_int = int(eid)
    except (TypeError, ValueError):
        return None
    handler = _HANDLERS.get(eid_int)
    return handler(rec) if handler else None


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__,
    )
    parser.add_argument("input", help="Security-Datasets .json file (JSONL format)")
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output JSONL path (default: <input_stem>_aegis.jsonl)",
    )
    parser.add_argument(
        "--event-ids",
        default=None,
        help="Comma-separated EventIDs to include (default: all supported). E.g. 4625,3",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Stop after mapping this many events (0 = unlimited)",
    )
    args = parser.parse_args()

    in_path = Path(args.input).expanduser().resolve()
    if not in_path.exists():
        sys.exit(f"[ERROR] Input file not found: {in_path}")

    out_path = (
        Path(args.output).expanduser()
        if args.output
        else in_path.with_name(in_path.stem + "_aegis.jsonl")
    )

    filter_ids: Optional[set[int]] = None
    if args.event_ids:
        filter_ids = {int(x.strip()) for x in args.event_ids.split(",")}

    total = skipped = mapped = 0
    counts: dict[str, int] = {}

    print(f"[+] Source   : {in_path}")
    print(f"[+] Output   : {out_path}")
    if filter_ids:
        print(f"[+] EventIDs : {sorted(filter_ids)}")
    print()

    with in_path.open("r", encoding="utf-8", errors="replace") as fin, \
         out_path.open("w", encoding="utf-8") as fout:

        for line in fin:
            line = line.strip()
            if not line:
                continue
            total += 1

            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            eid = rec.get("EventID")
            if eid is None:
                skipped += 1
                continue

            if filter_ids and int(eid) not in filter_ids:
                skipped += 1
                continue

            envelope = map_record(rec)
            if envelope is None:
                skipped += 1
                continue

            fout.write(json.dumps(envelope, separators=(",", ":")) + "\n")
            mapped += 1
            et = envelope["event_type"]
            counts[et] = counts.get(et, 0) + 1

            if args.limit and mapped >= args.limit:
                break

            if total % 10000 == 0:
                print(f"    processed {total} lines, mapped {mapped} …", end="\r")

    print(f"\n{'─'*50}")
    print(f"  Total lines read : {total:>8,}")
    print(f"  Mapped events    : {mapped:>8,}")
    print(f"  Skipped          : {skipped:>8,}")
    print(f"\n  Breakdown by event_type:")
    for et, cnt in sorted(counts.items()):
        print(f"    {et:<22} {cnt:>6,}")
    print(f"\n[+] Output → {out_path}")


if __name__ == "__main__":
    main()
