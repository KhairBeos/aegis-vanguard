#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from attack_sim import (
    scenario_auth_burst,
    scenario_data_staging,
    scenario_dns_tunnel_tool,
    scenario_download_chmod_exec,
    scenario_download_pipe_bash,
    scenario_lsass_dump,
    scenario_port_scan,
    scenario_reverse_shell,
    scenario_sensitive_file_enum,
    scenario_temp_dropper,
    scenario_tmp_interpreter_exec,
)
from demo_stream import build_aegis_envelope


def _build_records(base: datetime, host: str, volume: int) -> dict[str, list[dict]]:
    records: dict[str, list[dict]] = {
        "windows-ntlm-bruteforce-cluster": [],
        "windows-lsass-dump-cluster": [],
        "windows-lateral-movement-cluster": [],
        "linux-exec-cluster": [],
    }

    src_pool = ["172.16.0.5", "203.0.113.77", "198.51.100.44", "185.220.101.5"]
    dst_pool = ["198.51.100.10", "203.0.113.250", "198.51.100.44", "168.63.129.16"]
    user_pool = ["alice", "administrator", "root", "ubuntu", "svc-backup"]

    for i in range(volume):
        offset = i * 7
        t = base + timedelta(seconds=offset)
        src_ip = random.choice(src_pool)
        dst_ip = random.choice(dst_pool)
        user = random.choice(user_pool)

        records["windows-ntlm-bruteforce-cluster"].extend(
            scenario_auth_burst(t, src_ip, random.randint(5, 12), user_name=random.choice(["administrator", "admin", "root"]), method=random.choice(["domain-ntlm", "interactive-ntlm", "ssh"]), reason=random.choice(["wrong_password", "bad_credentials", "invalid_password"]))
        )
        records["windows-lsass-dump-cluster"].extend(scenario_lsass_dump(t, host, random.choice(["SYSTEM", "administrator"])))
        records["windows-lsass-dump-cluster"].extend(scenario_sensitive_file_enum(t + timedelta(seconds=2), host, "root"))

        records["windows-lateral-movement-cluster"].extend(scenario_port_scan(t, host, dst_ip))
        if i % 2 == 0:
            records["windows-lateral-movement-cluster"].extend(scenario_reverse_shell(t + timedelta(seconds=3), host, user))

        records["linux-exec-cluster"].extend(scenario_download_pipe_bash(t, host, user))
        records["linux-exec-cluster"].extend(scenario_download_chmod_exec(t + timedelta(seconds=1), host, user))
        records["linux-exec-cluster"].extend(scenario_tmp_interpreter_exec(t + timedelta(seconds=2), host, user))
        records["linux-exec-cluster"].extend(scenario_dns_tunnel_tool(t + timedelta(seconds=3), host, user, dst_ip))
        records["linux-exec-cluster"].extend(scenario_temp_dropper(t + timedelta(seconds=4), host, user))
        records["linux-exec-cluster"].extend(scenario_data_staging(t + timedelta(seconds=5), host, user))

    return records


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate large synthetic Aegis JSONL seed files for demo_stream targets")
    parser.add_argument("--volume", type=int, default=35, help="Number of generation rounds per target (default: 35)")
    parser.add_argument("--host", default="seed-host", help="Host value for generated events")
    parser.add_argument("--agent-id", default="seed-generator")
    parser.add_argument("--tenant-id", default="default")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    out_dir = repo_root / "runtime" / "mordor"
    out_dir.mkdir(parents=True, exist_ok=True)

    base = datetime.now(timezone.utc)
    scenario_by_target = _build_records(base, args.host, max(1, args.volume))

    total = 0
    for target, records in scenario_by_target.items():
        out_path = out_dir / f"{target}.aegis.jsonl"
        with out_path.open("w", encoding="utf-8") as handle:
            for raw in records:
                envelope = build_aegis_envelope(raw, args.host, args.agent_id, args.tenant_id)
                handle.write(json.dumps(envelope, separators=(",", ":")) + "\n")
        print(f"[seed] wrote {len(records)} events -> {out_path}")
        total += len(records)

    print(f"[seed] total events written: {total}")


if __name__ == "__main__":
    main()
