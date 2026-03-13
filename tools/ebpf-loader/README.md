# Advanced eBPF Userspace Loader

Enterprise-grade eBPF event capture system for AEGIS SIEM collector, providing real-time process, network, and file activity monitoring from the Linux kernel.

## Features

### Advanced Capabilities
- **Multiple syscall hooks**: Process execution (execve), network connections (connect), file operations (openat)
- **Kernel ringbuffer**: Modern kernel 5.8+ ringbuffer output with fallback to perf buffer
- **Intelligent filtering**: UID/PID range filtering, system process exclusion, namespace awareness
- **Event deduplication**: Automatic throttling of rapid duplicates within configurable window
- **Atomic file writes**: Safe concurrent appending of JSONL events  
- **Performance metrics**: Real-time tracking of captured, filtered, written, and dropped events
- **Graceful shutdown**: Signal handlers with buffer flushing on exit
- **Error recovery**: Comprehensive error handling with lost event tracking

### Event Types Supported
- **process_start**: Process execution with PID, UID, command line, parent PID
- **network_connect**: TCP connections with source/destination IP and port
- **file_open**: File access with path and operation flags

### Integration with AEGIS Collector
- **Output format**: JSONL matching collector `SourceRecord` v1.1 schema
- **File mode**: Writes to `/var/run/aegis/ebpf-events.jsonl` (collector polls with follow)
- **Configurable**: Works with collector's `source: ebpf` + `ebpf_input_path`

## Architecture

```
┌─────────────────────────────────┐
│      Linux Kernel (eBPF)        │
├─────────────────────────────────┤
│ Tracepoints (sched, syscalls)   │
│ ├─ sched:sched_process_exec     │
│ ├─ syscalls:sys_enter_connect   │
│ └─ syscalls:sys_enter_openat    │
└──────────────┬──────────────────┘
               │ ringbuffer events
               ▼
┌─────────────────────────────────┐
│   Userspace eBPF Loader         │
├─────────────────────────────────┤
│ 1. Event Handler                │
│    ├─ Parse ringbuffer          │
│    ├─ Filter UID/PID            │
│    └─ Throttle duplicates       │
│ 2. Event Formatter              │
│    └─ SourceRecord → JSONL      │
│ 3. Buffer Manager               │
│    ├─ Accumulate events         │
│    └─ Flush atomically          │
│ 4. Metrics Tracker              │
│    ├─ Captured events           │
│    ├─ Filtered events           │
│    └─ Written events            │
└──────────────┬──────────────────┘
               │ JSONL events
               ▼
┌─────────────────────────────────┐
│  /var/run/aegis/ebpf-events.jsonl
└──────────────┬──────────────────┘
               │ collector polls
               ▼
┌─────────────────────────────────┐
│   AEGIS C++ Collector           │
│   source: ebpf                  │
└──────────────┬──────────────────┘
               │ normalized events
               ▼
┌─────────────────────────────────┐
│   Apache Kafka Broker           │
└──────────────┬──────────────────┘
               │ siem.events topic
               ▼
┌─────────────────────────────────┐
│   AEGIS Engine (Rust/WASM)      │
│   Rule evaluation & alerting    │
└─────────────────────────────────┘
```

## Requirements

### System
- Linux kernel 5.4+ (5.8+ for ringbuffer; earlier with perf buffer)
- BCC (Berkeley Packet Filter Compiler Collection) >= 0.18.0
- Python 3.7+
- Root/sudo access for kernel probe attachment

### Environments
- **Native Linux**: Standard installation via package manager
- **WSL2**: Requires kernel 5.10+ with `kernel-command-line = systemd.unified_cgroup_hierarchy=1`
- **Docker**: Overlay network namespace support required

### Install Dependencies

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y \
  linux-headers-$(uname -r) \
  python3 python3-pip \
  bpftrace llvm clang libelf-dev libz-dev

pip3 install -r requirements.txt
```

#### Fedora/RHEL/CentOS
```bash
sudo dnf install -y \
  kernel-devel \
  python3 python3-pip \
  bcc bcc-tools python3-bcc bpftrace llvm clang \
  elfutils-libelf-devel zlib-devel

pip3 install -r requirements.txt
```

#### Automated Setup (Ubuntu/Debian/Fedora)
```bash
sudo bash setup.sh
```

## Usage

### Basic Execution
```bash
# Run with defaults (requires sudo)
sudo python3 loader.py

# Specify output file
sudo python3 loader.py --output /var/run/aegis/ebpf-events.jsonl

# Debug mode with verbose logging
sudo python3 loader.py --log-level DEBUG

# Test run with temporary output
sudo python3 loader.py --output /tmp/ebpf-test.jsonl --throttle-ms 50
```

### Configuration Options
```
--output PATH              Output JSONL file path 
                          (default: /var/run/aegis/ebpf-events.jsonl)

--log-level {DEBUG,INFO,WARNING,ERROR}
                          Logging verbosity (default: INFO)

--disable-filtering        Disable UID/PID filtering (capture all)

--throttle-ms MS          Event throttle window in milliseconds 
                          (default: 100)

--events TYPE[,TYPE,...]  Comma-separated event types to enable
                          (default: process_start,network_connect,file_open)
```

### Examples

#### Capture all events with debug logging
```bash
sudo python3 loader.py \
  --log-level DEBUG \
  --disable-filtering \
  --throttle-ms 250
```

#### Capture only network connections
```bash
sudo python3 loader.py \
  --events network_connect \
  --log-level INFO
```

#### Test mode with temporary file
```bash
sudo python3 loader.py \
  --output /tmp/test-events.jsonl \
  --throttle-ms 50 \
  --log-level DEBUG
```

## Integration with AEGIS Collector

### Configuration

1. **Ensure collector config specifies eBPF source**:
   ```yaml
   # config/prod/collector.yaml or config/dev/collector.yaml
   runtime:
     source: ebpf
     ebpf_input_path: /var/run/aegis/ebpf-events.jsonl
     ebpf_follow: true
     poll_interval_ms: 250
   ```

2. **Start loader before or alongside collector**:
   ```bash
   # Terminal 1: Start eBPF loader
   sudo python3 tools/ebpf-loader/loader.py
   
   # Terminal 2 (after sudo setup): Start collector
   ./build/collector --config config/prod/collector.yaml
   ```

3. **Verify integration**:
   ```bash
   # Check JSONL output
   tail -f /var/run/aegis/ebpf-events.jsonl
   
   # Monitor metrics (every 10 seconds)
   grep "STATS" /var/log/aegis/collector.log
   ```

## Event Format

Loader outputs JSONL events matching collector's `SourceRecord` v1.1 schema:

```json
{
  "event_type": "process_start",
  "host_name": "ubuntu-wsl2",
  "timestamp": 1710300000.123456,
  "process_id": 12345,
  "process_name": "bash",
  "user_id": 1000,
  "user_name": "ubuntu",
  "parent_process_id": 5432,
  "process_start_time": 1710300000.111111,
  "source_ip": "",
  "source_port": 0,
  "dest_ip": "",
  "dest_port": 0,
  "protocol": "",
  "file_path": "",
  "file_operation": "",
  "allowed": true
}
```

## Performance Tuning

### Throttle Duration
- **Process events**: 100-500 ms (suppress rapid execs)
- **Network events**: 50-200 ms (suppress connection storms)
- **File events**: 100-250 ms (suppress rapid file access)

Too low → high CPU; too high → data loss

### Buffer Size
- **10000 events**: Default, ~40 KB JSON in memory
- **50000 events**: High-volume environments
- **1000 events**: Embedded/low-resource

### Flush Interval
- **1.0 sec**: Default, good balance
- **0.5 sec**: Real-time priority
- **5.0 sec**: Batch optimization

### Filtering
- **Enable filtering**: Excludes UIDs 0-999 (system accounts), reduces noise
- **Disable filtering**: Full tracing, higher CPU/disk

## Troubleshooting

### Issue: "Permission denied" when loading eBPF
```bash
# Solution: Must run as root
sudo python3 loader.py
```

### Issue: "BCC module not found"
```bash
# Solution: Install BCC
pip3 install bcc
# Or on Linux:
sudo apt-get install python3-bcc  # Debian/Ubuntu
sudo dnf install python3-bcc      # Fedora/RHEL
```

### Issue: No events captured
```bash
# Check: Is system idle?
sudo python3 loader.py --log-level DEBUG

# Check: Kernel supports ringbuffer?
cat /sys/kernel/debug/kconfig/CONFIG_BPF_SYSCALL

# Check: Required tracepoints exist?
ls /sys/kernel/debug/tracing/events/sched/
ls /sys/kernel/debug/tracing/events/syscalls/
```

### Issue: High CPU usage
```bash
# Solution: Increase throttle window
sudo python3 loader.py --throttle-ms 500

# Solution: Disable filtering (adds overhead)
# Or enable filtering (reduces event volume):
# Already enabled by default
```

### Issue: Output file fills disk
```bash
# Solution: Rotate output file
sudo logrotate -f /etc/logrotate.d/ebpf-loader

# Or: Clear manually
sudo truncate -s 0 /var/run/aegis/ebpf-events.jsonl
```

### Issue: WSL2 permission denied on /var/run/aegis
```bash
# Solution: Ensure directory accessible by collector
sudo mkdir -p /var/run/aegis
sudo chmod 755 /var/run/aegis
sudo chown root:root /var/run/aegis
```

## WSL2 Setup Guide

### 1. Update WSL2 Kernel
```bash
wsl --update
wsl --list --verbose  # Verify kernel version >= 5.10
```

### 2. Enable Nested eBPF Features
Edit `~/.wslconfig`:
```ini
[wsl2]
kernel=C:\path\to\custom\kernel
kernelCommandLine = systemd.unified_cgroup_hierarchy=1
```

### 3. Install BCC on WSL2
```bash
sudo apt-get update
sudo apt-get install -y \
  linux-headers-$(uname -r) \
  bpftrace python3-bcc llvm clang

cd /path/to/aegis-vanguard
sudo bash tools/ebpf-loader/setup.sh
```

### 4. Create Output Directory
```bash
sudo mkdir -p /var/run/aegis
sudo chmod 755 /var/run/aegis
```

### 5. Test Integration
```bash
# Terminal 1: Run loader
cd /path/to/aegis-vanguard
sudo python3 tools/ebpf-loader/loader.py --log-level INFO

# Terminal 2: Trigger events (generate activity)
sudo apt-get update  # Process + network events
cd /tmp && ls -la    # File activity

# Terminal 3: Monitor output
tail -f /var/run/aegis/ebpf-events.jsonl
```

## Development

### Adding New Syscall Hooks

1. Add tracepoint probe to kernel program:
```c
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat)
{
    // Capture file deletion
}
```

2. Add event type to `EventHandler._is_enabled()`:
```python
type_map = {
    1: "process_start",
    2: "network_connect", 
    3: "file_open",
    4: "file_delete",  # new
}
```

3. Parse in `_parse_event()`:
```python
elif event_type == "file_delete":
    record.file_path = evt.filename.decode('utf-8')
    record.file_operation = "unlink"
```

### Performance Profiling
```bash
# CPU usage
sudo python3 -m cProfile -s cumtime loader.py 2>&1 | head -20

# Memory usage
sudo pmap -x $(pgrep -f loader.py)

# Event throughput
strace -e write -c sudo python3 loader.py 2>&1 | head -10
```

## Limitations

1. **Kernel version dependency**: Ringbuffer requires 5.8+; perf buffer fallback for earlier kernels
2. **Namespace scope**: Captures events from container where loader runs
3. **Local connections only**: IPv4 TCP; IPv6 UDP connections need custom hooks
4. **No file content**: Only path and flags captured, not file  data
5. **No authentication context**: PAM integration not included
6. **Performance trade-off**: Higher fidelity = higher overhead

## Future Enhancements

- [ ] IPv6 and UDP event support
- [ ] File content hashing (MD5/SHA256 for executed files)
- [ ] Container/namespace isolation visibility
- [ ] Aggregated statistics exports (Prometheus/OpenTelemetry)
- [ ] Go rewrite for production performance
- [ ] Dynamic hotpatching of eBPF maps without reload

## License

Apache License 2.0

## Contributing

Contributions welcome! Test all changes on WSL2 and native Linux before submitting PRs.

---

**Maintained by**: AEGIS Development Team  
**Last Updated**: 2026-03-12  
**Kernel Support**: Linux 5.4+ (5.8+ recommended)
