# Guide: Running Advanced eBPF Loader with AEGIS Collector
# Full integration test on Linux/WSL2

## Prerequisites

1. **System**:
   - Linux/WSL2 kernel 5.4+
   - Python 3.7+
   - Root access (sudo)
   
2. **Dependencies**:
   ```bash
   sudo bash tools/ebpf-loader/quick-start.sh
   ```

3. **Build collector** (if not already built):
   ```bash
   cmake -B build -DCMAKE_BUILD_TYPE=Debug
   cmake --build build
   ```

## Integration Test - Full Pipeline

### Method 1: Single Integration Test Command

Run all tests (loader, collector, throughput, error handling):
```bash
cd d:/Learning/Security/SIEM/aegis-vanguard
sudo bash tools/ebpf-loader/test-integration.sh full
```

This will:
- ✓ Verify BCC installation
- ✓ Start eBPF loader 
- ✓ Generate system activity
- ✓ Capture events to /tmp/ebpf-integration-test.jsonl
- ✓ Validate JSONL format
- ✓ Test collector dry-run with eBPF source
- ✓ Run performance/throughput test
- ✓ Test error handling and graceful shutdown
- ✓ Report statistics

### Method 2: Step-by-Step Manual Test

#### Step 1: Start eBPF Loader
```bash
sudo python3 tools/ebpf-loader/loader.py \
  --output /var/run/aegis/ebpf-events.jsonl \
  --log-level INFO \
  --throttle-ms 100
```

This will:
- Attach eBPF probes to kernel
- Listen on tracepoints (execve, connect, openat)
- Write JSONL events to `/var/run/aegis/ebpf-events.jsonl`
- Report stats every 10 seconds

#### Step 2: Generate System Activity (in another terminal)
```bash
# Run commands that trigger eBPF events:

# Process events (execve)
for i in {1..10}; do 
  ls -la /tmp
  echo test
done

# Network events (connect)
curl https://www.google.com >/dev/null 2>&1 || true
ping -c 2 8.8.8.8 >/dev/null 2>&1 || true

# File events (openat)
cat /etc/hosts
vi /tmp/test.txt
find /etc -name "*.conf"
```

You should see output in loader terminal:
```
[2026-03-12 10:15:30] INFO: eBPF program loaded and attached
[2026-03-12 10:15:31] INFO: [STATS] uptime=1.2s captured={'process_start': 5, 'network_connect': 2, 'file_open': 12} written=19 errors=0 host=ubuntu-wsl2
```

#### Step 3: Monitor Captured Events
```bash
# View events being written
tail -f /var/run/aegis/ebpf-events.jsonl

# Or in another terminal, count events
watch -n 1 'wc -l /var/run/aegis/ebpf-events.jsonl'
```

#### Step 4: Test Collector Integration
```bash
# Run collector with eBPF source (dry-run mode doesn't require Kafka)
./build/aegis_collector_agent \
  --config config/ebpf-integration-test.yaml

# Or with logging enabled:
RUST_LOG=debug ./build/aegis_collector_agent \
  --config config/ebpf-integration-test.yaml
```

Expected output:
```
[2026-03-12 10:16:20.123] INFO: Starting AEGIS Collector
[2026-03-12 10:16:20.124] INFO: Loading config: config/ebpf-integration-test.yaml
[2026-03-12 10:16:20.125] INFO: Using source: ebpf
[2026-03-12 10:16:20.126] INFO: eBPF source initialized, will read from /var/run/aegis/ebpf-events.jsonl
[2026-03-12 10:16:20.127] INFO: Event 1: process_start (pid=12345, cmd=bash, host=ubuntu-wsl2)
[2026-03-12 10:16:20.128] INFO: Event 2: file_open (pid=12346, path=/etc/hosts)
[2026-03-12 10:16:20.129] INFO: Event 3: network_connect (pid=12347, dest=142.251.41.14:443, host=ubuntu-wsl2)
[2026-03-12 10:16:21.130] INFO: Processed 3 events (1 published to Kafka)
```

#### Step 5: Verify End-to-End

If running with actual Kafka:
```bash
# Terminal 1: Start Zookeeper
./scripts/start-zookeeper.sh

# Terminal 2: Start Kafka
./scripts/start-kafka.sh

# Terminal 3: Start eBPF loader
sudo python3 tools/ebpf-loader/loader.py

# Terminal 4: Start collector
./build/aegis_collector_agent --config config/prod/collector.yaml

# Terminal 5: Monitor Kafka topic
kafka-console-consumer.sh --bootstrap-server localhost:9092 \
  --topic siem.events --from-beginning

# Terminal 6: Generate activity
curl https://example.com
```

## Configuration Modes

### File Mode (Recommended for Testing)
Loader writes JSONL to file; collector reads with file follow:
```yaml
runtime:
  source: ebpf
  ebpf_input_path: /var/run/aegis/ebpf-events.jsonl
  ebpf_reader_command: ""
  ebpf_follow: true
```

### Command Mode (Pipe Mode)
Collector directly pipes from loader command:
```yaml
runtime:
  source: ebpf
  ebpf_input_path: ""
  ebpf_reader_command: "python3 tools/ebpf-loader/loader.py --output /dev/stdout"
  ebpf_follow: false
```

## Troubleshooting

### No Events Captured
```bash
# Check: Are there any events in the system?
# Generate more activity:
for i in {1..100}; do ls -la /tmp; sleep 0.1; done

# Check: Is eBPF loader running?
ps aux | grep loader.py

# Check: Is output file being written?
ls -la /var/run/aegis/ebpf-events.jsonl
tail -f /var/run/aegis/ebpf-events.jsonl
```

### BCC Module Not Found
```bash
pip3 install -U bcc
# Or on Linux:
sudo apt-get install python3-bcc
sudo dnf install python3-bcc
```

### Permission Denied
```bash
# All eBPF operations require root
sudo python3 tools/ebpf-loader/loader.py
sudo bash tools/ebpf-loader/test-integration.sh
```

### Collector Hangs Reading File

If collector is stuck waiting for events:
```bash
# Make sure loader is running
ps aux | grep loader.py

# Check file exists and has content
ls -la /var/run/aegis/ebpf-events.jsonl
wc -l /var/run/aegis/ebpf-events.jsonl
```

## Performance Expectations

On typical Linux/WSL2 system:
- **Throughput**: 500-2000 events/second (depends on system load)
- **Latency**: <100ms from kernel to JSONL
- **CPU**: <5% for idle system
- **Memory**: ~20-50 MB Python process

## Next Steps

1. **Test on WSL2**:
   - Clone repo to WSL2 filesystem
   - Run `sudo bash tools/ebpf-loader/quick-start.sh`
   - Run integration test

2. **Test on Native Linux**:
   - Same setup, better kernel support for eBPF

3. **Production Deployment**:
   - Configure systemd service for loader
   - Set up log rotation for JSONL output
   - Tune throttle/buffer settings

4. **Advanced Features** (future):
   - Add more syscall hooks
   - Implement aggregation
   - Add container namespace filtering
   - Export metrics to Prometheus

## Reference Documentation

- [eBPF Loader README](./README.md)
- [Collector Config](../config/)
- [Integration Tests](./test-integration.sh)

---

For questions or issues, check the troubleshooting guide in README.md or run:
```bash
sudo python3 tools/ebpf-loader/loader.py --log-level DEBUG
```
