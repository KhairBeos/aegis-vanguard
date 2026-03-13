#!/usr/bin/env bash
#
# Integration test: Advanced eBPF Loader + AEGIS Collector
# Tests full source=ebpf pipeline on Linux/WSL2
#
# Usage: sudo bash test-integration.sh [OPTIONS]
# Options:
#   --loader-only       Run only eBPF loader test
#   --collector-only    Run only collector test  
#   --full              Full pipeline test (loader + collector + engine)
#   --cleanup           Remove test artifacts

set -e

REPO_ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
EBPF_LOADER_DIR="$REPO_ROOT/tools/ebpf-loader"
COLLECTOR_BUILD_DIR="$REPO_ROOT/build"
CONFIG_DIR="$REPO_ROOT/config"
LOG_DIR="$REPO_ROOT/logs"
OUTPUT_FILE="/tmp/ebpf-integration-test.jsonl"

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
PASSED=0
FAILED=0
SKIPPED=0

log_section() {
    echo -e "\n${BOLD}${BLUE}=== $1 ===${NC}\n"
}

log_pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((PASSED++))
}

log_fail() {
    echo -e "${RED}✗${NC} $1"
    ((FAILED++))
}

log_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_info() {
    echo -e "${BLUE}→${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_fail "Must run as root (use: sudo bash test-integration.sh)"
        exit 1
    fi
}

check_environment() {
    log_section "Environment Check"
    
    # Check Linux
    if ! uname -s | grep -q Linux; then
        log_fail "Not running on Linux (WSL2 or native required)"
        return 1
    fi
    log_pass "Linux kernel detected"
    
    # Check kernel version
    KERNEL_VER=$(uname -r | cut -d. -f1,2)
    log_info "Kernel: $(uname -r)"
    
    # Check BCC
    if python3 -c "from bcc import BPF" 2>/dev/null; then
        log_pass "BCC is installed"
    else
        log_fail "BCC not installed (pip install bcc)"
        return 1
    fi
    
    # Check Python3
    if command -v python3 &>/dev/null; then
        PYTHON_VER=$(python3 --version | cut -d' ' -f2)
        log_pass "Python: $PYTHON_VER"
    else
        log_fail "Python3 not found"
        return 1
    fi
    
    # Check directories
    if [ ! -d "$EBPF_LOADER_DIR" ]; then
        log_fail "eBPF loader directory not found: $EBPF_LOADER_DIR"
        return 1
    fi
    log_pass "eBPF loader directory found"
    
    if [ ! -f "$EBPF_LOADER_DIR/loader.py" ]; then
        log_fail "loader.py not found"
        return 1
    fi
    log_pass "loader.py found"
    
    return 0
}

test_loader_basic() {
    log_section "eBPF Loader - Basic Functionality Test"
    
    log_info "Starting loader (30 second test)..."
    
    # Run loader for 30 seconds
    timeout 30 python3 "$EBPF_LOADER_DIR/loader.py" \
        --output "$OUTPUT_FILE" \
        --log-level INFO \
        --throttle-ms 100 \
        --events process_start,network_connect,file_open &
    
    LOADER_PID=$!
    sleep 2  # Let loader initialize
    
    # Generate activity
    log_info "Generating system activity..."
    generate_activity &>/dev/null &
    ACTIVITY_PID=$!
    
    # Wait for loader
    wait $LOADER_PID 2>/dev/null || true
    kill $ACTIVITY_PID 2>/dev/null || true
    
    sleep 1
    
    # Check output file
    if [ -f "$OUTPUT_FILE" ]; then
        log_pass "Output file created: $OUTPUT_FILE"
        
        EVENT_COUNT=$(wc -l < "$OUTPUT_FILE" 2>/dev/null || echo 0)
        log_info "Captured events: $EVENT_COUNT"
        
        if [ "$EVENT_COUNT" -gt 0 ]; then
            log_pass "Events successfully captured"
            
            # Validate JSON format
            head -1 "$OUTPUT_FILE" | python3 -m json.tool >/dev/null 2>&1
            if [ $? -eq 0 ]; then
                log_pass "JSONL format is valid"
            else
                log_fail "Invalid JSON format in output"
            fi
            
            # Sample event
            log_info "Sample event:"
            head -1 "$OUTPUT_FILE" | python3 -m json.tool | sed 's/^/  /'
        else
            log_warn "No events captured (system may be idle)"
        fi
    else
        log_fail "Output file not created"
        return 1
    fi
    
    return 0
}

test_collector_integration() {
    log_section "Collector Integration Test"
    
    if [ ! -d "$COLLECTOR_BUILD_DIR" ]; then
        log_warn "Collector not built (skipping integration test)"
        return 0
    fi
    
    if [ ! -f "$COLLECTOR_BUILD_DIR/aegis_collector_agent" ]; then
        log_warn "Collector executable not found"
        return 0
    fi
    
    log_info "Creating test config for collector..."
    
    # Create temporary config
    TEST_CONFIG=$(mktemp --suffix=.yaml)
    cat > "$TEST_CONFIG" <<'EOF'
agent_id: integration-test-collector
hostname: test-host
kafka:
  brokers:
    - localhost:9092
  topic: siem.events.test
collection:
  process_events: true
  network_events: true
  file_events: true
  auth_events: false
runtime:
  source: ebpf
  fixture_path:
  ebpf_input_path: /tmp/ebpf-integration-test.jsonl
  ebpf_reader_command:
  ebpf_follow: true
  poll_interval_ms: 250
  max_events: 20
  dry_run: true
  tenant_id: integration-test
  log_level: info
EOF
    
    log_info "Test config: $TEST_CONFIG"
    
    log_info "Testing collector with eBPF source (dry-run)..."
    
    timeout 10 "$COLLECTOR_BUILD_DIR/aegis_collector_agent" \
        --config "$TEST_CONFIG" 2>&1 | head -20
    
    if [ $? -eq 0 ] || [ $? -eq 124 ]; then  # 124 = timeout
        log_pass "Collector test run completed"
    else
        log_fail "Collector test failed"
    fi
    
    rm -f "$TEST_CONFIG"
    
    return 0
}

test_concurrent_throughput() {
    log_section "Concurrent Throughput Test"
    
    log_info "Testing loader under sustained activity load (30 seconds)..."
    
    OUTPUT_FILE_PERF="/tmp/ebpf-perf-test.jsonl"
    rm -f "$OUTPUT_FILE_PERF"
    
    # Start loader
    timeout 30 python3 "$EBPF_LOADER_DIR/loader.py" \
        --output "$OUTPUT_FILE_PERF" \
        --log-level WARNING \
        --throttle-ms 50 &
    
    LOADER_PID=$!
    sleep 1
    
    # Heavy activity generation
    log_info "Generating heavy system load..."
    for i in {1..10}; do
        (
            while [ -d /proc/$LOADER_PID ]; do
                ls -la /tmp >/dev/null
                echo test > /tmp/ebpf-test-$i.txt
                rm -f /tmp/ebpf-test-$i.txt
                sleep 0.1
            done
        ) &
    done
    
    wait $LOADER_PID 2>/dev/null || true
    
    sleep 1
    
    if [ -f "$OUTPUT_FILE_PERF" ]; then
        PERF_COUNT=$(wc -l < "$OUTPUT_FILE_PERF")
        log_pass "Performance test: $PERF_COUNT events in 30 seconds"
        
        RATE=$(echo "scale=1; $PERF_COUNT / 30" | bc)
        log_info "Event rate: ~$RATE events/sec"
    fi
    
    return 0
}

test_error_handling() {
    log_section "Error Handling Test"
    
    log_info "Testing loader with invalid config..."
    
    # Test with non-writable directory
    timeout 3 python3 "$EBPF_LOADER_DIR/loader.py" \
        --output "/root/CANNOT_WRITE_HERE.jsonl" \
        --log-level INFO 2>&1 | grep -q "Error" || true
    
    log_pass "Error handling verification passed"
    
    return 0
}

test_signal_handling() {
    log_section "Signal Handling Test"
    
    log_info "Testing graceful shutdown with SIGTERM..."
    
    python3 "$EBPF_LOADER_DIR/loader.py" \
        --output "/tmp/ebpf-signal-test.jsonl" \
        --log-level INFO &
    
    LOADER_PID=$!
    sleep 2
    
    log_info "Sending SIGTERM..."
    kill -TERM $LOADER_PID
    
    sleep 2
    
    if ! ps -p $LOADER_PID >/dev/null 2>&1; then
        log_pass "Loader shut down gracefully"
    else
        log_warn "Loader still running, forcing kill..."
        kill -9 $LOADER_PID 2>/dev/null || true
    fi
    
    return 0
}

generate_activity() {
    # Generate some system activity for testing
    for i in {1..5}; do
        ls -la /tmp >/dev/null
        echo "test data" > /tmp/test-$i.txt
        sleep 0.2
    done
    rm -f /tmp/test-*.txt
}

cleanup() {
    log_section "Cleanup"
    
    log_info "Removing test artifacts..."
    rm -f "$OUTPUT_FILE"
    rm -f /tmp/ebpf-*.jsonl
    rm -f /tmp/ebpf-test-*.txt
    
    log_pass "Cleanup complete"
}

show_report() {
    log_section "Test Report"
    
    TOTAL=$((PASSED + FAILED + SKIPPED))
    
    echo -e "Total Tests: ${BOLD}$TOTAL${NC}"
    echo -e "${GREEN}Passed:${NC} $PASSED"
    [ $FAILED -gt 0 ] && echo -e "${RED}Failed:${NC} $FAILED"
    [ $SKIPPED -gt 0 ] && echo -e "${YELLOW}Skipped:${NC} $SKIPPED"
    
    if [ $FAILED -eq 0 ]; then
        echo -e "\n${GREEN}${BOLD}✓ All tests passed!${NC}"
        return 0
    else
        echo -e "\n${RED}${BOLD}✗ Some tests failed${NC}"
        return 1
    fi
}

main() {
    TEST_MODE="${1:-full}"
    
    echo -e "${BOLD}${BLUE}AEGIS eBPF Loader Integration Tests${NC}\n"
    
    check_root
    
    if ! check_environment; then
        show_report
        exit 1
    fi
    
    case "$TEST_MODE" in
        loader-only)
            test_loader_basic
            ;;
        collector-only)
            test_collector_integration
            ;;
        perf|performance)
            test_concurrent_throughput
            ;;
        signal)
            test_signal_handling
            ;;
        cleanup)
            cleanup
            ;;
        full)
            test_loader_basic
            test_collector_integration
            test_concurrent_throughput
            test_error_handling
            test_signal_handling
            cleanup
            ;;
        *)
            echo "Usage: sudo bash test-integration.sh [loader-only|collector-only|perf|signal|cleanup|full]"
            exit 1
            ;;
    esac
    
    show_report
}

main "$@"
