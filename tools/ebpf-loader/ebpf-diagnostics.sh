#!/usr/bin/env bash
#
# Diagnostic tool for eBPF loader troubleshooting
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}AEGIS eBPF Loader Diagnostics${NC}\n"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}⚠ Some checks require root. Run: sudo bash ebpf-diagnostics.sh${NC}\n"
fi

# Kernel version
echo -e "${BLUE}=== Kernel ===${NC}"
KERNEL=$(uname -r)
echo "Kernel: $KERNEL"

# Check Linux
if ! grep -qi linux /proc/version 2>/dev/null; then
    echo -e "${RED}✗ Not Linux/WSL2${NC}"
else
    echo -e "${GREEN}✓ Linux kernel${NC}"
fi

# Check kernel features
echo ""
echo -e "${BLUE}=== eBPF Kernel Features ===${NC}"

# BPF_SYSCALL
if [ -f /boot/config-$(uname -r) ]; then
    if grep -q "CONFIG_BPF_SYSCALL=y" /boot/config-$(uname -r); then
        echo -e "${GREEN}✓${NC} CONFIG_BPF_SYSCALL enabled"
    else
        echo -e "${RED}✗${NC} CONFIG_BPF_SYSCALL not enabled"
    fi
else
    echo -e "${YELLOW}⚠${NC} Cannot verify /boot/config"
fi

# Ringbuffer support (5.8+)
if [ -d /sys/kernel/debug/tracing/events/syscalls ]; then
    echo -e "${GREEN}✓${NC} Tracepoints available"
else
    echo -e "${RED}✗${NC} Tracepoints not found"
fi

# BPF debugfs
if [ -d /sys/kernel/debug/tracing ]; then
    echo -e "${GREEN}✓${NC} BPF debugfs available"
else
    echo -e "${RED}✗${NC} BPF debugfs not available"
fi

# Dependencies
echo ""
echo -e "${BLUE}=== Dependencies ===${NC}"

# Python3
if command -v python3 >/dev/null; then
    PYVER=$(python3 --version | cut -d' ' -f2)
    echo -e "${GREEN}✓${NC} Python $PYVER"
else
    echo -e "${RED}✗${NC} Python3 not found"
fi

# BCC
if python3 -c "from bcc import BPF" 2>/dev/null; then
    BCCVER=$(python3 -c "import bcc; print(bcc.version)" 2>/dev/null || echo "unknown")
    echo -e "${GREEN}✓${NC} BCC installed"
else
    echo -e "${RED}✗${NC} BCC not installed"
    echo "  Install with: pip3 install bcc"
fi

# llvm/clang
if command -v llvm-config >/dev/null; then
    LLVMVER=$(llvm-config --version)
    echo -e "${GREEN}✓${NC} LLVM $LLVMVER"
else
    echo -e "${YELLOW}⚠${NC} LLVM not found"
fi

if command -v clang >/dev/null; then
    CLANGVER=$(clang --version | head -1)
    echo -e "${GREEN}✓${NC} Clang found"
else
    echo -e "${YELLOW}⚠${NC} Clang not found"
fi

# Kernel headers
if [ -d "/lib/modules/$(uname -r)/build" ]; then
    echo -e "${GREEN}✓${NC} Kernel headers available"
else
    echo -e "${RED}✗${NC} Kernel headers not found"
fi

# System
echo ""
echo -e "${BLUE}=== System ===${NC}"

# Available memory
MEMFREE=$(free -m | awk 'NR==2{print $7}')
echo "Free memory: ${MEMFREE}M"

if [ "$MEMFREE" -lt 256 ]; then
    echo -e "${YELLOW}⚠${NC} Low memory, may impact BPF programs"
fi

# CPU cores
CORES=$(nproc)
echo "CPU cores: $CORES"

# File permissions
echo ""
echo -e "${BLUE}=== File Permissions ===${NC}"

OUTPUT_DIR="/var/run/aegis"
if [ -d "$OUTPUT_DIR" ]; then
    if [ -w "$OUTPUT_DIR" ]; then
        echo -e "${GREEN}✓${NC} $OUTPUT_DIR is writable"
    else
        echo -e "${RED}✗${NC} $OUTPUT_DIR is not writable"
    fi
else
    echo -e "${YELLOW}⚠${NC} $OUTPUT_DIR does not exist"
    echo "  Create with: sudo mkdir -p $OUTPUT_DIR && sudo chmod 755 $OUTPUT_DIR"
fi

# Tracepoint availability
echo ""
echo -e "${BLUE}=== Available Tracepoints ===${NC}"

if [ -d /sys/kernel/debug/tracing/events ]; then
    for tp in sched syscalls tracepoints; do
        if [ -d "/sys/kernel/debug/tracing/events/$tp" ]; then
            COUNT=$(ls /sys/kernel/debug/tracing/events/$tp 2>/dev/null | wc -l)
            echo -e "${GREEN}✓${NC} $tp: $COUNT tracepoints"
        fi
    done
    
    # Check specific syscalls we need
    for syscall in execve connect openat; do
        if [ -d "/sys/kernel/debug/tracing/events/syscalls/sys_enter_$syscall" ]; then
            echo -e "  ${GREEN}✓${NC} sys_enter_$syscall"
        else
            echo -e "  ${YELLOW}⚠${NC} sys_enter_$syscall not available"
        fi
    done
    
    if [ -d "/sys/kernel/debug/tracing/events/sched/sched_process_exec" ]; then
        echo -e "  ${GREEN}✓${NC} sched_process_exec"
    else
        echo -e "  ${YELLOW}⚠${NC} sched_process_exec not available"
    fi
fi

# Loaded eBPF programs
echo ""
echo -e "${BLUE}=== Active eBPF Programs ===${NC}"

if [ "$EUID" -eq 0 ]; then
    if command -v bpftool >/dev/null; then
        COUNT=$(bpftool prog list 2>/dev/null | wc -l)
        echo "Active BPF programs: $COUNT"
    else
        echo -e "${YELLOW}⚠${NC} bpftool not found (install linux-tools)"
    fi
else
    echo -e "${YELLOW}⚠${NC} Run as root to check active programs"
fi

# Output file status
echo ""
echo -e "${BLUE}=== Output File Status ===${NC}"

OUTPUT_FILE="/var/run/aegis/ebpf-events.jsonl"
if [ -f "$OUTPUT_FILE" ]; then
    LINES=$(wc -l < "$OUTPUT_FILE")
    SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)
    MTIME=$(date -r "$OUTPUT_FILE" '+%Y-%m-%d %H:%M:%S')
    echo -e "${GREEN}✓${NC} Output file exists"
    echo "  Path: $OUTPUT_FILE"
    echo "  Size: $SIZE"
    echo "  Lines: $LINES"
    echo "  Modified: $MTIME"
    
    # Sample event
    if [ "$LINES" -gt 0 ]; then
        echo "  Sample:"
        head -1 "$OUTPUT_FILE" | python3 -m json.tool 2>/dev/null | sed 's/^/    /'
    fi
else
    echo -e "${YELLOW}⚠${NC} Output file not found: $OUTPUT_FILE"
fi

# Running processes
echo ""
echo -e "${BLUE}=== Running Processes ===${NC}"

if pgrep -f "python.*loader.py" >/dev/null; then
    echo -e "${GREEN}✓${NC} eBPF loader is running"
    pgrep -f "python.*loader.py" -a | sed 's/^/  /'
else
    echo -e "${YELLOW}⚠${NC} eBPF loader not running"
fi

echo ""
echo -e "${BLUE}=== Summary ===${NC}"

# Score
SCORE=0
[ -f /boot/config-$(uname -r) ] && SCORE=$((SCORE+10))
[ -d /sys/kernel/debug/tracing ] && SCORE=$((SCORE+10))
command -v python3 >/dev/null && SCORE=$((SCORE+10))
python3 -c "from bcc import BPF" 2>/dev/null && SCORE=$((SCORE+20))
[ -d "$OUTPUT_DIR" ] && SCORE=$((SCORE+10))
[ -w "$OUTPUT_DIR" ] && SCORE=$((SCORE+10))
[ -f "$OUTPUT_FILE" ] && SCORE=$((SCORE+20))

echo "Compatibility score: ${SCORE}%"

if [ "$SCORE" -ge 80 ]; then
    echo -e "${GREEN}✓ Ready to run eBPF loader${NC}"
elif [ "$SCORE" -ge 50 ]; then
    echo -e "${YELLOW}⚠ May run, but with limitations${NC}"
    echo "Missing: Kernel headers or BCC"
else
    echo -e "${RED}✗ Not ready for eBPF loader${NC}"
    echo "Install BCC: pip3 install bcc"
    echo "Install headers: sudo apt-get install linux-headers-\$(uname -r)"
fi

echo ""
