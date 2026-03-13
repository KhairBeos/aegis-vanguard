#!/usr/bin/env bash
#
# Quick start guide for advanced eBPF loader integration
# Run this to get started on Linux/WSL2 in 5 minutes
#

REPO_ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
EBPF_DIR="$REPO_ROOT/tools/ebpf-loader"

echo "================================================"
echo "AEGIS eBPF Loader - Quick Start"
echo "================================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "⚠ This setup requires root. Run with: sudo bash quick-start.sh"
    exit 1
fi

echo "Step 1: Checking environment..."
if ! grep -qi linux /proc/version 2>/dev/null; then
    echo "✗ Not on Linux/WSL2. Cannot proceed."
    exit 1
fi
echo "✓ Linux environment detected"

echo ""
echo "Step 2: Installing dependencies..."
if python3 -c "from bcc import BPF" 2>/dev/null; then
    echo "✓ BCC already installed"
else
    echo "→ Installing BCC..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq
        apt-get install -y -qq python3-bcc linux-headers-$(uname -r) >/dev/null
        echo "✓ BCC installed (Debian/Ubuntu)"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q bcc python3-bcc >/dev/null
        echo "✓ BCC installed (Fedora/RHEL)"
    else
        pip3 install -q bcc
        echo "✓ BCC installed (pip)"
    fi
fi

echo ""
echo "Step 3: Setting up output directory..."
mkdir -p /var/run/aegis
chmod 755 /var/run/aegis
echo "✓ Output directory ready: /var/run/aegis"

echo ""
echo "Step 4: Verifying loader..."
if [ ! -f "$EBPF_DIR/loader.py" ]; then
    echo "✗ loader.py not found at $EBPF_DIR"
    exit 1
fi
chmod +x "$EBPF_DIR/loader.py"
echo "✓ loader.py ready"

echo ""
echo "================================================"
echo "Quick Start Complete! Ready to test."
echo "================================================"
echo ""
echo "To run eBPF loader:"
echo ""
echo "  sudo python3 $EBPF_DIR/loader.py"
echo ""
echo "For full integration test (loader + collector):"
echo ""
echo "  sudo bash $EBPF_DIR/test-integration.sh full"
echo ""
echo "To view captured events:"
echo ""
echo "  tail -f /var/run/aegis/ebpf-events.jsonl"
echo ""
echo "For more details, see: $EBPF_DIR/README.md"
echo ""
