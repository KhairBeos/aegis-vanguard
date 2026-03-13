#!/usr/bin/env bash
#
# WSL2/Linux setup script for advanced eBPF loader
# Detects environment and installs dependencies
#

set -e

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must run as root (use: sudo $0)"
        exit 1
    fi
}

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        log_error "Cannot detect Linux distribution"
        exit 1
    fi
}

setup_ubuntu_debian() {
    log_info "Detected Ubuntu/Debian"
    
    log_info "Updating package manager..."
    apt-get update -qq
    
    log_info "Installing kernel headers..."
    apt-get install -y linux-headers-$(uname -r)
    
    log_info "Installing Python3 and pip..."
    apt-get install -y python3 python3-pip python3-venv
    
    log_info "Installing BCC and dependencies..."
    apt-get install -y bpftrace llvm clang libelf-dev libz-dev
    
    # Try installing BCC package
    if apt-cache search libbcc > /dev/null 2>&1; then
        apt-get install -y libbcc python3-bcc
        log_info "Installed BCC from package repository"
    else
        log_warn "BCC package not found in APT, will install via pip"
    fi
    
    log_info "Installing Python dependencies..."
    pip3 install -q -r requirements.txt
}

setup_fedora_rhel() {
    log_info "Detected Fedora/RHEL/CentOS"
    
    log_info "Updating package manager..."
    dnf update -y -q
    
    log_info "Installing kernel headers..."
    dnf install -y kernel-devel
    
    log_info "Installing Python3 and pip..."
    dnf install -y python3 python3-pip
    
    log_info "Installing BCC and dependencies..."
    dnf install -y bcc bcc-tools python3-bcc bpftrace llvm clang elfutils-libelf-devel zlib-devel
    
    log_info "Installing Python dependencies..."
    pip3 install -q -r requirements.txt
}

setup_environment() {
    log_info "Setting up output directory..."
    mkdir -p /var/run/aegis
    chmod 755 /var/run/aegis
    
    log_info "Verifying BCC installation..."
    if python3 -c "from bcc import BPF" 2>/dev/null; then
        log_info "✓ BCC is installed and working"
    else
        log_error "BCC installation failed - try: pip3 install bcc"
        exit 1
    fi
}

detect_wsl2() {
    if grep -qi microsoft /proc/version 2>/dev/null; then
        return 0  # On WSL2
    else
        return 1  # Not on WSL2
    fi
}

main() {
    log_info "eBPF Loader Setup Script"
    
    check_root
    detect_distro
    
    if detect_wsl2; then
        log_info "Detected WSL2 environment"
    fi
    
    case "$OS" in
        ubuntu|debian)
            setup_ubuntu_debian
            ;;
        fedora|rhel|centos)
            setup_fedora_rhel
            ;;
        *)
            log_error "Unsupported distribution: $OS"
            exit 1
            ;;
    esac
    
    setup_environment
    
    log_info "✓ Setup complete! Run with: sudo python3 loader.py"
}

main "$@"
