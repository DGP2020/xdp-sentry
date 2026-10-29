#!/usr/bin/env bash
# ==============================================================================
# setup_wsl.sh - Automated Environment Setup for WSL2 / Linux
# Configures dependencies for compiling and executing Pure-Rust XDP eBPF programs
# ==============================================================================

set -euo pipefail

echo "=================================================================="
echo "  Pure-Rust XDP Filter: Automated WSL2 / Ubuntu Setup"
echo "=================================================================="

# 1. Update APT and install essential eBPF build tools
echo "[1/4] Installing system dependencies (clang, llvm, libelf, bpftool)..."
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    linux-tools-generic \
    linux-headers-generic \
    iproute2 \
    iputils-ping \
    hping3 \
    pkg-config

# 2. Ensure rustup and cargo are available
if ! command -v rustup &> /dev/null; then
    echo "[!] rustup not found. Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# 3. Configure Nightly toolchain and bpfel target
echo "[2/4] Setting up Rust nightly channel and rust-src..."
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

# 4. Install bpf-linker (required to link eBPF bytecode into ELF)
echo "[3/4] Checking and installing bpf-linker..."
if ! command -v bpf-linker &> /dev/null; then
    echo "[+] Installing bpf-linker via precompiled binary (cargo-binstall)..."
    if ! command -v cargo-binstall &> /dev/null; then
        echo "[+] Installing cargo-binstall..."
        curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash
    fi
    source "$HOME/.cargo/env"
    cargo binstall -y bpf-linker
else
    echo "[✓] bpf-linker already installed: $(bpf-linker --version)"
fi

# 5. Check kernel eBPF / XDP support
echo "[4/4] Checking Linux kernel eBPF features..."
uname -r
if [ -d /sys/fs/bpf ]; then
    echo "[✓] BPF filesystem mounted at /sys/fs/bpf"
else
    echo "[+] Mounting BPF filesystem..."
    sudo mount -t bpf bpf /sys/fs/bpf
fi

echo "=================================================================="
echo "  Setup Complete! You are ready to build and run the XDP engine."
echo "  To run testbed: sudo ./scripts/test_veth.sh"
echo "=================================================================="
