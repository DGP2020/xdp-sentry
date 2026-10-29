#!/usr/bin/env bash
# ==============================================================================
# test_veth.sh - Automated Kernel XDP End-to-End Verification Testbed
# Uses Linux network namespaces and virtual ethernet (veth) pairs
# ==============================================================================

set -euo pipefail

# Ensure script is executed with root privileges
if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: Please execute as root (sudo ./scripts/test_veth.sh)"
    exit 1
fi

NS_ATTACKER="xdp_attacker_ns"
VETH_HOST="veth-host"
VETH_GUEST="veth-guest"

HOST_IP="192.168.200.1"
ATTACKER_IP="192.168.200.2"
SUBNET_MASK="24"

cleanup() {
    echo ""
    echo "[*] Cleaning up network namespaces and interfaces..."
    if [ -n "${CONTROLLER_PID:-}" ] && kill -0 "$CONTROLLER_PID" 2>/dev/null; then
        kill "$CONTROLLER_PID" 2>/dev/null || true
    fi
    ip link delete "$VETH_HOST" 2>/dev/null || true
    rm -rf /sys/fs/bpf/my_filter 2>/dev/null || true
    ip netns delete "$NS_ATTACKER" 2>/dev/null || true
    echo "[✓] Cleanup complete."
}
trap cleanup EXIT INT TERM

# Ensure the BPF filesystem is mounted for map pinning
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

# Ensure cargo is in PATH if running under sudo
if ! command -v cargo &> /dev/null; then
    if [ -n "${SUDO_USER:-}" ] && [ -d "/home/$SUDO_USER/.cargo/bin" ]; then
        export PATH="/home/$SUDO_USER/.cargo/bin:$PATH"
    elif [ -d "$HOME/.cargo/bin" ]; then
        export PATH="$HOME/.cargo/bin:$PATH"
    fi
fi

echo "=================================================================="
echo "  Pure-Rust XDP Automated Kernel Testbed"
echo "=================================================================="

# 1. Create Isolated Network Namespace
echo "[1/5] Creating isolated network namespace: $NS_ATTACKER..."
ip netns add "$NS_ATTACKER"

# 2. Create Virtual Ethernet (veth) Pair
echo "[2/5] Creating veth link: $VETH_HOST <---> $VETH_GUEST..."
ip link add "$VETH_HOST" type veth peer name "$VETH_GUEST"
ip link set "$VETH_GUEST" netns "$NS_ATTACKER"

# Configure Host IP and Interface
ip addr add "${HOST_IP}/${SUBNET_MASK}" dev "$VETH_HOST"
ip link set "$VETH_HOST" up

# Configure Attacker IP and Interface inside namespace
ip netns exec "$NS_ATTACKER" ip addr add "${ATTACKER_IP}/${SUBNET_MASK}" dev "$VETH_GUEST"
ip netns exec "$NS_ATTACKER" ip link set "$VETH_GUEST" up
ip netns exec "$NS_ATTACKER" ip link set lo up

# 3. Test Baseline Baseline Connectivity (Before XDP Attach)
echo "[3/5] Testing baseline network connectivity (unfiltered)..."
if ip netns exec "$NS_ATTACKER" ping -c 2 -W 1 "$HOST_IP" > /dev/null; then
    echo "[✓] Baseline ping successful: $ATTACKER_IP -> $HOST_IP"
else
    echo "[-] Baseline ping failed. Verify interface configuration."
    exit 1
fi

# 4. Build and Attach XDP Filter
echo "[4/5] Building eBPF target binary and userspace controller..."
if command -v cargo &> /dev/null; then
    if [ -n "${SUDO_USER:-}" ]; then
        sudo -u "$SUDO_USER" env PATH="$PATH" cargo run --package xtask -- build-ebpf --release
        sudo -u "$SUDO_USER" env PATH="$PATH" cargo build --release --package my-filter
    else
        cargo run --package xtask -- build-ebpf --release
        cargo build --release --package my-filter
    fi
elif [ ! -f "./target/release/my-filter" ]; then
    echo "[-] Error: 'cargo' not found in PATH and ./target/release/my-filter does not exist."
    echo "[-] Please build the project as your regular user first: cargo xtask build-ebpf --release && cargo build --release"
    exit 1
fi

if [ ! -f "./target/release/my-filter" ]; then
    echo "[-] Error: ./target/release/my-filter not found. Build may have failed."
    exit 1
fi

echo "[+] Attaching XDP program to $VETH_HOST (generic SKB mode)..."
./target/release/my-filter attach --iface "$VETH_HOST" --mode skb &
CONTROLLER_PID=$!
for _ in $(seq 1 30); do
    [ -e /sys/fs/bpf/my_filter/BLOCKLIST ] && break
    sleep 0.1
done
if [ ! -e /sys/fs/bpf/my_filter/BLOCKLIST ]; then
    echo "[-] Error: XDP loader did not pin BLOCKLIST map in time."
    exit 1
fi

# 5. Block the Attacker IP and Verify Dropping
echo "[5/5] Dynamically blocking attacker IP: $ATTACKER_IP..."
./target/release/my-filter block "$ATTACKER_IP"

echo "[+] Sending attack packets from $ATTACKER_IP to $HOST_IP..."
if ip netns exec "$NS_ATTACKER" ping -c 3 -W 1 "$HOST_IP" > /dev/null 2>&1; then
    echo "[-] FAIL: Packets were NOT dropped! Check eBPF map."
    exit 1
else
    echo "[✓] SUCCESS: 100% packet loss! Packets dropped at XDP hook."
fi

echo ""
echo "=================================================================="
echo "  All Kernel XDP Tests Passed Successfully!"
echo "=================================================================="
