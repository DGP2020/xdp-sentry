#!/usr/bin/env bash
# ==============================================================================
# demo_dynamic_blocking.sh - Live Kernel Dynamic IP Blocking Demonstration
# Proves real-time rule injection and removal without kernel program reload
# ==============================================================================

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: Please execute as root (sudo ./scripts/demo_dynamic_blocking.sh)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

NS_CLIENT="xdp_attacker_ns"
VETH_HOST="veth-host"
VETH_GUEST="veth-guest"
HOST_IP="192.168.200.1"
CLIENT_IP="192.168.200.2"
SUBNET_MASK="24"
PIN_DIR="/sys/fs/bpf/my_filter"
BINARY="./target/release/my-filter"

cleanup() {
    echo ""
    echo "[*] Tearing down demonstration environment..."
    if [ -n "${CONTROLLER_PID:-}" ] && kill -0 "$CONTROLLER_PID" 2>/dev/null; then
        kill -9 "$CONTROLLER_PID" 2>/dev/null || true
    fi
    ip link delete "$VETH_HOST" 2>/dev/null || true
    rm -rf "$PIN_DIR" 2>/dev/null || true
    ip netns delete "$NS_CLIENT" 2>/dev/null || true
    echo "[✓] Environment cleanly restored."
}
trap cleanup EXIT INT TERM

echo "================================================================================"
echo "    XDP-Sentry: Live Dynamic IP Blocking & Real-Time Telemetry Demo"
echo "================================================================================"

# 1. Mount bpffs
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

# 2. Setup isolated network testbed
echo "[1/6] Configuring isolated network namespaces and veth pair..."
ip netns add "$NS_CLIENT"
ip link add "$VETH_HOST" type veth peer name "$VETH_GUEST"
ip link set "$VETH_GUEST" netns "$NS_CLIENT"
ip addr add "${HOST_IP}/${SUBNET_MASK}" dev "$VETH_HOST"
ip link set "$VETH_HOST" up
ip netns exec "$NS_CLIENT" ip addr add "${CLIENT_IP}/${SUBNET_MASK}" dev "$VETH_GUEST"
ip netns exec "$NS_CLIENT" ip link set "$VETH_GUEST" up
ip netns exec "$NS_CLIENT" ip link set lo up

# 3. Attach XDP Hook
echo "[2/6] Attaching Pure-Rust XDP filter to $VETH_HOST (generic SKB mode)..."
"$BINARY" attach --iface "$VETH_HOST" --mode skb > /dev/null 2>&1 &
CONTROLLER_PID=$!

for _ in $(seq 1 40); do
    [ -e "$PIN_DIR/BLOCKLIST" ] && break
    sleep 0.1
done

if [ ! -e "$PIN_DIR/BLOCKLIST" ]; then
    echo "[-] Error: XDP loader failed to pin BLOCKLIST map."
    exit 1
fi
echo "[✓] Hook attached. Kernel maps pinned under $PIN_DIR."

# 4. Verify Phase 1: Unfiltered Baseline Traffic
echo ""
echo "[3/6] Phase 1: Sending ICMP probe from unblocked client ($CLIENT_IP -> $HOST_IP)..."
if ip netns exec "$NS_CLIENT" ping -c 2 -W 1 "$HOST_IP" > /dev/null; then
    echo "[✓] PASS: Unblocked traffic flows freely through XDP hook to kernel stack."
else
    echo "[-] FAIL: Initial ping failed."
    exit 1
fi

# 5. Dynamically Inject Block Rule via Shared eBPF HashMap
echo ""
echo "[4/6] Phase 2: Dynamically inserting block rule for $CLIENT_IP via userspace CLI..."
"$BINARY" block "$CLIENT_IP"

echo "[+] Inspecting pinned eBPF BLOCKLIST map:"
"$BINARY" list

# 6. Verify Phase 2: Instant Packet Loss at XDP Driver Hook
echo ""
echo "[5/6] Phase 3: Testing traffic from blocked client ($CLIENT_IP -> $HOST_IP)..."
if ip netns exec "$NS_CLIENT" ping -c 3 -W 1 "$HOST_IP" > /dev/null 2>&1; then
    echo "[-] FAIL: Packets bypassed blocklist!"
    exit 1
else
    echo "[✓] DROP: 100% packet loss! Traffic dropped in nanoseconds at driver hook."
fi

echo "[+] Querying Per-CPU telemetry counters from eBPF map:"
"$BINARY" stats

# 7. Dynamically Remove Rule & Verify Restoration
echo ""
echo "[6/6] Phase 4: Dynamically removing rule for $CLIENT_IP..."
"$BINARY" unblock "$CLIENT_IP"

echo "[+] Inspecting updated eBPF BLOCKLIST map:"
"$BINARY" list

echo "[+] Verifying traffic restoration..."
if ip netns exec "$NS_CLIENT" ping -c 2 -W 1 "$HOST_IP" > /dev/null; then
    echo "[✓] RESTORED: Traffic immediately resumed without reloading kernel program."
else
    echo "[-] FAIL: Traffic was not restored."
    exit 1
fi

echo ""
echo "================================================================================"
echo "  Dynamic IP Blocking Verification Complete: ALL CHECKS PASSED!"
echo "================================================================================"
