#!/usr/bin/env bash
# ==============================================================================
# benchmark_drop.sh - High-Throughput Packet Drop Benchmark
# Floods the XDP interface to measure drop latency and CPU impact
# ==============================================================================

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: Please execute as root (sudo ./scripts/benchmark_drop.sh)"
    exit 1
fi

NS_ATTACKER="xdp_attacker_ns"
HOST_IP="192.168.200.1"

echo "=================================================================="
echo "  XDP Ultra-Low Latency Drop Benchmark"
echo "=================================================================="

if ! ip netns list | grep -q "$NS_ATTACKER"; then
    echo "[-] Testbed namespace not found. Please run ./scripts/test_veth.sh first."
    exit 1
fi

echo "[+] Initiating TCP SYN flood test (10,000 packets) at $HOST_IP:80..."
ip netns exec "$NS_ATTACKER" hping3 --fast -c 10000 -S -p 80 "$HOST_IP" || true

echo ""
if [ ! -e /sys/fs/bpf/my_filter/METRICS ]; then
    echo "[-] Pinned METRICS map not found. Run the XDP loader (my-filter attach) first."
    exit 1
fi

echo "[+] Retrieving live telemetry metrics from pinned eBPF maps..."
./target/release/my-filter stats
