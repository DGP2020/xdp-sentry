#!/usr/bin/env python3
"""
benchmark_suite.py - Empirical Performance Benchmark Suite
Compares XDP (Generic/SKB mode), iptables, nftables, and baseline (unfiltered)
Measures:
  1. Packet Throughput (pps, Mbps)
  2. CPU Utilisation (Total, System, SoftIRQ, User)
  3. Packet Drop Counts and Ratios
  4. Per-packet latency / overhead
"""

import os
import sys
import time
import subprocess
import json
import socket
from pathlib import Path

NS_NAME = "xdp_attacker_ns"
VETH_HOST = "veth-host"
VETH_GUEST = "veth-guest"
HOST_IP = "192.168.200.1"
ATTACKER_IP = "192.168.200.2"
SUBNET_MASK = "24"
PIN_DIR = "/sys/fs/bpf/my_filter"
BINARY_PATH = "./target/release/my-filter"

def run_cmd(cmd, check=True, capture=True):
    res = subprocess.run(cmd, shell=True, text=True, capture_output=capture)
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed [{res.returncode}]: {cmd}\nOutput: {res.stdout}\nError: {res.stderr}")
    return res

def read_cpu_stat():
    """Reads /proc/stat and returns dictionary of aggregate CPU metrics in jiffies."""
    with open("/proc/stat", "r") as f:
        line = f.readline() # first line is 'cpu' aggregate
    parts = line.strip().split()
    # parts: ['cpu', user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice]
    values = [int(p) for p in parts[1:]]
    user = values[0]
    nice = values[1]
    system = values[2]
    idle = values[3]
    iowait = values[4] if len(values) > 4 else 0
    irq = values[5] if len(values) > 5 else 0
    softirq = values[6] if len(values) > 6 else 0
    steal = values[7] if len(values) > 7 else 0
    total = sum(values)
    return {
        "user": user,
        "system": system,
        "idle": idle,
        "softirq": softirq,
        "irq": irq,
        "total": total
    }

def calculate_cpu_usage(before, after):
    """Calculates CPU percentages between two /proc/stat snapshots."""
    total_delta = max(after["total"] - before["total"], 1)
    user_delta = after["user"] - before["user"]
    system_delta = after["system"] - before["system"]
    softirq_delta = after["softirq"] - before["softirq"]
    idle_delta = after["idle"] - before["idle"]

    cpu_total = 100.0 * (total_delta - idle_delta) / total_delta
    cpu_system = 100.0 * system_delta / total_delta
    cpu_softirq = 100.0 * softirq_delta / total_delta
    cpu_user = 100.0 * user_delta / total_delta
    return {
        "total_percent": max(0.0, cpu_total),
        "system_percent": max(0.0, cpu_system),
        "softirq_percent": max(0.0, cpu_softirq),
        "user_percent": max(0.0, cpu_user),
    }

def cleanup():
    run_cmd(f"ip link del {VETH_HOST} 2>/dev/null || true", check=False)
    run_cmd(f"ip netns del {NS_NAME} 2>/dev/null || true", check=False)
    run_cmd("iptables -D INPUT -s 192.168.200.2 -j DROP 2>/dev/null || true", check=False)
    run_cmd("nft delete table inet benchmark_tbl 2>/dev/null || true", check=False)
    run_cmd("killall -9 my-filter 2>/dev/null || true", check=False)
    run_cmd(f"rm -rf {PIN_DIR} 2>/dev/null || true", check=False)

def setup_testbed():
    cleanup()
    run_cmd("mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf", check=False)
    run_cmd(f"ip netns add {NS_NAME}")
    run_cmd(f"ip link add {VETH_HOST} type veth peer name {VETH_GUEST}")
    run_cmd(f"ip link set {VETH_GUEST} netns {NS_NAME}")
    run_cmd(f"ip addr add {HOST_IP}/{SUBNET_MASK} dev {VETH_HOST}")
    run_cmd(f"ip link set {VETH_HOST} up")
    run_cmd(f"ip netns exec {NS_NAME} ip addr add {ATTACKER_IP}/{SUBNET_MASK} dev {VETH_GUEST}")
    run_cmd(f"ip netns exec {NS_NAME} ip link set {VETH_GUEST} up")
    run_cmd(f"ip netns exec {NS_NAME} ip link set lo up")
    # Verify ping
    res = run_cmd(f"ip netns exec {NS_NAME} ping -c 1 -W 1 {HOST_IP}")
    if res.returncode != 0:
        raise RuntimeError("Testbed setup failed: ping failed")

def generate_traffic(packet_count=50000, payload_size=64):
    """Generates UDP packet stream from inside the namespace using high-speed socket."""
    cmd = (
        f"ip netns exec {NS_NAME} python3 -c \""
        f"import socket, time\n"
        f"s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        f"payload = b'X' * {payload_size}\n"
        f"target = ('{HOST_IP}', 9999)\n"
        f"t0 = time.perf_counter()\n"
        f"for _ in range({packet_count}):\n"
        f"    s.sendto(payload, target)\n"
        f"t1 = time.perf_counter()\n"
        f"print(t1 - t0)\n"
        f"\""
    )
    res = run_cmd(cmd)
    elapsed = float(res.stdout.strip())
    return elapsed

def benchmark_baseline(packet_count=50000):
    print("[*] Benchmarking Baseline (Unfiltered)...")
    cpu_before = read_cpu_stat()
    elapsed = generate_traffic(packet_count)
    cpu_after = read_cpu_stat()
    cpu_metrics = calculate_cpu_usage(cpu_before, cpu_after)
    pps = packet_count / elapsed
    mbps = (packet_count * 64 * 8) / (elapsed * 1_000_000)
    return {
        "name": "Baseline (No Filter)",
        "packets_sent": packet_count,
        "packets_dropped": 0,
        "drop_rate_pct": 0.0,
        "elapsed_sec": elapsed,
        "throughput_pps": pps,
        "throughput_mbps": mbps,
        "cpu": cpu_metrics,
        "latency_us": (elapsed / packet_count) * 1_000_000
    }

def benchmark_iptables(packet_count=50000):
    print("[*] Benchmarking iptables (Netfilter INPUT hook)...")
    run_cmd(f"iptables -A INPUT -s {ATTACKER_IP} -j DROP")
    cpu_before = read_cpu_stat()
    elapsed = generate_traffic(packet_count)
    cpu_after = read_cpu_stat()
    cpu_metrics = calculate_cpu_usage(cpu_before, cpu_after)

    # Get drop count from iptables
    res = run_cmd("iptables -L INPUT -v -x -n")
    dropped = 0
    for line in res.stdout.splitlines():
        if ATTACKER_IP in line and "DROP" in line:
            parts = line.split()
            dropped = int(parts[0])
            break

    run_cmd(f"iptables -D INPUT -s {ATTACKER_IP} -j DROP")
    pps = packet_count / elapsed
    mbps = (packet_count * 64 * 8) / (elapsed * 1_000_000)
    return {
        "name": "iptables (DROP)",
        "packets_sent": packet_count,
        "packets_dropped": dropped,
        "drop_rate_pct": (dropped / packet_count) * 100.0 if packet_count else 0,
        "elapsed_sec": elapsed,
        "throughput_pps": pps,
        "throughput_mbps": mbps,
        "cpu": cpu_metrics,
        "latency_us": (elapsed / packet_count) * 1_000_000
    }

def benchmark_nftables(packet_count=50000):
    print("[*] Benchmarking nftables...")
    run_cmd("nft add table inet benchmark_tbl")
    run_cmd("nft 'add chain inet benchmark_tbl input { type filter hook input priority 0; policy accept; }'")
    run_cmd(f"nft add rule inet benchmark_tbl input ip saddr {ATTACKER_IP} counter drop")

    cpu_before = read_cpu_stat()
    elapsed = generate_traffic(packet_count)
    cpu_after = read_cpu_stat()
    cpu_metrics = calculate_cpu_usage(cpu_before, cpu_after)

    # Read nft drop count
    res = run_cmd("nft list table inet benchmark_tbl")
    dropped = 0
    for line in res.stdout.splitlines():
        if "counter packets" in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "packets":
                    dropped = int(parts[i+1])
                    break

    run_cmd("nft delete table inet benchmark_tbl")
    pps = packet_count / elapsed
    mbps = (packet_count * 64 * 8) / (elapsed * 1_000_000)
    return {
        "name": "nftables (DROP)",
        "packets_sent": packet_count,
        "packets_dropped": dropped,
        "drop_rate_pct": (dropped / packet_count) * 100.0 if packet_count else 0,
        "elapsed_sec": elapsed,
        "throughput_pps": pps,
        "throughput_mbps": mbps,
        "cpu": cpu_metrics,
        "latency_us": (elapsed / packet_count) * 1_000_000
    }

def benchmark_xdp(packet_count=50000):
    print("[*] Benchmarking Pure-Rust XDP (Generic/SKB mode)...")
    # Attach XDP program
    loader_proc = subprocess.Popen([BINARY_PATH, "attach", "--iface", VETH_HOST, "--mode", "skb"])
    # Wait for map pin
    blocklist_pin = Path(PIN_DIR) / "BLOCKLIST"
    for _ in range(50):
        if blocklist_pin.exists():
            break
        time.sleep(0.1)

    if not blocklist_pin.exists():
        loader_proc.kill()
        raise RuntimeError("XDP BLOCKLIST map was not pinned in time")

    # Block attacker IP
    run_cmd(f"{BINARY_PATH} block {ATTACKER_IP}")

    cpu_before = read_cpu_stat()
    elapsed = generate_traffic(packet_count)
    cpu_after = read_cpu_stat()
    cpu_metrics = calculate_cpu_usage(cpu_before, cpu_after)

    # Read stats from my-filter stats
    res = run_cmd(f"{BINARY_PATH} stats")
    dropped = 0
    for line in res.stdout.splitlines():
        if "Filtered (Dropped) Packets" in line:
            parts = [p.strip() for p in line.split("║") if p.strip()]
            if len(parts) >= 2:
                dropped = int(parts[1])
                break

    loader_proc.kill()
    run_cmd(f"rm -rf {PIN_DIR} 2>/dev/null || true", check=False)
    pps = packet_count / elapsed
    mbps = (packet_count * 64 * 8) / (elapsed * 1_000_000)
    return {
        "name": "Pure-Rust XDP (SKB Mode)",
        "packets_sent": packet_count,
        "packets_dropped": dropped,
        "drop_rate_pct": (dropped / packet_count) * 100.0 if packet_count else 0,
        "elapsed_sec": elapsed,
        "throughput_pps": pps,
        "throughput_mbps": mbps,
        "cpu": cpu_metrics,
        "latency_us": (elapsed / packet_count) * 1_000_000
    }

def main():
    if os.geteuid() != 0:
        print("[-] Error: benchmark_suite.py must be run as root (sudo)")
        sys.exit(1)

    print("================================================================================")
    print(" XDP-Sentry: High-Throughput Kernel Filtering Benchmark & Empirical Profiler")
    print("================================================================================")
    setup_testbed()

    packet_count = 60000
    results = []

    try:
        res_baseline = benchmark_baseline(packet_count)
        results.append(res_baseline)

        res_iptables = benchmark_iptables(packet_count)
        results.append(res_iptables)

        res_nftables = benchmark_nftables(packet_count)
        results.append(res_nftables)

        res_xdp = benchmark_xdp(packet_count)
        results.append(res_xdp)

    finally:
        cleanup()

    print("\n" + "="*95)
    print(f" {'Mechanism':<26} | {'Throughput (pps)':<18} | {'Bandwidth':<12} | {'CPU Load':<10} | {'SoftIRQ%':<10} | {'Drops':<8}")
    print("="*95)
    for r in results:
        print(f" {r['name']:<26} | {r['throughput_pps']:>14,.0f} pps | {r['throughput_mbps']:>8.2f} Mbps | {r['cpu']['total_percent']:>8.1f} % | {r['cpu']['softirq_percent']:>8.1f} % | {r['packets_dropped']:>8,}")
    print("="*95)

    # Save results to JSON
    out_file = Path("docs") / "benchmark_results.json"
    out_file.parent.mkdir(exist_ok=True)
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[✓] Detailed benchmark telemetry saved to {out_file}")

if __name__ == "__main__":
    main()
