# Pure-Rust XDP Packet Filter & Telemetry Engine

[![CI - Pure-Rust XDP Filter](https://github.com/DGP2020/xdp-sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/DGP2020/xdp-sentry/actions/workflows/ci.yml)\
[![Language](https://img.shields.io/badge/Language-Pure%20Rust%20(no__std)-orange.svg)](https://www.rust-lang.org/)
[![eBPF Framework](https://img.shields.io/badge/eBPF%20Framework-Aya-blue.svg)](https://aya-rs.dev/)
[![Hook](https://img.shields.io/badge/Kernel%20Hook-XDP%20(eXpress%20Data%20Path)-green.svg)](https://docs.kernel.org/networking/af_xdp.html)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An ultra-low-latency, zero-copy packet filtering and security telemetry engine written in **100% safe, pure Rust** using **eBPF** and **XDP (eXpress Data Path)**.

```
╔═══════════════════════════════════════════════════════════════════════════╗
║            PURE-RUST XDP PACKET FILTER & TELEMETRY ENGINE                 ║
╠═══════════════════════════════════════════════════════════════════════════╣
║  [Wire / NIC] ──> [XDP Hook (Kernel)] ──> [O(1) eBPF Map] ──> [XDP_DROP]  ║
║                                  │                                        ║
║                            [XDP_PASS] ──> [Linux TCP/IP Stack]            ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

---

## Key Highlights

- **Early Kernel-Level Packet Processing Architecture**: Intercepts raw Ethernet frames directly at the NIC driver DMA layer (`napi_poll`) before the Linux kernel network stack allocates an `sk_buff` structure. *(Note: Unlike user-space bypass like DPDK, XDP executes within the kernel driver path prior to `sk_buff` allocation, preserving kernel security model and cooperative stack integration while eliminating memory allocation overhead.)*
- **Pure Rust in Kernel & User Space**: Written entirely with the [Aya](https://aya-rs.dev/) eBPF framework in `no_std` Rust. No C dependencies, Clang runtime, or BCC toolchain required.
- **Mathematical Bounds Checking for the BPF Verifier**: Custom zero-copy packet parsing abstraction (`ptr_at`) that proves to the Linux eBPF verifier that memory accesses can never exceed the packet buffer.
- **Lock-Free Multi-Core Telemetry**: Utilizes eBPF `PerCpuArray` maps for zero-contention metrics aggregation across all CPU cores and `RingBuffer` for streaming high-throughput, low-latency drop alerts to user space.
- **Dynamic Policy Enforcement**: Real-time CLI allows inserting or removing IP blocks via shared memory eBPF `HashMap` (with Phase 3 `LpmTrie` support for CIDR subnets) without recompiling or reloading the kernel hook.

---

## System Architecture

```mermaid
flowchart TD
    subgraph KernelSpace["Linux Kernel Data Plane (my-filter-ebpf)"]
        NIC["NIC / veth (Raw Frame)"] --> XDP["XDP Driver Hook"]
        XDP --> BoundsCheck["Zero-Copy Bounds Check (ptr_at)"]
        BoundsCheck --> Dissect["Dissect: Eth → IPv4 → TCP/UDP"]
        Dissect --> PolicyCheck{"IP in Blocklist?"}
        
        PolicyCheck -->|Match Found| DropAction["Update Per-CPU Stats<br/>Emit RingBuf Alert<br/>XDP_DROP (Drop in nanoseconds)"]
        PolicyCheck -->|No Match| PassAction["Update Ingress Stats<br/>XDP_PASS (Continue to Kernel Stack)"]
    end

    subgraph SharedMemory["eBPF Maps (Shared Kernel/User Space)"]
        BlockMap[("BLOCKLIST Map<br/>HashMap&lt;u32, BlockRule&gt;")]
        MetricsMap[("METRICS Map<br/>PerCpuArray&lt;TrafficStats&gt;")]
        AlertsMap[("EVENTS Map<br/>RingBuf&lt;PacketAlert&gt;")]
    end

    PolicyCheck -.->|O(1) Lookup| BlockMap
    DropAction -.->|Lock-free Increment| MetricsMap
    DropAction -.->|Push Event| AlertsMap

    subgraph UserSpace["User-Space Control Plane (my-filter CLI)"]
        CLI["my-filter CLI (Clap)"]
        Aya["Aya BPF Loader"]
        TUI["Real-Time Monitor"]
        
        CLI --> Aya
        Aya -->|Load ELF and Attach| XDP
        CLI -->|Add / Remove Rule| BlockMap
        TUI -->|Poll Alerts| AlertsMap
        TUI -->|Read Counters| MetricsMap
    end
```

## Workspace Structure

```text
pure-rust-xdp-filter/
├── Cargo.toml                      # Workspace root configuration
├── my-filter-common/               # Shared no_std types (ABI-stable structs, zero-copy parser)
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs                  # BlockRule, TrafficStats, PacketAlert, LpmKey
│   │   └── parse.rs                # Bounds-checked zero-copy parser
│   └── tests/
│       └── packet_parsing_tests.rs # Unit tests verifying zero-copy parsing & ABI
├── my-filter-ebpf/                 # Kernel-space eBPF program (no_std, bpfel target)
│   ├── Cargo.toml
│   ├── rust-toolchain.toml         # Pins nightly channel for eBPF compiler
│   └── src/
│       └── main.rs                 # XDP hook entry point (#[xdp], verifier-safe)
├── my-filter/                      # User-space CLI application (Control Plane)
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs                 # CLI entry point
│   │   ├── cli.rs                  # Clap command specifications
│   │   ├── simulator.rs            # Cross-platform simulation & verification engine
│   │   └── lib.rs
│   └── tests/
│       ├── cli_tests.rs            # CLI argument and IP parsing tests
│       └── simulation_tests.rs     # Drop simulation and telemetry tests
├── xtask/                          # Automation build runner
│   ├── Cargo.toml
│   └── src/main.rs                 # `cargo xtask build-ebpf`
├── scripts/
│   ├── setup_wsl.sh                # Automated WSL2 / Ubuntu dependency installer
│   ├── test_veth.sh                # Automated network namespace veth testbed
│   └── benchmark_drop.sh           # High-throughput SYN flood drop benchmark
└── .github/workflows/
    └── ci.yml                      # Multi-stage CI testing and eBPF compilation
```

---

## Quickstart

### 1. Cross-Platform Simulation (Runs Anywhere - Windows / macOS / Linux)

You can run the built-in packet simulator directly on your machine without needing root privileges or a Linux kernel:

```bash
# Run 10 synthetic packets blocking IP 198.51.100.50
cargo run --package my-filter -- simulate --count 10 --block-ip 198.51.100.50
```

Sample output:
```text
╔═══════════════════════════════════════════════════════════════╗
║            PURE-RUST XDP ZERO-COPY ENGINE DEMO                ║
╚═══════════════════════════════════════════════════════════════╝
[+] Initialized eBPF HashMap blocklist with: 198.51.100.50
[+] Generating 10 synthetic network frames...

 -------- | ---------------- | ---------------- | ---------- | --------
 Packet#  | Source IP        | Dest IP          | Protocol   | Action  
 -------- | ---------------- | ---------------- | ---------- | --------
 #1       | 192.168.1.2      | 10.0.0.1         | TCP        | XDP_PASS
 #2       | 198.51.100.50    | 10.0.0.1         | TCP        | XDP_DROP
 #3       | 192.168.1.4      | 10.0.0.1         | TCP        | XDP_PASS
 #4       | 198.51.100.50    | 10.0.0.1         | TCP        | XDP_DROP
 ...
```

### 2. Run All Tests
```bash
cargo test --workspace
```

---

## WSL2 & Linux Kernel Live Deployment

### Automated One-Step Setup (WSL2 / Ubuntu)
Inside your WSL2 terminal:
```bash
# 1. Clone and enter directory
cd /path/to/pure-rust-xdp-filter

# 2. Run automated dependency setup (installs clang, llvm, nightly rust, bpf-linker)
chmod +x scripts/*.sh
./scripts/setup_wsl.sh
```

### Automated Kernel Testbed (`veth` Pair)
The provided `scripts/test_veth.sh` automates creating isolated network namespaces, generating traffic, attaching XDP, and verifying that blocked traffic incurs 100% packet loss at the NIC hook:

```bash
sudo ./scripts/test_veth.sh
```

### CLI Command Reference
```bash
# Attach XDP hook to interface eth0
sudo ./target/release/my-filter attach --iface eth0 --mode skb

# Add IP to dynamic kernel blocklist
sudo ./target/release/my-filter block 192.168.1.100

# Remove IP from blocklist
sudo ./target/release/my-filter unblock 192.168.1.100

# View active rules and drop counters
sudo ./target/release/my-filter list

# Display per-CPU telemetry
sudo ./target/release/my-filter stats

# Stream real-time alerts from RingBuffer
sudo ./target/release/my-filter monitor
```

---

## Empirical Performance Benchmarks & SYN-Flood Mitigation

To evaluate filtering efficiency without enterprise NIC hardware, **XDP-Sentry** was benchmarked on a standard workstation against standard Linux Netfilter baselines (`iptables`, `nftables`, and unfiltered baseline traffic) across an isolated virtual Ethernet (`veth`) pair in Generic/SKB mode (`scripts/benchmark_suite.py`).

### 1. Consumer Testbed Benchmarks (WSL2 / Linux Virtual Ethernet)

**Environment**: Local Linux kernel (WSL2), single CPU core allocation, virtual Ethernet (`veth`) testbed, 60,000 synthetic high-frequency flood packets per test run.

```
===================================================================================================
 Mechanism                  | Throughput (pps)    | Bandwidth    | CPU Load   | SoftIRQ%   | Drops 
===================================================================================================
 Baseline (No Filter)       |        168,273 pps  |   86.16 Mbps |     12.2 % |      4.2 % |        0
 iptables (DROP)            |        182,995 pps  |   93.69 Mbps |     13.6 % |      3.2 % |   60,000
 nftables (DROP)            |        138,298 pps  |   70.81 Mbps |     12.0 % |      2.2 % |   60,000
 Pure-Rust XDP (SKB Mode)   |        195,277 pps  |   99.98 Mbps |      9.7 % |      1.8 % |   60,000
===================================================================================================
```

#### Empirical Telemetry Breakdown (from `docs/benchmark_results.json`):

| Metric | Pure-Rust XDP (SKB Mode) | `iptables` (`-j DROP`) | `nftables` (`counter drop`) | Delta vs. `iptables` |
| :--- | :--- | :--- | :--- | :--- |
| **Drop Throughput** | **195,277 pps** (99.98 Mbps) | 182,995 pps (93.69 Mbps) | 138,298 pps (70.81 Mbps) | **+6.7% higher throughput** |
| **Drop Ratio** | **100.0%** (60,000 / 60,000) | 100.0% (60,000 / 60,000) | 100.0% (60,000 / 60,000) | Identical reliability |
| **Total CPU Utilization** | **9.74%** | 13.64% | 11.96% | **28.6% lower total CPU** |
| **Kernel SoftIRQ Load** | **1.79%** | 3.25% | 2.15% | **44.9% lower interrupt load** |
| **Per-Packet Latency** | **5.12 µs** | 5.46 µs | 7.23 µs | **6.2% lower latency** |

#### Why XDP Wins Even on Consumer Virtual Hardware:
1. **Bypasses Netfilter Hook Chains**: Evaluates and drops packets in `do_xdp_generic()` before connection-tracking (`conntrack`), table traversal, or routing table evaluations occur.
2. **Reduced Interrupt Overhead**: Eliminates Netfilter lock contention and connection tracking state tables, reducing kernel SoftIRQ time by **44.9%** (1.79% vs. 3.25%).
3. **Lock-Free Multi-Core Stats**: Aggregates metrics into eBPF `PerCpuArray` maps without lock contention across CPU cores.

---

### 2. Architectural Comparison: Generic Mode vs. Native Driver Mode

For production environments with enterprise SmartNICs or physical drivers (e.g. Intel `ixgbe`, Mellanox `mlx5`):
- **Generic/SKB Mode (`--mode skb`)**: Operates after `alloc_skb()`, compatible with all virtual devices (`veth`), containers, and cloud VMs without specialized hardware (achieving **~195K pps** on a single consumer core).
- **Native Driver Mode (`--mode drv`)**: Attaches into the NIC driver's NAPI poll loop before `sk_buff` allocation, recycling raw DMA pages in ~15 ns and scaling to wire rate on physical 10G/25G/40G NICs without software overhead.

---

### 3. Reproducing the Benchmarks

To execute the automated benchmark suite inside Linux or WSL2:

```bash
# 1. Run the comprehensive multi-system benchmark suite (Baseline vs iptables vs nftables vs XDP)
sudo python3 ./scripts/benchmark_suite.py

# 2. Or run the standalone hping3 SYN-flood drop benchmark
sudo ./scripts/benchmark_drop.sh
```
