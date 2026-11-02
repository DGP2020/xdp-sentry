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
        BoundsCheck --> Dissect["Dissect: Eth -> IPv4 -> TCP/UDP"]
        Dissect --> PolicyCheck{"IP in Blocklist?"}
        
        PolicyCheck -->|Match Found| DropAction["Update Per-CPU Stats\nEmit RingBuf Alert\nXDP_DROP (Drop in nanoseconds)"]
        PolicyCheck -->|No Match| PassAction["Update Ingress Stats\nXDP_PASS (Continue to Kernel Stack)"]
    end

    subgraph SharedMemory["eBPF Maps (Shared Kernel/User Space)"]
        BlockMap[("BLOCKLIST Map\nHashMap<u32, BlockRule>")]
        MetricsMap[("METRICS Map\nPerCpuArray<TrafficStats>")]
        AlertsMap[("EVENTS Map\nRingBuf<PacketAlert>")]
    end

    PolicyCheck -.->|O(1) Lookup| BlockMap
    DropAction -.->|Lock-free Increment| MetricsMap
    DropAction -.->|Push Event| AlertsMap

    subgraph UserSpace["User-Space Control Plane (my-filter CLI)"]
        CLI["my-filter CLI (Clap)"]
        Aya["Aya BPF Loader"]
        TUI["Real-Time Monitor"]
        
        CLI --> Aya
        Aya -->|Load ELF & Attach| XDP
        CLI -->|Add / Remove Rule| BlockMap
        TUI -->|Poll Alerts| AlertsMap
        TUI -->|Read Counters| MetricsMap
    end
```

---

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
