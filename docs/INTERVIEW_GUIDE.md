# Interview Preparation & Systems Architecture Guide

This document prepares you to discuss the **Pure-Rust XDP Packet Filter and Telemetry Engine** in engineering interviews for **Cloud Infrastructure**, **Kernel / Systems**, **Cybersecurity / SOC Automation**, and **Hardware-Acceleration / SmartNIC** roles.

---

## 1. The 30-Second Elevator Pitch

> *"I engineered an ultra-low-latency, zero-copy packet filtering and telemetry engine written in 100% pure Rust using eBPF and XDP (eXpress Data Path). Rather than relying on traditional C toolchains, I used the modern **Aya** framework to write both the `no_std` kernel-space data plane and the asynchronous user-space control plane in Rust.*
> 
> *By attaching directly to the network driver hook, the engine intercepts raw Ethernet frames off the wire, performs formal bounds-checked zero-copy packet dissection, evaluates traffic against shared eBPF HashMaps in nanoseconds, and drops malicious traffic before the Linux TCP/IP network stack allocates an `sk_buff`. Real-time telemetry is streamed to user space via lock-free per-CPU arrays and BPF RingBuffers."*

---

## 2. Core Concepts & Technical Deep Dive

### Q1: Why XDP instead of standard Linux firewalls (`iptables`, `nftables`)?
- **The Problem with `iptables` / `nftables`**:
  Standard Linux firewalls operate inside `netfilter`, which runs deep inside the Linux networking subsystem. Before a packet reaches `iptables`, the kernel must:
  1. Allocate a complex `sk_buff` (socket buffer) heap structure.
  2. Parse the network headers into kernel structs.
  3. Traverse multiple tables, chains, and connection tracking tables (`conntrack`).
  Under a multi-gigabit DDoS attack (e.g. 10M+ packets per second), the CPU spends 90%+ of its time merely allocating and freeing `sk_buff` structures before dropping packets, leading to kernel CPU starvation.
- **The XDP Solution**:
  XDP attaches to the lowest possible software hook in the network subsystem—right inside the NIC driver receive path (`napi_poll`). It intercepts raw DMA buffers (`xdp_buff`) before any `sk_buff` is allocated. Returning `XDP_DROP` recycles the packet buffer immediately at the driver queue level with zero memory allocation, dropping malicious frames in nanoseconds before they reach `netfilter` or socket allocation.

---

### Q2: Why XDP over DPDK (Data Plane Development Kit)?
- **DPDK (Bypass Kernel Completely)**:
  - Requires dedicated CPU cores pinned at 100% polling in user space.
  - Takes exclusive ownership of the NIC; standard Linux networking tools (`ssh`, `curl`, `ip`, `systemd`) stop functioning on that interface without complex virtual interfaces (KNI/TAP).
- **XDP (In-Kernel Early Driver Processing)**:
  - *Technical Clarification*: Calling XDP "kernel-bypass" is inaccurate. Unlike DPDK (which unbinds the NIC from the kernel to run user-space drivers), XDP executes inside the Linux kernel in the driver's RX path (`napi_poll`) prior to `sk_buff` allocation.
  - Cooperates with the kernel: non-dropped traffic returns `XDP_PASS` and seamlessly continues up the standard Linux network stack without copying.
  - No CPU busy-polling when idle; uses standard Linux interrupt/NAPI handling.
  - Can be offloaded directly into hardware SmartNICs (e.g., Netronome, Nvidia BlueField, AMD/Pensando) via `XDP_FLAGS_HW_MODE`.

---

### Q3: Why pure Rust (Aya) instead of C (libbpf / BCC)?
1. **Memory Safety & Correctness**:
   Traditional eBPF written in C is prone to out-of-bounds pointer reads and undefined behavior if bounds checking is subtly miscalculated. Rust's strict type system and compile-time guarantees catch bugs early.
2. **Unified Language Across Planes**:
   Both the kernel data plane (`my-filter-ebpf`) and the user-space CLI (`my-filter`) share the exact same `no_std` crate (`my-filter-common`). This guarantees identical struct layout (`repr(C)`), field alignment, and constant definitions without manual C header syncing.
3. **No Clang/LLVM C Dependency in Production**:
   Unlike BCC (which compiles C code at runtime on the host), Aya reads precompiled ELF binaries using Rust's native object parsers.

---

### Q4: How did you satisfy the Linux Kernel eBPF Verifier?
The Linux kernel BPF verifier is notoriously strict. It performs static analysis of every possible execution path to prevent kernel crashes, page faults, and infinite loops.

If you attempt to read raw packet data:
```rust
let ip_header = *(data as *const Ipv4Hdr); // REJECTED BY VERIFIER!
```
The verifier will immediately reject the program with `invalid access to packet, id=0, off=14, size=20, R1(id=0,off=0,r=0)`.

**Our Solution**:
We designed an inline bounds-checking abstraction `ptr_at<T>`:
```rust
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    // The verifier checks that this branch is taken before any dereference:
    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}
```
By comparing `start + offset + len > end`, we provide a mathematical proof that the pointer arithmetic cannot exceed the DMA buffer boundary.

---

### Q5: Explain the eBPF Map choices and memory architecture.
| Map Name | Map Type | Use Case & Design Decision |
| :--- | :--- | :--- |
| `BLOCKLIST` | `BPF_MAP_TYPE_HASH` | Dynamic O(1) IP address lookup. User space can insert/delete IPs without restarting the kernel program. *(Phase 3 extends this to `BPF_MAP_TYPE_LPM_TRIE` for CIDR subnet blocks).* |
| `METRICS` | `BPF_MAP_TYPE_PERCPU_ARRAY` | High-throughput telemetry. Standard maps suffer from multi-core atomic cache-line bouncing (false sharing). Per-CPU maps allocate dedicated memory per CPU core, enabling zero-contention atomic increments. |
| `EVENTS` | `BPF_MAP_TYPE_RINGBUF` | Lockless, multi-producer single-consumer circular buffer for streaming drop alerts to user space with minimal memory overhead and zero per-event syscall overhead, replacing legacy `PerfEventArray`. |

---

### Q6: How do you transition from single IP blocking to CIDR subnet blocking (Phase 3)?
In eBPF, CIDR subnet matching uses `BPF_MAP_TYPE_LPM_TRIE` (Longest Prefix Match Trie).
The key structure is:
```rust
#[repr(C)]
pub struct LpmKey {
    pub prefix_len: u32,  // e.g. 24 for a /24 subnet, 32 for single IP
    pub ip_bytes: [u8; 4], // 192.168.1.0 in network byte order
}
```
When a packet arrives from `192.168.1.150`, the kernel traverses the trie in `O(k)` time (where `k = 32` for IPv4) to find the longest matching prefix rule, allowing a single rule to block entire compromised ASNs or subnets.
