# ADR-0002: In-Kernel Pre-sk_buff XDP Hook Architecture

**Date**: 2026-11-11
**Status**: accepted
**Deciders**: Danie (Security Infrastructure Architect)

## Context

Volumetric denial-of-service attacks and malicious packet floods degrade host performance primarily through memory allocation overhead. In standard Linux networking, each incoming frame requires allocating a socket buffer structure (`sk_buff`) and initializing connection tracking state before reaching user space or Netfilter rules. When filtering at higher network layers, CPU resources are consumed allocating and immediately freeing memory buffers for discarded traffic.

## Decision

We implement packet filtering at the XDP (eXpress Data Path) hook directly within the Linux kernel driver path (`napi_poll`) before `sk_buff` allocation. Packets identified by policy as blocked return `XDP_DROP` in nanoseconds, discarding frames at the network driver descriptor layer while allowing clean traffic (`XDP_PASS`) to continue seamlessly into the standard Linux TCP/IP stack.

## Alternatives Considered

### Alternative 1: Netfilter (iptables / nftables)
- **Pros**: Established standard in Linux system administration; wide tooling ecosystem; rich stateful connection matching.
- **Cons**: Executes inside the network layer (`ip_rcv` / `nf_hook`) after `sk_buff` memory allocation; causes conntrack table contention under SYN floods.
- **Why not**: Empirical benchmarks show nftables/iptables throughput capping at 138k–182k pps with 12–14% CPU utilization, compared to XDP achieving 195k+ pps in generic mode and up to 14.88 Mpps line rate in native driver mode.

### Alternative 2: DPDK (Data Plane Development Kit) Userspace Kernel Bypass
- **Pros**: Delivers maximum raw packet throughput by taking direct ownership of the physical NIC.
- **Cons**: Completely unbinds the NIC from the Linux kernel; requires dedicated CPU cores running 100% busy-polling in user space; breaks standard Linux networking utilities (`ip`, `ss`, `tcpdump`, container bridges).
- **Why not**: XDP provides early packet dropping while preserving Linux kernel device ownership, safety verifier guarantees, and cooperative integration with host applications and socket APIs.

## Consequences

### Positive
- Nanosecond packet drop latency with zero memory allocations on blocked frames in native driver mode.
- Preserves the Linux kernel security model and device governance without dedicating CPU cores to 100% busy polling.
- Clean traffic continues unmodified into standard Linux socket APIs without userspace intervention.

### Negative
- Logic is constrained by Linux kernel eBPF verifier safety rules (bounded loops, strict pointer verification, stack limits).
- Requires elevated root permissions (`CAP_NET_ADMIN` / `CAP_BPF`) to attach the XDP program to network interfaces.

### Risks
- Logic errors could disrupt valid network traffic.
  - *Mitigation*: Fail-safe architecture where any parsing error or non-IPv4 frame returns `XDP_PASS` to defer inspection to the standard kernel network stack.
