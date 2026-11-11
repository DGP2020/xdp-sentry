# ADR-0004: Lock-Free eBPF Map Architecture for Dynamic Policy and Telemetry

**Date**: 2026-11-11
**Status**: accepted
**Deciders**: Danie (Security Infrastructure Architect)

## Context

High-throughput packet filtering requires real-time policy evaluation and telemetry aggregation across multi-core systems. Traditional synchronization techniques using mutexes or atomic operations on shared global counters cause severe lock contention and cache line bouncing when multiple CPU cores process millions of packets per second simultaneously. Furthermore, streaming security alerts to user space must not introduce backpressure or stall kernel-space packet processing.

## Decision

We partition data storage into three specialized, lock-free eBPF map structures:
1. `BLOCKLIST` (`HashMap<u32, BlockRule>`, max 1024 entries) for $O(1)$ dynamic IP lookup and individual rule drop accounting.
2. `METRICS` (`PerCpuArray<TrafficStats>`, 1 entry per core) for zero-contention aggregate traffic counters updated core-locally.
3. `EVENTS` (`RingBuf`, 256 KB) for high-speed, lockless streaming of `PacketAlert` security events to user space.

## Alternatives Considered

### Alternative 1: Global Array Map with eBPF Spinlocks
- **Pros**: Single shared counter that simplifies user-space reading without requiring per-CPU summation.
- **Cons**: eBPF spinlocks serialize packet processing across cores, creating major lock contention and CPU bottlenecks under high packet arrival rates.
- **Why not**: Eliminates multi-core scalability; `PerCpuArray` allows independent core-local increments with zero contention.

### Alternative 2: PerfEventArray for Alert Streaming
- **Pros**: Legacy compatibility with older Linux kernels (pre-5.8).
- **Cons**: Allocates fixed memory buffers per CPU core, leading to inefficient memory usage and dropped events during bursty traffic on unevenly distributed cores.
- **Why not**: BPF `RingBuf` provides a single shared, memory-efficient ring buffer across all CPU cores with strict ordering, lower overhead, and zero-copy notifications.

## Consequences

### Positive
- Zero lock contention across CPU cores during packet processing and telemetry collection.
- $O(1)$ IP lookup and instantaneous policy enforcement in kernel space.
- Ordered, low-latency delivery of security alerts to user-space listeners via `RingBuf`.

### Negative
- Reading total traffic statistics in user space (`my-filter stats`) requires querying each CPU's array slice and computing the sum.
- Static capacity limits (1024 blocklist rules, 256 KB ring buffer) enforce memory bounds in the kernel.

### Risks
- Under overwhelming drop rates, the 256 KB ring buffer could experience event drops if user space does not consume alerts fast enough.
  - *Mitigation*: Ring buffer drop behavior does not block or impair the packet filtering data path; dropped telemetry events are logged while line-rate packet drops continue uninterrupted.
