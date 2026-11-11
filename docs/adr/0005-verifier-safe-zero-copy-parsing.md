# ADR-0005: Verifier-Safe Zero-Copy Packet Parsing via Mathematical Bounds Checking

**Date**: 2026-11-11
**Status**: accepted
**Deciders**: Danie (Security Infrastructure Architect)

## Context

The Linux kernel eBPF verifier statically analyzes all eBPF programs prior to execution to enforce memory safety and system stability. If any pointer arithmetic can potentially read beyond the packet boundary (`ctx.data()` to `ctx.data_end()`), the verifier rejects the bytecode immediately. In a zero-copy packet parser, accessing variable-length headers (such as IPv4 options or TCP headers) without intermediate memory copies requires rigorous bounds verification at every protocol layer.

## Decision

We implement a zero-copy bounds checking abstraction `ptr_at<T>` that mathematically proves to the verifier that `start + offset + size_of::<T>() <= end` before returning a typed pointer to packed header structures (`EthHdr`, `Ipv4Hdr`, `TcpHdr`, `UdpHdr`). If bounds checks fail due to truncated frames, invalid versions, or invalid header lengths (IHL), the program aborts parsing and immediately returns `XDP_PASS` to delegate inspection to the standard Linux networking stack.

## Alternatives Considered

### Alternative 1: Copying Packet Bytes to the eBPF Stack
- **Pros**: Reading from stack memory avoids direct pointer bounds tracking on variable offsets.
- **Cons**: eBPF stack space is strictly limited to 512 bytes; copying payload introduces significant memory and instruction overhead.
- **Why not**: Violates the zero-copy architecture and degrades packet processing throughput.

### Alternative 2: Unsafe Raw Pointer Offsets Without Abstraction
- **Pros**: Reduces helper functions in kernel code.
- **Cons**: Repetitive manual bounds checks increase the likelihood of missing a condition; any verification oversight causes verifier load rejection.
- **Why not**: Encapsulating bounds proof in `ptr_at` guarantees safety consistency across all protocol parsing layers.

## Consequences

### Positive
- 100% zero-copy packet parsing with zero intermediate allocations.
- Mathematical safety proof satisfies the Linux kernel eBPF verifier without warnings or rejection.
- Graceful degradation: truncated, fuzzed, or non-IPv4 frames pass safely to the kernel stack without causing kernel panics or dropped valid packets.

### Negative
- Every header layer dissection incurs explicit bounds checking instructions.
- Protocol support is currently bounded to Ethernet, IPv4, TCP, and UDP in kernel space.

### Risks
- Unaligned memory access on architectures that do not support unaligned reads.
  - *Mitigation*: Protocol header structs are annotated with `#[repr(C, packed)]` and verified via layout tests in `my-filter-common/tests/pod_tests.rs`.
