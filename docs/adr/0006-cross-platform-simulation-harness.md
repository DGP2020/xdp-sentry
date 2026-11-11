# ADR-0006: Cross-Platform In-Memory Packet Filter Simulator for Non-Linux Verification

**Date**: 2026-11-11
**Status**: accepted
**Deciders**: Danie (Security Infrastructure Architect)

## Context

eBPF and XDP are Linux-kernel-specific technologies that require root privileges, specific kernel versions, and Linux networking interfaces to execute. Requiring a live Linux kernel for all testing prevents developers working on macOS or Windows workstations from running local tests, and complicates CI/CD matrix jobs on non-Linux platforms. Furthermore, automated unit testing of packet dissection and rule evaluation logic should not depend on kernel state.

## Decision

We implement a cross-platform in-memory simulation engine (`PacketFilterSimulator`) in `my-filter/src/simulator.rs` and expose it via the CLI subcommand `my-filter simulate`. The simulator exercises the identical zero-copy packet parser (`parse_packet`) and policy evaluation logic against synthetic raw Ethernet frames using standard Rust collections, enabling full unit and regression testing (`cargo test --workspace`) on Windows, macOS, and Linux without root access or a kernel environment.

## Alternatives Considered

### Alternative 1: Linux Virtual Machine / Container Dependency for All Tests
- **Pros**: Executes against the real Linux kernel network stack.
- **Cons**: High setup friction on non-Linux workstations; requires Vagrant, WSL2, or privileged Docker containers; slow test execution in CI/CD.
- **Why not**: Creates barrier for rapid developer feedback and cross-platform verification of parsing algorithms.

### Alternative 2: User-Space eBPF Bytecode Emulators
- **Pros**: Executes actual `bpfel` bytecode in user space.
- **Cons**: Adds complex C/C++ emulator dependencies (e.g. uBPF); high maintenance burden; fragile multi-platform support.
- **Why not**: Testing the pure-Rust parsing and filtering algorithms directly in Rust provides faster execution, native debugging, and full unit test coverage.

## Consequences

### Positive
- Cross-platform development: developers can test packet parsing, boundary conditions, and filtering behavior on Windows and macOS.
- Instant feedback in CI pipelines via `cargo test --workspace` without needing privileged containers or virtual ethernet pairs.
- Interactive demonstration mode (`my-filter simulate`) allows testing without modifying system network interfaces.

### Negative
- Simulation tests algorithms in memory and cannot validate driver-level NAPI polling, ring buffer overrun, or hardware NIC offload.
- Developers must rely on Tier 3 integration testbeds (`scripts/test_veth.sh`) for final kernel-level validation.

### Risks
- Behavioral drift between user-space simulator logic and kernel eBPF program logic.
  - *Mitigation*: Both simulator and kernel program share identical types and parsing logic from `my-filter-common`, and end-to-end integration tests run on Linux kernels in CI.
