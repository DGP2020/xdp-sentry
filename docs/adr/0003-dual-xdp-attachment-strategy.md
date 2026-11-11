# ADR-0003: Dual-Mode XDP Attachment Strategy (Generic SKB and Native Driver)

**Date**: 2026-11-11
**Status**: accepted
**Deciders**: Danie (Security Infrastructure Architect)

## Context

XDP operates across multiple attachment modes with differing hardware requirements and execution points. Native Driver Mode (`XDP_FLAGS_DRV_MODE`) executes directly inside the physical NIC driver queue, but is unavailable on virtual interfaces (`veth` pairs), virtualized hypervisors, and WSL2. Conversely, Generic/SKB Mode (`XDP_FLAGS_SKB_MODE`) operates after `sk_buff` allocation on any Linux interface. Constraining the engine to only one mode would either prevent automated CI/CD and container testing or prevent line-rate production performance.

## Decision

We support configurable attachment modes exposed via the user-space CLI `--mode` parameter: `skb` (Generic SKB mode via `XDP_FLAGS_SKB_MODE`), `drv` (Native Driver mode via `XDP_FLAGS_DRV_MODE`), and `hw` (SmartNIC hardware offload via `XDP_FLAGS_HW_MODE`). The default attachment mode is set to `skb` to guarantee seamless execution on virtual ethernet testbeds, WSL2, and developer environments, while allowing production deployments to specify `--mode drv` for zero-allocation line-rate dropping.

## Alternatives Considered

### Alternative 1: Native Driver Mode Only (`drv`)
- **Pros**: Guarantees true zero-allocation dropping and maximum performance (up to 14.88 Mpps on 10GbE).
- **Cons**: Driver attachment fails unconditionally on virtual ethernet interfaces (`veth`), standard cloud virtual machines without SR-IOV, and WSL2.
- **Why not**: Prevents local development, automated integration testing with network namespaces, and CI/CD validation.

### Alternative 2: Generic / SKB Mode Only (`skb`)
- **Pros**: Universal compatibility across all Linux networking drivers and virtual devices without specialized hardware.
- **Cons**: Executes inside `do_xdp_generic()` after `alloc_skb()`, incurring memory allocation and deallocation overhead per dropped frame, capping throughput at ~1.8–2.5 Mpps.
- **Why not**: Unacceptable throughput ceiling for physical bare-metal deployments under multi-gigabit DDoS conditions.

## Consequences

### Positive
- Enables automated end-to-end testing in isolated Linux network namespaces (`scripts/test_veth.sh`) on developer machines and CI/CD without physical NICs.
- Enables production line-rate performance on supported enterprise NICs (Intel `ixgbe`/`i40e`/`ice`, Mellanox `mlx5`, Broadcom `bnxt_en`) via `--mode drv`.
- Provides future compatibility with SmartNIC hardware offload via `--mode hw`.

### Negative
- Operators must be aware of the difference between `skb` and `drv` modes when deploying.
- Performance characteristics differ substantially between modes (~195 kpps on virtual `veth` vs line-rate on physical NICs).

### Risks
- Attempting to attach with `--mode drv` on interfaces that lack native XDP support results in kernel attachment errors.
  - *Mitigation*: Fallback guidance documented in CLI help text and `docs/XDP_DRIVER_VS_GENERIC_MODE.md`.
