# CONTEXT.md — Domain Language

This document establishes the canonical domain language, concept definitions, and structural relationships for XDP-Sentry (Pure-Rust XDP Packet Filter & Telemetry Engine).

## Core Terms

| Term | Precise definition | Avoid in this context | Evidence/source |
|---|---|---|---|
| `Early Packet Processing (In-Kernel Pre-sk_buff)` | Inspecting and filtering network frames directly within the Linux kernel driver path (`napi_poll`) prior to socket buffer (`sk_buff`) allocation, retaining OS kernel device ownership and security boundaries. | `Kernel Bypass` (which unbinds drivers from OS ownership), `Userspace Networking` | `README.md`, `docs/XDP_DRIVER_VS_GENERIC_MODE.md#section-4` |
| `XDP (eXpress Data Path)` | A Linux kernel data plane hook that executes verified eBPF bytecode at the lowest level of the network subsystem immediately upon packet reception. | `AF_XDP` (userspace packet socket), `TC` (Traffic Control running post-sk_buff) | `README.md`, `my-filter-ebpf/src/main.rs` |
| `Native Driver Mode (drv)` | An XDP attachment mode (`XDP_FLAGS_DRV_MODE`) where the eBPF program executes directly within the physical network interface driver's receive ring on raw DMA pages (`xdp_buff`) before `sk_buff` allocation. | `Hardware Offload` (executing on SmartNIC silicon), `Generic Mode` | `my-filter/src/loader.rs`, `docs/XDP_DRIVER_VS_GENERIC_MODE.md` |
| `Generic / SKB Mode (skb)` | An XDP attachment mode (`XDP_FLAGS_SKB_MODE`) executing in `netif_receive_skb()` after socket buffer allocation, enabling XDP functionality across any Linux interface including virtual devices (`veth`) and WSL2. | `Native Mode`, `Kernel Bypass` | `my-filter/src/loader.rs`, `docs/XDP_DRIVER_VS_GENERIC_MODE.md` |
| `XDP Action` | The kernel verdict returned by the XDP hook determining frame disposition: `XDP_PASS` (forward to Linux network stack), `XDP_DROP` (immediate wire-level drop), `XDP_TX` (retransmit out same interface), `XDP_REDIRECT` (forward to other interface/socket), or `XDP_ABORTED` (error drop). | `Netfilter Verdict` (`NF_ACCEPT`, `NF_DROP`), `Firewall Action` | `my-filter-common/src/lib.rs` (`XdpAction`), Linux `<linux/bpf.h>` |
| `Block Rule` | A 24-byte, 8-byte aligned security policy record containing rule hit counters (`drop_count`), creation timestamp (`blocked_at_secs`), and configuration flags (`rule_flags`) associated with an IPv4 address in eBPF shared memory. | `Access Control Entry (ACE)`, `iptables rule` | `my-filter-common/src/lib.rs` (`BlockRule`), `my-filter-common/tests/pod_tests.rs` |
| `Traffic Stats` | A 32-byte, 8-byte aligned telemetry structure tracking total received packets/bytes and filtered (dropped) packets/bytes in kernel space. | `Interface Counters`, `ethtool stats` | `my-filter-common/src/lib.rs` (`TrafficStats`), `my-filter-ebpf/src/main.rs` |
| `Packet Alert` | A 24-byte security event record emitted via eBPF RingBuffer containing packet 5-tuple metadata (source IP, destination IP, source port, destination port, protocol), action taken, and kernel nanosecond timestamp. | `Syslog event`, `SNMP trap` | `my-filter-common/src/lib.rs` (`PacketAlert`), `my-filter-ebpf/src/main.rs` |
| `Zero-Copy Parser (ptr_at)` | An inline memory verification routine asserting that `start + offset + len <= end` against packet boundaries, proving memory safety to the Linux eBPF verifier without allocating or copying buffer memory. | `Buffer copy`, `skb_pull` | `my-filter-ebpf/src/main.rs`, `my-filter-common/src/parse.rs` |
| `BPF Map Pinning` | Exposing and persisting kernel eBPF map file descriptors within the virtual BPF filesystem (`/sys/fs/bpf/my_filter`) to enable decoupled, stateless CLI processes to read and mutate kernel state. | `IPC daemon socket`, `Config file sync` | `my-filter/src/loader.rs`, `scripts/test_veth.sh` |
| `LPM Trie Key (LpmKey)` | A Longest Prefix Match key structure containing prefix bit length and IPv4 network octets enabling CIDR subnet rule matching (`BPF_MAP_TYPE_LPM_TRIE`). | `Exact IP match`, `Radix key` | `my-filter-common/src/lib.rs` (`LpmKey`) |

## Concept Relationships

- `XDP Hook` and `XDP Action`: Every incoming packet evaluated by the `XDP Hook` terminates in an explicit `XDP Action` (`XDP_DROP` or `XDP_PASS`).
- `Block Rule` and `Packet Alert`: When an incoming packet matches an active `Block Rule`, the rule's `drop_count` increments, aggregate `TrafficStats` update, a `PacketAlert` is emitted to `EVENTS` RingBuffer, and the frame is discarded with `XDP_DROP`.
- `Traffic Stats` and `PerCpuArray`: `TrafficStats` are distributed across CPU cores in a `PerCpuArray` to maintain lock-free, zero-contention telemetry updates under high packet arrival rates.
- `User-Space CLI` and `BPF Map Pinning`: Ephemeral `my-filter` CLI invocations (`block`, `unblock`, `list`, `stats`, `monitor`) access active kernel state via pinned paths in `/sys/fs/bpf/my_filter` without requiring a persistent daemon or program reload.
- `Generic Mode` and `Native Driver Mode`: Both execute the identical eBPF bytecode and evaluate the same `BLOCKLIST` map, differing only in whether execution occurs before (`drv`) or after (`skb`) socket buffer (`sk_buff`) allocation.

## Resolved Ambiguities

- `Kernel Bypass` vs. `In-Kernel Early Processing`: "Kernel Bypass" previously conflated XDP with userspace drivers (e.g., DPDK); XDP-Sentry operates strictly as in-kernel pre-`sk_buff` processing where the Linux kernel retains network device ownership, security verification, and normal stack forwarding for permitted traffic. Stop using "kernel bypass" when describing XDP-Sentry.
- `SKB Mode` vs. `Driver Mode`: `SKB Mode` runs after `sk_buff` allocation for compatibility with virtual network devices (`veth`), while `Driver Mode` operates directly on raw DMA pages in the driver poll loop.

## Needs Confirmation

- `IPv6 Rule Evaluation`: `parse.rs` defines `ETHER_TYPE_IPV6` but currently rejects non-IPv4 traffic as unsupported, passing it to the kernel stack; awaiting domain owner confirmation on extending `BLOCKLIST` and `LpmKey` to support 128-bit IPv6 filtering.
- `LPM Trie Live Migration`: `LpmKey` is defined in `my-filter-common`, but the active kernel program in `my-filter-ebpf` currently uses exact-match `HashMap<u32, BlockRule>`; awaiting confirmation on when to migrate the active kernel map to `LpmTrie`.
