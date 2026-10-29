#![no_std]

#[cfg(feature = "std")]
extern crate std;

pub mod parse;

/// eBPF XDP Actions matching Linux kernel <linux/bpf.h> enum xdp_action
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpAction {
    Aborted = 0,
    Drop = 1,
    Pass = 2,
    Tx = 3,
    Redirect = 4,
}

/// Key structure for Linux eBPF Longest Prefix Match (LPM) Trie (BPF_MAP_TYPE_LPM_TRIE)
/// Enables CIDR subnet filtering (e.g., 10.0.0.0/16 or 192.168.1.0/24).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LpmKey {
    /// CIDR prefix length in bits (0 to 32 for IPv4)
    pub prefix_len: u32,
    /// IPv4 network bytes in big-endian network byte order
    pub ip_bytes: [u8; 4],
}

impl LpmKey {
    pub fn new(prefix_len: u32, ip_bytes: [u8; 4]) -> Self {
        Self { prefix_len, ip_bytes }
    }

    pub fn exact(ip_bytes: [u8; 4]) -> Self {
        Self { prefix_len: 32, ip_bytes }
    }
}

/// Dynamic block rule stored in eBPF HashMap<u32, BlockRule> or LpmTrie<LpmKey, BlockRule>
/// Strictly 8-byte aligned and 24 bytes in length for C ABI stability across kernel/user space.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlockRule {
    pub drop_count: u64,
    pub blocked_at_secs: u64,
    pub rule_flags: u32,
    pub _pad: u32,
}

/// Aggregate traffic telemetry stored in eBPF PerCpuArray<TrafficStats>
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TrafficStats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
}

/// Real-time security event emitted through eBPF RingBuffer
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PacketAlert {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub action: u8,
    pub _pad: u16,
    pub timestamp_ns: u64,
}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for BlockRule {}
#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for TrafficStats {}
#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for PacketAlert {}
