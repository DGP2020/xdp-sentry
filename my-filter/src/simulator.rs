//! Cross-platform simulation and verification engine for XDP packet filtering logic.

use my_filter_common::parse::parse_packet;
use my_filter_common::{BlockRule, PacketAlert, TrafficStats, XdpAction};
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// In-memory packet filtering pipeline simulating the kernel-space eBPF XDP hook.
#[derive(Debug, Default)]
pub struct PacketFilterSimulator {
    pub blocklist: HashMap<u32, BlockRule>,
    pub stats: TrafficStats,
    pub alerts: Vec<PacketAlert>,
}

impl PacketFilterSimulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an IP into the blocklist (mimicking aya::maps::HashMap::insert)
    pub fn block_ip(&mut self, ip: Ipv4Addr) {
        let key = u32::from(ip);
        self.blocklist.entry(key).or_insert(BlockRule {
            drop_count: 0,
            blocked_at_secs: 0,
            rule_flags: 1,
            _pad: 0,
        });
    }

    /// Remove an IP from the blocklist (mimicking aya::maps::HashMap::remove)
    pub fn unblock_ip(&mut self, ip: Ipv4Addr) -> bool {
        let key = u32::from(ip);
        self.blocklist.remove(&key).is_some()
    }

    /// Process a raw packet buffer through the zero-copy pipeline
    pub fn process_packet(&mut self, raw_packet: &[u8]) -> XdpAction {
        self.stats.rx_packets += 1;
        self.stats.rx_bytes += raw_packet.len() as u64;

        let parsed = match parse_packet(raw_packet) {
            Ok(p) => p,
            Err(_) => {
                // If not IPv4 or malformed, default XDP action is pass to standard kernel stack
                return XdpAction::Pass;
            }
        };

        // Note: parsed.src_ip is parsed as u32::from_be_bytes(ip_bytes), which equals u32::from(Ipv4Addr)
        if let Some(rule) = self.blocklist.get_mut(&parsed.src_ip) {
            rule.drop_count += 1;
            self.stats.dropped_packets += 1;
            self.stats.dropped_bytes += raw_packet.len() as u64;

            self.alerts.push(PacketAlert {
                src_ip: parsed.src_ip,
                dst_ip: parsed.dst_ip,
                src_port: parsed.src_port.unwrap_or(0),
                dst_port: parsed.dst_port.unwrap_or(0),
                protocol: parsed.protocol,
                action: XdpAction::Drop as u8,
                _pad: 0,
                timestamp_ns: 1_000_000_000,
            });

            XdpAction::Drop
        } else {
            XdpAction::Pass
        }
    }
}

/// Helper utility to synthesize raw test packets
pub fn synthesize_ipv4_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut frame = Vec::with_capacity(54);
    // Ethernet Header: 14 bytes
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // Dst MAC
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // Src MAC
    frame.extend_from_slice(&[0x08, 0x00]); // IPv4

    // IPv4 Header: 20 bytes
    let src_octets = src_ip.octets();
    let dst_octets = dst_ip.octets();
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, // Ver/IHL, DSCP, Total Len (40)
        0x00, 0x01, 0x00, 0x00, // ID, Flags/Frag
        0x40, 0x06, 0x00, 0x00, // TTL=64, Proto=TCP(6), Checksum
        src_octets[0], src_octets[1], src_octets[2], src_octets[3],
        dst_octets[0], dst_octets[1], dst_octets[2], dst_octets[3],
    ]);

    // TCP Header: 20 bytes
    let sp = src_port.to_be_bytes();
    let dp = dst_port.to_be_bytes();
    frame.extend_from_slice(&[
        sp[0], sp[1], dp[0], dp[1],
        0x00, 0x00, 0x00, 0x01, // Seq
        0x00, 0x00, 0x00, 0x00, // Ack
        0x50, 0x02, 0x72, 0x10, // Data offset 5, SYN flag, Window
        0x00, 0x00, 0x00, 0x00, // Checksum, Urg
    ]);

    frame
}
