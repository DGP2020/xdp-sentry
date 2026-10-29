use my_filter_common::{BlockRule, PacketAlert, TrafficStats};

#[test]
fn test_block_rule_pod_layout_and_bytes_roundtrip() {
    assert_eq!(core::mem::size_of::<BlockRule>(), 24);
    assert_eq!(core::mem::align_of::<BlockRule>(), 8);

    let rule = BlockRule {
        drop_count: 0x0102030405060708,
        blocked_at_secs: 0x1122334455667788,
        rule_flags: 0xaabbccdd,
        _pad: 0,
    };

    // Zero-copy byte representation verification (essential for eBPF map serialization)
    let bytes: [u8; 24] = unsafe { core::mem::transmute(rule) };
    
    // Verify drop_count in native endianness at bytes 0..8
    let read_drop_count = u64::from_ne_bytes(bytes[0..8].try_into().unwrap());
    assert_eq!(read_drop_count, 0x0102030405060708);

    // Verify blocked_at_secs at bytes 8..16
    let read_blocked_at = u64::from_ne_bytes(bytes[8..16].try_into().unwrap());
    assert_eq!(read_blocked_at, 0x1122334455667788);

    // Verify rule_flags at bytes 16..20
    let read_flags = u32::from_ne_bytes(bytes[16..20].try_into().unwrap());
    assert_eq!(read_flags, 0xaabbccdd);

    // Reconstruct struct from bytes and assert equality
    let recovered: BlockRule = unsafe { core::mem::transmute(bytes) };
    assert_eq!(rule, recovered);
}

#[test]
fn test_traffic_stats_pod_layout_and_bytes_roundtrip() {
    assert_eq!(core::mem::size_of::<TrafficStats>(), 32);
    assert_eq!(core::mem::align_of::<TrafficStats>(), 8);

    let stats = TrafficStats {
        rx_packets: 1000,
        rx_bytes: 1500000,
        dropped_packets: 50,
        dropped_bytes: 75000,
    };

    let bytes: [u8; 32] = unsafe { core::mem::transmute(stats) };
    let recovered: TrafficStats = unsafe { core::mem::transmute(bytes) };
    assert_eq!(stats, recovered);
}

#[test]
fn test_packet_alert_pod_layout_and_bytes_roundtrip() {
    assert_eq!(core::mem::size_of::<PacketAlert>(), 24);
    assert_eq!(core::mem::align_of::<PacketAlert>(), 8);

    let alert = PacketAlert {
        src_ip: 0xc0a80002, // 192.168.0.2
        dst_ip: 0x0a000001, // 10.0.0.1
        src_port: 54321,
        dst_port: 80,
        protocol: 6,
        action: 1, // XDP_DROP
        _pad: 0,
        timestamp_ns: 12345678901234,
    };

    let bytes: [u8; 24] = unsafe { core::mem::transmute(alert) };
    let recovered: PacketAlert = unsafe { core::mem::transmute(bytes) };
    assert_eq!(alert, recovered);
}

#[cfg(all(feature = "user", target_os = "linux"))]
fn assert_pod<T: aya::Pod>() {}

#[cfg(all(feature = "user", target_os = "linux"))]
#[test]
fn shared_abi_types_are_aya_pod() {
    assert_pod::<BlockRule>();
    assert_pod::<TrafficStats>();
    assert_pod::<PacketAlert>();
}
