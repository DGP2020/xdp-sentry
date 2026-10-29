use my_filter::simulator::{synthesize_ipv4_packet, PacketFilterSimulator};
use my_filter_common::XdpAction;
use std::net::Ipv4Addr;

#[test]
fn test_simulator_drops_blocked_ip_and_records_stats() {
    let mut sim = PacketFilterSimulator::new();
    let attacker_ip: Ipv4Addr = "198.51.100.24".parse().unwrap();
    let legitimate_ip: Ipv4Addr = "203.0.113.10".parse().unwrap();
    let destination_ip: Ipv4Addr = "10.0.0.1".parse().unwrap();

    // Block the attacker
    sim.block_ip(attacker_ip);

    // Send legitimate packet
    let legit_pkt = synthesize_ipv4_packet(legitimate_ip, destination_ip, 12345, 80);
    let action1 = sim.process_packet(&legit_pkt);
    assert_eq!(action1, XdpAction::Pass);

    // Send attack packet
    let attack_pkt = synthesize_ipv4_packet(attacker_ip, destination_ip, 54321, 80);
    let action2 = sim.process_packet(&attack_pkt);
    assert_eq!(action2, XdpAction::Drop);

    // Check stats
    assert_eq!(sim.stats.rx_packets, 2);
    assert_eq!(sim.stats.dropped_packets, 1);
    assert_eq!(sim.alerts.len(), 1);

    let alert = &sim.alerts[0];
    assert_eq!(alert.src_ip, u32::from(attacker_ip));
    assert_eq!(alert.src_port, 54321);
    assert_eq!(alert.dst_port, 80);
    assert_eq!(alert.action, XdpAction::Drop as u8);

    // Unblock attacker and verify traffic passes
    assert!(sim.unblock_ip(attacker_ip));
    let action3 = sim.process_packet(&attack_pkt);
    assert_eq!(action3, XdpAction::Pass);
    assert_eq!(sim.stats.rx_packets, 3);
    assert_eq!(sim.stats.dropped_packets, 1);
}

#[test]
fn test_simulator_unblock_nonexistent_ip_returns_false() {
    let mut sim = PacketFilterSimulator::new();
    let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
    assert!(!sim.unblock_ip(ip));
}

#[test]
fn test_simulator_malformed_and_truncated_packet_passes_to_kernel_stack() {
    let mut sim = PacketFilterSimulator::new();
    let attacker_ip: Ipv4Addr = "198.51.100.1".parse().unwrap();
    sim.block_ip(attacker_ip);

    // Completely bogus packet (less than 14 bytes)
    let tiny_garbage = [0xde, 0xad, 0xbe, 0xef];
    let action = sim.process_packet(&tiny_garbage);
    // Malformed packet cannot be dissected, so XDP passes it to standard Linux network stack
    assert_eq!(action, XdpAction::Pass);
    assert_eq!(sim.stats.rx_packets, 1);
    assert_eq!(sim.stats.dropped_packets, 0);
    assert_eq!(sim.alerts.len(), 0);
}

#[test]
fn test_simulator_multiple_ips_blocklist_and_hit_counters() {
    let mut sim = PacketFilterSimulator::new();
    let ip1: Ipv4Addr = "192.168.100.1".parse().unwrap();
    let ip2: Ipv4Addr = "192.168.100.2".parse().unwrap();
    let dest: Ipv4Addr = "10.0.0.1".parse().unwrap();

    sim.block_ip(ip1);
    sim.block_ip(ip2);

    let pkt1 = synthesize_ipv4_packet(ip1, dest, 1111, 80);
    let pkt2 = synthesize_ipv4_packet(ip2, dest, 2222, 80);

    // Send 3 packets from ip1
    sim.process_packet(&pkt1);
    sim.process_packet(&pkt1);
    sim.process_packet(&pkt1);

    // Send 2 packets from ip2
    sim.process_packet(&pkt2);
    sim.process_packet(&pkt2);

    assert_eq!(sim.stats.rx_packets, 5);
    assert_eq!(sim.stats.dropped_packets, 5);
    assert_eq!(sim.alerts.len(), 5);

    // Verify per-rule drop counts
    let rule1 = sim.blocklist.get(&u32::from(ip1)).unwrap();
    assert_eq!(rule1.drop_count, 3);

    let rule2 = sim.blocklist.get(&u32::from(ip2)).unwrap();
    assert_eq!(rule2.drop_count, 2);

    // Unblock ip1 only
    assert!(sim.unblock_ip(ip1));
    assert_eq!(sim.process_packet(&pkt1), XdpAction::Pass);
    // ip2 should still be dropped
    assert_eq!(sim.process_packet(&pkt2), XdpAction::Drop);
}
