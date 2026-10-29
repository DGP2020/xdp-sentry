use my_filter_common::parse::{parse_packet, ParseError};
use my_filter_common::{BlockRule, PacketAlert, TrafficStats, XdpAction};

#[test]
fn test_parse_valid_ipv4_udp_packet() {
    // Construct a raw Ethernet frame + IPv4 Header + UDP Header
    let mut frame = Vec::new();
    
    // Ethernet Header (14 bytes):
    // Dst MAC: 00:11:22:33:44:55
    // Src MAC: 66:77:88:99:aa:bb
    // EtherType: 0x0800 (IPv4)
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    frame.extend_from_slice(&[0x08, 0x00]);

    // IPv4 Header (20 bytes):
    // Version = 4, IHL = 5 (0x45)
    // DSCP/ECN = 0x00
    // Total Length = 28 bytes (20 byte IP + 8 byte UDP)
    // Identification = 0x1234
    // Flags/FragOffset = 0x0000
    // TTL = 64 (0x40)
    // Protocol = 17 (UDP)
    // Checksum = 0x0000
    // Src IP = 192.168.1.50 (0xc0, 0xa8, 0x01, 0x32)
    // Dst IP = 10.0.0.1     (0x0a, 0x00, 0x00, 0x01)
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c,
        0x12, 0x34, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x32,
        0x0a, 0x00, 0x00, 0x01,
    ]);

    // UDP Header (8 bytes):
    // Src Port = 5353 (0x14e9)
    // Dst Port = 53 (0x0035)
    // Length = 8 (0x0008)
    // Checksum = 0x0000
    frame.extend_from_slice(&[0x14, 0xe9, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]);

    let parsed = parse_packet(&frame).expect("Failed to parse valid IPv4 UDP packet");
    assert_eq!(parsed.src_ip, u32::from_be_bytes([192, 168, 1, 50]));
    assert_eq!(parsed.dst_ip, u32::from_be_bytes([10, 0, 0, 1]));
    assert_eq!(parsed.src_port, Some(5353));
    assert_eq!(parsed.dst_port, Some(53));
    assert_eq!(parsed.protocol, 17);
}

#[test]
fn test_parse_valid_ipv4_tcp_syn_packet() {
    let mut frame = Vec::new();
    // Ethernet: 14 bytes
    frame.extend_from_slice(&[0x00, 0x50, 0x56, 0xc0, 0x00, 0x01]);
    frame.extend_from_slice(&[0x00, 0x50, 0x56, 0xc0, 0x00, 0x02]);
    frame.extend_from_slice(&[0x08, 0x00]); // IPv4

    // IPv4 Header: 20 bytes (TCP, proto 6)
    // Src: 172.16.0.4, Dst: 172.16.0.1
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x34,
        0xab, 0xcd, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xac, 0x10, 0x00, 0x04,
        0xac, 0x10, 0x00, 0x01,
    ]);

    // TCP Header: 20 bytes (Data Offset = 5, Flags = SYN (0x0002))
    // Src Port = 44444 (0xad9c), Dst Port = 80 (0x0050)
    frame.extend_from_slice(&[
        0xad, 0x9c, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x72, 0x10,
        0x00, 0x00, 0x00, 0x00,
    ]);

    let parsed = parse_packet(&frame).expect("Failed to parse valid IPv4 TCP packet");
    assert_eq!(parsed.src_ip, u32::from_be_bytes([172, 16, 0, 4]));
    assert_eq!(parsed.dst_ip, u32::from_be_bytes([172, 16, 0, 1]));
    assert_eq!(parsed.src_port, Some(44444));
    assert_eq!(parsed.dst_port, Some(80));
    assert_eq!(parsed.protocol, 6);
    assert_eq!(parsed.payload.len(), 0);
}

#[test]
fn test_parse_arp_frame_rejected() {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&[0xaa; 6]);
    frame.extend_from_slice(&[0x08, 0x06]); // ARP EtherType
    frame.extend_from_slice(&[0x00; 28]);

    assert_eq!(parse_packet(&frame), Err(ParseError::UnsupportedEtherType));
}

#[test]
fn test_parse_invalid_ihl_rejected() {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x00; 12]);
    frame.extend_from_slice(&[0x08, 0x00]); // IPv4
    // Ver=4, IHL=4 (invalid, minimum valid IHL is 5 = 20 bytes)
    frame.extend_from_slice(&[0x44, 0x00, 0x00, 0x20]);
    frame.extend_from_slice(&[0x00; 16]);

    assert_eq!(parse_packet(&frame), Err(ParseError::InvalidIpv4HeaderLength));
}

#[test]
fn test_parse_truncated_packet_returns_error() {
    let tiny_frame = [0x00, 0x11, 0x22, 0x33]; // Only 4 bytes (less than 14 byte Ethernet header)
    let res = parse_packet(&tiny_frame);
    assert_eq!(res, Err(ParseError::TruncatedEthernet));
}

#[test]
fn test_block_rule_and_stats_abi_layout() {
    // Verifying C ABI compatibility and alignment
    assert_eq!(core::mem::size_of::<BlockRule>(), 24);
    assert_eq!(core::mem::size_of::<TrafficStats>(), 32);
    assert_eq!(core::mem::size_of::<PacketAlert>(), 24);
    assert_eq!(core::mem::size_of::<my_filter_common::LpmKey>(), 8);
    assert_eq!(XdpAction::Drop as u32, 1);
    assert_eq!(XdpAction::Pass as u32, 2);
}

#[test]
fn test_parse_ipv6_frame_rejected() {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x00; 12]);
    frame.extend_from_slice(&[0x86, 0xdd]); // IPv6 EtherType
    frame.extend_from_slice(&[0x00; 40]);

    assert_eq!(parse_packet(&frame), Err(ParseError::UnsupportedEtherType));
}

#[test]
fn test_parse_icmp_packet_without_transport_ports() {
    let mut frame = Vec::new();
    // Ethernet Header (14 bytes)
    frame.extend_from_slice(&[0x00; 12]);
    frame.extend_from_slice(&[0x08, 0x00]); // IPv4

    // IPv4 Header (20 bytes, protocol 1 = ICMP)
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x01, 0x00, 0x00, // proto 1 (ICMP)
        192, 168, 1, 10,
        192, 168, 1, 1,
    ]);

    // ICMP Echo Request payload (8 bytes)
    let icmp_payload = [0x08, 0x00, 0xf7, 0xff, 0x00, 0x01, 0x00, 0x01];
    frame.extend_from_slice(&icmp_payload);

    let parsed = parse_packet(&frame).expect("Failed to parse valid ICMP packet");
    assert_eq!(parsed.protocol, 1);
    assert_eq!(parsed.src_port, None);
    assert_eq!(parsed.dst_port, None);
    assert_eq!(parsed.payload, &icmp_payload);
}

#[test]
fn test_parse_truncated_ipv4_header() {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x00; 12]);
    frame.extend_from_slice(&[0x08, 0x00]); // IPv4
    frame.extend_from_slice(&[0x45, 0x00, 0x00]); // Only 3 bytes of IPv4 header

    assert_eq!(parse_packet(&frame), Err(ParseError::TruncatedIpv4Header));
}

#[test]
fn test_parse_truncated_tcp_header() {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x00; 12]);
    frame.extend_from_slice(&[0x08, 0x00]); // IPv4
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x24,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00, // TCP
        10, 0, 0, 1,
        10, 0, 0, 2,
    ]);
    // Only 10 bytes of TCP header (minimum is 20)
    frame.extend_from_slice(&[0x00; 10]);

    assert_eq!(parse_packet(&frame), Err(ParseError::TruncatedTransportHeader));
}

#[test]
fn test_parse_truncated_udp_header() {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x00; 12]);
    frame.extend_from_slice(&[0x08, 0x00]); // IPv4
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x18,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00, // UDP
        10, 0, 0, 1,
        10, 0, 0, 2,
    ]);
    // Only 4 bytes of UDP header (minimum is 8)
    frame.extend_from_slice(&[0x00; 4]);

    assert_eq!(parse_packet(&frame), Err(ParseError::TruncatedTransportHeader));
}

