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

#[test]
fn test_parse_empty_and_sub_ethernet_frames() {
    // 0 bytes (empty buffer)
    assert_eq!(parse_packet(&[]), Err(ParseError::TruncatedEthernet));

    // 1 byte
    assert_eq!(parse_packet(&[0xaa]), Err(ParseError::TruncatedEthernet));

    // 6 bytes (destination MAC only)
    assert_eq!(parse_packet(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]), Err(ParseError::TruncatedEthernet));

    // 12 bytes (MAC addresses only, missing 2-byte EtherType)
    assert_eq!(parse_packet(&[0x00; 12]), Err(ParseError::TruncatedEthernet));

    // 13 bytes (exactly 1 byte short of 14-byte Ethernet header)
    assert_eq!(parse_packet(&[0x00; 13]), Err(ParseError::TruncatedEthernet));
}

#[test]
fn test_parse_non_ipv4_ethertypes() {
    let make_frame = |ethertype: u16| {
        let mut f = Vec::new();
        f.extend_from_slice(&[0x00; 12]);
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(&[0x00; 30]); // arbitrary payload
        f
    };

    // 0x8100 (802.1Q VLAN)
    assert_eq!(parse_packet(&make_frame(0x8100)), Err(ParseError::UnsupportedEtherType));
    // 0x88A8 (802.1ad QinQ)
    assert_eq!(parse_packet(&make_frame(0x88A8)), Err(ParseError::UnsupportedEtherType));
    // 0x8847 (MPLS Unicast)
    assert_eq!(parse_packet(&make_frame(0x8847)), Err(ParseError::UnsupportedEtherType));
    // 0x88CC (LLDP)
    assert_eq!(parse_packet(&make_frame(0x88CC)), Err(ParseError::UnsupportedEtherType));
    // 0x0000 (Zero/Undefined)
    assert_eq!(parse_packet(&make_frame(0x0000)), Err(ParseError::UnsupportedEtherType));
}

#[test]
fn test_parse_ipv4_boundary_lengths() {
    // Exactly 14 bytes (Ethernet only, 0 bytes of IPv4)
    let mut frame14 = Vec::new();
    frame14.extend_from_slice(&[0x00; 12]);
    frame14.extend_from_slice(&[0x08, 0x00]);
    assert_eq!(parse_packet(&frame14), Err(ParseError::TruncatedIpv4Header));

    // Exactly 33 bytes (14 Ethernet + 19 bytes IPv4 -> exactly 1 byte short of 20)
    let mut frame33 = Vec::new();
    frame33.extend_from_slice(&[0x00; 12]);
    frame33.extend_from_slice(&[0x08, 0x00]);
    frame33.extend_from_slice(&[0x45; 19]);
    assert_eq!(parse_packet(&frame33), Err(ParseError::TruncatedIpv4Header));
}

#[test]
fn test_parse_ipv4_version_mutations() {
    let mut base_frame = Vec::new();
    base_frame.extend_from_slice(&[0x00; 12]);
    base_frame.extend_from_slice(&[0x08, 0x00]); // IPv4 EtherType
    // 20 bytes IPv4 header placeholder
    base_frame.extend_from_slice(&[0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 1, 1, 1, 1, 2, 2, 2, 2]);

    for &bad_version in &[0x05, 0x15, 0x25, 0x35, 0x55, 0x65, 0xf5] {
        let mut test_frame = base_frame.clone();
        test_frame[14] = bad_version; // modify ver_ihl
        assert_eq!(parse_packet(&test_frame), Err(ParseError::InvalidIpv4HeaderLength));
    }
}

#[test]
fn test_parse_ipv4_ihl_boundary_conditions() {
    let mut base_frame = Vec::new();
    base_frame.extend_from_slice(&[0x00; 12]);
    base_frame.extend_from_slice(&[0x08, 0x00]);
    base_frame.extend_from_slice(&[0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 1, 1, 1, 1, 2, 2, 2, 2]);

    // IHL < 5 (e.g. 0, 1, 2, 3, 4)
    for ihl in 0..=4 {
        let mut f = base_frame.clone();
        f[14] = 0x40 | ihl;
        assert_eq!(parse_packet(&f), Err(ParseError::InvalidIpv4HeaderLength));
    }

    // IHL = 6 (24 bytes) but packet only contains 20 bytes of IP
    let mut short_f = base_frame.clone();
    short_f[14] = 0x46; // IHL=6 (24 bytes)
    assert_eq!(parse_packet(&short_f), Err(ParseError::InvalidIpv4HeaderLength));

    // IHL = 6 (24 bytes) with 24 bytes present -> Should succeed
    let mut valid_opt_f = base_frame.clone();
    valid_opt_f[14] = 0x46;
    valid_opt_f.extend_from_slice(&[0x00; 4]); // 4 bytes of IP options
    let parsed = parse_packet(&valid_opt_f).expect("Valid IPv4 with options should parse");
    assert_eq!(parsed.protocol, 0);

    // IHL = 15 (60 bytes max) but packet is truncated to 30 bytes
    let mut max_ihl_short = base_frame.clone();
    max_ihl_short[14] = 0x4f; // IHL=15 (60 bytes)
    max_ihl_short.extend_from_slice(&[0x00; 10]); // Total 30 bytes
    assert_eq!(parse_packet(&max_ihl_short), Err(ParseError::InvalidIpv4HeaderLength));

    // IHL = 15 (60 bytes max) with all 60 bytes present -> Should succeed
    let mut max_ihl_full = base_frame.clone();
    max_ihl_full[14] = 0x4f;
    max_ihl_full.extend_from_slice(&[0x00; 40]); // 20 + 40 = 60 bytes
    let parsed = parse_packet(&max_ihl_full).expect("Valid 60-byte IPv4 header should parse");
    assert_eq!(parsed.protocol, 0);
}

#[test]
fn test_parse_tcp_boundary_and_data_offset_conditions() {
    let mut base_frame = Vec::new();
    base_frame.extend_from_slice(&[0x00; 12]);
    base_frame.extend_from_slice(&[0x08, 0x00]); // IPv4
    base_frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x34,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00, // TCP
        10, 0, 0, 1,
        10, 0, 0, 2,
    ]);

    // 19 bytes of TCP (1 byte short of 20)
    let mut frame19 = base_frame.clone();
    frame19.extend_from_slice(&[0x00; 19]);
    assert_eq!(parse_packet(&frame19), Err(ParseError::TruncatedTransportHeader));

    // Exactly 20 bytes TCP, but Data Offset (doff) < 5
    // doff is high 4 bits of byte 12 in TCP header (offset 14 + 20 + 12 = 46)
    for &bad_doff in &[0x00, 0x10, 0x20, 0x30, 0x40] {
        let mut f = base_frame.clone();
        let mut tcp_hdr = vec![0x00; 20];
        tcp_hdr[12] = bad_doff;
        f.extend_from_slice(&tcp_hdr);
        assert_eq!(parse_packet(&f), Err(ParseError::TruncatedTransportHeader));
    }

    // doff = 8 (32 bytes), but only 20 bytes provided
    let mut f_short_opts = base_frame.clone();
    let mut tcp_hdr = vec![0x00; 20];
    tcp_hdr[12] = 0x80; // 8 * 4 = 32 bytes required
    f_short_opts.extend_from_slice(&tcp_hdr);
    assert_eq!(parse_packet(&f_short_opts), Err(ParseError::TruncatedTransportHeader));

    // doff = 8 (32 bytes), full 32 bytes provided + payload
    let mut f_full_opts = base_frame.clone();
    let mut tcp_hdr = vec![0x00; 32];
    tcp_hdr[0] = 0x12; tcp_hdr[1] = 0x34; // src port 4660
    tcp_hdr[2] = 0x00; tcp_hdr[3] = 0x50; // dst port 80
    tcp_hdr[12] = 0x80; // 32 bytes
    f_full_opts.extend_from_slice(&tcp_hdr);
    f_full_opts.extend_from_slice(b"HTTP/1.1");
    let parsed = parse_packet(&f_full_opts).expect("TCP with options should parse");
    assert_eq!(parsed.src_port, Some(4660));
    assert_eq!(parsed.dst_port, Some(80));
    assert_eq!(parsed.payload, b"HTTP/1.1");
}

#[test]
fn test_parse_udp_boundary_conditions() {
    let mut base_frame = Vec::new();
    base_frame.extend_from_slice(&[0x00; 12]);
    base_frame.extend_from_slice(&[0x08, 0x00]);
    base_frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x20,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00, // UDP
        10, 0, 0, 1,
        10, 0, 0, 2,
    ]);

    // 7 bytes UDP (1 byte short of 8)
    let mut frame7 = base_frame.clone();
    frame7.extend_from_slice(&[0x00; 7]);
    assert_eq!(parse_packet(&frame7), Err(ParseError::TruncatedTransportHeader));

    // Valid 8 bytes UDP with payload
    let mut valid_udp = base_frame.clone();
    valid_udp.extend_from_slice(&[
        0x04, 0xd2, // src port 1234
        0x00, 0x35, // dst port 53 (DNS)
        0x00, 0x0c, // len 12 (8 hdr + 4 data)
        0x00, 0x00, // checksum
        0xde, 0xad, 0xbe, 0xef, // payload
    ]);
    let parsed = parse_packet(&valid_udp).expect("Valid UDP with payload should parse");
    assert_eq!(parsed.src_port, Some(1234));
    assert_eq!(parsed.dst_port, Some(53));
    assert_eq!(parsed.payload, &[0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn test_fuzz_random_byte_mutations_never_panic() {
    // Pseudo-random linear congruential generator for reproducible fuzzing
    let mut seed = 0xdeadbeef_u64;
    let mut lcg = || {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        (seed >> 32) as u32
    };

    let mut buffer = [0u8; 1500];
    for _ in 0..2000 {
        let len = (lcg() as usize) % buffer.len();
        for b in buffer[..len].iter_mut() {
            *b = (lcg() & 0xff) as u8;
        }

        // Must never panic! Returns Ok or Err safely.
        let _ = parse_packet(&buffer[..len]);
    }
}

