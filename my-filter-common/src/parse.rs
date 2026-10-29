//! Zero-copy, verifier-safe packet parsing routines for pure Rust network inspection.

pub const ETHER_TYPE_IPV4: u16 = 0x0800;
pub const ETHER_TYPE_IPV6: u16 = 0x86DD;
pub const ETHER_TYPE_ARP: u16 = 0x0806;

pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_UDP: u8 = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    TruncatedEthernet,
    UnsupportedEtherType,
    TruncatedIpv4Header,
    InvalidIpv4HeaderLength,
    TruncatedIpv4Payload,
    TruncatedTransportHeader,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct EthHdr {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Hdr {
    pub ver_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TcpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub doff_res_flags: u16,
    pub window: u16,
    pub check: u16,
    pub urg_ptr: u16,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct UdpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub len: u16,
    pub check: u16,
}

/// Parsed metadata extracted zero-copy from raw packet bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedPacket<'a> {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub ether_type: u16,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub protocol: u8,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub payload: &'a [u8],
}

/// Zero-copy packet parser operating over raw byte slices.
///
/// Guaranteed never to panic: every offset and subslice access is strictly bounds-checked.
pub fn parse_packet<'a>(data: &'a [u8]) -> Result<ParsedPacket<'a>, ParseError> {
    const ETH_LEN: usize = 14;
    if data.len() < ETH_LEN {
        return Err(ParseError::TruncatedEthernet);
    }

    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];
    dst_mac.copy_from_slice(&data[0..6]);
    src_mac.copy_from_slice(&data[6..12]);
    let ether_type = u16::from_be_bytes([data[12], data[13]]);

    if ether_type != ETHER_TYPE_IPV4 {
        return Err(ParseError::UnsupportedEtherType);
    }

    let ip_data = &data[ETH_LEN..];
    const MIN_IPV4_LEN: usize = 20;
    if ip_data.len() < MIN_IPV4_LEN {
        return Err(ParseError::TruncatedIpv4Header);
    }

    let ver_ihl = ip_data[0];
    let version = ver_ihl >> 4;
    let ihl = (ver_ihl & 0x0f) as usize * 4;

    if version != 4 || ihl < MIN_IPV4_LEN || ip_data.len() < ihl {
        return Err(ParseError::InvalidIpv4HeaderLength);
    }

    let protocol = ip_data[9];
    let src_ip = u32::from_be_bytes([ip_data[12], ip_data[13], ip_data[14], ip_data[15]]);
    let dst_ip = u32::from_be_bytes([ip_data[16], ip_data[17], ip_data[18], ip_data[19]]);

    let transport_data = &ip_data[ihl..];
    let (src_port, dst_port, payload) = match protocol {
        IP_PROTO_TCP => {
            const MIN_TCP_LEN: usize = 20;
            if transport_data.len() < MIN_TCP_LEN {
                return Err(ParseError::TruncatedTransportHeader);
            }
            let sp = u16::from_be_bytes([transport_data[0], transport_data[1]]);
            let dp = u16::from_be_bytes([transport_data[2], transport_data[3]]);
            let data_offset = ((transport_data[12] >> 4) as usize) * 4;
            if data_offset < MIN_TCP_LEN || transport_data.len() < data_offset {
                return Err(ParseError::TruncatedTransportHeader);
            }
            (Some(sp), Some(dp), &transport_data[data_offset..])
        }
        IP_PROTO_UDP => {
            const UDP_LEN: usize = 8;
            if transport_data.len() < UDP_LEN {
                return Err(ParseError::TruncatedTransportHeader);
            }
            let sp = u16::from_be_bytes([transport_data[0], transport_data[1]]);
            let dp = u16::from_be_bytes([transport_data[2], transport_data[3]]);
            (Some(sp), Some(dp), &transport_data[UDP_LEN..])
        }
        _ => (None, None, transport_data),
    };

    Ok(ParsedPacket {
        src_mac,
        dst_mac,
        ether_type,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        payload,
    })
}
