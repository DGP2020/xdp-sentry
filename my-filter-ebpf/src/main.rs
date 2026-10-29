#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::XdpContext,
    helpers::bpf_ktime_get_ns,
};
use core::mem;
use my_filter_common::{
    parse::{EthHdr, Ipv4Hdr, TcpHdr, UdpHdr, ETHER_TYPE_IPV4, IP_PROTO_TCP, IP_PROTO_UDP},
    BlockRule, PacketAlert, TrafficStats,
};

/// Dynamic blocklist shared with user-space controller.
/// Key: IPv4 address as u32 (host byte order). Value: BlockRule metadata.
#[map]
static BLOCKLIST: HashMap<u32, BlockRule> = HashMap::with_max_entries(1024, 0);

/// Per-CPU array tracking high-throughput traffic telemetry without lock contention.
#[map]
static METRICS: PerCpuArray<TrafficStats> = PerCpuArray::with_max_entries(1, 0);

/// High-speed ring buffer for streaming security alerts to user-space.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    // Mathematical proof for the Linux kernel eBPF verifier:
    // Pointers must never exceed the bounds of the packet data buffer.
    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[xdp]
pub fn my_filter(ctx: XdpContext) -> u32 {
    match try_filter(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_filter(ctx: &XdpContext) -> Result<u32, ()> {
    // 1. Inspect Ethernet Frame
    let eth_hdr = unsafe { &*ptr_at::<EthHdr>(ctx, 0)? };
    let ether_type = u16::from_be(eth_hdr.ether_type);

    if ether_type != ETHER_TYPE_IPV4 {
        return Ok(xdp_action::XDP_PASS);
    }

    // 2. Inspect IPv4 Header
    let eth_len = mem::size_of::<EthHdr>();
    let ip_hdr = unsafe { &*ptr_at::<Ipv4Hdr>(ctx, eth_len)? };

    let ver_ihl = ip_hdr.ver_ihl;
    let version = ver_ihl >> 4;
    let ihl = ((ver_ihl & 0x0f) as usize) * 4;

    if version != 4 || ihl < mem::size_of::<Ipv4Hdr>() {
        return Ok(xdp_action::XDP_PASS);
    }

    let src_ip = u32::from_be(ip_hdr.src_addr);
    let dst_ip = u32::from_be(ip_hdr.dst_addr);
    let protocol = ip_hdr.protocol;

    // 3. Inspect Layer 4 Ports (TCP / UDP)
    let transport_offset = eth_len + ihl;
    let mut src_port = 0u16;
    let mut dst_port = 0u16;

    if protocol == IP_PROTO_TCP {
        if let Ok(tcp) = unsafe { ptr_at::<TcpHdr>(ctx, transport_offset) } {
            let tcp_hdr = unsafe { &*tcp };
            src_port = u16::from_be(tcp_hdr.src_port);
            dst_port = u16::from_be(tcp_hdr.dst_port);
        }
    } else if protocol == IP_PROTO_UDP {
        if let Ok(udp) = unsafe { ptr_at::<UdpHdr>(ctx, transport_offset) } {
            let udp_hdr = unsafe { &*udp };
            src_port = u16::from_be(udp_hdr.src_port);
            dst_port = u16::from_be(udp_hdr.dst_port);
        }
    }

    let packet_len = (ctx.data_end() - ctx.data()) as u64;

    // 4. Update Ingress Telemetry in Per-CPU Array
    if let Some(stats_ptr) = METRICS.get_ptr_mut(0) {
        unsafe {
            (*stats_ptr).rx_packets += 1;
            (*stats_ptr).rx_bytes += packet_len;
        }
    }

    // 5. Evaluate Security Policy against eBPF Blocklist Map
    if let Some(rule) = unsafe { BLOCKLIST.get_ptr_mut(&src_ip) } {
        // Increment rule drop counter
        unsafe {
            (*rule).drop_count += 1;
        }

        // Increment total drop metrics
        if let Some(stats_ptr) = METRICS.get_ptr_mut(0) {
            unsafe {
                (*stats_ptr).dropped_packets += 1;
                (*stats_ptr).dropped_bytes += packet_len;
            }
        }

        // Stream real-time alert to user-space RingBuffer
        let now_ns = unsafe { bpf_ktime_get_ns() };
        let alert = PacketAlert {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            action: xdp_action::XDP_DROP as u8,
            _pad: 0,
            timestamp_ns: now_ns,
        };

        let _ = EVENTS.output(&alert, 0);

        // Nanosecond hardware-level packet drop
        return Ok(xdp_action::XDP_DROP);
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
