//! Linux-only live eBPF/XDP kernel loader built on Aya.
//! Maps are pinned under `/sys/fs/bpf/my_filter/` so separate CLI invocations
//! (`block`, `list`, `stats`, `monitor`) can talk to the running filter.

use anyhow::{anyhow, bail, Context, Result};
use aya::maps::{HashMap, Map, MapData, PerCpuArray, RingBuf};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use my_filter_common::{BlockRule, PacketAlert, TrafficStats};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const PIN_DIR: &str = "/sys/fs/bpf/my_filter";
const EBPF_CANDIDATES: &[&str] = &[
    "target/bpfel-unknown-none/release/my-filter-ebpf",
    "my-filter-ebpf/target/bpfel-unknown-none/release/my-filter-ebpf",
];

fn pin_path(name: &str) -> PathBuf {
    Path::new(PIN_DIR).join(name)
}

fn open_pinned(name: &str) -> Result<Map> {
    let data = MapData::from_pin(pin_path(name)).with_context(|| {
        format!("map {name} not pinned at {PIN_DIR}; is `my-filter attach` running (as root)?")
    })?;
    Ok(match name {
        "BLOCKLIST" => Map::HashMap(data),
        "METRICS" => Map::PerCpuArray(data),
        "EVENTS" => Map::RingBuf(data),
        other => bail!("unknown map {other}"),
    })
}

fn parse_flags(mode: &str) -> Result<XdpFlags> {
    match mode {
        "skb" => Ok(XdpFlags::SKB_MODE),
        "drv" => Ok(XdpFlags::DRV_MODE),
        "hw" => Ok(XdpFlags::HW_MODE),
        other => bail!("unknown XDP mode '{other}' (expected skb|drv|hw)"),
    }
}

pub fn attach_xdp(iface: &str, mode: &str) -> Result<()> {
    let flags = parse_flags(mode)?;
    let obj = EBPF_CANDIDATES
        .iter()
        .find(|p| Path::new(p).exists())
        .ok_or_else(|| anyhow!("eBPF binary not found; run `cargo xtask build-ebpf --release`"))?;

    let mut ebpf = Ebpf::load_file(obj).context("failed to load eBPF object")?;

    std::fs::create_dir_all(PIN_DIR).context("failed to create pin dir (is bpffs mounted?)")?;
    for name in ["BLOCKLIST", "METRICS", "EVENTS"] {
        let path = pin_path(name);
        let _ = std::fs::remove_file(&path);
        ebpf.map_mut(name)
            .ok_or_else(|| anyhow!("map {name} missing from eBPF object"))?
            .pin(&path)
            .with_context(|| format!("failed to pin {name}"))?;
    }

    let program: &mut Xdp = ebpf
        .program_mut("my_filter")
        .ok_or_else(|| anyhow!("program my_filter missing"))?
        .try_into()?;
    program.load().context("kernel verifier rejected program")?;
    program.attach(iface, flags).with_context(|| format!("failed to attach XDP to {iface}"))?;

    println!("[✓] XDP program attached to {iface} ({mode}); maps pinned at {PIN_DIR}");
    println!("[Press Ctrl+C to detach]");
    loop {
        std::thread::park();
    }
}

pub fn block_ip(ip: Ipv4Addr) -> Result<()> {
    let mut map: HashMap<_, u32, BlockRule> = HashMap::try_from(open_pinned("BLOCKLIST")?)?;
    let rule = BlockRule {
        drop_count: 0,
        blocked_at_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        rule_flags: 1,
        _pad: 0,
    };
    map.insert(u32::from(ip), rule, 0)?;
    Ok(())
}

pub fn unblock_ip(ip: Ipv4Addr) -> Result<bool> {
    let mut map: HashMap<_, u32, BlockRule> = HashMap::try_from(open_pinned("BLOCKLIST")?)?;
    Ok(map.remove(&u32::from(ip)).is_ok())
}

pub fn list_rules() -> Result<Vec<(Ipv4Addr, BlockRule)>> {
    let map: HashMap<_, u32, BlockRule> = HashMap::try_from(open_pinned("BLOCKLIST")?)?;
    let mut out = Vec::new();
    for item in map.iter() {
        let (k, v) = item?;
        out.push((Ipv4Addr::from(k), v));
    }
    Ok(out)
}

pub fn get_stats() -> Result<TrafficStats> {
    let map: PerCpuArray<_, TrafficStats> = PerCpuArray::try_from(open_pinned("METRICS")?)?;
    let mut total = TrafficStats::default();
    for s in map.get(&0, 0)?.iter() {
        total.rx_packets += s.rx_packets;
        total.rx_bytes += s.rx_bytes;
        total.dropped_packets += s.dropped_packets;
        total.dropped_bytes += s.dropped_bytes;
    }
    Ok(total)
}

pub fn monitor_events() -> Result<()> {
    let mut ring = RingBuf::try_from(open_pinned("EVENTS")?)?;
    println!("[+] Listening for real-time drop events from eBPF RingBuffer...");
    println!("[Press Ctrl+C to stop]");
    loop {
        while let Some(item) = ring.next() {
            if item.len() >= core::mem::size_of::<PacketAlert>() {
                let a: PacketAlert =
                    unsafe { core::ptr::read_unaligned(item.as_ptr() as *const PacketAlert) };
                println!(
                    "[DROP] {}:{} -> {}:{} proto={} ts={}ns",
                    Ipv4Addr::from(a.src_ip),
                    a.src_port,
                    Ipv4Addr::from(a.dst_ip),
                    a.dst_port,
                    a.protocol,
                    a.timestamp_ns
                );
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_path_construction() {
        assert_eq!(pin_path("BLOCKLIST"), PathBuf::from("/sys/fs/bpf/my_filter/BLOCKLIST"));
        assert_eq!(pin_path("METRICS"), PathBuf::from("/sys/fs/bpf/my_filter/METRICS"));
        assert_eq!(pin_path("EVENTS"), PathBuf::from("/sys/fs/bpf/my_filter/EVENTS"));
    }

    #[test]
    fn test_parse_flags_modes() {
        assert!(parse_flags("skb").is_ok());
        assert!(parse_flags("drv").is_ok());
        assert!(parse_flags("hw").is_ok());
        assert!(parse_flags("invalid").is_err());
    }
}

