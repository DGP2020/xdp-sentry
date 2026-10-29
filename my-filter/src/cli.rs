use clap::{Parser, Subcommand};
use std::net::Ipv4Addr;

#[derive(Parser, Debug)]
#[command(
    name = "my-filter",
    author = "Danie",
    version = "0.1.0",
    about = "Pure-Rust XDP Packet Filter & High-Speed Telemetry Engine",
    long_about = "A zero-copy, kernel-level packet filtering and telemetry engine written in pure Rust using eBPF and XDP."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub enum Commands {
    /// Attach the XDP packet filter to a network interface
    Attach {
        /// Network interface name (e.g. eth0, veth0)
        #[arg(short, long)]
        iface: String,

        /// XDP attachment mode: 'skb' (generic), 'drv' (native driver), or 'hw' (SmartNIC offload)
        #[arg(short, long, default_value = "skb")]
        mode: String,
    },

    /// Add an IPv4 address to the active eBPF blocklist
    Block {
        /// Target IPv4 address to drop immediately at XDP hook (e.g. 192.168.1.100)
        ip: Ipv4Addr,
    },

    /// Remove an IPv4 address from the active eBPF blocklist
    Unblock {
        /// Target IPv4 address to unblock
        ip: Ipv4Addr,
    },

    /// List all currently blocked IP addresses and their hit counters
    List,

    /// Display current traffic statistics and drop counters
    Stats,

    /// Stream real-time drop events and alerts from the eBPF RingBuffer
    Monitor,

    /// Run synthetic packet simulation & drop verification (cross-platform demo mode)
    Simulate {
        /// Number of synthetic packets to generate
        #[arg(short, long, default_value = "10")]
        count: u64,

        /// IP address to block during simulation
        #[arg(short, long)]
        block_ip: Option<Ipv4Addr>,
    },
}
