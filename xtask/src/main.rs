use anyhow::{bail, Context, Result};
use clap::Parser;
use std::process::Command;

#[derive(Parser, Debug, PartialEq, Eq)]
pub struct Options {
    #[command(subcommand)]
    pub command: SubCommands,
}

#[derive(Parser, Debug, PartialEq, Eq)]
pub enum SubCommands {
    /// Build the kernel-space eBPF program targeting bpfel-unknown-none
    BuildEbpf(BuildOptions),
    /// Build eBPF and launch user-space controller
    Run(RunOptions),
}

#[derive(Parser, Debug, PartialEq, Eq)]
pub struct BuildOptions {
    /// Build in release mode
    #[arg(short, long)]
    pub release: bool,
}

#[derive(Parser, Debug, PartialEq, Eq)]
pub struct RunOptions {
    /// Network interface name (e.g. eth0, veth0)
    #[arg(short, long, default_value = "veth0")]
    pub iface: String,

    /// Build in release mode
    #[arg(short, long)]
    pub release: bool,
}

fn main() -> Result<()> {
    let opts = Options::parse();

    match opts.command {
        SubCommands::BuildEbpf(b) => build_ebpf(&b),
        SubCommands::Run(r) => {
            build_ebpf(&BuildOptions { release: r.release })?;
            run(&r)
        }
    }
}

fn build_ebpf(opts: &BuildOptions) -> Result<()> {
    println!("[+] Compiling my-filter-ebpf targeting bpfel-unknown-none...");

    let mut args = vec![
        "+nightly",
        "build",
        "--manifest-path",
        "my-filter-ebpf/Cargo.toml",
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
        "--target-dir",
        "target",
    ];

    if opts.release {
        args.push("--release");
    }

    let status = Command::new("cargo")
        .args(&args)
        .status()
        .context("Failed to invoke cargo build for eBPF")?;

    if !status.success() {
        bail!("eBPF compilation failed with exit code: {:?}", status.code());
    }

    println!("[✓] eBPF ELF binary successfully built!");
    Ok(())
}

fn run(opts: &RunOptions) -> Result<()> {
    println!("[+] Launching user-space controller on interface: {}", opts.iface);

    let mut args = vec!["run", "--package", "my-filter", "--", "attach", "--iface", &opts.iface];
    if opts.release {
        args.insert(1, "--release");
    }

    let status = Command::new("cargo")
        .args(&args)
        .status()
        .context("Failed to run user-space controller")?;

    if !status.success() {
        bail!("Controller exited with error: {:?}", status.code());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xtask_parse_build_ebpf_release() {
        let args = ["xtask", "build-ebpf", "--release"];
        let opts = Options::try_parse_from(args).expect("Failed to parse build-ebpf");
        assert_eq!(
            opts.command,
            SubCommands::BuildEbpf(BuildOptions { release: true })
        );
    }

    #[test]
    fn test_xtask_parse_build_ebpf_debug() {
        let args = ["xtask", "build-ebpf"];
        let opts = Options::try_parse_from(args).expect("Failed to parse build-ebpf debug");
        assert_eq!(
            opts.command,
            SubCommands::BuildEbpf(BuildOptions { release: false })
        );
    }

    #[test]
    fn test_xtask_parse_run_defaults() {
        let args = ["xtask", "run"];
        let opts = Options::try_parse_from(args).expect("Failed to parse run defaults");
        assert_eq!(
            opts.command,
            SubCommands::Run(RunOptions {
                iface: "veth0".to_string(),
                release: false
            })
        );
    }

    #[test]
    fn test_xtask_parse_run_custom() {
        let args = ["xtask", "run", "--iface", "eth1", "--release"];
        let opts = Options::try_parse_from(args).expect("Failed to parse run custom");
        assert_eq!(
            opts.command,
            SubCommands::Run(RunOptions {
                iface: "eth1".to_string(),
                release: true
            })
        );
    }

    #[test]
    fn test_xtask_invalid_subcommand() {
        let args = ["xtask", "nonexistent"];
        assert!(Options::try_parse_from(args).is_err());
    }
}
