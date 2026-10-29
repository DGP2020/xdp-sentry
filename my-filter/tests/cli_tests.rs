use clap::Parser;
use std::net::Ipv4Addr;

use my_filter::cli::{Cli, Commands};

#[test]
fn test_cli_block_command_parsing() {
    let args = vec!["my-filter", "block", "192.168.1.50"];
    let cli = Cli::try_parse_from(args).expect("Failed to parse block command");
    match cli.command {
        Commands::Block { ip } => {
            assert_eq!(ip, "192.168.1.50".parse::<Ipv4Addr>().unwrap());
        }
        _ => panic!("Expected Block command"),
    }
}

#[test]
fn test_cli_unblock_command_parsing() {
    let args = vec!["my-filter", "unblock", "10.0.0.99"];
    let cli = Cli::try_parse_from(args).expect("Failed to parse unblock command");
    match cli.command {
        Commands::Unblock { ip } => {
            assert_eq!(ip, "10.0.0.99".parse::<Ipv4Addr>().unwrap());
        }
        _ => panic!("Expected Unblock command"),
    }
}

#[test]
fn test_cli_attach_command_parsing() {
    let args = vec!["my-filter", "attach", "--iface", "eth0", "--mode", "skb"];
    let cli = Cli::try_parse_from(args).expect("Failed to parse attach command");
    match cli.command {
        Commands::Attach { iface, mode } => {
            assert_eq!(iface, "eth0");
            assert_eq!(mode, "skb");
        }
        _ => panic!("Expected Attach command"),
    }
}

#[test]
fn test_cli_attach_default_mode_is_skb() {
    let args = vec!["my-filter", "attach", "-i", "veth-host"];
    let cli = Cli::try_parse_from(args).expect("Failed to parse attach command with short flag");
    match cli.command {
        Commands::Attach { iface, mode } => {
            assert_eq!(iface, "veth-host");
            assert_eq!(mode, "skb");
        }
        _ => panic!("Expected Attach command"),
    }
}

#[test]
fn test_cli_list_command_parsing() {
    let args = vec!["my-filter", "list"];
    let cli = Cli::try_parse_from(args).expect("Failed to parse list command");
    assert_eq!(cli.command, Commands::List);
}

#[test]
fn test_cli_stats_command_parsing() {
    let args = vec!["my-filter", "stats"];
    let cli = Cli::try_parse_from(args).expect("Failed to parse stats command");
    assert_eq!(cli.command, Commands::Stats);
}

#[test]
fn test_cli_monitor_command_parsing() {
    let args = vec!["my-filter", "monitor"];
    let cli = Cli::try_parse_from(args).expect("Failed to parse monitor command");
    assert_eq!(cli.command, Commands::Monitor);
}

#[test]
fn test_cli_simulate_default_parsing() {
    let args = vec!["my-filter", "simulate"];
    let cli = Cli::try_parse_from(args).expect("Failed to parse simulate default");
    match cli.command {
        Commands::Simulate { count, block_ip } => {
            assert_eq!(count, 10);
            assert_eq!(block_ip, None);
        }
        _ => panic!("Expected Simulate command"),
    }
}

#[test]
fn test_cli_simulate_custom_options() {
    let args = vec!["my-filter", "simulate", "--count", "100", "--block-ip", "192.0.2.1"];
    let cli = Cli::try_parse_from(args).expect("Failed to parse simulate with custom args");
    match cli.command {
        Commands::Simulate { count, block_ip } => {
            assert_eq!(count, 100);
            assert_eq!(block_ip, Some("192.0.2.1".parse::<Ipv4Addr>().unwrap()));
        }
        _ => panic!("Expected Simulate command"),
    }
}

#[test]
fn test_cli_invalid_ip_rejected() {
    let args = vec!["my-filter", "block", "999.999.999.999"];
    let res = Cli::try_parse_from(args);
    assert!(res.is_err());
}

#[test]
fn test_cli_missing_subcommand_rejected() {
    let args = vec!["my-filter"];
    let res = Cli::try_parse_from(args);
    assert!(res.is_err());
}

#[test]
fn test_cli_unknown_subcommand_rejected() {
    let args = vec!["my-filter", "invalid-cmd"];
    let res = Cli::try_parse_from(args);
    assert!(res.is_err());
}
