use std::{ffi::OsString, net::Ipv6Addr, path::PathBuf};

use clap::{Args, Parser, Subcommand};
use v6alias::{Alias, Config, Invocation, NetworkTool};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Human-friendly aliases for managed IPv6 ULA addresses"
)]
struct Cli {
    #[arg(short, long, default_value = "v6alias.yaml", global = true)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Expand an alias such as corp:42 into an IPv6 address.
    Resolve { alias: Alias },
    /// Format a managed IPv6 address as its shortest alias.
    Reverse { address: Ipv6Addr },
    /// Resolve an alias and run the platform ping command over IPv6.
    Ping(NetworkCommand),
    /// Resolve an alias and run tracert or traceroute over IPv6.
    #[command(alias = "tracert", alias = "traceroute")]
    Trace(NetworkCommand),
    /// Resolve an alias and run the OpenSSH client over IPv6.
    Ssh(NetworkCommand),
}

#[derive(Debug, Args)]
struct NetworkCommand {
    alias: Alias,
    /// Print the exact invocation without running it.
    #[arg(long)]
    dry_run: bool,
    /// Options passed directly to the underlying command before the address.
    #[arg(last = true)]
    arguments: Vec<OsString>,
}

fn main() {
    match run() {
        Ok(Some(exit_code)) => std::process::exit(exit_code),
        Ok(None) => {}
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<Option<i32>, Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let config = Config::from_path(cli.config)?;

    match cli.command {
        Command::Resolve { alias } => println!("{}", config.resolve(&alias)?),
        Command::Reverse { address } => println!("{}", config.reverse(address)?),
        Command::Ping(command) => {
            return run_network_command(&config, command, NetworkTool::Ping);
        }
        Command::Trace(command) => {
            return run_network_command(&config, command, NetworkTool::Trace);
        }
        Command::Ssh(command) => {
            return run_network_command(&config, command, NetworkTool::Ssh);
        }
    }

    Ok(None)
}

fn run_network_command(
    config: &Config,
    command: NetworkCommand,
    tool: NetworkTool,
) -> Result<Option<i32>, Box<dyn std::error::Error>> {
    let address = config.resolve(&command.alias)?;
    let invocation = Invocation::for_current_platform(tool, address, command.arguments);

    println!("Resolved: {} -> {address}", command.alias);
    println!("Command:  {invocation}");

    if command.dry_run {
        return Ok(None);
    }

    let status = invocation.execute()?;
    Ok(Some(status.code().unwrap_or(1)))
}
