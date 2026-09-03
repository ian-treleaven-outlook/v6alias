use std::{net::Ipv6Addr, path::PathBuf};

use clap::{Parser, Subcommand};
use v6alias::{Alias, Config};

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
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let config = Config::from_path(cli.config)?;

    match cli.command {
        Command::Resolve { alias } => println!("{}", config.resolve(&alias)?),
        Command::Reverse { address } => println!("{}", config.reverse(address)?),
    }

    Ok(())
}
