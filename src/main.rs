use std::{ffi::OsString, net::Ipv6Addr, path::PathBuf};

use clap::{Args, Parser, Subcommand};
use v6alias::{
    Alias, Config, Invocation, NetworkTool, UlaPrefix, interface_views, local_interfaces,
    write_interfaces_colored,
};

mod presentation;
mod service_cli;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Human-friendly aliases for managed IPv6 ULA addresses"
)]
struct Cli {
    #[arg(short, long, default_value = "v6alias.yaml", global = true)]
    config: PathBuf,
    /// Color readable listings/previews; JSON and resolver output remain plain.
    #[arg(long, value_enum, default_value = "auto", global = true)]
    color: presentation::ColorMode,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Expand an alias such as corp:42 into an IPv6 address.
    Resolve { alias: Alias },
    /// Format a managed IPv6 address as its shortest alias.
    Reverse { address: Ipv6Addr },
    /// List local interface IPs; annotate only configured, representable ULA aliases.
    #[command(visible_alias = "ifconfig")]
    Interfaces {
        /// Exact OS interface name to display; omit to show all.
        #[arg(long)]
        interface: Option<String>,
        /// Show only actual IPs without reading the alias configuration.
        #[arg(long)]
        raw: bool,
        /// Emit structured JSON retaining actual addresses and optional aliases.
        #[arg(long)]
        json: bool,
    },
    /// Resolve an alias and run the platform ping command over IPv6.
    Ping(NetworkCommand),
    /// Resolve an alias and run tracert or traceroute over IPv6.
    #[command(alias = "tracert", alias = "traceroute")]
    Trace(NetworkCommand),
    /// Resolve an alias and run the OpenSSH client over IPv6.
    Ssh(NetworkCommand),
    /// Manage RFC 4193 Unique Local Address prefixes.
    Ula {
        #[command(subcommand)]
        command: UlaCommand,
    },
    /// Manage authoritative inventory in an explicit local database (offline).
    Inventory(service_cli::InventoryArgs),
    /// Explain offline policy using operator-supplied trusted link placement.
    Policy(service_cli::PolicyArgs),
    /// Allocate locally or preview service records offline; never contact endpoints.
    Service(service_cli::ServiceArgs),
}

#[derive(Debug, Subcommand)]
enum UlaCommand {
    /// Generate a cryptographically random locally assigned ULA /48.
    Generate,
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
    let colored = cli.color.enabled();

    match cli.command {
        Command::Resolve { alias } => {
            let config = Config::from_path(&cli.config)?;
            println!("{}", config.resolve(&alias)?);
        }
        Command::Reverse { address } => {
            let config = Config::from_path(&cli.config)?;
            println!("{}", config.reverse(address)?);
        }
        Command::Interfaces {
            interface,
            raw,
            json,
        } => {
            let config = if raw {
                None
            } else {
                Some(Config::from_path(&cli.config)?)
            };
            let views =
                interface_views(local_interfaces()?, config.as_ref(), interface.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&views)?);
            } else {
                let mut output = String::new();
                write_interfaces_colored(&mut output, &views, colored)?;
                presentation::print(&output, colored)?;
            }
        }
        Command::Ping(command) => {
            let config = Config::from_path(&cli.config)?;
            return run_network_command(&config, command, NetworkTool::Ping, colored);
        }
        Command::Trace(command) => {
            let config = Config::from_path(&cli.config)?;
            return run_network_command(&config, command, NetworkTool::Trace, colored);
        }
        Command::Ssh(command) => {
            let config = Config::from_path(&cli.config)?;
            return run_network_command(&config, command, NetworkTool::Ssh, colored);
        }
        Command::Ula {
            command: UlaCommand::Generate,
        } => println!("{}", UlaPrefix::generate()?),
        Command::Inventory(command) => return command.run(),
        Command::Policy(command) => return command.run(),
        Command::Service(command) => return command.run(),
    }

    Ok(None)
}

fn run_network_command(
    config: &Config,
    command: NetworkCommand,
    tool: NetworkTool,
    colored: bool,
) -> Result<Option<i32>, Box<dyn std::error::Error>> {
    let address = config.resolve(&command.alias)?;
    let invocation = Invocation::for_current_platform(tool, address, command.arguments);

    let cyan = if colored { "\x1b[1;96m" } else { "" };
    let green = if colored { "\x1b[1;92m" } else { "" };
    let reset = if colored { "\x1b[0m" } else { "" };
    presentation::print(
        &format!(
            "{cyan}Resolved:{reset} {green}{}{reset} -> {address}\n{cyan}Command:{reset}  {invocation}\n",
            command.alias
        ),
        colored,
    )?;

    if command.dry_run {
        return Ok(None);
    }

    let status = invocation.execute()?;
    Ok(Some(status.code().unwrap_or(1)))
}
