use std::{
    error::Error,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use clap::{ArgGroup, Args, Subcommand};
use serde::{Serialize, de::DeserializeOwned};
use v6alias_service::{
    Decision, InventoryDevice, Observation, ServiceConfig, Store, reconcile, validate_dns_label,
};

type CliResult = Result<Option<i32>, Box<dyn Error>>;

const MAX_INPUT_BYTES: u64 = 1024 * 1024;
const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;

// A required group enforces --database without clap's required-global restriction.
#[derive(Debug, Args)]
#[command(group(ArgGroup::new("database-required").args(["database"]).required(true)))]
pub struct InventoryArgs {
    /// Explicit local SQLite database path; no default database is created.
    #[arg(long, global = true, required = false, value_name = "PATH")]
    database: PathBuf,
    #[command(subcommand)]
    command: InventoryCommand,
}

#[derive(Debug, Subcommand)]
enum InventoryCommand {
    /// Initialize or validate the local inventory database offline.
    Init,
    /// Register authoritative inventory from a strictly validated JSON device file.
    Register {
        #[arg(long, value_name = "PATH")]
        device: PathBuf,
    },
    /// List authoritative inventory without creating or changing the database.
    List,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("database-required").args(["database"]).required(true)))]
pub struct PolicyArgs {
    /// Existing local SQLite inventory database.
    #[arg(long, global = true, required = false, value_name = "PATH")]
    database: PathBuf,
    /// Offline service policy YAML, independent of the resolver's --config.
    #[arg(
        long,
        global = true,
        default_value = "service.example.yaml",
        value_name = "PATH"
    )]
    service_config: PathBuf,
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Explain policy offline without modifying the database; denial exits with code 2.
    Explain(ObservationArgs),
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("database-required").args(["database"]).required(true)))]
pub struct ServiceArgs {
    /// Explicit local SQLite inventory database.
    #[arg(long, global = true, required = false, value_name = "PATH")]
    database: PathBuf,
    /// Offline service policy YAML, independent of the resolver's --config.
    #[arg(
        long,
        global = true,
        default_value = "service.example.yaml",
        value_name = "PATH"
    )]
    service_config: PathBuf,
    #[command(subcommand)]
    command: ServiceCommand,
}

#[derive(Debug, Subcommand)]
enum ServiceCommand {
    /// Persist a permanent local assignment offline; never configure a live endpoint.
    Allocate(ObservationArgs),
    /// Read active assignments and permanent retired tombstones without modifying them.
    Assignments,
    /// Permanently retire an assignment; its tombstone prevents address reuse.
    Retire {
        #[arg(long, value_name = "ID")]
        asset_id: String,
    },
    /// Preview desired records and optional snapshot differences offline; never apply changes.
    Plan {
        /// Strict JSON snapshot of observed records; no endpoint is queried.
        #[arg(long, value_name = "PATH")]
        observed: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
struct ObservationArgs {
    /// Strict JSON observation containing guest identity and an optional hostname hint.
    #[arg(long, value_name = "PATH")]
    observation: PathBuf,
    /// Trusted placement supplied by the operator, never by guest observation JSON.
    #[arg(long, value_name = "LINK")]
    trusted_link: String,
}

impl InventoryArgs {
    pub fn run(self) -> CliResult {
        match self.command {
            InventoryCommand::Init => {
                Store::open(&self.database)?;
                print_json(&serde_json::json!({
                    "schema_version": 1,
                    "initialized": true
                }))?;
            }
            InventoryCommand::Register { device: path } => {
                let device: InventoryDevice = read_json(&path)?;
                device
                    .validate()
                    .map_err(|error| format!("invalid device in `{}`: {error}", path.display()))?;
                let mut store = Store::open(&self.database)?;
                print_json(&store.register(&device)?)?;
            }
            InventoryCommand::List => {
                let store = Store::read_only(&self.database)?;
                print_json(&store.devices()?)?;
            }
        }
        Ok(None)
    }
}

impl PolicyArgs {
    pub fn run(self) -> CliResult {
        let config = read_config(&self.service_config)?;
        match self.command {
            PolicyCommand::Explain(arguments) => {
                let observation: Observation = read_json(&arguments.observation)?;
                let store = Store::read_only(&self.database)?;
                let decision = store.explain(&config, &observation, &arguments.trusted_link)?;
                print_decision(&decision)
            }
        }
    }
}

impl ServiceArgs {
    pub fn run(self) -> CliResult {
        let config = read_config(&self.service_config)?;
        match self.command {
            ServiceCommand::Allocate(arguments) => {
                let observation: Observation = read_json(&arguments.observation)?;
                {
                    let store = Store::read_only(&self.database)?;
                    store.assignments(&config)?;
                }
                let mut store = Store::open(&self.database)?;
                print_json(&store.allocate(&config, &observation, &arguments.trusted_link)?)?;
            }
            ServiceCommand::Assignments => {
                let store = Store::read_only(&self.database)?;
                print_json(&store.assignments(&config)?)?;
            }
            ServiceCommand::Retire { asset_id } => {
                validate_dns_label(&asset_id)?;
                {
                    let store = Store::read_only(&self.database)?;
                    store.assignments(&config)?;
                }
                let mut store = Store::open(&self.database)?;
                print_json(&store.retire(&config, &asset_id)?)?;
            }
            ServiceCommand::Plan { observed } => {
                let snapshot: Option<reconcile::Snapshot> =
                    observed.as_deref().map(read_snapshot).transpose()?;
                let store = Store::read_only(&self.database)?;
                let assignments = store.assignments(&config)?;
                print_json(&reconcile::plan(&config, &assignments, snapshot.as_ref())?)?;
            }
        }
        Ok(None)
    }
}

fn read_input(path: &Path, max_bytes: u64) -> Result<Vec<u8>, Box<dyn Error>> {
    let file = File::open(path)
        .map_err(|error| format!("cannot open input `{}`: {error}", path.display()))?;
    let mut reader = file.take(max_bytes + 1);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read input `{}`: {error}", path.display()))?;
    if reader.limit() == 0 {
        return Err(format!(
            "input `{}` exceeds the {} MiB limit",
            path.display(),
            max_bytes / (1024 * 1024)
        )
        .into());
    }
    Ok(bytes)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, Box<dyn Error>> {
    serde_json::from_slice(&read_input(path, MAX_INPUT_BYTES)?)
        .map_err(|error| format!("invalid JSON in `{}`: {error}", path.display()).into())
}

fn read_snapshot(path: &Path) -> Result<reconcile::Snapshot, Box<dyn Error>> {
    serde_json::from_slice(&read_input(path, MAX_SNAPSHOT_BYTES)?)
        .map_err(|error| format!("invalid snapshot JSON in `{}`: {error}", path.display()).into())
}

fn read_config(path: &Path) -> Result<ServiceConfig, Box<dyn Error>> {
    let bytes = read_input(path, MAX_INPUT_BYTES)?;
    let yaml = std::str::from_utf8(&bytes)
        .map_err(|error| format!("invalid UTF-8 in `{}`: {error}", path.display()))?;
    ServiceConfig::from_yaml(yaml)
        .map_err(|error| format!("invalid service config `{}`: {error}", path.display()).into())
}

fn print_json(value: &impl Serialize) -> Result<(), Box<dyn Error>> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn print_decision(decision: &Decision) -> CliResult {
    print_json(decision)?;
    Ok(if decision.allowed { None } else { Some(2) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use v6alias_core::Alias;
    use v6alias_service::{Assignment, AssignmentState};

    #[test]
    fn full_pool_snapshot_round_trips_through_the_cli_reader() {
        let config = ServiceConfig::from_yaml(include_str!("../service.example.yaml")).unwrap();
        let assignments = (2..=4095_u16)
            .filter(|n| *n != 53)
            .map(|device| Assignment {
                asset_id: format!("asset-{device}"),
                duid: format!("0001{device:04x}").parse().unwrap(),
                iaid: u32::from(device),
                link: "corp-link".into(),
                profile: "corp".into(),
                subnet: 23,
                device,
                address: config
                    .address_config()
                    .resolve(&Alias {
                        profile: "corp".into(),
                        subnet: Some(23),
                        device,
                    })
                    .unwrap(),
                fqdn: config.fqdn(&format!("host-{device}")).unwrap(),
                state: AssignmentState::Active,
                policy_rule: "managed-corporate".into(),
            })
            .collect::<Vec<_>>();
        let desired = reconcile::plan(&config, &assignments, None)
            .unwrap()
            .desired;
        let bytes = serde_json::to_vec_pretty(&desired).unwrap();
        assert!(bytes.len() as u64 > MAX_INPUT_BYTES);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("observed.json");
        std::fs::write(&path, bytes).unwrap();
        let read_back = read_snapshot(&path).unwrap();
        assert_eq!(read_back, desired);
        assert_eq!(
            reconcile::plan(&config, &assignments, Some(&read_back))
                .unwrap()
                .changes,
            reconcile::Changes::default()
        );
    }
}
