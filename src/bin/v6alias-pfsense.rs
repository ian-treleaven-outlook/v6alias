use std::{
    error::Error,
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::{ColorChoice, Parser, Subcommand};
use v6alias::publication::{Publisher, Shutdown};
use v6alias_service::{
    ServiceConfig, Store,
    pfsense::{self, Bindings, MAX_BYTES, Projection, Request, Simulation},
    shadow::MAX_INPUT_BYTES,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[cfg(unix)]
fn same_file(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.dev() == after.dev() && before.ino() == after.ino()
}

#[cfg(not(unix))]
fn same_file(_: &fs::Metadata, _: &fs::Metadata) -> bool {
    // Stable portable metadata has no Windows file identity; directory trust is required.
    true
}

#[derive(Debug, Parser)]
#[command(
    name = "v6alias-pfsense", version, color = ColorChoice::Never,
    about = "Native pfSense request compiler and offline projection simulator; no live apply or network I/O"
)]
struct Args {
    /// Existing authoritative inventory, opened read-only; never initialized.
    #[arg(long)]
    database: PathBuf,
    /// Service configuration pinned to DNS TTL 3600.
    #[arg(long)]
    service_config: PathBuf,
    /// Operator link/interface mapping and independently approved addresses.
    #[arg(long)]
    bindings: PathBuf,
    /// Complete fresh native baseline projection, not config.xml.
    #[arg(long)]
    capture: PathBuf,
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..=86400))]
    max_age_secs: u64,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Compile guarded native collection replacements; write JSON to stdout only.
    Plan,
    /// Recompile an optional reviewed request and transform the supplied projection locally.
    Simulate {
        #[arg(long)]
        request: Option<PathBuf>,
    },
    /// Reverse an exact simulated candidate only; requires original baseline and unchanged authority.
    Rollback {
        #[arg(long)]
        simulation: PathBuf,
        #[arg(long)]
        current: PathBuf,
    },
}

fn read_regular(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() || before.len() > limit {
        return Err("input must be a bounded regular non-symlink file".into());
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if bytes.len() as u64 > limit
        || bytes.len() as u64 != before.len()
        || [opened, after, named].iter().any(|m| {
            !m.is_file()
                || m.len() != before.len()
                || m.modified().ok() != before.modified().ok()
                || m.created().ok() != before.created().ok()
                || !same_file(&before, m)
        })
    {
        return Err("input changed while reading".into());
    }
    Ok(bytes)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(pfsense::from_json(&read_regular(path, MAX_BYTES)?)?)
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn run(stdout: &mut Publisher, shutdown: &Shutdown) -> Result<()> {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(error) if !error.use_stderr() => {
            stdout.publish(
                error.to_string().into_bytes(),
                Duration::from_secs(5),
                || shutdown.requested(),
            )?;
            return Ok(());
        }
        // Do not echo untrusted CLI values or input contents in diagnostics.
        Err(_) => return Err("invalid arguments; use --help (no live apply option exists)".into()),
    };
    let config = ServiceConfig::from_yaml(std::str::from_utf8(&read_regular(
        &args.service_config,
        MAX_INPUT_BYTES,
    )?)?)?;
    let bindings: Bindings = read_json(&args.bindings)?;
    let baseline: Projection = read_json(&args.capture)?;
    let store = Store::read_only(&args.database)?;
    let compiled = pfsense::compile(
        &store,
        &config,
        &bindings,
        &baseline,
        now()?,
        args.max_age_secs,
    )?;
    let value = match args.command {
        Command::Plan => serde_json::to_value(&compiled)?,
        Command::Simulate { request } => {
            let request: Request = request
                .as_deref()
                .map(read_json)
                .transpose()?
                .unwrap_or_else(|| compiled.clone());
            serde_json::to_value(pfsense::simulate(
                &store,
                &config,
                &bindings,
                &baseline,
                &request,
                now()?,
                args.max_age_secs,
            )?)?
        }
        Command::Rollback {
            simulation,
            current,
        } => {
            let simulation: Simulation = read_json(&simulation)?;
            let current: Projection = read_json(&current)?;
            serde_json::to_value(pfsense::rollback(
                &store,
                &config,
                &bindings,
                &baseline,
                (&current, &simulation),
                now()?,
                args.max_age_secs,
            )?)?
        }
    };
    let mut bytes = serde_json::to_vec_pretty(&value)?;
    if bytes.len() as u64 >= MAX_BYTES {
        return Err("output exceeds 16 MiB".into());
    }
    bytes.push(b'\n');
    // Re-read authoritative history and recheck original capture freshness immediately
    // before publication. No long-lived request can bypass an intervening retirement.
    if pfsense::canonical_sha256(&compiled)?
        != pfsense::canonical_sha256(&pfsense::compile(
            &store,
            &config,
            &bindings,
            &baseline,
            now()?,
            args.max_age_secs,
        )?)?
    {
        return Err("authoritative inventory changed before publication".into());
    }
    baseline.validate_freshness(&bindings.source, now()?, args.max_age_secs)?;
    stdout.publish(bytes, Duration::from_secs(5), || shutdown.requested())?;
    Ok(())
}

fn main() -> ExitCode {
    let Ok(mut stderr) = Publisher::new("stderr", io::stderr()) else {
        return ExitCode::FAILURE;
    };
    let result = (|| {
        let shutdown = Shutdown::install()?;
        let mut stdout = Publisher::new("stdout", io::stdout())?;
        run(&mut stdout, &shutdown)
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            // Deliberately bounded and payload-free, including parser/SQLite errors.
            let _ = stderr.publish(
                b"{\"schema_version\":1,\"mode\":\"offline_simulation\",\"event\":\"refused\",\"network_writes\":false,\"error\":\"invalid input, stale capture, unsupported contract, authority mismatch, conflict, or publication failure; no files written\"}\n".to_vec(),
                Duration::from_millis(100), || false,
            );
            ExitCode::FAILURE
        }
    }
}
