use std::{
    error::Error,
    fs::{self, File, Metadata},
    io::{self, Read},
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::{ColorChoice, Parser};
use serde_json::json;
use v6alias::publication::{Publisher, Shutdown};
use v6alias_service::{
    ServiceConfig,
    isc::{Capture, MAX_CAPTURE_BYTES, collect},
    shadow::MAX_INPUT_BYTES,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug, Parser)]
#[command(
    name = "v6alias-collect-isc",
    version,
    color = ColorChoice::Never,
    about = "Read-only ISC DHCPv6 capture normalizer; one finite run, no network or database writes"
)]
struct Args {
    /// Strict JSON with schema_version, source, captured_at_unix_secs, lease_file.
    #[arg(long)]
    capture: PathBuf,
    #[arg(long)]
    service_config: PathBuf,
    /// Expected local operator-managed provenance label (not authentication).
    #[arg(long)]
    source: String,
    /// Filter by the configured /64 after validating ALL live identities and scopes.
    #[arg(long)]
    trusted_link: String,
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..=86400))]
    max_age_secs: u64,
    /// Explicit spelling of the default: always finite, never polls.
    #[arg(long)]
    once: bool,
}

fn unchanged(before: &Metadata, after: &Metadata) -> bool {
    before.is_file()
        && after.is_file()
        && before.len() == after.len()
        && before.modified().ok() == after.modified().ok()
        && before.created().ok() == after.created().ok()
        && same_file(before, after)
}

#[cfg(unix)]
fn same_file(before: &Metadata, after: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.dev() == after.dev() && before.ino() == after.ino()
}

#[cfg(not(unix))]
fn same_file(_: &Metadata, _: &Metadata) -> bool {
    // Portable metadata cannot establish Windows file identity on stable Rust.
    true
}

fn read_regular(path: &Path, limit: u64) -> Result<Vec<u8>> {
    // Refuse symlinks as well as devices/FIFOs before open. A protected directory
    // is still necessary: portable pre-open metadata cannot eliminate hostile races.
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err("input must be a regular, non-symlink file".into());
    }
    if before.len() > limit {
        return Err(format!("input exceeds {limit} bytes").into());
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if !unchanged(&before, &opened) {
        return Err("input changed before reading".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(format!("input exceeds {limit} bytes").into());
    }
    let after = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if bytes.len() as u64 != opened.len()
        || !unchanged(&opened, &after)
        || !unchanged(&opened, &named)
    {
        return Err("input changed while reading; recapture and retry".into());
    }
    Ok(bytes)
}

fn diagnostic(stderr: &mut Publisher, event: &str, details: serde_json::Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(&json!({
        "schema_version": 1, "mode": "read_only", "collector": "isc",
        "event": event, "details": details
    }))?;
    bytes.push(b'\n');
    stderr.publish(bytes, Duration::from_millis(100), || false)?;
    Ok(())
}

fn run(stdout: &mut Publisher, stderr: &mut Publisher) -> Result<ExitCode> {
    let shutdown = Shutdown::install()?;
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(error) if !error.use_stderr() => {
            stdout.publish(
                error.to_string().into_bytes(),
                Duration::from_secs(5),
                || shutdown.requested(),
            )?;
            return Ok(ExitCode::SUCCESS);
        }
        Err(error) => {
            diagnostic(
                stderr,
                "argument_error",
                json!({"error": error.to_string()}),
            )?;
            return Ok(ExitCode::from(2));
        }
    };
    if shutdown.requested() {
        return Err("collection interrupted".into());
    }
    let capture = Capture::from_json(&read_regular(&args.capture, MAX_CAPTURE_BYTES)?)?;
    let config = ServiceConfig::from_yaml(std::str::from_utf8(&read_regular(
        &args.service_config,
        MAX_INPUT_BYTES,
    )?)?)?;
    let result = collect(
        &capture,
        &config,
        &args.source,
        &args.trusted_link,
        args.max_age_secs,
    )?;
    let bytes = result.snapshot_json()?;
    diagnostic(
        stderr,
        "validated",
        json!({
            "source": args.source, "trusted_link": args.trusted_link,
            "captured_at_unix_secs": capture.captured_at_unix_secs, "counts": result.counts
        }),
    )?;
    // Preserve source capture time and recheck it after parsing/serialization.
    result.snapshot.validate(
        &args.source,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        args.max_age_secs,
    )?;
    stdout.publish(bytes, Duration::from_secs(5), || shutdown.requested())?;
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let Ok(mut stderr) = Publisher::new("stderr", io::stderr()) else {
        return ExitCode::FAILURE;
    };
    let mut stdout = match Publisher::new("stdout", io::stdout()) {
        Ok(stdout) => stdout,
        Err(error) => {
            let _ = diagnostic(&mut stderr, "fatal", json!({"error": error.to_string()}));
            return ExitCode::FAILURE;
        }
    };
    match run(&mut stdout, &mut stderr) {
        Ok(code) => code,
        Err(error) => {
            let _ = diagnostic(&mut stderr, "fatal", json!({"error": error.to_string()}));
            ExitCode::FAILURE
        }
    }
}
