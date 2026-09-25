use std::{
    error::Error,
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use v6alias::publication::{Publisher, Shutdown};
use v6alias_service::{
    ServiceConfig, Store,
    shadow::{
        BackendSnapshot, MAX_INPUT_BYTES, MAX_SNAPSHOT_BYTES, ObservationSnapshot, SourceBinding,
    },
    validate_dns_label,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug, Parser)]
#[command(
    name = "v6aliasd",
    version,
    about = "Foreground shadow observer: local assignments and review plans only; no network I/O"
)]
struct Args {
    /// Existing recognized inventory; never created or initialized by the daemon.
    #[arg(long)]
    database: PathBuf,
    #[arg(long)]
    service_config: PathBuf,
    /// Strict normalized JSON snapshot file, not a raw DHCP lease file.
    #[arg(long)]
    observations: PathBuf,
    /// Expected provenance label; binds this entire file to --trusted-link.
    #[arg(long)]
    source: String,
    /// Operator-verified placement, never derived from client data.
    #[arg(long)]
    trusted_link: String,
    /// Optional versioned, timestamped backend envelope; never assume an empty backend.
    #[arg(long)]
    observed: Option<PathBuf>,
    /// One cycle; no retries. Otherwise poll until interrupted or retries are exhausted.
    #[arg(long)]
    once: bool,
    #[arg(long, default_value_t = 5000, value_parser = clap::value_parser!(u64).range(100..=3_600_000))]
    poll_ms: u64,
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..=86400))]
    max_age_secs: u64,
    /// Additional attempts after a failed cycle; counter resets only on success.
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u32).range(0..=20))]
    max_retries: u32,
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(100..=60000))]
    retry_ms: u64,
    #[arg(long, default_value_t = 30000, value_parser = clap::value_parser!(u64).range(100..=300000))]
    max_retry_ms: u64,
}

struct Output {
    stdout: Publisher,
    stderr: Publisher,
}

impl Output {
    fn diagnostic(
        &mut self,
        event: &str,
        details: serde_json::Value,
        shutdown: Option<&Shutdown>,
    ) -> Result<()> {
        let mut bytes = serde_json::to_vec(
            &json!({"schema_version": 1, "mode": "shadow", "event": event, "details": details}),
        )?;
        bytes.push(b'\n');
        // Final diagnostics get a short bounded attempt even after an interrupt.
        self.stderr.publish(
            bytes,
            if shutdown.is_some() {
                Duration::from_secs(5)
            } else {
                Duration::from_millis(100)
            },
            || shutdown.is_some_and(Shutdown::requested),
        )?;
        Ok(())
    }

    fn emit(&mut self, value: &impl Serialize, shutdown: &Shutdown) -> Result<()> {
        let mut bytes = serde_json::to_vec(value)?;
        bytes.push(b'\n');
        self.stdout
            .publish(bytes, Duration::from_secs(5), || shutdown.requested())?;
        Ok(())
    }
}

fn main() -> ExitCode {
    let mut stderr = match Publisher::new("stderr", io::stderr()) {
        Ok(publisher) => publisher,
        Err(_) => return ExitCode::FAILURE,
    };
    let stdout = match Publisher::new("stdout", io::stdout()) {
        Ok(publisher) => publisher,
        Err(error) => {
            let bytes = format!(
                "{}\n",
                json!({"schema_version": 1, "mode": "shadow", "event": "fatal",
                       "details": {"error": error.to_string()}})
            );
            // No usable stdout worker; even startup failure must not block on stderr.
            if stderr
                .publish(bytes.into_bytes(), Duration::from_millis(100), || false)
                .is_err()
            {
                return ExitCode::FAILURE;
            }
            return ExitCode::FAILURE;
        }
    };
    let mut output = Output { stdout, stderr };
    let result = execute(&mut output);
    match result {
        Ok(code) => code,
        Err(error) => {
            if output
                .diagnostic("fatal", json!({"error": error.to_string()}), None)
                .is_err()
            {
                return ExitCode::FAILURE;
            }
            ExitCode::FAILURE
        }
    }
}

fn execute(output: &mut Output) -> Result<ExitCode> {
    let shutdown = Shutdown::install()?;
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(error) if !error.use_stderr() => {
            output.stdout.publish(
                error.to_string().into_bytes(),
                Duration::from_secs(5),
                || shutdown.requested(),
            )?;
            return Ok(ExitCode::SUCCESS);
        }
        Err(error) => {
            output.diagnostic(
                "argument_error",
                json!({"error": error.to_string()}),
                Some(&shutdown),
            )?;
            return Ok(ExitCode::from(2));
        }
    };
    run(&args, output, &shutdown)?;
    Ok(ExitCode::SUCCESS)
}

fn read_input(path: &Path, limit: u64) -> Result<Vec<u8>> {
    // Refuse directories/devices/FIFOs before open, which could otherwise block forever.
    // The operator must protect the source directory against hostile replacement races.
    if !fs::metadata(path)?.is_file() {
        return Err(format!("input `{}` must be a regular file", path.display()).into());
    }
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err("input changed to a non-regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(format!("input `{}` exceeds {limit} bytes", path.display()).into());
    }
    Ok(bytes)
}

fn read_json<T: DeserializeOwned>(path: &Path, limit: u64) -> Result<T> {
    serde_json::from_slice(&read_input(path, limit)?)
        .map_err(|error| format!("invalid JSON in `{}`: {error}", path.display()).into())
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn cycle(args: &Args, config: &ServiceConfig, store: &mut Store) -> Result<serde_json::Value> {
    let snapshot: ObservationSnapshot = read_json(&args.observations, MAX_INPUT_BYTES)?;
    let observed: Option<BackendSnapshot> = args
        .observed
        .as_deref()
        .map(|path| read_json(path, MAX_SNAPSHOT_BYTES))
        .transpose()?;
    let evaluated_at = now()?;
    snapshot.validate(&args.source, evaluated_at, args.max_age_secs)?;
    let result = store.shadow_cycle(
        config,
        &snapshot,
        &SourceBinding {
            source: &args.source,
            trusted_link: &args.trusted_link,
            max_age_secs: args.max_age_secs,
        },
        observed.as_ref(),
    )?;
    Ok(json!({
        "schema_version": 1,
        "event": "cycle",
        "mode": "shadow",
        "local_writes_permitted": true,
        "source": snapshot.source,
        "trusted_link": args.trusted_link,
        "captured_at_unix_secs": snapshot.captured_at_unix_secs,
        "backend_captured_at_unix_secs": observed.as_ref().map(|s| s.captured_at_unix_secs),
        "evaluated_at_unix_secs": evaluated_at,
        "outcomes": result.outcomes,
        "plan": result.plan
    }))
}

fn retry_delay(args: &Args, failures: u32) -> Duration {
    Duration::from_millis(
        args.retry_ms
            .saturating_mul(1_u64 << failures.saturating_sub(1).min(20))
            .min(args.max_retry_ms),
    )
}

fn wait_for_shutdown(
    shutdown: &Shutdown,
    output: &mut Output,
    delay: Duration,
    failed: bool,
) -> Result<bool> {
    if !shutdown.wait(delay)? {
        return Ok(false);
    }
    output.diagnostic(
        "shutdown",
        json!({"reason": "interrupt", "failed_cycle_pending": failed}),
        None,
    )?;
    if failed {
        return Err("interrupted while a failed cycle was pending; no fresh plan available".into());
    }
    Ok(true)
}

fn run(args: &Args, output: &mut Output, shutdown: &Shutdown) -> Result<()> {
    if args.retry_ms > args.max_retry_ms {
        return Err("--retry-ms must not exceed --max-retry-ms".into());
    }
    validate_dns_label(&args.source)?;
    validate_dns_label(&args.trusted_link)?;
    let config = ServiceConfig::from_yaml(std::str::from_utf8(&read_input(
        &args.service_config,
        MAX_INPUT_BYTES,
    )?)?)?;
    if !config.links.contains_key(&args.trusted_link) {
        return Err("unknown --trusted-link in service configuration".into());
    }
    let mut store = Store::open_existing(&args.database)?;
    store.assignments(&config)?;
    output.diagnostic(
        "started",
        json!({"source": args.source, "trusted_link": args.trusted_link, "once": args.once}),
        Some(shutdown),
    )?;
    let mut failures = 0;
    loop {
        if wait_for_shutdown(shutdown, output, Duration::ZERO, failures > 0)? {
            return Ok(());
        }
        let delay = match cycle(args, &config, &mut store) {
            Ok(result) => {
                // A commit precedes publication. Broken output is fatal, not a retryable
                // input error; restarting safely replays the committed assignments.
                output.emit(&result, shutdown)?;
                failures = 0;
                if args.once {
                    return Ok(());
                }
                Duration::from_millis(args.poll_ms)
            }
            Err(error) => {
                failures += 1;
                let retry = !args.once && failures <= args.max_retries;
                let delay = retry_delay(args, failures);
                output.diagnostic(
                    "cycle_error",
                    json!({
                        "error": error.to_string(), "consecutive_failures": failures,
                        "will_retry": retry,
                        "retry_in_ms": if retry { Some(delay.as_millis()) } else { None }
                    }),
                    Some(shutdown),
                )?;
                if !retry {
                    return Err("cycle failed; retry budget exhausted (or --once)".into());
                }
                delay
            }
        };
        if wait_for_shutdown(shutdown, output, delay, failures > 0)? {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exponential_backoff_is_capped() {
        let args = Args::parse_from([
            "v6aliasd",
            "--database",
            "db",
            "--service-config",
            "cfg",
            "--observations",
            "obs",
            "--source",
            "source",
            "--trusted-link",
            "corp-link",
        ]);
        for (failures, expected) in [
            (1, 1000),
            (2, 2000),
            (5, 16000),
            (6, 30000),
            (u32::MAX, 30000),
        ] {
            assert_eq!(retry_delay(&args, failures).as_millis(), expected);
        }
    }
}
