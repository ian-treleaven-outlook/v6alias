use std::{
    fs,
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use tempfile::TempDir;
use v6alias_service::{InventoryDevice, ServiceConfig, Store};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn backend_envelope(snapshot: &Value) -> Value {
    json!({
        "schema_version": 1,
        "captured_at_unix_secs": now(),
        "snapshot": snapshot
    })
}

fn empty_backend() -> Value {
    backend_envelope(&json!({
        "schema_version": 1, "owner": "v6alias", "reservations": [], "dns_records": []
    }))
}

struct Sandbox {
    directory: TempDir,
    database: PathBuf,
    config: PathBuf,
    observations: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        fs::create_dir_all(root.join("state")).unwrap();
        let directory = tempfile::Builder::new()
            .prefix("daemon-tests-")
            .tempdir_in(root.join("state"))
            .unwrap();
        let database = directory.path().join("inventory.sqlite");
        let config = directory.path().join("service.yaml");
        let observations = directory.path().join("observations.json");
        fs::copy(root.join("service.example.yaml"), &config).unwrap();
        // Exercise the original CLI's explicit initialization and registration contract.
        for tail in [
            vec!["init".into()],
            vec![
                "register".into(),
                "--device".into(),
                root.join("examples")
                    .join("offline")
                    .join("device.json")
                    .into_os_string(),
            ],
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_v6alias"))
                .arg("inventory")
                .arg("--database")
                .arg(&database)
                .args(tail)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let sandbox = Self {
            directory,
            database,
            config,
            observations,
        };
        sandbox.write(&sandbox.snapshot());
        sandbox
    }

    fn snapshot(&self) -> Value {
        let mut snapshot: Value = serde_json::from_str(include_str!(
            "../examples/offline/observation-snapshot.json"
        ))
        .unwrap();
        snapshot["captured_at_unix_secs"] = now().into();
        snapshot
    }

    fn write(&self, snapshot: &Value) {
        fs::write(&self.observations, serde_json::to_vec(snapshot).unwrap()).unwrap();
    }

    fn write_backend(&self, snapshot: &Value) -> PathBuf {
        let path = self.directory.path().join("observed.json");
        fs::write(&path, serde_json::to_vec(snapshot).unwrap()).unwrap();
        path
    }

    fn assert_unallocated_and_unpinned(&self) {
        let mut config = self.service_config();
        config.links.get_mut("corp-link").unwrap().pool.last -= 1;
        assert!(
            Store::read_only(&self.database)
                .unwrap()
                .assignments(&config)
                .unwrap()
                .is_empty()
        );
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_v6aliasd"));
        command
            .current_dir(self.directory.path())
            .arg("--database")
            .arg(&self.database)
            .arg("--service-config")
            .arg(&self.config)
            .arg("--observations")
            .arg(&self.observations)
            .args(["--source", "synthetic-corp", "--trusted-link", "corp-link"]);
        command
    }

    fn once(&self) -> Output {
        self.command().arg("--once").output().unwrap()
    }

    fn assignments(&self) -> Vec<v6alias_service::Assignment> {
        Store::read_only(&self.database)
            .unwrap()
            .assignments(&self.service_config())
            .unwrap()
    }

    fn service_config(&self) -> ServiceConfig {
        ServiceConfig::from_yaml(&fs::read_to_string(&self.config).unwrap()).unwrap()
    }

    fn register(&self, duid: &str, managed: bool) -> Value {
        let device = InventoryDevice {
            asset_id: format!("asset-{duid}"),
            duid: duid.parse().unwrap(),
            iaid: 1,
            managed,
            dns_label: format!("host-{duid}"),
        };
        Store::open_existing(&self.database)
            .unwrap()
            .register(&device)
            .unwrap();
        json!({"duid":duid, "iaid":1, "hostname":"untrusted-hint"})
    }
}

fn success(output: &Output) -> Value {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines = String::from_utf8_lossy(&output.stdout);
    assert_eq!(lines.lines().count(), 1);
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["mode"], "shadow");
    assert_eq!(value["event"], "cycle");
    assert_eq!(value["local_writes_permitted"], true);
    value
}

fn failure(output: &Output, code: i32) -> Vec<Value> {
    assert_eq!(
        output.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "failed cycle must not emit a plan"
    );
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

// Readers drain both pipes; RAII and deadlines prevent hung/background children on failure.
struct Running {
    child: Child,
    stdout: Receiver<String>,
    stderr: Option<thread::JoinHandle<String>>,
    reader: Option<thread::JoinHandle<()>>,
}

impl Running {
    fn spawn(command: &mut Command) -> Self {
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if sender.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        let stderr = thread::spawn(move || {
            let mut text = String::new();
            stderr.read_to_string(&mut text).unwrap();
            text
        });
        Self {
            child,
            stdout: receiver,
            stderr: Some(stderr),
            reader: Some(reader),
        }
    }

    fn line(&self) -> Value {
        serde_json::from_str(&self.stdout.recv_timeout(Duration::from_secs(20)).unwrap()).unwrap()
    }

    fn finish(&mut self, code: i32) -> String {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                let stderr = self.stderr.take().unwrap().join().unwrap();
                self.reader.take().unwrap().join().unwrap();
                assert_eq!(status.code(), Some(code), "{stderr}");
                return stderr;
            }
            assert!(Instant::now() < deadline, "daemon did not terminate");
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        if let Some(stderr) = self.stderr.take() {
            let _ = stderr.join();
        }
    }
}

#[test]
fn once_restart_replay_and_explicit_snapshot_semantics() {
    let sandbox = Sandbox::new();
    let first = success(&sandbox.once());
    assert_eq!(first["source"], "synthetic-corp");
    assert_eq!(first["trusted_link"], "corp-link");
    assert_eq!(first["outcomes"][0]["alias"], "corp:2");
    assert_eq!(
        first["outcomes"][0]["assignment"]["address"],
        "fd7a:115c:a1e0:17::2"
    );
    assert_eq!(
        first["outcomes"][0]["assignment"]["fqdn"],
        "demo-workstation.v6alias.home.arpa."
    );
    assert_eq!(first["plan"]["mode"], "dry_run");
    assert_eq!(first["plan"]["basis"], "desired_only");
    assert!(
        first["plan"]["changes"]
            .as_object()
            .unwrap()
            .values()
            .all(|v| v.as_array().unwrap().is_empty())
    );
    let replay = success(&sandbox.once());
    assert_eq!(first["outcomes"], replay["outcomes"]);
    assert_eq!(sandbox.assignments().len(), 1);

    let observed = sandbox.write_backend(&backend_envelope(&first["plan"]["desired"]));
    let matching = success(
        &sandbox
            .command()
            .arg("--once")
            .arg("--observed")
            .arg(&observed)
            .output()
            .unwrap(),
    );
    assert_eq!(matching["plan"]["basis"], "owned_snapshot");
    assert_eq!(matching["plan"]["changes"], first["plan"]["changes"]);
    sandbox.write_backend(&empty_backend());
    let empty = success(
        &sandbox
            .command()
            .arg("--once")
            .arg("--observed")
            .arg(&observed)
            .output()
            .unwrap(),
    );
    assert_eq!(
        empty["plan"]["changes"]["add_reservations"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        empty["plan"]["changes"]["add_dns_records"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn denials_are_explicit_and_absence_does_not_reclaim() {
    let sandbox = Sandbox::new();
    let denied = sandbox.register("0002", false);
    let mut snapshot = sandbox.snapshot();
    snapshot["observations"].as_array_mut().unwrap().extend([
        denied,
        json!({"duid":"0003","iaid":1,"hostname":"managed-admin"}),
    ]);
    sandbox.write(&snapshot);
    let result = success(&sandbox.once());
    let outcomes = result["outcomes"].as_array().unwrap();
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| o["decision"]["allowed"] == false && o["assignment"].is_null())
            .count(),
        2
    );
    assert_eq!(sandbox.assignments().len(), 1);
    assert_eq!(
        Store::read_only(&sandbox.database)
            .unwrap()
            .devices()
            .unwrap()
            .len(),
        2
    );
    snapshot["observations"] = json!([]);
    sandbox.write(&snapshot);
    let empty = success(&sandbox.once());
    assert_eq!(empty["outcomes"], json!([]));
    assert_eq!(
        empty["plan"]["desired"]["reservations"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    snapshot["observations"] = sandbox.snapshot()["observations"].clone();
    snapshot["observations"][0]["iaid"] = 99.into();
    sandbox.write(&snapshot);
    assert_eq!(
        success(&sandbox.once())["outcomes"][0]["decision"]["allowed"],
        false
    );
    assert_eq!(sandbox.assignments().len(), 1);
}

#[test]
fn strict_invalid_batches_never_allocate() {
    let sandbox = Sandbox::new();
    let original = sandbox.snapshot();
    let mut variants = Vec::new();
    for (field, value) in [
        ("schema_version", json!(2)),
        ("source", json!("other")),
        ("captured_at_unix_secs", json!(0)),
        ("captured_at_unix_secs", json!(u64::MAX)),
        ("captured_at_unix_secs", json!(-1)),
        ("trusted_link", json!("corp-link")),
    ] {
        let mut variant = original.clone();
        variant[field] = value;
        variants.push(variant);
    }
    for (field, value) in [
        ("link", json!("corp-link")),
        ("managed", json!(true)),
        ("hostname", json!("evil.example")),
        ("duid", json!("not-hex")),
        ("iaid", json!(4294967296_u64)),
    ] {
        let mut variant = original.clone();
        let mut invalid = original["observations"][0].clone();
        invalid["duid"] = "0002".into();
        invalid[field] = value;
        variant["observations"]
            .as_array_mut()
            .unwrap()
            .push(invalid);
        variants.push(variant);
    }
    let mut duplicate = original.clone();
    let mut other_iaid = duplicate["observations"][0].clone();
    other_iaid["iaid"] = 2.into();
    duplicate["observations"]
        .as_array_mut()
        .unwrap()
        .push(other_iaid);
    variants.push(duplicate);
    let mut excessive = original.clone();
    excessive["observations"] = Value::Array(
        (0..4097)
            .map(|i| json!({"duid":format!("{i:08x}"),"iaid":1}))
            .collect(),
    );
    variants.push(excessive);
    let mut missing = original.clone();
    missing.as_object_mut().unwrap().remove("observations");
    variants.push(missing);
    for variant in variants {
        sandbox.write(&variant);
        failure(&sandbox.once(), 1);
        assert!(sandbox.assignments().is_empty());
    }
    for text in [
        "{".to_owned(), String::new(), " ".repeat(1024 * 1024 + 1),
        r#"{"schema_version":1,"schema_version":1,"source":"synthetic-corp","captured_at_unix_secs":1,"observations":[]}"#.into(),
    ] {
        fs::write(&sandbox.observations, text).unwrap();
        failure(&sandbox.once(), 1);
        assert!(sandbox.assignments().is_empty());
    }
    fs::remove_file(&sandbox.observations).unwrap();
    failure(&sandbox.once(), 1);
}

#[test]
fn invalid_owned_snapshot_and_retired_conflicts_roll_back_whole_cycle() {
    let sandbox = Sandbox::new();
    let mut backend = empty_backend();
    backend["snapshot"]["owner"] = "untrusted".into();
    let observed = sandbox.write_backend(&backend);
    failure(
        &sandbox
            .command()
            .arg("--once")
            .arg("--observed")
            .arg(&observed)
            .output()
            .unwrap(),
        1,
    );
    assert!(sandbox.assignments().is_empty());
    // Oversized sparse file tests the separate 64 MiB reader bound.
    fs::File::create(&observed)
        .unwrap()
        .set_len(64 * 1024 * 1024 + 1)
        .unwrap();
    failure(
        &sandbox
            .command()
            .arg("--once")
            .arg("--observed")
            .arg(&observed)
            .output()
            .unwrap(),
        1,
    );
    assert!(sandbox.assignments().is_empty());
    success(&sandbox.once());
    Store::open_existing(&sandbox.database)
        .unwrap()
        .retire(&sandbox.service_config(), "demo-workstation")
        .unwrap();
    let mut snapshot = sandbox.snapshot();
    // This sorts before the retired asset; its tentative allocation must roll back.
    snapshot["observations"]
        .as_array_mut()
        .unwrap()
        .push(sandbox.register("0001", true));
    sandbox.write(&snapshot);
    failure(&sandbox.once(), 1);
    assert_eq!(sandbox.assignments().len(), 1);
}

#[test]
fn backend_envelope_rejects_stale_future_raw_and_malformed_without_pinning() {
    let sandbox = Sandbox::new();
    let original = empty_backend();
    let mut variants = vec![original["snapshot"].clone()];
    for (field, value) in [
        ("schema_version", json!(2)),
        ("captured_at_unix_secs", json!(0)),
        ("captured_at_unix_secs", json!(u64::MAX)),
        ("captured_at_unix_secs", json!(-1)),
        ("source", json!("unbound-source")),
    ] {
        let mut variant = original.clone();
        variant[field] = value;
        variants.push(variant);
    }
    for field in ["schema_version", "captured_at_unix_secs", "snapshot"] {
        let mut variant = original.clone();
        variant.as_object_mut().unwrap().remove(field);
        variants.push(variant);
    }
    for (field, value) in [
        ("owner", json!("unknown")),
        ("schema_version", json!(2)),
        ("unexpected", json!(true)),
        (
            "dns_records",
            json!([{"type": "AAAA", "name": "bad.", "value": "::1", "ttl": 0}]),
        ),
    ] {
        let mut variant = original.clone();
        variant["snapshot"][field] = value;
        variants.push(variant);
    }
    for variant in variants {
        let path = sandbox.write_backend(&variant);
        failure(
            &sandbox
                .command()
                .arg("--once")
                .arg("--observed")
                .arg(path)
                .output()
                .unwrap(),
            1,
        );
        sandbox.assert_unallocated_and_unpinned();
    }
    let path = sandbox.write_backend(&original);
    fs::write(
        &path,
        r#"{"schema_version":1,"schema_version":1,"captured_at_unix_secs":1,"snapshot":{}}"#,
    )
    .unwrap();
    failure(
        &sandbox
            .command()
            .arg("--once")
            .arg("--observed")
            .arg(&path)
            .output()
            .unwrap(),
        1,
    );
    sandbox.assert_unallocated_and_unpinned();
    // The original offline CLI still accepts the unwrapped reconciliation contract.
    sandbox.write_backend(&original["snapshot"]);
    let offline = Command::new(env!("CARGO_BIN_EXE_v6alias"))
        .arg("service")
        .arg("--database")
        .arg(&sandbox.database)
        .arg("--service-config")
        .arg(&sandbox.config)
        .arg("plan")
        .arg("--observed")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        offline.status.success(),
        "{}",
        String::from_utf8_lossy(&offline.stderr)
    );
}

#[test]
fn malformed_later_backend_record_rejects_entire_new_batch() {
    let sandbox = Sandbox::new();
    let first = success(&sandbox.once());
    let mut backend = backend_envelope(&first["plan"]["desired"]);
    // A valid known first record must not hide an invalid later record.
    backend["snapshot"]["dns_records"][1]["ttl"] = 0.into();
    let path = sandbox.write_backend(&backend);
    let mut observations = sandbox.snapshot();
    observations["observations"] = json!([
        sandbox.register("0001", true),
        sandbox.register("0002", true)
    ]);
    sandbox.write(&observations);
    failure(
        &sandbox
            .command()
            .arg("--once")
            .arg("--observed")
            .arg(&path)
            .output()
            .unwrap(),
        1,
    );
    assert_eq!(sandbox.assignments().len(), 1);
    backend["snapshot"]["dns_records"][1]["extra"] = true.into();
    sandbox.write_backend(&backend);
    failure(
        &sandbox
            .command()
            .arg("--once")
            .arg("--observed")
            .arg(&path)
            .output()
            .unwrap(),
        1,
    );
    assert_eq!(sandbox.assignments().len(), 1);
    assert_eq!(
        success(&sandbox.once())["outcomes"][0]["assignment"]["device"],
        3
    );
}

#[test]
fn loop_rejects_aging_backend_even_when_observations_are_refreshed() {
    let sandbox = Sandbox::new();
    let backend = empty_backend();
    let path = sandbox.write_backend(&backend);
    let mut running = Running::spawn(sandbox.command().arg("--observed").arg(path).args([
        "--poll-ms",
        "100",
        "--max-age-secs",
        "1",
        "--max-retries",
        "3",
        "--retry-ms",
        "100",
        "--max-retry-ms",
        "200",
    ]));
    let first = running.line();
    assert_eq!(
        first["backend_captured_at_unix_secs"],
        backend["captured_at_unix_secs"]
    );
    // Mounted filesystems can briefly fail opens during replacement; exercise the
    // supported retry path rather than confuse that race with backend freshness.
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline && running.child.try_wait().unwrap().is_none() {
        let next = sandbox.directory.path().join("observations.next");
        fs::write(&next, serde_json::to_vec(&sandbox.snapshot()).unwrap()).unwrap();
        fs::rename(next, &sandbox.observations).unwrap();
        thread::sleep(Duration::from_millis(50));
    }
    let stderr = running.finish(1);
    assert!(stderr.contains("backend snapshot is stale"), "{stderr}");
    assert!(
        !stderr.contains("observation snapshot is stale"),
        "{stderr}"
    );
    assert_eq!(sandbox.assignments().len(), 1);
}

#[test]
fn allocator_skips_reservations_and_permanent_tombstones() {
    let sandbox = Sandbox::new();
    let config = fs::read_to_string(&sandbox.config)
        .unwrap()
        .replace("reserved: [53]", "reserved: [2, 4, 53]");
    fs::write(&sandbox.config, config).unwrap();
    assert_eq!(success(&sandbox.once())["outcomes"][0]["alias"], "corp:3");
    Store::open_existing(&sandbox.database)
        .unwrap()
        .retire(&sandbox.service_config(), "demo-workstation")
        .unwrap();
    let mut snapshot = sandbox.snapshot();
    snapshot["observations"] = json!([sandbox.register("0005", true)]);
    sandbox.write(&snapshot);
    assert_eq!(success(&sandbox.once())["outcomes"][0]["alias"], "corp:5");
    assert_eq!(sandbox.assignments().len(), 2);
}

#[test]
fn database_must_already_be_recognized_and_config_compatible() {
    let sandbox = Sandbox::new();
    fs::remove_file(&sandbox.database).unwrap();
    failure(&sandbox.once(), 1);
    assert!(!sandbox.database.exists());
    for bytes in [vec![], b"not sqlite".to_vec()] {
        fs::write(&sandbox.database, &bytes).unwrap();
        failure(&sandbox.once(), 1);
        assert_eq!(fs::read(&sandbox.database).unwrap(), bytes);
    }
    fs::remove_file(&sandbox.database).unwrap();
    let mut store = Store::open(&sandbox.database).unwrap();
    let device: InventoryDevice =
        serde_json::from_str(include_str!("../examples/offline/device.json")).unwrap();
    store.register(&device).unwrap();
    drop(store);
    success(&sandbox.once());
    let config = fs::read_to_string(&sandbox.config)
        .unwrap()
        .replace("reserved: [53]", "reserved: [54]");
    fs::write(&sandbox.config, config).unwrap();
    failure(&sandbox.once(), 1);
}

#[test]
fn retry_budget_and_argument_bounds_have_nonzero_structured_errors() {
    let sandbox = Sandbox::new();
    fs::write(&sandbox.observations, "{").unwrap();
    let mut running = Running::spawn(sandbox.command().args([
        "--max-retries",
        "2",
        "--retry-ms",
        "100",
        "--max-retry-ms",
        "150",
    ]));
    let stderr = running.finish(1);
    assert!(running.stdout.try_recv().is_err());
    let errors: Vec<Value> = stderr
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|value| value["event"] == "cycle_error")
        .collect();
    assert_eq!(errors.len(), 3);
    assert_eq!(errors[0]["details"]["retry_in_ms"], 100);
    assert_eq!(errors[1]["details"]["retry_in_ms"], 150);
    assert_eq!(errors[2]["details"]["will_retry"], false);
    for args in [
        vec!["--poll-ms", "99"],
        vec!["--poll-ms", "3600001"],
        vec!["--max-retries", "21"],
        vec!["--max-age-secs", "0"],
        vec!["--max-age-secs", "86401"],
        vec!["--retry-ms", "0"],
        vec!["--max-retry-ms", "300001"],
        vec!["--apply"],
    ] {
        failure(&sandbox.command().args(args).output().unwrap(), 2);
    }
    failure(
        &sandbox
            .command()
            .args(["--retry-ms", "200", "--max-retry-ms", "100"])
            .output()
            .unwrap(),
        1,
    );
    failure(
        &Command::new(env!("CARGO_BIN_EXE_v6aliasd"))
            .arg("--once")
            .output()
            .unwrap(),
        2,
    );
    let errors = failure(&sandbox.once(), 1);
    assert_eq!(
        errors
            .iter()
            .filter(|e| e["event"] == "cycle_error")
            .count(),
        1
    );
}

#[test]
fn concurrent_daemons_replay_one_assignment() {
    let sandbox = Sandbox::new();
    let mut first = Running::spawn(sandbox.command().arg("--once"));
    let mut second = Running::spawn(sandbox.command().arg("--once"));
    let a = first.line();
    let b = second.line();
    first.finish(0);
    second.finish(0);
    assert_eq!(a["outcomes"], b["outcomes"]);
    assert_eq!(sandbox.assignments().len(), 1);
}

#[test]
fn loop_reads_new_snapshots_retries_without_stale_output_and_recovers() {
    let sandbox = Sandbox::new();
    let running = Running::spawn(sandbox.command().args([
        "--poll-ms",
        "100",
        "--retry-ms",
        "100",
        "--max-retries",
        "20",
    ]));
    assert_eq!(running.line()["outcomes"][0]["alias"], "corp:2");
    // Wait for a complete repeat first, proving this is not a renamed once command.
    assert_eq!(running.line()["outcomes"][0]["alias"], "corp:2");
    fs::write(&sandbox.observations, "{").unwrap();
    thread::sleep(Duration::from_millis(350));
    while running.stdout.try_recv().is_ok() {}
    assert!(
        running
            .stdout
            .recv_timeout(Duration::from_millis(150))
            .is_err()
    );
    let mut snapshot = sandbox.snapshot();
    snapshot["observations"] = json!([sandbox.register("0005", true)]);
    sandbox.write(&snapshot);
    let recovered = running.line();
    assert_eq!(recovered["outcomes"][0]["alias"], "corp:3");
    // A hard stop simulates loss after commit/publication; restart must reuse its ID.
    drop(running);
    assert_eq!(success(&sandbox.once())["outcomes"], recovered["outcomes"]);
    assert_eq!(sandbox.assignments().len(), 2);
}

#[cfg(unix)]
#[test]
fn signals_interrupt_poll_and_backoff_without_leaving_children() {
    for signal in ["-TERM", "-INT"] {
        let sandbox = Sandbox::new();
        let mut running = Running::spawn(sandbox.command().args(["--poll-ms", "3600000"]));
        running.line();
        assert!(
            Command::new("kill")
                .args([signal, &running.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let stderr = running.finish(0);
        assert!(stderr.contains("\"event\":\"shutdown\""));
    }
    let sandbox = Sandbox::new();
    let mut running = Running::spawn(sandbox.command().args([
        "--poll-ms",
        "100",
        "--retry-ms",
        "60000",
        "--max-retry-ms",
        "60000",
    ]));
    running.line();
    fs::write(&sandbox.observations, "{").unwrap();
    thread::sleep(Duration::from_millis(350));
    assert!(
        Command::new("kill")
            .args(["-TERM", &running.child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let stderr = running.finish(1);
    assert!(stderr.contains("\"event\":\"cycle_error\""));
    assert!(stderr.contains("\"failed_cycle_pending\":true"));
}

#[test]
fn nonregular_input_is_rejected_without_blocking() {
    let sandbox = Sandbox::new();
    fs::remove_file(&sandbox.observations).unwrap();
    fs::create_dir(&sandbox.observations).unwrap();
    let mut running = Running::spawn(sandbox.command().arg("--once"));
    assert!(running.finish(1).contains("regular file"));
    assert!(sandbox.assignments().is_empty());
}

#[cfg(target_os = "linux")]
mod pipe_tests {
    use super::*;

    fn oversized_publication(sandbox: &Sandbox, stderr: bool) {
        let mut snapshot = sandbox.snapshot();
        if stderr {
            snapshot["x".repeat(256 * 1024)] = true.into();
        } else {
            snapshot["observations"]
                .as_array_mut()
                .unwrap()
                .extend((0..4095).map(|i| json!({"duid": format!("{i:08x}"), "iaid": 1})));
        }
        sandbox.write(&snapshot);
    }

    struct ChildGuard {
        child: Child,
        reader: Option<thread::JoinHandle<()>>,
    }

    impl ChildGuard {
        fn spawn(command: &mut Command) -> Self {
            Self {
                child: command
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap(),
                reader: None,
            }
        }

        fn finish(&mut self, limit: Duration) {
            let deadline = Instant::now() + limit;
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    assert_eq!(status.code(), Some(1), "{status}");
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "publication prevented bounded shutdown"
                );
                thread::sleep(Duration::from_millis(10));
            }
        }

        fn hold_after_prefix(&mut self, stderr: bool, skip_started: bool) -> Box<dyn Read + Send> {
            let mut pipe: Box<dyn Read + Send> = if stderr {
                Box::new(self.child.stderr.take().unwrap())
            } else {
                Box::new(self.child.stdout.take().unwrap())
            };
            let (sender, ready) = mpsc::sync_channel(1);
            self.reader = Some(thread::spawn(move || {
                let result = (|| {
                    let mut byte = [0];
                    if skip_started {
                        loop {
                            pipe.read_exact(&mut byte)?;
                            if byte[0] == b'\n' {
                                break;
                            }
                        }
                    }
                    pipe.read_exact(&mut byte)
                })();
                // Return the still-open consumer without draining the oversized line.
                let _ = sender.send((pipe, result));
            }));
            let (pipe, result) = ready.recv_timeout(Duration::from_secs(10)).unwrap();
            result.unwrap();
            self.reader.take().unwrap().join().unwrap();
            pipe
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
        }
    }

    #[test]
    fn signals_terminate_blocked_stdout_and_stderr_with_failure() {
        for signal in ["-TERM", "-INT"] {
            for stream in ["stdout", "stderr", "argument_error"] {
                let sandbox = Sandbox::new();
                let mut command = sandbox.command();
                command.arg("--once");
                match stream {
                    "stdout" => oversized_publication(&sandbox, false),
                    "stderr" => oversized_publication(&sandbox, true),
                    _ => {
                        command.arg(format!("--{}", "x".repeat(100_000)));
                    }
                }
                let mut running = ChildGuard::spawn(&mut command);
                let pipe = running.hold_after_prefix(stream != "stdout", stream == "stderr");
                thread::sleep(Duration::from_millis(100));
                assert!(
                    running.child.try_wait().unwrap().is_none(),
                    "{stream} did not block"
                );
                assert!(
                    Command::new("kill")
                        .args([signal, &running.child.id().to_string()])
                        .status()
                        .unwrap()
                        .success()
                );
                running.finish(Duration::from_secs(2));
                // Keep the consumer open until after exit: EOF/EPIPE cannot rescue the writer.
                drop(pipe);
                if stream == "stdout" {
                    let mut diagnostics = String::new();
                    running
                        .child
                        .stderr
                        .take()
                        .unwrap()
                        .read_to_string(&mut diagnostics)
                        .unwrap();
                    assert!(diagnostics.contains("stdout publication"), "{diagnostics}");
                    assert!(diagnostics.contains("\"event\":\"fatal\""), "{diagnostics}");
                }
            }
        }
    }

    #[test]
    fn blocked_fatal_diagnostic_has_a_deadline_without_a_signal() {
        let sandbox = Sandbox::new();
        fs::write(
            &sandbox.config,
            format!("\"{}\": true\n", "x".repeat(256 * 1024)),
        )
        .unwrap();
        let mut running = ChildGuard::spawn(sandbox.command().arg("--once"));
        let pipe = running.hold_after_prefix(true, false);
        running.finish(Duration::from_secs(2));
        drop(pipe);
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("service.example.yaml"),
            &sandbox.config,
        )
        .unwrap();
        sandbox.assert_unallocated_and_unpinned();
    }

    #[test]
    fn broken_stdout_and_stderr_are_not_successful_publications() {
        for stderr in [false, true] {
            let sandbox = Sandbox::new();
            oversized_publication(&sandbox, stderr);
            let mut running = ChildGuard::spawn(sandbox.command().arg("--once"));
            if stderr {
                drop(running.child.stderr.take());
            } else {
                drop(running.child.stdout.take());
            }
            running.finish(Duration::from_secs(2));
            if !stderr {
                let mut diagnostics = String::new();
                running
                    .child
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut diagnostics)
                    .unwrap();
                assert!(diagnostics.contains("stdout publication"), "{diagnostics}");
            }
        }
    }
}
