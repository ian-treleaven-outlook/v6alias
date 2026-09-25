use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use tempfile::TempDir;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn example(name: &str) -> PathBuf {
    root().join("examples").join("pfsense").join(name)
}

struct Fixture {
    directory: TempDir,
    database: PathBuf,
    capture: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix(".native-cli-")
            .tempdir_in(root())
            .unwrap();
        let database = directory.path().join("inventory.sqlite");
        let capture = directory.path().join("capture.json");
        let f = Self {
            directory,
            database,
            capture,
        };
        let mut baseline: Value =
            serde_json::from_slice(&fs::read(example("native-foreign.json")).unwrap()).unwrap();
        baseline["captured_at_unix_secs"] = json!(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        f.write("capture.json", &baseline);
        f
    }

    fn write(&self, name: &str, value: &Value) -> PathBuf {
        let path = self.directory.path().join(name);
        fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
        path
    }

    fn native(&self, operation: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_v6alias-pfsense"));
        command
            .current_dir(self.directory.path())
            .args(["--database"])
            .arg(&self.database)
            .arg("--service-config")
            .arg(example("service.yaml"))
            .arg("--bindings")
            .arg(example("bindings.json"))
            .arg("--capture")
            .arg(&self.capture)
            .arg(operation);
        command
    }

    fn setup(&self) {
        let mut inventory = Command::new(env!("CARGO_BIN_EXE_v6alias"));
        success(
            inventory
                .arg("inventory")
                .arg("--database")
                .arg(&self.database)
                .arg("init"),
        );
        let mut register = Command::new(env!("CARGO_BIN_EXE_v6alias"));
        success(
            register
                .arg("inventory")
                .arg("--database")
                .arg(&self.database)
                .arg("register")
                .arg("--device")
                .arg(example("device.json")),
        );
        let mut allocate = Command::new(env!("CARGO_BIN_EXE_v6alias"));
        let result = success(
            allocate
                .arg("service")
                .arg("--database")
                .arg(&self.database)
                .arg("--service-config")
                .arg(example("service.yaml"))
                .arg("allocate")
                .arg("--observation")
                .arg(example("observation.json"))
                .args(["--trusted-link", "demo-link"]),
        );
        assert_eq!(result["address"], "fd12:3456:789a:a::2");
    }
}

fn success(command: &mut Command) -> Value {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{:?}: {}",
        command,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(!output.stdout.contains(&27));
    serde_json::from_slice(&output.stdout).unwrap()
}

fn refused(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.len() < 1024);
    let diagnostic: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(diagnostic["event"], "refused");
    output
}

#[test]
fn actual_binary_roundtrip_replay_rollback_and_database_bytes_are_unchanged() {
    let f = Fixture::new();
    f.setup();
    let before = fs::read(&f.database).unwrap();
    let capture_before = fs::read(&f.capture).unwrap();
    let request = success(&mut f.native("plan"));
    assert_eq!(request["mode"], "native_plan");
    assert_eq!(request["changes"].as_array().unwrap().len(), 2);
    let request_path = f.write("request.json", &request);
    let simulation = success(f.native("simulate").arg("--request").arg(request_path));
    assert_eq!(simulation["mode"], "offline_simulation");
    let simulation_path = f.write("simulation.json", &simulation);
    let current_path = f.write("current.json", &simulation["projection"]);
    let rollback = success(
        f.native("rollback")
            .arg("--simulation")
            .arg(&simulation_path)
            .arg("--current")
            .arg(&current_path),
    );
    let original: Value = serde_json::from_slice(&capture_before).unwrap();
    assert_eq!(rollback["projection"]["config"], original["config"]);
    let rolled_path = f.write("rolled.json", &rollback["projection"]);
    refused(
        f.native("rollback")
            .arg("--simulation")
            .arg(&simulation_path)
            .arg("--current")
            .arg(rolled_path),
    );
    f.write("capture.json", &simulation["projection"]);
    assert!(
        success(&mut f.native("plan"))["changes"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(fs::read(&f.database).unwrap(), before);
}

#[test]
fn missing_read_only_inventory_never_initializes_or_writes_output() {
    let f = Fixture::new();
    refused(&mut f.native("plan"));
    assert!(!f.database.exists());
    assert_eq!(fs::read_dir(f.directory.path()).unwrap().count(), 1);
}

#[test]
fn drifted_revision_and_projection_refuse_without_input_changes() {
    let f = Fixture::new();
    f.setup();
    let request = success(&mut f.native("plan"));
    let request_path = f.write("request.json", &request);
    let original: Value = serde_json::from_slice(&fs::read(&f.capture).unwrap()).unwrap();
    for revision in [false, true] {
        let mut capture = original.clone();
        capture["config"]["opaque_synthetic_note"]["z"] = json!("concurrent");
        if revision {
            capture["config_revision_sha256"] = json!("3".repeat(64));
        }
        f.write("capture.json", &capture);
        let before = fs::read(&f.capture).unwrap();
        refused(f.native("simulate").arg("--request").arg(&request_path));
        assert_eq!(fs::read(&f.capture).unwrap(), before);
    }
}

#[test]
fn stale_future_unknown_envelope_and_incomplete_projection_refuse() {
    let f = Fixture::new();
    f.setup();
    let original: Value = serde_json::from_slice(&fs::read(&f.capture).unwrap()).unwrap();
    let now = original["captured_at_unix_secs"].as_u64().unwrap();
    for (field, value) in [
        ("captured_at_unix_secs", json!(now - 1000)),
        ("captured_at_unix_secs", json!(now + 3600)),
        ("complete", json!(false)),
        ("command", json!("never-executed")),
        ("dhcp_backend", json!("kea")),
    ] {
        let mut capture = original.clone();
        capture[field] = value;
        f.write("capture.json", &capture);
        refused(&mut f.native("plan"));
    }
}

#[test]
fn native_tracking_and_lossy_numbers_refuse_without_output_or_database_changes() {
    let f = Fixture::new();
    f.setup();
    let database = fs::read(&f.database).unwrap();
    let original: Value = serde_json::from_slice(&fs::read(&f.capture).unwrap()).unwrap();
    let mut tracked = original.clone();
    tracked["config"]["interfaces"]["lan"] =
        json!({"ipaddrv6":"track6","track6-interface":"wan","track6-prefix-id":"0"});
    f.write("capture.json", &tracked);
    refused(&mut f.native("plan"));
    for number in ["18446744073709551616", "18446744073709551617", "0.1"] {
        let mut capture = original.clone();
        capture["config"]["opaque_synthetic_note"]["number"] = json!("RAW_NUMBER");
        let raw = serde_json::to_string(&capture)
            .unwrap()
            .replace("\"RAW_NUMBER\"", number);
        fs::write(&f.capture, raw.as_bytes()).unwrap();
        refused(&mut f.native("plan"));
        assert_eq!(fs::read(&f.capture).unwrap(), raw.as_bytes());
    }
    assert_eq!(fs::read(&f.database).unwrap(), database);
}

#[test]
fn forged_request_and_rollback_token_refuse_without_overwriting_files() {
    let f = Fixture::new();
    f.setup();
    let mut request = success(&mut f.native("plan"));
    request["changes"][0]["path"]["interface"] = json!("../../filter");
    let path = f.write("tampered.json", &request);
    let before = fs::read(&path).unwrap();
    refused(f.native("simulate").arg("--request").arg(&path));
    assert_eq!(fs::read(path).unwrap(), before);
    let mut simulation = success(&mut f.native("simulate"));
    let current = f.write("current.json", &simulation["projection"]);
    simulation["rollback"]["candidate_projection_sha256"] = json!("3".repeat(64));
    let path = f.write("simulation.json", &simulation);
    refused(
        f.native("rollback")
            .arg("--simulation")
            .arg(path)
            .arg("--current")
            .arg(current),
    );
}

#[test]
fn live_apply_flags_paths_and_unsupported_output_files_are_not_available() {
    let f = Fixture::new();
    f.setup();
    for flag in ["--apply", "--ssh", "--program", "--output"] {
        refused(f.native("plan").arg(flag));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_v6alias-pfsense"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("rollback")
    );
}

#[cfg(unix)]
#[test]
fn nonregular_and_symlink_inputs_are_rejected_without_blocking() {
    let f = Fixture::new();
    f.setup();
    let saved = f.directory.path().join("saved.json");
    fs::rename(&f.capture, &saved).unwrap();
    std::os::unix::fs::symlink(&saved, &f.capture).unwrap();
    refused(&mut f.native("plan"));
    fs::remove_file(&f.capture).unwrap();
    fs::create_dir(&f.capture).unwrap();
    refused(&mut f.native("plan"));
}

#[test]
fn ttl_3600_is_observable_in_original_provider_neutral_cli() {
    let f = Fixture::new();
    f.setup();
    let mut command = Command::new(env!("CARGO_BIN_EXE_v6alias"));
    let plan = success(
        command
            .arg("service")
            .arg("--database")
            .arg(&f.database)
            .arg("--service-config")
            .arg(example("service.yaml"))
            .arg("plan"),
    );
    let records = plan["desired"]["dns_records"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|record| record["ttl"] == 3600));
    assert!(Path::new(env!("CARGO_BIN_EXE_v6alias-pfsense")).is_file());
}
