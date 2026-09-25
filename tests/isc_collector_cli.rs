use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use tempfile::TempDir;
use v6alias_service::{ServiceConfig, Store};

const ACTIVE: &str = include_str!("../examples/isc/synthetic-active.leases");
const EMPTY: &str = include_str!("../examples/isc/synthetic-empty.leases");

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct Sandbox {
    directory: TempDir,
    capture: PathBuf,
    config: PathBuf,
    database: PathBuf,
    snapshot: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        fs::create_dir_all(root.join("state")).unwrap();
        let directory = tempfile::Builder::new()
            .prefix("isc-tests-")
            .tempdir_in(root.join("state"))
            .unwrap();
        let sandbox = Self {
            capture: directory.path().join("capture.json"),
            config: directory.path().join("service.yaml"),
            database: directory.path().join("inventory.sqlite"),
            snapshot: directory.path().join("observations.json"),
            directory,
        };
        fs::copy(root.join("service.example.yaml"), &sandbox.config).unwrap();
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
                .args(["inventory", "--database"])
                .arg(&sandbox.database)
                .args(tail)
                .output()
                .unwrap();
            assert!(output.status.success(), "{:?}", output);
        }
        sandbox.write(ACTIVE);
        sandbox
    }

    fn write(&self, leases: &str) -> Value {
        let time = now();
        let value = json!({
            "schema_version": 1, "source": "synthetic-isc",
            "captured_at_unix_secs": time,
            "lease_file": leases.replace("ends never;", &format!("ends epoch {};", time + 3600))
        });
        self.write_value(&value);
        value
    }

    fn write_value(&self, value: &Value) {
        fs::write(&self.capture, serde_json::to_vec(value).unwrap()).unwrap();
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_v6alias-collect-isc"));
        cmd.current_dir(self.directory.path())
            .arg("--capture")
            .arg(&self.capture)
            .arg("--service-config")
            .arg(&self.config)
            .args(["--source", "synthetic-isc", "--trusted-link", "corp-link"]);
        cmd
    }

    fn collect(&self) -> Output {
        self.command().arg("--once").output().unwrap()
    }

    fn daemon(&self) -> Value {
        let output = Command::new(env!("CARGO_BIN_EXE_v6aliasd"))
            .arg("--database")
            .arg(&self.database)
            .arg("--service-config")
            .arg(&self.config)
            .arg("--observations")
            .arg(&self.snapshot)
            .args([
                "--source",
                "synthetic-isc",
                "--trusted-link",
                "corp-link",
                "--once",
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn assert_unallocated(&self) {
        let store = Store::read_only(&self.database).unwrap();
        let mut config = ServiceConfig::from_path(&self.config).unwrap();
        config.links.get_mut("corp-link").unwrap().pool.last -= 1;
        assert!(store.assignments(&config).unwrap().is_empty());
        assert_eq!(store.devices().unwrap().len(), 1);
    }
}

fn failure(output: Output, expected: &str) {
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        output.stdout.is_empty(),
        "invalid capture must emit no stdout"
    );
    assert!(!output.stderr.contains(&0x1b));
    let lines: Vec<Value> = String::from_utf8(output.stderr)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(
        lines
            .iter()
            .any(|v| v["event"] == "fatal"
                && v["details"]["error"].as_str().unwrap().contains(expected)),
        "{lines:?}"
    );
}

#[test]
fn collector_to_shadow_daemon_allocates_replays_and_never_auto_registers() {
    let s = Sandbox::new();
    let raw_before = fs::read(&s.capture).unwrap();
    let db_before = fs::read(&s.database).unwrap();
    let output = s
        .command()
        .env("CLICOLOR_FORCE", "1")
        .env("FORCE_COLOR", "1")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(!output.stdout.contains(&0x1b));
    assert_eq!(fs::read(&s.capture).unwrap(), raw_before);
    assert_eq!(fs::read(&s.database).unwrap(), db_before);
    let normalized: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(normalized["observations"][0]["iaid"], 1);
    assert_eq!(normalized["observations"][0]["hostname"], Value::Null);
    let capture: Value = serde_json::from_slice(&raw_before).unwrap();
    assert_eq!(
        normalized["captured_at_unix_secs"],
        capture["captured_at_unix_secs"]
    );
    let diag: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(
        diag["details"]["counts"]["filtered_other_link_associations"],
        1
    );
    fs::write(&s.snapshot, &output.stdout).unwrap();
    let first = s.daemon();
    assert_eq!(first["outcomes"][0]["alias"], "corp:2");
    assert_eq!(
        first["outcomes"][0]["assignment"]["address"],
        "fd7a:115c:a1e0:17::2"
    );
    assert_eq!(
        first["outcomes"][0]["assignment"]["fqdn"],
        "demo-workstation.v6alias.home.arpa."
    );
    assert_eq!(first["plan"]["basis"], "desired_only");
    assert_eq!(first["outcomes"], s.daemon()["outcomes"]);
    s.write(&format!("{ACTIVE}\nia-na 01:00:00:00:cc:dd {{ iaaddr fd7a:115c:a1e0:17::1001 {{ binding state active; preferred-life 60; max-life 120; ends never; }} }}"));
    let output = s.collect();
    assert!(output.status.success());
    fs::write(&s.snapshot, output.stdout).unwrap();
    let result = s.daemon();
    assert_eq!(result["outcomes"].as_array().unwrap().len(), 2);
    let unknown = result["outcomes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["duid"] == "ccdd")
        .unwrap();
    assert_eq!(unknown["decision"]["allowed"], false);
    assert!(unknown["assignment"].is_null());
    let store = Store::read_only(&s.database).unwrap();
    assert_eq!(store.devices().unwrap().len(), 1);
    assert_eq!(
        store
            .assignments(&ServiceConfig::from_path(&s.config).unwrap())
            .unwrap()
            .len(),
        1
    );
    // Disappearance is not inventory deletion or assignment retirement.
    s.write(EMPTY);
    let output = s.collect();
    assert!(output.status.success());
    fs::write(&s.snapshot, output.stdout).unwrap();
    assert!(s.daemon()["outcomes"].as_array().unwrap().is_empty());
    assert_eq!(
        Store::read_only(&s.database)
            .unwrap()
            .assignments(&ServiceConfig::from_path(&s.config).unwrap())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn repeated_server_header_accepts_empty_capture_but_rejects_identity_change() {
    let s = Sandbox::new();
    let capture = s.write(EMPTY);
    let before = fs::read(&s.database).unwrap();
    let output = s.collect();
    assert!(output.status.success(), "{output:?}");
    let snapshot: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(snapshot["observations"].as_array().unwrap().is_empty());
    assert_eq!(
        snapshot["captured_at_unix_secs"],
        capture["captured_at_unix_secs"]
    );
    assert_eq!(fs::read(&s.database).unwrap(), before);
    s.write(&format!("{EMPTY}\nserver-duid 00:01:ff;"));
    failure(s.collect(), "conflicting server-duid");
    assert_eq!(fs::read(&s.database).unwrap(), before);
    s.assert_unallocated();
}

#[test]
fn invalid_late_record_provenance_and_timestamps_leave_no_output_or_writes() {
    let s = Sandbox::new();
    let db = fs::read(&s.database).unwrap();
    s.write(&format!("{ACTIVE}\nia-na 01:00:00:00:cc:dd {{"));
    failure(s.collect(), "unexpected end");
    for (field, bad, error) in [
        ("source", json!("wrong-source"), "source"),
        ("captured_at_unix_secs", json!(now() - 1000), "stale"),
        ("captured_at_unix_secs", json!(now() + 3600), "future"),
        ("schema_version", json!(2), "version"),
        ("extra", json!(1), "unknown field"),
    ] {
        let mut value = s.write(ACTIVE);
        value[field] = bad;
        s.write_value(&value);
        failure(s.collect(), error);
    }
    assert_eq!(fs::read(&s.database).unwrap(), db);
    s.assert_unallocated();
}

#[test]
fn empty_metadata_only_capture_succeeds_but_missing_and_zero_byte_inputs_fail() {
    let s = Sandbox::new();
    s.write("server-duid 00:01:aa;");
    let output = s.collect();
    assert!(output.status.success(), "{output:?}");
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(value["observations"].as_array().unwrap().is_empty());
    s.write("");
    failure(s.collect(), "header");
    fs::write(&s.capture, []).unwrap();
    failure(s.collect(), "EOF");
    fs::remove_file(&s.capture).unwrap();
    let output = s.collect();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    s.assert_unallocated();
}

#[test]
fn bounded_regular_files_and_cli_flags_fail_closed() {
    let s = Sandbox::new();
    fs::remove_file(&s.capture).unwrap();
    fs::create_dir(&s.capture).unwrap();
    failure(s.collect(), "regular");
    fs::remove_dir(&s.capture).unwrap();
    fs::File::create(&s.capture)
        .unwrap()
        .set_len(v6alias_service::isc::MAX_CAPTURE_BYTES + 1)
        .unwrap();
    failure(s.collect(), "67108864");
    s.write(ACTIVE);
    fs::File::create(&s.config)
        .unwrap()
        .set_len(1024 * 1024 + 1)
        .unwrap();
    failure(s.collect(), "1048576");
    for args in [
        vec!["--apply"],
        vec!["--max-age-secs", "0"],
        vec!["--max-age-secs", "86401"],
        vec!["--now", "0"],
    ] {
        let output = s.command().args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stderr).unwrap()["event"],
            "argument_error"
        );
    }
    let help = s
        .command()
        .arg("--help")
        .env("CLICOLOR_FORCE", "1")
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(!help.stdout.contains(&0x1b));
}

#[cfg(unix)]
#[test]
fn symlinks_and_devices_are_rejected_before_opening() {
    let mut s = Sandbox::new();
    let saved = s.directory.path().join("saved.json");
    fs::rename(&s.capture, &saved).unwrap();
    std::os::unix::fs::symlink(&saved, &s.capture).unwrap();
    failure(s.collect(), "regular");
    fs::remove_file(&s.capture).unwrap();
    // DrvFS cannot create FIFOs. A character device exercises the same
    // nonregular-file guard without depending on that filesystem feature.
    s.capture = PathBuf::from("/dev/null");
    failure(s.collect(), "regular");
    s.assert_unallocated();
}

#[cfg(unix)]
#[test]
fn non_draining_stdout_exits_within_publication_deadline() {
    use std::{
        io::Read,
        process::Stdio,
        thread,
        time::{Duration, Instant},
    };
    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let s = Sandbox::new();
    let mut text = String::from("authoring-byte-order little-endian;\n");
    for i in 0..4096 {
        text.push_str(&format!("ia-na 01:00:00:00:{:02x}:{:02x} {{ iaaddr fd7a:115c:a1e0:17::{:x} {{ binding state active; preferred-life 60; max-life 120; ends never; }} }}\n", i >> 8, i & 255, i + 4096));
    }
    s.write(&text);
    let mut child = OwnedChild(
        s.command()
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            started.elapsed() < Duration::from_secs(12),
            "publisher failed to stop"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert!(!status.success());
    let mut error = String::new();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut error)
        .unwrap();
    assert!(
        error.contains("stdout publication did not complete"),
        "{error}"
    );
    s.assert_unallocated();
}
