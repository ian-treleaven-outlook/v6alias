use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::{Value, json};
use v6alias_service::ServiceConfig;

struct Fixture {
    directory: tempfile::TempDir,
    source: PathBuf,
    destination: PathBuf,
    old: PathBuf,
    new: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix(".expansion-cli-")
            .tempdir_in(
                std::env::var_os("V6ALIAS_TEST_ROOT")
                    .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
            )
            .unwrap();
        let source = directory.path().join("source.sqlite");
        let destination = directory.path().join("expanded.sqlite");
        let old = directory.path().join("old.yaml");
        let new = directory.path().join("new.yaml");
        for (path, contents) in [
            (
                &old,
                include_str!("../examples/offline/service-corporate.yaml"),
            ),
            (&new, include_str!("../service.example.yaml")),
        ] {
            let mut config = ServiceConfig::from_yaml(contents).unwrap();
            config.dns_ttl_seconds = 3600;
            config
                .links
                .get_mut("corp-link")
                .unwrap()
                .reserved
                .insert(4);
            fs::write(path, serde_json::to_vec(&config).unwrap()).unwrap();
        }
        let fixture = Self {
            directory,
            source,
            destination,
            old,
            new,
        };
        success(fixture.inventory(&fixture.source).arg("init"));
        for id in 1..=4 {
            let device = fixture.directory.path().join(format!("device-{id}.json"));
            let observation = fixture.observation(id);
            fs::write(
                &device,
                serde_json::to_vec(&json!({
                    "asset_id": format!("asset-{id}"), "duid": format!("0001{id:08x}"),
                    "iaid": id, "managed": true, "dns_label": format!("host-{id}"),
                }))
                .unwrap(),
            )
            .unwrap();
            fs::write(
                &observation,
                serde_json::to_vec(&json!({
                    "duid": format!("0001{id:08x}"), "iaid": id, "hostname": null,
                }))
                .unwrap(),
            )
            .unwrap();
            success(
                fixture
                    .inventory(&fixture.source)
                    .args(["register", "--device"])
                    .arg(device),
            );
            if id <= 2 {
                assert_eq!(
                    fixture.allocate(&fixture.source, &fixture.old, id, "corp-link")["device"],
                    id + 1
                );
            }
        }
        success(fixture.service(&fixture.source, &fixture.old).args([
            "retire",
            "--asset-id",
            "asset-2",
        ]));
        fixture
    }

    fn command(&self) -> Command {
        let mut command = Command::new(
            std::env::var_os("V6ALIAS_TEST_BINARY")
                .unwrap_or_else(|| env!("CARGO_BIN_EXE_v6alias").into()),
        );
        command.current_dir(self.directory.path());
        command
    }

    fn inventory(&self, database: &Path) -> Command {
        let mut command = self.command();
        command.args(["inventory", "--database"]).arg(database);
        command
    }

    fn service(&self, database: &Path, config: &Path) -> Command {
        let mut command = self.command();
        command
            .args(["service", "--database"])
            .arg(database)
            .arg("--service-config")
            .arg(config);
        command
    }

    fn expand(&self) -> Command {
        let mut command = self.service(&self.source, &self.old);
        command
            .args(["expand-config", "--new-service-config"])
            .arg(&self.new)
            .arg("--destination")
            .arg(&self.destination);
        command
    }

    fn observation(&self, id: u32) -> PathBuf {
        self.directory.path().join(format!("observation-{id}.json"))
    }

    fn allocate(&self, database: &Path, config: &Path, id: u32, link: &str) -> Value {
        success(
            self.service(database, config)
                .args(["allocate", "--observation"])
                .arg(self.observation(id))
                .args(["--trusted-link", link]),
        )
    }

    fn assignments(&self, database: &Path, config: &Path) -> Value {
        success(self.service(database, config).arg("assignments"))
    }

    fn entries(&self) -> Vec<PathBuf> {
        let mut entries: Vec<_> = fs::read_dir(self.directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        entries.sort();
        entries
    }
}

fn run(command: &mut Command) -> Output {
    command
        .output()
        .unwrap_or_else(|error| panic!("{command:?}: {error}"))
}

fn success(command: &mut Command) -> Value {
    let output = run(command);
    assert!(
        output.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn failure(command: &mut Command) {
    let output = run(command);
    assert!(!output.status.success(), "{command:?}");
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty() && output.stderr.len() < 2200);
}

#[test]
fn real_cli_expansion_reopens_both_pins_replays_and_retains_tombstones() {
    let fixture = Fixture::new();
    let bytes = fs::read(&fixture.source).unwrap();
    let assignments = fixture.assignments(&fixture.source, &fixture.old);
    let inventory = success(fixture.inventory(&fixture.source).arg("list"));
    let receipt = success(&mut fixture.expand());
    assert_eq!(receipt["operation"], "additive_config_expansion");
    assert_eq!(receipt["devices"], 4);
    assert_eq!(receipt["active_assignments"], 1);
    assert_eq!(receipt["retired_assignments"], 1);
    for field in [
        "source_unchanged",
        "all_retained_records_verified",
        "needs_operator_cutover",
    ] {
        assert_eq!(receipt[field], true);
    }
    for field in [
        "before_config_identity_sha256",
        "after_config_identity_sha256",
        "retained_records_sha256",
    ] {
        assert_eq!(receipt[field].as_str().unwrap().len(), 64);
    }
    assert_ne!(
        receipt["before_config_identity_sha256"],
        receipt["after_config_identity_sha256"]
    );
    assert_eq!(
        fixture.assignments(&fixture.destination, &fixture.new),
        assignments
    );
    assert_eq!(
        success(fixture.inventory(&fixture.destination).arg("list")),
        inventory
    );
    assert_eq!(
        fixture.allocate(&fixture.destination, &fixture.new, 1, "corp-link"),
        assignments[0]
    );
    assert_eq!(
        fixture.allocate(&fixture.destination, &fixture.new, 3, "corp-link")["device"],
        5
    );
    assert_eq!(
        fixture.allocate(&fixture.destination, &fixture.new, 4, "lab-link")["device"],
        2
    );
    let unknown = fixture.observation(5);
    fs::write(
        &unknown,
        br#"{"duid":"00112233","iaid":5,"hostname":"corp-promotion"}"#,
    )
    .unwrap();
    let output = run(fixture
        .command()
        .args(["policy", "--database"])
        .arg(&fixture.destination)
        .arg("--service-config")
        .arg(&fixture.new)
        .args(["explain", "--observation"])
        .arg(&unknown)
        .args(["--trusted-link", "lab-link"]));
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["allowed"],
        false
    );
    failure(
        fixture
            .service(&fixture.source, &fixture.new)
            .arg("assignments"),
    );
    failure(
        fixture
            .service(&fixture.destination, &fixture.old)
            .arg("assignments"),
    );
    failure(
        fixture
            .service(&fixture.destination, &fixture.new)
            .args(["allocate", "--observation"])
            .arg(fixture.observation(2))
            .args(["--trusted-link", "corp-link"]),
    );
    let plan = success(
        fixture
            .service(&fixture.destination, &fixture.new)
            .arg("plan"),
    );
    assert_eq!(plan["desired"]["reservations"].as_array().unwrap().len(), 3);
    assert_eq!(
        fixture.assignments(&fixture.source, &fixture.old),
        assignments
    );
    assert_eq!(bytes, fs::read(&fixture.source).unwrap());
    assert!(!fixture.entries().iter().any(|path| {
        path.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(".v6alias-expand-")
    }));
}

#[test]
fn cli_rejects_changes_noops_bad_and_oversized_configs_without_artifacts() {
    let fixture = Fixture::new();
    let source = fs::read(&fixture.source).unwrap();
    let original = fs::read(&fixture.new).unwrap();
    let old = fs::read(&fixture.old).unwrap();
    let mut changed: Value = serde_json::from_slice(&original).unwrap();
    changed["dns_ttl_seconds"] = json!(300);
    for bytes in [
        serde_json::to_vec(&changed).unwrap(),
        old.clone(),
        b"unknown: invalid".to_vec(),
        vec![b' '; 1024 * 1024 + 1],
        b"\xff".to_vec(),
    ] {
        fs::write(&fixture.new, bytes).unwrap();
        let entries = fixture.entries();
        failure(&mut fixture.expand());
        assert_eq!(fixture.entries(), entries);
        assert_eq!(fs::read(&fixture.source).unwrap(), source);
    }
    fs::write(&fixture.new, original).unwrap();
    fs::write(&fixture.old, vec![b' '; 1024 * 1024 + 1]).unwrap();
    failure(&mut fixture.expand());
    assert!(!fixture.destination.exists());
}

#[test]
fn cli_never_overwrites_existing_destination_or_source_alias() {
    let mut fixture = Fixture::new();
    let source = fs::read(&fixture.source).unwrap();
    fs::write(&fixture.destination, b"foreign").unwrap();
    failure(&mut fixture.expand());
    assert_eq!(fs::read(&fixture.destination).unwrap(), b"foreign");
    fs::remove_file(&fixture.destination).unwrap();
    fs::hard_link(&fixture.source, &fixture.destination).unwrap();
    failure(&mut fixture.expand());
    assert_eq!(fs::read(&fixture.destination).unwrap(), source);
    fs::remove_file(&fixture.destination).unwrap();
    fixture.destination = fixture.source.clone();
    failure(&mut fixture.expand());
    #[cfg(windows)]
    {
        fixture.destination = fixture.source.with_file_name("SOURCE.SQLITE");
        failure(&mut fixture.expand());
    }
    assert_eq!(fs::read(&fixture.source).unwrap(), source);
}

#[test]
fn cli_requires_real_pinned_source_and_existing_destination_parent() {
    let mut fixture = Fixture::new();
    let source = fs::read(&fixture.source).unwrap();
    let original = fixture.source.clone();
    fixture.destination = fixture
        .directory
        .path()
        .join("missing-parent")
        .join("new.sqlite");
    failure(&mut fixture.expand());
    assert!(!fixture.directory.path().join("missing-parent").exists());
    fixture.destination = fixture.directory.path().join("new.sqlite");
    fixture.source = fixture.directory.path().join("missing.sqlite");
    failure(&mut fixture.expand());
    assert!(!fixture.source.exists());
    success(fixture.inventory(&fixture.source).arg("init"));
    let unpinned = fs::read(&fixture.source).unwrap();
    failure(&mut fixture.expand());
    assert_eq!(fs::read(&fixture.source).unwrap(), unpinned);
    fs::write(&fixture.source, b"not sqlite").unwrap();
    failure(&mut fixture.expand());
    assert_eq!(fs::read(original).unwrap(), source);
    assert!(!fixture.destination.exists());
}

#[cfg(unix)]
#[test]
fn cli_rejects_symlink_configs_and_parent_directories() {
    use std::os::unix::fs::symlink;
    let mut fixture = Fixture::new();
    let config = fixture.new.clone();
    fixture.new = fixture.directory.path().join("symlink.yaml");
    symlink(&config, &fixture.new).unwrap();
    failure(&mut fixture.expand());
    fixture.new = config;
    let parent = fixture.directory.path().join("parent");
    symlink(fixture.directory.path(), &parent).unwrap();
    fixture.destination = parent.join("new.sqlite");
    failure(&mut fixture.expand());
    assert!(!fixture.destination.exists());
}
