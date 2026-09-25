use std::{
    fs,
    net::Ipv6Addr,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::{Value, json};
use tempfile::TempDir;

const NORMALIZED_DUID: &str = "000400112233445566778899aabbccddeeff";
const CORPORATE_ADDRESS: &str = "fd7a:115c:a1e0:17::2";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture(name: &str) -> PathBuf {
    root().join("examples").join("offline").join(name)
}

fn fixture_json(name: &str) -> Value {
    serde_json::from_slice(&fs::read(fixture(name)).unwrap()).unwrap()
}

struct Sandbox {
    directory: TempDir,
    database: PathBuf,
    config: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix(".service-cli-")
            .tempdir_in(root())
            .unwrap();
        let database = directory.path().join("inventory.sqlite");
        Self {
            directory,
            database,
            config: root().join("service.example.yaml"),
        }
    }

    fn cli(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_v6alias"));
        command.current_dir(self.directory.path());
        command
    }

    fn scoped(&self, group: &str) -> Command {
        let mut command = self.cli();
        command.arg(group).arg("--database").arg(&self.database);
        if group != "inventory" {
            command.arg("--service-config").arg(&self.config);
        }
        command
    }

    fn write_json(&self, name: &str, value: &Value) -> PathBuf {
        let path = self.directory.path().join(name);
        fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
        path
    }

    fn init(&self) {
        let result = success(self.scoped("inventory").arg("init"));
        assert_eq!(result["schema_version"], 1);
        assert_eq!(result["initialized"], true);
        assert!(self.database.is_file());
    }

    fn register(&self, device: &Path) -> Value {
        success(
            self.scoped("inventory")
                .arg("register")
                .arg("--device")
                .arg(device),
        )
    }

    fn observation_command(&self, group: &str, input: &Path, link: &str) -> Command {
        let mut command = self.scoped(group);
        command
            .arg(if group == "policy" {
                "explain"
            } else {
                "allocate"
            })
            .arg("--observation")
            .arg(input)
            .arg("--trusted-link")
            .arg(link);
        command
    }

    fn explain(&self, input: &Path, link: &str) -> Value {
        success(&mut self.observation_command("policy", input, link))
    }

    fn allocate(&self, input: &Path, link: &str) -> Value {
        success(&mut self.observation_command("service", input, link))
    }

    fn assignments(&self) -> Value {
        success(self.scoped("service").arg("assignments"))
    }

    fn plan(&self, observed: Option<&Path>) -> Value {
        let mut command = self.scoped("service");
        command.arg("plan");
        if let Some(observed) = observed {
            command.arg("--observed").arg(observed);
        }
        success(&mut command)
    }
}

fn run(command: &mut Command) -> Output {
    command
        .output()
        .unwrap_or_else(|error| panic!("could not run {command:?}: {error}"))
}

fn json_status(command: &mut Command, code: i32) -> Value {
    let output = run(command);
    assert_eq!(
        output.status.code(),
        Some(code),
        "{command:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    let value: Value = serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{command:?}: invalid JSON ({error}): {text}"));
    if value.as_object().is_some_and(|object| !object.is_empty())
        || value.as_array().is_some_and(|array| !array.is_empty())
    {
        assert!(text.contains("\n  "), "expected pretty JSON: {text}");
    }
    value
}

fn success(command: &mut Command) -> Value {
    json_status(command, 0)
}

fn failure(command: &mut Command) {
    let output = run(command);
    assert!(
        !output.status.success(),
        "{command:?} unexpectedly succeeded: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .to_ascii_lowercase()
            .contains("error"),
        "{command:?} did not report an error on stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn text_success(command: &mut Command) -> String {
    let output = run(command);
    assert!(
        output.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn assert_decision(decision: &Value, allowed: bool) {
    assert_eq!(decision["allowed"], allowed);
    assert!(!decision["reason"].as_str().unwrap().is_empty());
    for field in ["matched_rule", "profile", "subnet", "trace"] {
        assert!(decision.get(field).is_some(), "missing {field}: {decision}");
    }
    assert!(decision["trace"].is_array());
}

fn assert_plan(plan: &Value, basis: &str, reservations: usize, dns_records: usize) {
    assert_eq!(plan["mode"], "dry_run");
    assert_eq!(plan["basis"], basis);
    assert_eq!(plan["desired"]["schema_version"], 1);
    assert_eq!(plan["desired"]["owner"], "v6alias");
    assert_eq!(
        plan["desired"]["reservations"].as_array().unwrap().len(),
        reservations
    );
    assert_eq!(
        plan["desired"]["dns_records"].as_array().unwrap().len(),
        dns_records
    );
}

fn assert_changes(plan: &Value, counts: [usize; 4]) {
    for (field, expected) in [
        "add_reservations",
        "remove_reservations",
        "add_dns_records",
        "remove_dns_records",
    ]
    .into_iter()
    .zip(counts)
    {
        assert_eq!(
            plan["changes"][field].as_array().unwrap().len(),
            expected,
            "{field}: {plan}"
        );
    }
}

#[test]
fn complete_workflow_survives_process_restarts_and_never_reuses_retired_numbers() {
    let sandbox = Sandbox::new();
    let observation = fixture("observation.json");
    sandbox.init();
    sandbox.init();

    let registered = sandbox.register(&fixture("device.json"));
    let mut expected_device = fixture_json("device.json");
    expected_device["duid"] = json!(NORMALIZED_DUID);
    assert_eq!(registered, expected_device);
    assert_eq!(sandbox.register(&fixture("device.json")), registered);
    assert_eq!(
        success(sandbox.scoped("inventory").arg("list")),
        json!([registered])
    );

    let decision = sandbox.explain(&observation, "corp-link");
    assert_decision(&decision, true);
    assert_eq!(decision["matched_rule"], "managed-corporate");
    assert_eq!(decision["profile"], "corp");
    assert_eq!(decision["subnet"], 23);
    assert_eq!(sandbox.assignments(), json!([]));

    let assignment = sandbox.allocate(&observation, "corp-link");
    for (field, expected) in [
        ("asset_id", json!("demo-workstation")),
        ("duid", json!(NORMALIZED_DUID)),
        ("iaid", json!(1)),
        ("link", json!("corp-link")),
        ("profile", json!("corp")),
        ("subnet", json!(23)),
        ("device", json!(2)),
        ("address", json!(CORPORATE_ADDRESS)),
        ("state", json!("active")),
        ("policy_rule", json!("managed-corporate")),
    ] {
        assert_eq!(assignment[field], expected, "{field}: {assignment}");
    }
    assert_eq!(
        assignment["fqdn"].as_str().unwrap().trim_end_matches('.'),
        "demo-workstation.v6alias.home.arpa"
    );
    assert_eq!(sandbox.allocate(&observation, "corp-link"), assignment);
    assert_eq!(sandbox.assignments(), json!([assignment]));

    let desired_only = sandbox.plan(None);
    assert_plan(&desired_only, "desired_only", 1, 2);
    assert_changes(&desired_only, [0, 0, 0, 0]);
    let observed = sandbox.write_json("observed.json", &desired_only["desired"]);
    let unchanged = sandbox.plan(Some(&observed));
    assert_plan(&unchanged, "owned_snapshot", 1, 2);
    assert_changes(&unchanged, [0, 0, 0, 0]);
    assert_eq!(unchanged["desired"], desired_only["desired"]);

    let empty = sandbox.write_json(
        "empty.json",
        &json!({
            "schema_version": 1,
            "owner": "v6alias",
            "reservations": [],
            "dns_records": []
        }),
    );
    let additions = sandbox.plan(Some(&empty));
    assert_plan(&additions, "owned_snapshot", 1, 2);
    assert_changes(&additions, [1, 0, 2, 0]);
    assert_eq!(
        additions["changes"]["add_reservations"],
        desired_only["desired"]["reservations"]
    );
    assert_eq!(
        additions["changes"]["add_dns_records"],
        desired_only["desired"]["dns_records"]
    );
    assert_eq!(sandbox.assignments(), json!([assignment]));

    let retired =
        success(
            sandbox
                .scoped("service")
                .args(["retire", "--asset-id", "demo-workstation"]),
        );
    let mut expected_retired = assignment.clone();
    expected_retired["state"] = json!("retired");
    assert_eq!(retired, expected_retired);
    assert_eq!(sandbox.assignments(), json!([expected_retired]));
    failure(&mut sandbox.observation_command("service", &observation, "corp-link"));

    let retired_desired_only = sandbox.plan(None);
    assert_plan(&retired_desired_only, "desired_only", 0, 0);
    assert_changes(&retired_desired_only, [0, 0, 0, 0]);
    let removals = sandbox.plan(Some(&observed));
    assert_plan(&removals, "owned_snapshot", 0, 0);
    assert_changes(&removals, [0, 1, 0, 2]);
    assert_eq!(
        removals["changes"]["remove_reservations"],
        desired_only["desired"]["reservations"]
    );
    assert_eq!(
        removals["changes"]["remove_dns_records"],
        desired_only["desired"]["dns_records"]
    );

    let mut next_device = fixture_json("device.json");
    next_device["asset_id"] = json!("demo-workstation-2");
    next_device["dns_label"] = json!("demo-workstation-2");
    next_device["duid"] = fixture_json("unknown.json")["duid"].clone();
    sandbox.register(&sandbox.write_json("next-device.json", &next_device));
    let next = sandbox.allocate(&fixture("unknown.json"), "corp-link");
    assert_eq!(next["asset_id"], "demo-workstation-2");
    assert_eq!(next["device"], 3);
    assert_eq!(next["address"], "fd7a:115c:a1e0:17::3");
    assert_eq!(next["state"], "active");
    assert_eq!(
        sandbox.allocate(&fixture("unknown.json"), "corp-link"),
        next
    );
    let assignments = sandbox.assignments();
    let assignments = assignments.as_array().unwrap();
    assert_eq!(assignments.len(), 2);
    assert!(assignments.contains(&expected_retired));
    assert!(assignments.contains(&next));
}

#[test]
fn unknown_unmanaged_and_mismatched_identities_are_denied_without_assignments() {
    let sandbox = Sandbox::new();
    sandbox.init();
    sandbox.register(&fixture("device.json"));

    let mut unmanaged = fixture_json("device.json");
    unmanaged["asset_id"] = json!("demo-lab-workstation");
    unmanaged["dns_label"] = json!("demo-lab-workstation");
    unmanaged["duid"] = json!("00:04:20:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff");
    unmanaged["managed"] = json!(false);
    sandbox.register(&sandbox.write_json("unmanaged-device.json", &unmanaged));
    let mut unmanaged_observation = fixture_json("observation.json");
    unmanaged_observation["duid"] = unmanaged["duid"].clone();
    let unmanaged_input = sandbox.write_json("unmanaged-observation.json", &unmanaged_observation);
    let mut mismatched = fixture_json("observation.json");
    mismatched["iaid"] = json!(2);
    let mismatched_input = sandbox.write_json("mismatched.json", &mismatched);

    for (input, link) in [
        (fixture("unknown.json"), "corp-link"),
        (fixture("unknown.json"), "lab-link"),
        (fixture("unknown.json"), "quarantine-link"),
        (unmanaged_input.clone(), "corp-link"),
        (mismatched_input, "corp-link"),
        (fixture("observation.json"), "unrecognized-link"),
    ] {
        let denied = json_status(&mut sandbox.observation_command("policy", &input, link), 2);
        assert_decision(&denied, false);
        failure(&mut sandbox.observation_command("service", &input, link));
        assert_eq!(sandbox.assignments(), json!([]));
    }

    let lab_decision = sandbox.explain(&unmanaged_input, "lab-link");
    assert_decision(&lab_decision, true);
    assert_eq!(lab_decision["matched_rule"], "inventoried-lab");
    let lab = sandbox.allocate(&unmanaged_input, "lab-link");
    assert_eq!(lab["profile"], "lab");
    assert_eq!(lab["link"], "lab-link");
    assert_eq!(lab["subnet"], 7);
    assert_eq!(lab["device"], 2);
    assert_eq!(lab["state"], "active");

    let quarantine_decision = sandbox.explain(&fixture("observation.json"), "quarantine-link");
    assert_decision(&quarantine_decision, true);
    assert_eq!(
        quarantine_decision["matched_rule"],
        "inventoried-quarantine"
    );
    assert_eq!(quarantine_decision["profile"], "quarantine");
    assert_eq!(sandbox.assignments(), json!([lab]));
}

#[test]
fn observation_cannot_supply_inventory_attributes_or_trusted_link() {
    let sandbox = Sandbox::new();
    sandbox.init();
    let device = sandbox.register(&fixture("device.json"));
    for (field, value) in [
        ("managed", json!(true)),
        ("trusted_link", json!("corp-link")),
        ("hostnmae", json!("untrusted-hint")),
    ] {
        let mut observation = fixture_json("observation.json");
        observation[field] = value;
        let input = sandbox.write_json(&format!("{field}.json"), &observation);
        failure(&mut sandbox.observation_command("policy", &input, "corp-link"));
        failure(&mut sandbox.observation_command("service", &input, "corp-link"));
        assert_eq!(sandbox.assignments(), json!([]));
    }
    assert_eq!(
        success(sandbox.scoped("inventory").arg("list")),
        json!([device])
    );
}

#[test]
fn invalid_pools_and_valid_but_changed_configuration_fail_closed() {
    let mut sandbox = Sandbox::new();
    sandbox.init();
    sandbox.register(&fixture("device.json"));
    let original_path = sandbox.config.clone();
    let original_config = fs::read_to_string(&original_path).unwrap();
    let original_pool = "pool: {first: 2, last: 4095}";
    assert!(original_config.contains(original_pool));
    let observation = fixture("observation.json");

    for (first, last) in [(0, 4095), (1, 4095), (2, 4096), (10, 9)] {
        let invalid = original_config.replacen(
            original_pool,
            &format!("pool: {{first: {first}, last: {last}}}"),
            1,
        );
        sandbox.config = sandbox
            .directory
            .path()
            .join(format!("invalid-pool-{first}-{last}.yaml"));
        fs::write(&sandbox.config, invalid).unwrap();
        failure(&mut sandbox.observation_command("policy", &observation, "corp-link"));
        failure(&mut sandbox.observation_command("service", &observation, "corp-link"));
        failure(sandbox.scoped("service").arg("assignments"));
        failure(sandbox.scoped("service").arg("plan"));
        sandbox.config = original_path.clone();
        assert_eq!(sandbox.assignments(), json!([]));
    }

    let assignment = sandbox.allocate(&observation, "corp-link");
    let original_plan = sandbox.plan(None);
    let drifted =
        original_config.replace("dns_zone: v6alias.home.arpa", "dns_zone: other.home.arpa");
    assert_ne!(drifted, original_config);
    sandbox.config = sandbox.directory.path().join("drifted.yaml");
    fs::write(&sandbox.config, drifted).unwrap();
    failure(&mut sandbox.observation_command("policy", &observation, "corp-link"));
    failure(&mut sandbox.observation_command("service", &observation, "corp-link"));
    failure(sandbox.scoped("service").arg("assignments"));
    failure(sandbox.scoped("service").arg("plan"));
    failure(
        sandbox
            .scoped("service")
            .args(["retire", "--asset-id", "demo-workstation"]),
    );

    sandbox.config = original_path;
    assert_eq!(sandbox.assignments(), json!([assignment]));
    assert_eq!(sandbox.allocate(&observation, "corp-link"), assignment);
    assert_eq!(sandbox.plan(None), original_plan);
}

#[test]
fn read_only_commands_do_not_create_missing_databases_or_sidecars() {
    let mut sandbox = Sandbox::new();
    for operation in ["list", "explain", "assignments", "plan"] {
        sandbox.database = sandbox.directory.path().join(format!("{operation}.sqlite"));
        match operation {
            "list" => failure(sandbox.scoped("inventory").arg("list")),
            "explain" => failure(&mut sandbox.observation_command(
                "policy",
                &fixture("observation.json"),
                "corp-link",
            )),
            _ => failure(sandbox.scoped("service").arg(operation)),
        }
        assert!(!sandbox.database.exists(), "{operation} created a database");
        assert_eq!(
            fs::read_dir(sandbox.directory.path()).unwrap().count(),
            0,
            "{operation} created a database or sidecar"
        );
    }
}

#[test]
fn malformed_and_oversized_json_inputs_do_not_change_persisted_state() {
    let sandbox = Sandbox::new();
    sandbox.init();
    let device = sandbox.register(&fixture("device.json"));
    let assignment = sandbox.allocate(&fixture("observation.json"), "corp-link");
    let desired = sandbox.plan(None)["desired"].clone();
    let malformed = sandbox.directory.path().join("malformed.json");
    fs::write(&malformed, b"{").unwrap();

    // Whitespace keeps these inputs valid JSON: rejection must enforce a byte limit.
    for (operation, valid) in [
        ("register", fixture_json("device.json")),
        ("explain", fixture_json("observation.json")),
        ("allocate", fixture_json("observation.json")),
        ("plan", desired),
    ] {
        let padding = " ".repeat(if operation == "plan" {
            64 * 1024 * 1024
        } else {
            1024 * 1024
        });
        let oversized = sandbox
            .directory
            .path()
            .join(format!("oversized-{operation}.json"));
        fs::write(
            &oversized,
            format!("{padding}{}", serde_json::to_string(&valid).unwrap()),
        )
        .unwrap();
        for input in [&malformed, &oversized] {
            match operation {
                "register" => failure(
                    sandbox
                        .scoped("inventory")
                        .arg("register")
                        .arg("--device")
                        .arg(input),
                ),
                "explain" => {
                    failure(&mut sandbox.observation_command("policy", input, "corp-link"))
                }
                "allocate" => {
                    failure(&mut sandbox.observation_command("service", input, "corp-link"))
                }
                _ => failure(
                    sandbox
                        .scoped("service")
                        .arg("plan")
                        .arg("--observed")
                        .arg(input),
                ),
            }
            assert_eq!(sandbox.assignments(), json!([assignment]));
            assert_eq!(
                success(sandbox.scoped("inventory").arg("list")),
                json!([device])
            );
        }
    }
}

#[test]
fn original_address_commands_and_network_wrapper_dry_runs_remain_offline() {
    let sandbox = Sandbox::new();
    let config = root().join("v6alias.example.yaml");
    let address = "fd7a:115c:a1e0:17::2a";
    assert_eq!(
        text_success(
            sandbox
                .cli()
                .arg("--config")
                .arg(&config)
                .args(["resolve", "corp:42"]),
        )
        .trim(),
        address
    );
    assert_eq!(
        text_success(
            sandbox
                .cli()
                .arg("--config")
                .arg(&config)
                .args(["reverse", address]),
        )
        .trim(),
        "corp:42"
    );
    let trace_program = if cfg!(windows) {
        "tracert"
    } else {
        "traceroute"
    };
    for (wrapper, program) in [
        ("ping", "ping"),
        ("trace", trace_program),
        ("tracert", trace_program),
        ("traceroute", trace_program),
        ("ssh", "ssh"),
    ] {
        let output = text_success(sandbox.cli().arg("--config").arg(&config).args([
            wrapper,
            "corp:42",
            "--dry-run",
        ]));
        assert!(output.contains(&format!("Resolved: corp:42 -> {address}")));
        assert!(output.contains(&format!("Command:  {program} -6 {address}")));
    }

    let generated = text_success(
        sandbox
            .cli()
            .arg("--config")
            .arg(sandbox.directory.path().join("absent.yaml"))
            .args(["ula", "generate"]),
    );
    let (prefix, length) = generated.trim().split_once('/').unwrap();
    assert_eq!(length, "48");
    let prefix: Ipv6Addr = prefix.parse().unwrap();
    assert_eq!(prefix.octets()[0], 0xfd);
    assert_eq!(&prefix.octets()[6..], &[0; 10]);

    let help = text_success(sandbox.cli().arg("--help"));
    for command in [
        "resolve",
        "reverse",
        "ping",
        "trace",
        "ssh",
        "ula",
        "inventory",
        "policy",
        "service",
    ] {
        assert!(help.contains(command), "missing {command} in help: {help}");
    }
    assert_eq!(fs::read_dir(sandbox.directory.path()).unwrap().count(), 0);
}
