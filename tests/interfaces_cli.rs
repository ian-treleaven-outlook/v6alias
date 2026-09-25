use std::{
    path::PathBuf,
    process::{Command, Output},
};

use serde_json::Value;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_v6alias"))
        .current_dir(root())
        .args(args)
        .output()
        .unwrap()
}

fn success(output: &Output) -> &str {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    std::str::from_utf8(&output.stdout).unwrap()
}

fn assert_snapshot(output: &Output, raw: bool) -> Value {
    let value: Value = serde_json::from_str(success(output)).unwrap();
    for interface in value.as_array().unwrap() {
        assert!(interface["name"].is_string());
        assert!(interface["index"].is_u64());
        for item in interface["addresses"].as_array().unwrap() {
            let address: std::net::IpAddr = item["address"].as_str().unwrap().parse().unwrap();
            if let Some(prefix) = item["prefix_length"].as_u64() {
                assert!(prefix <= if address.is_ipv4() { 32 } else { 128 });
            }
            if raw {
                assert!(item["alias"].is_null());
            } else if let Some(alias) = item["alias"].as_str() {
                let config =
                    v6alias::Config::from_path(root().join("v6alias.example.yaml")).unwrap();
                assert_eq!(
                    std::net::IpAddr::V6(config.resolve(&alias.parse().unwrap()).unwrap()),
                    address
                );
            }
        }
    }
    value
}

#[test]
fn both_command_spellings_read_local_addresses_in_raw_and_configured_modes() {
    for spelling in ["interfaces", "ifconfig"] {
        assert_snapshot(&cli(&[spelling, "--raw", "--json"]), true);
        assert_snapshot(
            &cli(&["--config", "v6alias.example.yaml", spelling, "--json"]),
            false,
        );
        let output = cli(&["--config", "v6alias.example.yaml", spelling]);
        let text = success(&output);
        assert!(text.contains("(index ") || text.contains("No interfaces reported"));
    }
}

#[test]
fn raw_mode_works_without_configuration_but_normal_mode_requires_valid_config() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("absent.yaml");
    for suffix in [vec!["interfaces", "--json"], vec!["ifconfig", "--json"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_v6alias"))
            .arg("--config")
            .arg(&missing)
            .args(&suffix)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("configuration"));
        let output = Command::new(env!("CARGO_BIN_EXE_v6alias"))
            .arg("--config")
            .arg(&missing)
            .args(&suffix)
            .arg("--raw")
            .output()
            .unwrap();
        assert_snapshot(&output, true);
    }
    assert!(!missing.exists());
    let invalid = dir.path().join("invalid.yaml");
    std::fs::write(&invalid, "profiles:\n  corp:\n    prefix: 2001:db8::/48\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_v6alias"))
        .arg("--config")
        .arg(invalid)
        .args(["interfaces", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ULA"));
}

#[test]
fn exact_interface_filter_and_missing_interface_errors_are_visible() {
    let snapshot = assert_snapshot(&cli(&["interfaces", "--raw", "--json"]), true);
    if let Some(first) = snapshot.as_array().unwrap().first() {
        let name = first["name"].as_str().unwrap();
        let selected = assert_snapshot(
            &cli(&["ifconfig", "--raw", "--json", "--interface", name]),
            true,
        );
        assert!(!selected.as_array().unwrap().is_empty());
        assert!(
            selected
                .as_array()
                .unwrap()
                .iter()
                .all(|item| item["name"] == name)
        );
    }
    let missing = "v6alias-nonexistent-interface-0cbf75bc";
    assert!(
        !snapshot
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["name"] == missing)
    );
    let output = cli(&["interfaces", "--raw", "--interface", missing]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("was not found"));
}

#[test]
fn help_lists_the_ifconfig_alias_and_does_not_accept_mutating_flags() {
    let output = cli(&["--help"]);
    let help = success(&output);
    assert!(help.contains("interfaces"));
    assert!(help.contains("ifconfig"));
    let output = cli(&["ifconfig", "--help"]);
    for flag in ["--raw", "--json", "--interface"] {
        assert!(success(&output).contains(flag));
    }
    for flag in ["--up", "--down", "--set-address"] {
        let output = cli(&["ifconfig", "--raw", flag]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}
