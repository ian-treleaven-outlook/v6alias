use std::process::{Command, Output};

fn run(color: &str, arguments: &[&str], no_color: bool, term: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_v6alias"));
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["--config", "v6alias.example.yaml", "--color", color])
        .args(arguments)
        .env_remove("CLICOLOR_FORCE")
        .env_remove("FORCE_COLOR")
        .env("TERM", term);
    if no_color {
        command.env("NO_COLOR", "1");
    } else {
        command.env_remove("NO_COLOR");
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn piped_auto_and_never_stay_plain_and_explicit_color_is_available() {
    for color in ["auto", "never"] {
        let output = run(
            color,
            &["ping", "corp:42", "--dry-run"],
            false,
            "xterm-256color",
        );
        assert!(!output.stdout.contains(&0x1b));
        assert!(String::from_utf8_lossy(&output.stdout).contains("Resolved: corp:42 ->"));
    }
    let output = run("always", &["ping", "corp:42", "--dry-run"], true, "dumb");
    assert!(output.stdout.contains(&0x1b));
}

#[test]
fn json_resolver_and_reverse_outputs_are_never_ansi_colored() {
    let json = run("always", &["ifconfig", "--json"], false, "xterm-256color");
    assert!(!json.stdout.contains(&0x1b));
    assert!(
        serde_json::from_slice::<serde_json::Value>(&json.stdout)
            .unwrap()
            .is_array()
    );
    let address = run("always", &["resolve", "corp:42"], false, "xterm-256color");
    assert_eq!(
        String::from_utf8(address.stdout).unwrap().trim(),
        "fd7a:115c:a1e0:17::2a"
    );
    let alias = run(
        "always",
        &["reverse", "fd7a:115c:a1e0:17::2a"],
        false,
        "xterm-256color",
    );
    assert_eq!(String::from_utf8(alias.stdout).unwrap().trim(), "corp:42");
}

#[test]
fn explicit_interface_color_does_not_change_plain_address_metadata() {
    let output = run("always", &["ifconfig", "--raw"], false, "xterm-256color");
    let text = String::from_utf8(output.stdout).unwrap();
    if text.contains("(index ") {
        assert!(text.contains("\x1b[1;96m"));
    }
    let plain = run("never", &["ifconfig", "--raw"], false, "xterm-256color");
    assert!(!plain.stdout.contains(&0x1b));
}
