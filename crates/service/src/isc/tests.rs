use super::*;

const EMPTY: &str = include_str!("../../../../examples/isc/synthetic-empty.leases");
const ACTIVE: &str = include_str!("../../../../examples/isc/synthetic-active.leases");
const HEADER: &str = "authoring-byte-order little-endian;\n";
const NOW: u64 = 1_790_200_000;

fn capture(lease_file: &str) -> Capture {
    Capture {
        schema_version: 1,
        source: "synthetic-isc".into(),
        captured_at_unix_secs: NOW,
        lease_file: lease_file.into(),
    }
}

fn config() -> ServiceConfig {
    ServiceConfig::from_yaml(include_str!("../../../../service.example.yaml")).unwrap()
}

fn normalized(text: &str) -> Result<Collection> {
    collect_at(
        &capture(text),
        &config(),
        "synthetic-isc",
        "corp-link",
        300,
        NOW,
    )
}

fn child(address: &str, state: &str, ends: &str) -> String {
    format!(
        "iaaddr {address} {{ binding state {state}; preferred-life 10; max-life 20; ends {ends}; }}"
    )
}

fn record(id: &str, children: &str) -> String {
    format!("ia-na {id} {{ {children} }}\n")
}

fn corp(id: &str, suffix: &str) -> String {
    record(
        id,
        &child(&format!("fd7a:115c:a1e0:17::{suffix}"), "active", "never"),
    )
}

#[test]
fn synthetic_fixtures_and_exact_daemon_contract() {
    assert!(normalized(EMPTY).unwrap().snapshot.observations.is_empty());
    let output = normalized(ACTIVE).unwrap();
    assert_eq!(output.snapshot.observations.len(), 1);
    let obs = &output.snapshot.observations[0];
    assert_eq!(obs.duid.as_str(), "000400112233445566778899aabbccddeeff");
    assert_eq!(obs.iaid, 1);
    assert!(obs.hostname.is_none());
    assert_eq!(output.snapshot.captured_at_unix_secs, NOW);
    assert_eq!(output.counts.filtered_other_link_associations, 1);
    assert_eq!(output.counts.live_addresses, 2);
    let bytes = output.snapshot_json().unwrap();
    let parsed: ObservationSnapshot = serde_json::from_slice(&bytes).unwrap();
    parsed.validate("synthetic-isc", NOW, 300).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes)
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        4
    );
}

#[test]
fn byte_order_and_identifier_encodings_preserve_exact_identity() {
    for (order, quoted, hex) in [
        (
            "little-endian",
            r#""\004\003\002\001\000\377""#,
            "04:03:02:01:00:ff",
        ),
        (
            "big-endian",
            r#""\001\002\003\004\000\377""#,
            "01:02:03:04:00:ff",
        ),
    ] {
        for id in [quoted, hex] {
            let result = normalized(&format!(
                "authoring-byte-order {order}; {}",
                corp(id, "1000")
            ))
            .unwrap();
            let obs = &result.snapshot.observations[0];
            assert_eq!(obs.iaid, 0x01020304);
            assert_eq!(obs.duid.as_str(), "00ff");
        }
    }
}

#[test]
fn latest_whole_record_wins_in_file_order_including_empty_and_inactive() {
    let initial = corp("01:00:00:00:aa:bb", "1000");
    for state in ["free", "released", "expired", "abandoned"] {
        let last = record(
            "01:00:00:00:aa:bb",
            &child("fd7a:115c:a1e0:17::1000", state, "never"),
        );
        let result = normalized(&format!("{HEADER}{initial}{last}")).unwrap();
        assert!(result.snapshot.observations.is_empty());
        assert_eq!(result.counts.replaced_associations, 1);
        assert_eq!(result.counts.inactive_addresses, 1);
    }
    let empty = record("01:00:00:00:aa:bb", "");
    assert!(
        normalized(&format!("{HEADER}{initial}{empty}"))
            .unwrap()
            .snapshot
            .observations
            .is_empty()
    );
    let older_cltt = initial.replace(" { iaaddr", " { cltt epoch 10; iaaddr");
    let newer_cltt = empty.replace(" { ", " { cltt epoch 20; ");
    assert_eq!(
        normalized(&format!("{HEADER}{newer_cltt}{older_cltt}"))
            .unwrap()
            .snapshot
            .observations
            .len(),
        1
    );
    // A late malformed record never resurrects the previous association.
    assert!(normalized(&format!("{HEADER}{initial}ia-na 01:00:00:00:aa:bb {{")).is_err());
}

#[test]
fn latest_record_replaces_addresses_not_just_matching_children() {
    let corp_record = corp("01:00:00:00:aa:bb", "1000");
    let lab_record = record(
        "01:00:00:00:aa:bb",
        &child("fdb4:82d1:930c:7::1000", "active", "never"),
    );
    let result = normalized(&format!("{HEADER}{corp_record}{lab_record}")).unwrap();
    assert!(result.snapshot.observations.is_empty());
    assert_eq!(result.counts.live_addresses, 1);
    assert_eq!(result.counts.filtered_other_link_associations, 1);
}

#[test]
fn expiration_uses_explicit_ends_and_current_time_not_cached_lifetimes() {
    for (end, expected) in [(NOW - 1, 0), (NOW, 0), (NOW + 1, 1)] {
        let text = format!(
            "{HEADER}{}",
            record(
                "01:00:00:00:aa:bb",
                &child("fd7a:115c:a1e0:17::1000", "active", &format!("epoch {end}"))
            )
        );
        assert_eq!(
            normalized(&text).unwrap().snapshot.observations.len(),
            expected
        );
        if expected == 1 {
            assert!(
                collect_at(
                    &capture(&text),
                    &config(),
                    "synthetic-isc",
                    "corp-link",
                    300,
                    NOW + 1
                )
                .unwrap()
                .snapshot
                .observations
                .is_empty()
            );
        }
    }
    let text = format!("{HEADER}{}", corp("01:00:00:00:aa:bb", "1000"))
        .replace("preferred-life 10", "preferred-life 0")
        .replace("max-life 20", "max-life 0");
    assert_eq!(normalized(&text).unwrap().snapshot.observations.len(), 1);
}

#[test]
fn scope_filtering_validates_every_live_identity_before_selection() {
    let id = "01:00:00:00:aa:bb";
    let first = child("fd7a:115c:a1e0:17::1000", "active", "never");
    let other = child("fdb4:82d1:930c:7::1000", "active", "never");
    for text in [
        record(id, &format!("{first}{other}")),
        record(id, &child("2001:db8::1", "active", "never")),
        format!(
            "{}{}",
            record(id, &other),
            record(
                "02:00:00:00:aa:bb",
                &child("fdb4:82d1:930c:7::1001", "active", "never")
            )
        ),
        format!(
            "{}{}",
            record(id, &other),
            record("01:00:00:00:cc:dd", &other)
        ),
        format!(
            "{}{}",
            record(id, &first),
            record("01:00:00:00:cc:dd", &first)
        ),
    ] {
        assert!(normalized(&format!("{HEADER}{text}")).is_err(), "{text}");
    }
    // Inactive/expired out-of-scope addresses cannot authorize anything.
    let text = format!(
        "{HEADER}{}",
        record(
            id,
            &format!(
                "{first}{}{}",
                child("2001:db8::1", "released", "never"),
                child("2001:db8::2", "active", "epoch 0")
            )
        )
    );
    assert_eq!(normalized(&text).unwrap().snapshot.observations.len(), 1);
}

#[test]
fn same_scope_addresses_deduplicate_without_accepting_duplicate_children() {
    let first = child("fd7a:115c:a1e0:17::1000", "active", "never");
    let second = child("fd7a:115c:a1e0:17::1001", "active", "never");
    let text = format!(
        "{HEADER}{}",
        record("01:00:00:00:aa:bb", &format!("{first}{second}"))
    );
    let result = normalized(&text).unwrap();
    assert_eq!(result.counts.live_addresses, 2);
    assert_eq!(result.snapshot.observations.len(), 1);
    assert!(normalized(&text.replace("::1001", "::1000")).is_err());
}

#[test]
fn configuration_aliases_or_unknown_links_cannot_ambigously_map_scope() {
    let mut cfg = config();
    cfg.profiles
        .insert("alias".into(), cfg.profiles["corp"].clone());
    let mut alias = cfg.links["corp-link"].clone();
    alias.profile = "alias".into();
    cfg.links.insert("alias-link".into(), alias);
    assert!(
        collect_at(
            &capture(ACTIVE),
            &cfg,
            "synthetic-isc",
            "corp-link",
            300,
            NOW
        )
        .is_err()
    );
    assert!(
        collect_at(
            &capture(ACTIVE),
            &config(),
            "synthetic-isc",
            "missing-link",
            300,
            NOW
        )
        .is_err()
    );
}

#[test]
fn freshness_source_versions_and_json_fields_fail_closed() {
    for (now, age, valid) in [
        (NOW, 1, true),
        (NOW + 300, 300, true),
        (NOW + 301, 300, false),
        (NOW - 1, 300, false),
        (NOW, 0, false),
        (NOW, 86401, false),
    ] {
        assert_eq!(
            collect_at(
                &capture(EMPTY),
                &config(),
                "synthetic-isc",
                "corp-link",
                age,
                now
            )
            .is_ok(),
            valid
        );
    }
    assert!(
        collect_at(
            &capture(EMPTY),
            &config(),
            "wrong-source",
            "corp-link",
            300,
            NOW
        )
        .is_err()
    );
    let base = serde_json::to_value(capture(EMPTY)).unwrap();
    for field in [
        "schema_version",
        "source",
        "captured_at_unix_secs",
        "lease_file",
    ] {
        let mut v = base.clone();
        v.as_object_mut().unwrap().remove(field);
        assert!(Capture::from_json(&serde_json::to_vec(&v).unwrap()).is_err());
    }
    let mut unknown = base;
    unknown["hostname"] = "evil".into();
    assert!(Capture::from_json(&serde_json::to_vec(&unknown).unwrap()).is_err());
    let duplicate = format!(
        r#"{{"schema_version":1,{}"#,
        &serde_json::to_string(&capture(EMPTY)).unwrap()[1..]
    );
    assert!(Capture::from_json(duplicate.as_bytes()).is_err());
    for version in [0, 2, u32::MAX] {
        let mut c = capture(EMPTY);
        c.schema_version = version;
        assert!(collect_at(&c, &config(), "synthetic-isc", "corp-link", 300, NOW).is_err());
    }
    let mut c = capture(EMPTY);
    c.source = "a".repeat(64);
    assert!(
        collect_at(&c, &config(), "synthetic-isc", "corp-link", 300, NOW)
            .unwrap_err()
            .to_string()
            .contains("63 bytes")
    );
}

#[test]
fn capture_and_decoded_input_limits_are_enforced() {
    let oversized = vec![b' '; MAX_CAPTURE_BYTES as usize + 1];
    assert!(
        Capture::from_json(&oversized)
            .unwrap_err()
            .to_string()
            .contains("67108864")
    );
    let mut c = capture(EMPTY);
    c.lease_file = " ".repeat(MAX_LEASE_BYTES + 1);
    assert!(
        collect_at(&c, &config(), "synthetic-isc", "corp-link", 300, NOW)
            .unwrap_err()
            .to_string()
            .contains("67108864")
    );
    let mut encoded = serde_json::to_vec(&capture(EMPTY)).unwrap();
    encoded.resize(MAX_CAPTURE_BYTES as usize, b' ');
    assert!(Capture::from_json(&encoded).is_ok());
}

#[test]
fn observation_count_and_serialized_output_bounds_are_independent() {
    let make = |count: usize, long: bool| {
        let mut text = HEADER.to_owned();
        for i in 0..count {
            let suffix = if long {
                ":aa".repeat(124)
            } else {
                String::new()
            };
            text.push_str(&corp(
                &format!("01:00:00:00:{:02x}:{:02x}{suffix}", i >> 8, i & 255),
                &format!("{:x}", i + 0x1000),
            ));
        }
        text
    };
    assert_eq!(
        normalized(&make(MAX_OBSERVATIONS, false))
            .unwrap()
            .snapshot
            .observations
            .len(),
        MAX_OBSERVATIONS
    );
    assert!(
        normalized(&make(MAX_OBSERVATIONS + 1, false))
            .unwrap_err()
            .to_string()
            .contains("count exceeds")
    );
    assert!(
        normalized(&make(MAX_OBSERVATIONS, true))
            .unwrap_err()
            .to_string()
            .contains("output exceeds")
    );
}
