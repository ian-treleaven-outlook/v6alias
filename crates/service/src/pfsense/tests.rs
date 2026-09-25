use super::*;
use crate::{InventoryDevice, Observation};

struct Fixture {
    store: Store,
    config: ServiceConfig,
    bindings: Bindings,
    baseline: Projection,
}

impl Fixture {
    fn new(foreign: bool) -> Self {
        let config =
            ServiceConfig::from_yaml(include_str!("../../../../examples/pfsense/service.yaml"))
                .unwrap();
        let bindings =
            from_json(include_bytes!("../../../../examples/pfsense/bindings.json")).unwrap();
        let baseline = from_json(if foreign {
            include_bytes!("../../../../examples/pfsense/native-foreign.json").as_slice()
        } else {
            include_bytes!("../../../../examples/pfsense/native-empty.json").as_slice()
        })
        .unwrap();
        let device: InventoryDevice =
            from_json(include_bytes!("../../../../examples/pfsense/device.json")).unwrap();
        let observation: Observation = from_json(include_bytes!(
            "../../../../examples/pfsense/observation.json"
        ))
        .unwrap();
        let mut store = Store::in_memory().unwrap();
        store.register(&device).unwrap();
        store.allocate(&config, &observation, "demo-link").unwrap();
        Self {
            store,
            config,
            bindings,
            baseline,
        }
    }

    fn plan(&self) -> Result<Request> {
        compile(
            &self.store,
            &self.config,
            &self.bindings,
            &self.baseline,
            100,
            300,
        )
    }

    fn simulation(&self) -> Simulation {
        simulate(
            &self.store,
            &self.config,
            &self.bindings,
            &self.baseline,
            &self.plan().unwrap(),
            100,
            300,
        )
        .unwrap()
    }
}

#[test]
fn native_objects_are_real_paths_no_iaid_no_ttl_and_foreign_order_is_preserved() {
    let f = Fixture::new(true);
    let result = f.simulation();
    assert_eq!(result.mode, "offline_simulation");
    assert!(!result.network_writes);
    assert!(result.approval_required);
    assert_eq!(
        result.request.allowed_paths,
        ["dhcpdv6/lan/staticmap", "unbound/hosts"]
    );
    assert_eq!(result.request.changes.len(), 2);
    for path in [
        NativePath::Hosts,
        NativePath::StaticMap {
            interface: "lan".into(),
        },
    ] {
        let before = path.collection(&f.baseline).unwrap();
        let after = path.collection(&result.projection).unwrap();
        assert_eq!(
            serde_json::to_string(&before[0]).unwrap(),
            serde_json::to_string(&after[0]).unwrap()
        );
        assert_eq!(after.len(), 2);
    }
    let native = &result.projection.config["dhcpdv6"]["lan"]["staticmap"][1];
    assert_eq!(
        native["duid"],
        "00:04:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff"
    );
    assert_eq!(native["ipaddrv6"], "fd12:3456:789a:a::2");
    assert_eq!(native["earlydnsregpolicy"], "disable");
    assert!(native.get("iaid").is_none());
    let host = &result.projection.config["unbound"]["hosts"][1];
    assert_eq!(host["ip"], "fd12:3456:789a:a::2");
    assert_eq!(host["aliases"], json!({"item":[]}));
    assert!(host.get("ttl").is_none());
    let mut stripped = result.projection.config.clone();
    stripped["dhcpdv6"]["lan"]["staticmap"]
        .as_array_mut()
        .unwrap()
        .pop();
    stripped["unbound"]["hosts"].as_array_mut().unwrap().pop();
    assert_eq!(
        serde_json::to_string(&stripped).unwrap(),
        serde_json::to_string(&f.baseline.config).unwrap()
    );
}

#[test]
fn exact_replay_is_noop_and_does_not_increment_offline_generation() {
    let mut f = Fixture::new(false);
    f.baseline = f.simulation().projection;
    assert!(f.plan().unwrap().changes.is_empty());
    assert_eq!(f.simulation().projection, f.baseline);
}

#[test]
fn retired_removal_requires_exact_retained_history() {
    let mut f = Fixture::new(true);
    f.baseline = f.simulation().projection;
    f.store.retire(&f.config, "synthetic-device").unwrap();
    let request = f.plan().unwrap();
    assert_eq!(request.changes.len(), 2);
    for change in &request.changes {
        assert_eq!(change.before.len(), 2);
        assert_eq!(change.after.len(), 1);
        assert_eq!(change.before[0], change.after[0]);
    }
    let simulation = f.simulation();
    let restored = rollback(
        &f.store,
        &f.config,
        &f.bindings,
        &f.baseline,
        (&simulation.projection, &simulation),
        100,
        300,
    )
    .unwrap();
    assert_eq!(restored.projection.config, f.baseline.config);
    f.baseline.config["unbound"]["hosts"][1]["descr"] = json!("v6alias:altered");
    assert!(f.plan().is_err());
}

#[test]
fn owner_tag_is_never_authority_and_all_owned_fields_must_match() {
    for retired in [false, true] {
        for (path, field, value) in [
            ("staticmap", "descr", json!("v6alias:unknown")),
            ("staticmap", "filename", json!("boot-changed")),
            ("staticmap", "rootpath", json!("/changed")),
            ("staticmap", "duid", json!("00:04:aa:bb")),
            ("staticmap", "hostname", json!("other")),
            ("staticmap", "earlydnsregpolicy", json!("enable")),
            ("staticmap", "extra", json!("new")),
            ("hosts", "ip", json!("fd12:3456:789a:a::3")),
            (
                "hosts",
                "aliases",
                json!({"item":[{"host":"alias","domain":"example"}]}),
            ),
            ("hosts", "descr", json!("v6alias:unknown")),
        ] {
            let mut f = Fixture::new(false);
            f.baseline = f.simulation().projection;
            if retired {
                f.store.retire(&f.config, "synthetic-device").unwrap();
            }
            let record = if path == "hosts" {
                &mut f.baseline.config["unbound"]["hosts"][0]
            } else {
                &mut f.baseline.config["dhcpdv6"]["lan"]["staticmap"][0]
            };
            record[field] = value;
            assert!(f.plan().is_err(), "{path} {field} retired={retired}");
        }
    }
    let mut f = Fixture::new(false);
    f.baseline = f.simulation().projection;
    f.store = Store::in_memory().unwrap();
    assert!(f.plan().is_err());
}

#[test]
fn identical_unmarked_foreign_records_are_not_adopted() {
    for collection in ["hosts", "staticmap"] {
        let mut f = Fixture::new(false);
        f.baseline = f.simulation().projection;
        let record = if collection == "hosts" {
            &mut f.baseline.config["unbound"]["hosts"][0]
        } else {
            &mut f.baseline.config["dhcpdv6"]["lan"]["staticmap"][0]
        };
        record["descr"] = json!("operator owned");
        assert!(f.plan().is_err());
    }
}

#[test]
fn foreign_names_addresses_aliases_and_ptrs_never_overwritten() {
    for (field, value) in [
        ("host", json!("synthetic-host")),
        ("ip", json!("192.0.2.53,fd12:3456:789a:a::2")),
        (
            "aliases",
            json!({"item":[{"host":"Synthetic-Host","domain":"DEMO.HOME.ARPA"}]}),
        ),
    ] {
        let mut f = Fixture::new(true);
        f.baseline.config["unbound"]["hosts"][0][field] = value;
        assert!(f.plan().is_err());
    }
    for name in [
        "synthetic-host.demo.home.arpa.".to_owned(),
        reconcile::reverse_name("fd12:3456:789a:a::2".parse().unwrap()),
    ] {
        let mut f = Fixture::new(false);
        f.baseline.external_dns.push(ExternalDns {
            name,
            addresses: vec![],
        });
        assert!(f.plan().is_err());
    }
}

#[test]
fn duplicate_aliases_names_ips_and_duids_fail_whole_input() {
    for kind in ["alias", "host", "ip", "duid"] {
        let mut f = Fixture::new(true);
        match kind {
            "alias" => {
                let items = f.baseline.config["unbound"]["hosts"][0]["aliases"]["item"]
                    .as_array_mut()
                    .unwrap();
                items.push(items[0].clone());
            }
            "host" => {
                let hosts = f.baseline.config["unbound"]["hosts"]
                    .as_array_mut()
                    .unwrap();
                hosts.push(hosts[0].clone());
            }
            "ip" => f.baseline.config["unbound"]["hosts"][0]["ip"] = json!("192.0.2.1,192.0.2.1"),
            _ => {
                let maps = f.baseline.config["dhcpdv6"]["lan"]["staticmap"]
                    .as_array_mut()
                    .unwrap();
                maps.push(maps[0].clone());
            }
        }
        assert!(f.plan().is_err(), "{kind}");
    }
}

#[test]
fn duid_format_iaid_and_unsupported_alias_shapes_fail_closed() {
    for raw in [
        "0001aabb",
        "00:01:AA:BB",
        "00-01-aa-bb",
        "00:1:aa:bb",
        "garbage",
    ] {
        let mut f = Fixture::new(true);
        f.baseline.config["dhcpdv6"]["lan"]["staticmap"][0]["duid"] = json!(raw);
        assert!(f.plan().is_err());
    }
    for aliases in [
        json!([]),
        json!(""),
        json!({"item":{}}),
        json!({"other":[]}),
        json!({"item":[{"host":"wild.*","domain":"example"}]}),
    ] {
        let mut f = Fixture::new(true);
        f.baseline.config["unbound"]["hosts"][0]["aliases"] = aliases;
        assert!(f.plan().is_err());
    }
    for field in ["iaid", "prefix"] {
        let mut f = Fixture::new(true);
        f.baseline.config["dhcpdv6"]["lan"]["staticmap"][0][field] = json!(7);
        assert!(f.plan().is_err());
    }
    for field in ["ttl", "cname"] {
        let mut f = Fixture::new(true);
        f.baseline.config["unbound"]["hosts"][0][field] = json!("unsupported");
        assert!(f.plan().is_err());
    }
}

#[test]
fn one_duid_one_iaid_is_enforced_in_full_authoritative_history() {
    let f = Fixture::new(false);
    let mut history = f.store.assignments(&f.config).unwrap();
    let mut other = history[0].clone();
    other.asset_id = "different".into();
    other.iaid += 1;
    other.address = "fd12:3456:789a:a::3".parse().unwrap();
    other.device = 3;
    other.fqdn = "other.demo.home.arpa.".into();
    other.state = AssignmentState::Retired;
    history.push(other);
    assert!(compile_history(&f.config, &history, &f.bindings, &f.baseline, 100, 300).is_err());
}

#[test]
fn global_conflicts_include_interfaces_without_managed_links() {
    let mut f = Fixture::new(true);
    let mut scope = f.baseline.scopes["lan"].clone();
    scope.subnet = "fd12:3456:789a:b::".parse().unwrap();
    scope.router_address = "fd12:3456:789a:b::1".parse().unwrap();
    scope.external_static_addresses.clear();
    f.baseline.scopes.insert("opt1".into(), scope);
    f.baseline.config["interfaces"]["opt1"] =
        json!({"ipaddrv6":"fd12:3456:789a:b::1", "subnetv6":"64"});
    f.baseline.config["dhcpdv6"]["opt1"] = json!({
        "range": {"from":"fd12:3456:789a:b::1000", "to":"fd12:3456:789a:b::ffff"},
        "staticmap": [{
            "duid":"00:04:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff",
            "ipaddrv6":"fd12:3456:789a:b::40","hostname":"other","descr":"unmanaged"
        }]
    });
    assert!(f.plan().is_err());
}

#[test]
fn lookalike_prefix_wrong_scope_bootstrap_router_and_external_addresses_refuse() {
    for case in [
        "lookalike",
        "prefix",
        "router",
        "external",
        "dynamic",
        "dynamic-end",
        "static-scope",
        "missing-scope",
        "binding",
        "approval",
    ] {
        let mut f = Fixture::new(true);
        match case {
            "lookalike" => {
                f.baseline.scopes.get_mut("lan").unwrap().subnet =
                    "fd12:3456:789a:aa::".parse().unwrap()
            }
            "prefix" => f.baseline.scopes.get_mut("lan").unwrap().prefix_length = 48,
            "router" => {
                f.baseline.scopes.get_mut("lan").unwrap().router_address =
                    "fd12:3456:789a:a::2".parse().unwrap()
            }
            "external" => f
                .baseline
                .scopes
                .get_mut("lan")
                .unwrap()
                .external_static_addresses
                .push("fd12:3456:789a:a::2".parse().unwrap()),
            "dynamic" => {
                f.baseline.config["dhcpdv6"]["lan"]["range"]["from"] = json!("fd12:3456:789a:a::2")
            }
            "dynamic-end" => {
                f.baseline.config["dhcpdv6"]["lan"]["range"]["to"] = json!("fd12:3456:789a:b::ffff")
            }
            "static-scope" => {
                f.baseline.config["dhcpdv6"]["lan"]["staticmap"][0]["ipaddrv6"] =
                    json!("fd12:3456:789a:b::35")
            }
            "missing-scope" => {
                f.baseline.scopes.clear();
            }
            "binding" => f.bindings.links.get_mut("demo-link").unwrap().interface = "opt1".into(),
            _ => f
                .bindings
                .links
                .get_mut("demo-link")
                .unwrap()
                .approved_reservation_addresses
                .clear(),
        }
        assert!(f.plan().is_err(), "{case}");
    }
}

#[test]
fn versions_backend_capabilities_coverage_and_revision_are_pinned() {
    let f = Fixture::new(false);
    let original = serde_json::to_value(&f.baseline).unwrap();
    for (key, value) in [
        ("schema_version", json!(2)),
        ("source", json!("other")),
        ("source_contract", json!("public-api")),
        ("pfsense_version", json!("2.8.2-RELEASE")),
        ("dhcp_backend", json!("kea")),
        ("isc_version", json!("4.4.3")),
        ("unbound_version", json!("1.24.3")),
        ("ttl_capability", json!("unknown")),
        ("complete", json!(false)),
        ("coverage", json!("partial")),
        ("config_revision_sha256", json!("abc")),
        ("config_revision_sha256", json!("A".repeat(64))),
    ] {
        let mut value_before = original.clone();
        value_before[key] = value;
        let bad: Projection = serde_json::from_value(value_before).unwrap();
        assert!(
            compile(&f.store, &f.config, &f.bindings, &bad, 100, 300).is_err(),
            "{key}"
        );
    }
    let mut config = f.config.clone();
    config.dns_ttl_seconds = 300;
    assert!(compile_history(&config, &[], &f.bindings, &f.baseline, 100, 300).is_err());
}

#[test]
fn finite_freshness_includes_boundary_and_future_rejection() {
    let f = Fixture::new(false);
    for (now, max_age, accepted) in [
        (100, 1, true),
        (101, 1, true),
        (102, 1, false),
        (99, 1, false),
        (100, 0, false),
        (100, 86401, false),
    ] {
        assert_eq!(
            compile(&f.store, &f.config, &f.bindings, &f.baseline, now, max_age).is_ok(),
            accepted
        );
    }
}

#[test]
fn request_tamper_cannot_supply_paths_programs_or_desired_values() {
    let f = Fixture::new(false);
    let request = f.plan().unwrap();
    for kind in [
        "path",
        "after",
        "before",
        "revision",
        "hash",
        "approval",
        "network",
        "authority",
        "allowed",
    ] {
        let mut bad = request.clone();
        match kind {
            "path" => {
                bad.changes[0].path = NativePath::StaticMap {
                    interface: "../../filter".into(),
                }
            }
            "after" => bad.changes[0].after[0]["filename"] = json!("injected"),
            "before" => bad.changes[0].before.push(json!({})),
            "revision" => bad.expected_revision_sha256 = "3".repeat(64),
            "hash" => bad.candidate_projection_sha256 = "3".repeat(64),
            "approval" => bad.approval_required = false,
            "network" => bad.network_writes = true,
            "authority" => bad.authority_sha256 = "3".repeat(64),
            _ => bad.allowed_paths.push("filter/rule".into()),
        }
        assert!(
            simulate(
                &f.store,
                &f.config,
                &f.bindings,
                &f.baseline,
                &bad,
                100,
                300
            )
            .is_err(),
            "{kind}"
        );
    }
    let mut json = serde_json::to_value(request).unwrap();
    json["program"] = json!("shell");
    assert!(from_json::<Request>(&serde_json::to_vec(&json).unwrap()).is_err());
}

#[test]
fn full_baseline_hash_prevents_conflict_data_swap_even_with_fresh_revision() {
    let f = Fixture::new(true);
    let request = f.plan().unwrap();
    for revision in [false, true] {
        let mut different = f.baseline.clone();
        different.config["opaque_synthetic_note"]["z"] = json!("concurrent");
        if revision {
            different.config_revision_sha256 = "3".repeat(64);
        }
        assert!(
            simulate(
                &f.store,
                &f.config,
                &f.bindings,
                &different,
                &request,
                100,
                300
            )
            .is_err()
        );
    }
}

#[test]
fn rollback_is_exact_guarded_and_retries_do_not_discard_concurrent_edits() {
    let f = Fixture::new(true);
    let simulation = f.simulation();
    let rolled = rollback(
        &f.store,
        &f.config,
        &f.bindings,
        &f.baseline,
        (&simulation.projection, &simulation),
        100,
        300,
    )
    .unwrap();
    assert_eq!(rolled.projection.config, f.baseline.config);
    assert_eq!(rolled.projection.offline_generation, 2);
    assert!(
        rollback(
            &f.store,
            &f.config,
            &f.bindings,
            &f.baseline,
            (&rolled.projection, &simulation),
            100,
            300
        )
        .is_err()
    );
    for kind in [
        "unmanaged",
        "owned",
        "revision",
        "time",
        "generation",
        "scope",
    ] {
        let mut current = simulation.projection.clone();
        match kind {
            "unmanaged" => current.config["opaque_synthetic_note"]["z"] = json!("concurrent"),
            "owned" => current.config["unbound"]["hosts"][1]["ip"] = json!("fd12:3456:789a:a::3"),
            "revision" => current.config_revision_sha256 = "3".repeat(64),
            "time" => current.captured_at_unix_secs = 101,
            "generation" => current.offline_generation += 1,
            _ => current
                .scopes
                .get_mut("lan")
                .unwrap()
                .external_static_addresses
                .clear(),
        }
        let before = current.clone();
        assert!(
            rollback(
                &f.store,
                &f.config,
                &f.bindings,
                &f.baseline,
                (&current, &simulation),
                100,
                300
            )
            .is_err(),
            "{kind}"
        );
        assert_eq!(current, before);
    }
}

#[test]
fn rollback_token_simulation_and_changed_authority_are_revalidated() {
    let mut f = Fixture::new(false);
    let original = f.simulation();
    for kind in ["token", "candidate", "mode"] {
        let mut bad = original.clone();
        match kind {
            "token" => bad.rollback.request_sha256 = "3".repeat(64),
            "candidate" => bad.projection.config["unbound"]["hosts"] = json!([]),
            _ => bad.network_writes = true,
        }
        assert!(
            rollback(
                &f.store,
                &f.config,
                &f.bindings,
                &f.baseline,
                (&original.projection, &bad),
                100,
                300
            )
            .is_err()
        );
    }
    f.store.retire(&f.config, "synthetic-device").unwrap();
    assert!(
        simulate(
            &f.store,
            &f.config,
            &f.bindings,
            &f.baseline,
            &original.request,
            100,
            300
        )
        .is_err()
    );
    assert!(
        rollback(
            &f.store,
            &f.config,
            &f.bindings,
            &f.baseline,
            (&original.projection, &original),
            100,
            300
        )
        .is_err()
    );
}

#[test]
fn canonical_hash_ignores_object_key_order_but_not_array_order() {
    let left: Value = from_json(br#"{"z":[{"b":2,"a":1},3],"a":"x"}"#).unwrap();
    let right: Value = from_json(br#"{"a":"x","z":[{"a":1,"b":2},3]}"#).unwrap();
    assert_ne!(
        serde_json::to_string(&left).unwrap(),
        serde_json::to_string(&right).unwrap()
    );
    assert_eq!(
        canonical_sha256(&left).unwrap(),
        canonical_sha256(&right).unwrap()
    );
    let reordered: Value = from_json(br#"{"a":"x","z":[3,{"a":1,"b":2}]}"#).unwrap();
    assert_ne!(
        canonical_sha256(&left).unwrap(),
        canonical_sha256(&reordered).unwrap()
    );
}

#[test]
fn lossy_json_numbers_are_rejected_before_hashing_or_preservation() {
    for number in [
        "18446744073709551616",
        "18446744073709551617",
        "-9223372036854775809",
        "0.1",
        "1.0",
        "1e0",
        "1e309",
    ] {
        let raw = format!(r#"{{"opaque":{{"items":[{number}]}}}}"#);
        assert!(from_json::<Value>(raw.as_bytes()).is_err(), "{number}");
    }
    let rounded: Value = serde_json::from_str(r#"{"opaque":18446744073709551617}"#).unwrap();
    assert!(canonical_sha256(&rounded).is_err());
    let mut f = Fixture::new(true);
    f.baseline.config["opaque_synthetic_note"] = rounded;
    assert!(f.plan().is_err());
}

#[test]
fn exact_integer_extremes_roundtrip_and_numeric_drift_changes_cas() {
    let first: Value = from_json(
        br#"{"min":-9223372036854775808,"max":18446744073709551615,"n":9007199254740992}"#,
    )
    .unwrap();
    let second: Value = from_json(
        br#"{"min":-9223372036854775808,"max":18446744073709551615,"n":9007199254740993}"#,
    )
    .unwrap();
    assert_ne!(
        canonical_sha256(&first).unwrap(),
        canonical_sha256(&second).unwrap()
    );
    let mut f = Fixture::new(true);
    f.baseline.config["opaque_synthetic_note"] = first.clone();
    let simulation = f.simulation();
    assert_eq!(simulation.projection.config["opaque_synthetic_note"], first);
    let encoded = serde_json::to_vec(&simulation.projection).unwrap();
    let roundtrip: Projection = from_json(&encoded).unwrap();
    assert_eq!(roundtrip, simulation.projection);
    let mut drifted = f.baseline.clone();
    drifted.config["opaque_synthetic_note"] = second;
    assert!(
        simulate(
            &f.store,
            &f.config,
            &f.bindings,
            &drifted,
            &simulation.request,
            100,
            300,
        )
        .is_err()
    );
}

#[test]
fn strict_envelopes_duplicate_json_keys_sizes_and_counts_fail() {
    let f = Fixture::new(false);
    let mut value = serde_json::to_value(&f.baseline).unwrap();
    value["ignored"] = json!(true);
    assert!(from_json::<Projection>(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(from_json::<Value>(br#"{"a":1,"a":2}"#).is_err());
    assert!(from_json::<Value>(&vec![b' '; MAX_BYTES as usize + 1]).is_err());
    let mut large = f.baseline.clone();
    large.external_dns = (0..MAX_RECORDS + 1)
        .map(|i| ExternalDns {
            name: format!("host-{i}.example."),
            addresses: vec![],
        })
        .collect();
    assert!(compile(&f.store, &f.config, &f.bindings, &large, 100, 300).is_err());
    large.external_dns.truncate(MAX_RECORDS);
    // Baseline fits, but the two proposed native objects exceed the shared record cap.
    assert!(compile(&f.store, &f.config, &f.bindings, &large, 100, 300).is_err());
    large.external_dns.truncate(MAX_RECORDS - 2);
    assert!(compile(&f.store, &f.config, &f.bindings, &large, 100, 300).is_ok());
}

#[test]
fn late_invalid_foreign_record_prevents_any_partial_application() {
    let mut f = Fixture::new(true);
    let request = f.plan().unwrap();
    f.baseline.config["unbound"]["hosts"]
        .as_array_mut()
        .unwrap()
        .push(json!({"host":"last-invalid"}));
    let before = serde_json::to_vec(&f.baseline).unwrap();
    assert!(
        simulate(
            &f.store,
            &f.config,
            &f.bindings,
            &f.baseline,
            &request,
            100,
            300
        )
        .is_err()
    );
    assert_eq!(serde_json::to_vec(&f.baseline).unwrap(), before);
}

#[test]
fn additional_pools_delegation_tracking_and_range_shapes_fail_closed() {
    for (field, value) in [
        (
            "pool",
            json!([{"range":{"from":"fd12:3456:789a:a::2","to":"fd12:3456:789a:a::10"}}]),
        ),
        (
            "prefixrange",
            json!({"from":"fd12:3456:789a:a::","to":"fd12:3456:789a:b::"}),
        ),
        ("custom_kea_config", json!("opaque")),
    ] {
        let mut f = Fixture::new(false);
        f.baseline.config["dhcpdv6"]["lan"][field] = value;
        assert!(f.plan().is_err(), "{field}");
    }
    let mut f = Fixture::new(false);
    f.baseline.config["dhcpdv6"]["lan"]["range"]["other"] = json!([]);
    assert!(f.plan().is_err());
    let mut f = Fixture::new(false);
    f.baseline.config["unbound"]["custom_options"] = json!("local-data: arbitrary");
    assert!(f.plan().is_err());
}

#[test]
fn actual_interface_path_requires_fixed_matching_address_and_prefix() {
    for interface in [
        Value::Null,
        json!({}),
        json!({"ipaddrv6":"track6","track6-interface":"wan","track6-prefix-id":"0","subnetv6":"64"}),
        json!({"ipaddrv6":"dhcp6","subnetv6":"64"}),
        json!({"ipaddrv6":"fd12:3456:789a:a::1","subnetv6":"48"}),
        json!({"ipaddrv6":"fd12:3456:789a:a::2","subnetv6":"64"}),
        json!({"ipaddrv6":"fd12:3456:789a:b::1","subnetv6":"64"}),
        json!({"ipaddrv6":"fd12:3456:789a:a::1","subnetv6":"64","track6-interface":"wan"}),
    ] {
        let mut f = Fixture::new(false);
        f.baseline.config["interfaces"]["lan"] = interface;
        assert!(f.plan().is_err());
    }
    let mut f = Fixture::new(false);
    f.baseline
        .config
        .as_object_mut()
        .unwrap()
        .remove("interfaces");
    assert!(f.plan().is_err());
    let mut f = Fixture::new(false);
    f.baseline.config["interfaces"]
        .as_object_mut()
        .unwrap()
        .remove("lan");
    assert!(f.plan().is_err());
    let mut f = Fixture::new(false);
    f.baseline.config["interfaces"]["wan"] =
        json!({"ipaddrv6":"dhcp6","opaque_field":"preserved, not a managed scope"});
    assert!(f.plan().is_ok());
}

#[test]
fn per_host_alias_address_and_operator_list_limits_are_enforced() {
    let mut f = Fixture::new(true);
    let aliases: Vec<_> = (0..128)
        .map(|i| {
            json!({
                "host": format!("alias-{i}"), "domain": "example", "description": "opaque"
            })
        })
        .collect();
    f.baseline.config["unbound"]["hosts"][0]["aliases"]["item"] = json!(aliases);
    assert!(f.plan().is_ok());
    f.baseline.config["unbound"]["hosts"][0]["aliases"]["item"]
        .as_array_mut()
        .unwrap()
        .push(json!({"host": "alias-128", "domain": "example"}));
    assert!(f.plan().is_err());
    let mut f = Fixture::new(true);
    f.baseline.config["unbound"]["hosts"][0]["ip"] = json!(
        (1..=128)
            .map(|n| format!("192.0.2.{n}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    assert!(f.plan().is_ok());
    let ips = f.baseline.config["unbound"]["hosts"][0]["ip"]
        .as_str()
        .unwrap()
        .to_owned();
    f.baseline.config["unbound"]["hosts"][0]["ip"] = json!(format!("{ips},192.0.2.129"));
    assert!(f.plan().is_err());
    let mut f = Fixture::new(false);
    f.bindings
        .links
        .get_mut("demo-link")
        .unwrap()
        .approved_reservation_addresses =
        vec!["fd12:3456:789a:a::2".parse().unwrap(); MAX_RECORDS + 1];
    assert!(f.plan().is_err());
    let mut f = Fixture::new(false);
    f.baseline
        .scopes
        .get_mut("lan")
        .unwrap()
        .external_static_addresses = vec!["fd12:3456:789a:a::35".parse().unwrap(); MAX_RECORDS + 1];
    assert!(f.plan().is_err());
}

#[test]
fn only_new_owned_entries_are_sorted_not_existing_objects() {
    let mut f = Fixture::new(true);
    let device = InventoryDevice {
        asset_id: "a-second".into(),
        duid: "00:04:aa:bb".parse().unwrap(),
        iaid: 8,
        managed: true,
        dns_label: "second".into(),
    };
    f.store.register(&device).unwrap();
    f.store
        .allocate(
            &f.config,
            &Observation {
                duid: device.duid,
                iaid: 8,
                hostname: None,
            },
            "demo-link",
        )
        .unwrap();
    let simulation = f.simulation();
    let hosts = NativePath::Hosts
        .collection(&simulation.projection)
        .unwrap();
    assert_eq!(hosts[0]["descr"], "operator-owned");
    assert_eq!(hosts[1]["descr"], "v6alias:a-second");
    assert_eq!(hosts[2]["descr"], "v6alias:synthetic-device");
}
