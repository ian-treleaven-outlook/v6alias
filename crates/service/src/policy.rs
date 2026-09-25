use crate::{
    Decision, InventoryDevice, Observation, Rule, RuleTrace, ServiceConfig, ServiceError,
    validate_dns_label,
};

/// Evaluates known inventory against operator-provided link placement, without side effects.
///
/// Hostnames are optional, untrusted policy hints, never DNS names or placement authority.
/// A supplied malformed hostname denies the entire request: treating it as absent could
/// otherwise let a wildcard rule grant access after a hostname-constrained rule fails.
pub fn evaluate(
    config: &ServiceConfig,
    observation: &Observation,
    trusted_link: &str,
    device: Option<&InventoryDevice>,
) -> Result<Decision, ServiceError> {
    config.validate()?;

    let mut rules: Vec<_> = config.rules.iter().collect();
    rules.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.name.cmp(&right.name))
    });

    let reject = |reason: &str| {
        denied(
            reason.to_owned(),
            rules
                .iter()
                .map(|rule| RuleTrace {
                    rule: rule.name.clone(),
                    priority: rule.priority,
                    matched: false,
                    reason: format!("not evaluated: {reason}"),
                })
                .collect(),
        )
    };

    if validate_dns_label(trusted_link).is_err() {
        return Ok(reject("invalid trusted link label"));
    }
    let Some(link) = config.links.get(trusted_link) else {
        return Ok(reject("unknown or unconfigured trusted link"));
    };
    let profile = config.profiles.get(&link.profile).ok_or_else(|| {
        ServiceError::Config(format!(
            "trusted link `{trusted_link}` references an unknown profile"
        ))
    })?;

    let Some(device) = device else {
        return Ok(reject(
            "inventory device is required; a hostname cannot establish identity",
        ));
    };
    device.validate()?;
    if device.duid != observation.duid {
        return Ok(reject("inventory DUID does not match the observation DUID"));
    }
    if device.iaid != observation.iaid {
        return Ok(reject("inventory IAID does not match the observation IAID"));
    }

    let hostname = observation.hostname.as_deref();
    if hostname.is_some_and(|hint| validate_dns_label(hint).is_err()) {
        return Ok(reject(
            "invalid hostname hint: expected one lowercase ASCII DNS label of 1-63 characters without edge hyphens; wildcard fallback is forbidden",
        ));
    }
    if profile.require_managed && !device.managed {
        return Ok(reject(
            "trusted link's profile requires managed inventory; rules and hostname hints cannot override this requirement",
        ));
    }

    let trace: Vec<_> = rules
        .iter()
        .map(|rule| trace_rule(rule, trusted_link, device, hostname))
        .collect();
    let Some(winner) = trace.iter().find(|entry| entry.matched) else {
        return Ok(denied("no matching policy rule".into(), trace));
    };
    let tied: Vec<_> = trace
        .iter()
        .filter(|entry| entry.matched && entry.priority == winner.priority)
        .map(|entry| entry.rule.as_str())
        .collect();
    if tied.len() > 1 {
        return Ok(denied(
            format!(
                "ambiguous policy: multiple rules match at highest priority {}: {}",
                winner.priority,
                tied.join(", ")
            ),
            trace,
        ));
    }

    Ok(Decision {
        allowed: true,
        reason: format!(
            "rule `{}` at priority {} permits known inventory on trusted link `{trusted_link}`; profile `{}` and subnet {} come from trusted link placement",
            winner.rule, winner.priority, link.profile, link.subnet
        ),
        matched_rule: Some(winner.rule.clone()),
        profile: Some(link.profile.clone()),
        subnet: Some(link.subnet),
        trace,
    })
}

fn denied(reason: String, trace: Vec<RuleTrace>) -> Decision {
    Decision {
        allowed: false,
        reason,
        matched_rule: None,
        profile: None,
        subnet: None,
        trace,
    }
}

fn trace_rule(
    rule: &Rule,
    trusted_link: &str,
    device: &InventoryDevice,
    hostname: Option<&str>,
) -> RuleTrace {
    let mut matched = true;
    let mut reasons = Vec::new();
    if rule.links.contains(trusted_link) {
        reasons.push("trusted link matches".to_owned());
    } else {
        matched = false;
        reasons.push("trusted link is not included in this rule".to_owned());
    }
    match rule.managed {
        Some(required) if required != device.managed => {
            matched = false;
            reasons.push(format!(
                "managed filter mismatch: requires {required}, inventory is {}",
                device.managed
            ));
        }
        Some(_) => reasons.push("managed filter matches inventory".to_owned()),
        None => reasons.push("no managed filter specified".to_owned()),
    }
    match (rule.hostname_prefix.as_deref(), hostname) {
        (Some(prefix), Some(hint)) if hint.starts_with(prefix) => {
            reasons.push("hostname prefix matches validated hint only".to_owned());
        }
        (Some(_), Some(_)) => {
            matched = false;
            reasons.push("hostname prefix does not match the validated hint".to_owned());
        }
        (Some(_), None) => {
            matched = false;
            reasons.push("hostname hint is missing but a prefix is required".to_owned());
        }
        (None, _) => reasons.push("no hostname hint required".to_owned()),
    }
    RuleTrace {
        rule: rule.name.clone(),
        priority: rule.priority,
        matched,
        reason: reasons.join("; "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../../service.example.yaml");

    fn config() -> ServiceConfig {
        ServiceConfig::from_yaml(EXAMPLE).unwrap()
    }

    fn device(managed: bool) -> InventoryDevice {
        InventoryDevice {
            asset_id: "asset-42".into(),
            duid: "00:01:ab:cd".parse().unwrap(),
            iaid: 42,
            managed,
            dns_label: "inventory-authoritative".into(),
        }
    }

    fn observation(device: &InventoryDevice, hostname: Option<&str>) -> Observation {
        Observation {
            duid: device.duid.clone(),
            iaid: device.iaid,
            hostname: hostname.map(str::to_owned),
        }
    }

    fn lab_rule(
        name: &str,
        priority: i32,
        managed: Option<bool>,
        hostname_prefix: Option<&str>,
    ) -> Rule {
        Rule {
            name: name.into(),
            priority,
            links: ["lab-link".into()].into(),
            managed,
            hostname_prefix: hostname_prefix.map(str::to_owned),
            profile: "lab".into(),
        }
    }

    fn assert_denied(decision: &Decision, reason: &str) {
        assert!(!decision.allowed, "{decision:?}");
        assert!(decision.reason.contains(reason), "{decision:?}");
        assert_eq!(decision.matched_rule, None);
        assert_eq!(decision.profile, None);
        assert_eq!(decision.subnet, None);
        assert!(!decision.trace.is_empty());
        assert!(decision.trace.iter().all(|entry| !entry.reason.is_empty()));
    }

    #[test]
    fn known_managed_corporate_device_uses_actual_link_placement() {
        let mut config = config();
        config.links.get_mut("corp-link").unwrap().subnet = 31;
        let device = device(true);
        let observation = observation(&device, Some("client-chosen"));
        let original_device = device.clone();
        let original_observation = observation.clone();
        let decision = evaluate(&config, &observation, "corp-link", Some(&device)).unwrap();

        assert!(decision.allowed, "{decision:?}");
        assert_eq!(decision.matched_rule.as_deref(), Some("managed-corporate"));
        assert_eq!(decision.profile.as_deref(), Some("corp"));
        assert_eq!(decision.subnet, Some(31));
        assert_ne!(
            decision.subnet,
            Some(config.profiles["corp"].default_subnet)
        );
        assert_eq!(device, original_device);
        assert_eq!(observation, original_observation);
        assert_eq!(device.dns_label, "inventory-authoritative");
        assert!(decision.reason.contains("trusted link placement"));
        assert!(decision.trace[0].matched);
        assert!(decision.trace[0].reason.contains("managed filter matches"));
        assert!(decision.trace[1..].iter().all(|entry| !entry.matched));
    }

    #[test]
    fn missing_hostname_does_not_block_an_inventory_only_rule() {
        let config = config();
        let device = device(true);
        let decision = evaluate(
            &config,
            &observation(&device, None),
            "corp-link",
            Some(&device),
        )
        .unwrap();
        assert!(decision.allowed);
        assert!(
            decision.trace[0]
                .reason
                .contains("no hostname hint required")
        );
    }

    #[test]
    fn corporate_managed_requirement_cannot_be_overridden_by_rules_or_hostname() {
        for managed in [None, Some(false), Some(true)] {
            let mut config = config();
            let rule = &mut config.rules[0];
            rule.managed = managed;
            rule.hostname_prefix = Some("corp-".into());
            let device = device(false);
            let decision = evaluate(
                &config,
                &observation(&device, Some("corp-admin")),
                "corp-link",
                Some(&device),
            )
            .unwrap();
            assert_denied(&decision, "requires managed inventory");
            assert!(decision.trace.iter().all(|entry| !entry.matched));
        }
    }

    #[test]
    fn managed_is_required_by_default_in_every_profile() {
        let yaml = EXAMPLE
            .replace("\r\n", "\n")
            .replace("    require_managed: true\n", "")
            .replace("    require_managed: false\n", "");
        let mut config = ServiceConfig::from_yaml(&yaml).unwrap();
        assert!(
            config
                .profiles
                .values()
                .all(|profile| profile.require_managed)
        );
        for rule in &mut config.rules {
            rule.managed = None;
        }
        let device = device(false);
        for link in ["corp-link", "lab-link", "quarantine-link"] {
            let decision =
                evaluate(&config, &observation(&device, None), link, Some(&device)).unwrap();
            assert_denied(&decision, "requires managed inventory");
        }
    }

    #[test]
    fn unknown_inventory_is_denied_even_with_a_convincing_hostname() {
        let mut config = config();
        config.rules[0].managed = None;
        config.rules[0].hostname_prefix = Some("corp-".into());
        let observation = observation(&device(true), Some("corp-admin"));
        for link in ["corp-link", "lab-link", "quarantine-link"] {
            let decision = evaluate(&config, &observation, link, None).unwrap();
            assert_denied(&decision, "inventory device is required");
            assert!(decision.trace.iter().all(|entry| !entry.matched));
        }
    }

    #[test]
    fn mismatched_duid_or_iaid_is_denied() {
        let config = config();
        let device = device(true);
        let mut wrong_duid = observation(&device, None);
        wrong_duid.duid = "0001ffff".parse().unwrap();
        let mut wrong_iaid = observation(&device, None);
        wrong_iaid.iaid += 1;
        for (observation, reason) in [(wrong_duid, "DUID"), (wrong_iaid, "IAID")] {
            let decision = evaluate(&config, &observation, "corp-link", Some(&device)).unwrap();
            assert_denied(&decision, reason);
        }
    }

    #[test]
    fn invalid_inventory_is_an_explicit_error() {
        let config = config();
        let mut invalid_asset = device(true);
        invalid_asset.asset_id = "bad.asset".into();
        let mut invalid_dns = device(true);
        invalid_dns.dns_label = "host.example".into();
        for device in [invalid_asset, invalid_dns] {
            let result = evaluate(
                &config,
                &observation(&device, None),
                "corp-link",
                Some(&device),
            );
            assert!(matches!(result, Err(ServiceError::Validation(_))));
        }
    }

    #[test]
    fn unknown_and_invalid_trusted_links_are_explicit_denials() {
        let config = config();
        let device = device(true);
        let observation = observation(&device, Some("corp-link"));
        let unknown = evaluate(&config, &observation, "unknown-link", Some(&device)).unwrap();
        assert_denied(&unknown, "unknown or unconfigured trusted link");
        for link in ["", "Corp-link", "corp-link.example", "corp-link ", "-corp"] {
            let decision = evaluate(&config, &observation, link, Some(&device)).unwrap();
            assert_denied(&decision, "invalid trusted link label");
        }
    }

    #[test]
    fn rules_are_confined_to_their_explicit_trusted_links() {
        let mut config = config();
        config.rules = vec![lab_rule("lab-only", 100, None, None)];
        let mut second_link = config.links["lab-link"].clone();
        second_link.subnet = 8;
        config.links.insert("second-lab-link".into(), second_link);
        let device = device(true);
        for link in ["corp-link", "quarantine-link", "second-lab-link"] {
            let decision = evaluate(
                &config,
                &observation(&device, Some("lab-node")),
                link,
                Some(&device),
            )
            .unwrap();
            assert_denied(&decision, "no matching policy rule");
            assert!(!decision.trace[0].matched);
            assert!(
                decision.trace[0]
                    .reason
                    .contains("trusted link is not included")
            );
        }
    }

    #[test]
    fn invalid_rules_are_configuration_errors_before_observation_denials() {
        let base = config();
        let mut invalid_rules = Vec::new();
        let mut cross_profile = base.clone();
        cross_profile.rules[0].profile = "lab".into();
        invalid_rules.push(cross_profile);
        let mut unknown_profile = base.clone();
        unknown_profile.rules[0].profile = "missing".into();
        invalid_rules.push(unknown_profile);
        let mut unknown_link = base.clone();
        unknown_link.rules[0].links = ["missing-link".into()].into();
        invalid_rules.push(unknown_link);
        let mut no_links = base.clone();
        no_links.rules[0].links.clear();
        invalid_rules.push(no_links);
        let mut duplicate = base.clone();
        duplicate.rules.push(duplicate.rules[0].clone());
        invalid_rules.push(duplicate);
        for prefix in ["", "*", "UPPER", "host.name", "host\n"] {
            let mut bad_prefix = base.clone();
            bad_prefix.rules[0].hostname_prefix = Some(prefix.into());
            invalid_rules.push(bad_prefix);
        }
        let mut long_prefix = base;
        long_prefix.rules[0].hostname_prefix = Some("a".repeat(64));
        invalid_rules.push(long_prefix);

        let observation = observation(&device(true), Some("bad.hostname"));
        for config in invalid_rules {
            let result = evaluate(&config, &observation, "unknown-link", None);
            assert!(matches!(result, Err(ServiceError::Config(_))), "{result:?}");
        }
    }

    #[test]
    fn missing_link_profile_is_an_error_not_a_panic_or_denial() {
        let mut config = config();
        config.profiles.remove("corp");
        let device = device(true);
        assert!(matches!(
            evaluate(
                &config,
                &observation(&device, None),
                "corp-link",
                Some(&device)
            ),
            Err(ServiceError::Config(_))
        ));
    }

    #[test]
    fn trace_is_priority_descending_then_name_and_independent_of_rule_order() {
        let mut config = config();
        let mut blocked = config.rules[0].clone();
        blocked.name = "blocked".into();
        blocked.priority = i32::MAX;
        config.rules = vec![
            lab_rule("low-z", i32::MIN, None, None),
            blocked,
            lab_rule("winner", 42, None, None),
            lab_rule("low-a", i32::MIN, None, None),
        ];
        let device = device(false);
        let observation = observation(&device, None);
        let expected = evaluate(&config, &observation, "lab-link", Some(&device)).unwrap();
        assert!(expected.allowed);
        assert_eq!(expected.matched_rule.as_deref(), Some("winner"));
        assert_eq!(
            expected
                .trace
                .iter()
                .map(|entry| (entry.rule.as_str(), entry.priority, entry.matched))
                .collect::<Vec<_>>(),
            [
                ("blocked", i32::MAX, false),
                ("winner", 42, true),
                ("low-a", i32::MIN, true),
                ("low-z", i32::MIN, true),
            ]
        );
        for _ in 0..config.rules.len() {
            config.rules.rotate_left(1);
            assert_eq!(
                evaluate(&config, &observation, "lab-link", Some(&device)).unwrap(),
                expected
            );
        }
        config.rules.reverse();
        assert_eq!(
            evaluate(&config, &observation, "lab-link", Some(&device)).unwrap(),
            expected
        );
    }

    #[test]
    fn equal_highest_priority_denies_even_when_profiles_are_identical() {
        let mut config = config();
        config.rules = vec![
            lab_rule("zeta", 42, None, None),
            lab_rule("lower", 41, None, None),
            lab_rule("alpha", 42, None, None),
        ];
        let device = device(false);
        let observation = observation(&device, None);
        let decision = evaluate(&config, &observation, "lab-link", Some(&device)).unwrap();
        assert_denied(&decision, "ambiguous policy");
        assert!(decision.reason.contains("highest priority 42: alpha, zeta"));
        assert!(decision.trace.iter().all(|entry| entry.matched));
        config.rules.reverse();
        assert_eq!(
            evaluate(&config, &observation, "lab-link", Some(&device)).unwrap(),
            decision
        );
    }

    #[test]
    fn a_nonmatching_high_rule_does_not_block_a_lower_match() {
        let mut config = config();
        config.rules = vec![
            lab_rule("high", 10, None, Some("admin-")),
            lab_rule("low", -10, None, None),
        ];
        let device = device(false);
        let decision = evaluate(
            &config,
            &observation(&device, Some("lab-node")),
            "lab-link",
            Some(&device),
        )
        .unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.matched_rule.as_deref(), Some("low"));
        assert!(!decision.trace[0].matched);
        assert!(
            decision.trace[0]
                .reason
                .contains("hostname prefix does not match")
        );
        assert!(decision.trace[1].matched);
    }

    #[test]
    fn managed_filters_match_inventory_in_both_directions() {
        for required in [false, true] {
            let mut config = config();
            config.rules = vec![lab_rule("managed-filter", 1, Some(required), None)];
            for managed in [false, true] {
                let device = device(managed);
                let decision = evaluate(
                    &config,
                    &observation(&device, None),
                    "lab-link",
                    Some(&device),
                )
                .unwrap();
                assert_eq!(decision.allowed, required == managed);
                if required != managed {
                    assert_denied(&decision, "no matching policy rule");
                    assert!(decision.trace[0].reason.contains("managed filter mismatch"));
                }
            }
        }
    }

    #[test]
    fn hostname_prefix_is_a_conjunctive_lab_hint_not_dns_authority() {
        let mut config = config();
        config.rules = vec![lab_rule("lab-hint", 1, Some(false), Some("lab-"))];
        let device = device(false);
        for (hint, allowed) in [
            (Some("lab-node"), true),
            (Some("lab"), false),
            (Some("xlab-node"), false),
            (Some("corp-node"), false),
            (None, false),
        ] {
            let decision = evaluate(
                &config,
                &observation(&device, hint),
                "lab-link",
                Some(&device),
            )
            .unwrap();
            assert_eq!(decision.allowed, allowed, "{decision:?}");
            if allowed {
                assert_eq!(decision.profile.as_deref(), Some("lab"));
                assert_eq!(decision.subnet, Some(config.links["lab-link"].subnet));
                assert!(decision.trace[0].reason.contains("validated hint only"));
            } else {
                assert_denied(&decision, "no matching policy rule");
                assert!(!decision.trace[0].matched);
                if hint.is_none() {
                    assert!(
                        decision.trace[0]
                            .reason
                            .contains("hostname hint is missing")
                    );
                }
            }
        }
        assert_eq!(device.dns_label, "inventory-authoritative");
        let mut managed_device = device.clone();
        managed_device.managed = true;
        let decision = evaluate(
            &config,
            &observation(&managed_device, Some("lab-node")),
            "lab-link",
            Some(&managed_device),
        )
        .unwrap();
        assert_denied(&decision, "no matching policy rule");
    }

    #[test]
    fn hostname_cannot_override_the_trusted_placement() {
        let config = config();
        let device = device(true);
        let decision = evaluate(
            &config,
            &observation(&device, Some("corp-admin")),
            "lab-link",
            Some(&device),
        )
        .unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.profile.as_deref(), Some("lab"));
        assert_eq!(decision.matched_rule.as_deref(), Some("inventoried-lab"));
        assert_eq!(decision.subnet, Some(config.links["lab-link"].subnet));
    }

    #[test]
    fn malformed_hostname_denies_instead_of_falling_through_to_a_wildcard() {
        let mut config = config();
        config.rules = vec![
            lab_rule("hint", 10, None, Some("lab-")),
            lab_rule("wildcard", 1, None, None),
        ];
        let device = device(false);
        let invalid_hints = [
            "".to_owned(),
            format!("lab-{}", "a".repeat(60)),
            "lab-café".to_owned(),
            "lab-node.example".to_owned(),
            "lab-Node".to_owned(),
            "-lab-node".to_owned(),
            "lab-".to_owned(),
            "lab-node\nAAAA".to_owned(),
            " lab-node".to_owned(),
            "lab-node.".to_owned(),
        ];
        for hint in invalid_hints {
            let decision = evaluate(
                &config,
                &observation(&device, Some(&hint)),
                "lab-link",
                Some(&device),
            )
            .unwrap();
            assert_denied(&decision, "invalid hostname hint");
            assert!(decision.reason.contains("wildcard fallback is forbidden"));
            assert_eq!(decision.trace.len(), 2);
            assert!(
                decision.trace.iter().all(|entry| {
                    !entry.matched && entry.reason.contains("invalid hostname hint")
                })
            );
        }
        let absent = evaluate(
            &config,
            &observation(&device, None),
            "lab-link",
            Some(&device),
        )
        .unwrap();
        assert!(absent.allowed);
        assert_eq!(absent.matched_rule.as_deref(), Some("wildcard"));
        let valid = format!("lab-{}", "a".repeat(59));
        let valid = evaluate(
            &config,
            &observation(&device, Some(&valid)),
            "lab-link",
            Some(&device),
        )
        .unwrap();
        assert!(valid.allowed);
        assert_eq!(valid.matched_rule.as_deref(), Some("hint"));
    }

    #[test]
    fn malformed_hostname_is_denied_even_without_any_hostname_rules() {
        let config = config();
        let device = device(true);
        let decision = evaluate(
            &config,
            &observation(&device, Some("client.example")),
            "corp-link",
            Some(&device),
        )
        .unwrap();
        assert_denied(&decision, "invalid hostname hint");
    }

    #[test]
    fn quarantine_requires_explicit_policy_and_its_own_trusted_link() {
        let mut config = config();
        config.rules.retain(|rule| rule.profile == "quarantine");
        let device = device(false);
        let observation = observation(&device, Some("corp-admin"));
        let decision = evaluate(&config, &observation, "quarantine-link", Some(&device)).unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.profile.as_deref(), Some("quarantine"));
        assert_eq!(
            decision.subnet,
            Some(config.links["quarantine-link"].subnet)
        );
        assert_eq!(
            decision.matched_rule.as_deref(),
            Some("inventoried-quarantine")
        );
        for (link, reason) in [
            ("corp-link", "requires managed inventory"),
            ("lab-link", "no matching policy rule"),
        ] {
            let denied = evaluate(&config, &observation, link, Some(&device)).unwrap();
            assert_denied(&denied, reason);
        }
        let mut without_quarantine = ServiceConfig::from_yaml(EXAMPLE).unwrap();
        without_quarantine
            .rules
            .retain(|rule| rule.profile != "quarantine");
        let denied = evaluate(
            &without_quarantine,
            &observation,
            "quarantine-link",
            Some(&device),
        )
        .unwrap();
        assert_denied(&denied, "no matching policy rule");
        config
            .profiles
            .get_mut("quarantine")
            .unwrap()
            .require_managed = true;
        let denied = evaluate(&config, &observation, "quarantine-link", Some(&device)).unwrap();
        assert_denied(&denied, "requires managed inventory");
    }
}
