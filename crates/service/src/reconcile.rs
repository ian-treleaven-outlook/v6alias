//! Offline, provider-neutral review manifests, not executable provider configuration.
//! Observations are trusted only when they exactly match validated active or retired assignments.

use std::{collections::BTreeSet, net::Ipv6Addr};

use serde::{Deserialize, Serialize};
use v6alias_core::Alias;

use crate::{Assignment, AssignmentState, Duid, ServiceConfig, ServiceError, validate_dns_label};

const SCHEMA_VERSION: u32 = 1;
const OWNER: &str = "v6alias";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    pub asset_id: String,
    pub link: String,
    pub duid: Duid,
    pub iaid: u32,
    pub address: Ipv6Addr,
    pub fqdn: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum DnsRecord {
    #[serde(rename = "AAAA")]
    Aaaa {
        name: String,
        value: Ipv6Addr,
        ttl: u32,
    },
    #[serde(rename = "PTR")]
    Ptr {
        name: String,
        value: String,
        ttl: u32,
    },
}

impl DnsRecord {
    fn key(&self) -> (&'static str, &str) {
        match self {
            Self::Aaaa { name, .. } => ("AAAA", name),
            Self::Ptr { name, .. } => ("PTR", name),
        }
    }

    fn ttl(&self) -> u32 {
        match self {
            Self::Aaaa { ttl, .. } | Self::Ptr { ttl, .. } => *ttl,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema_version: u32,
    pub owner: String,
    pub reservations: Vec<Reservation>,
    pub dns_records: Vec<DnsRecord>,
}

impl Snapshot {
    pub fn empty() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            owner: OWNER.into(),
            reservations: Vec::new(),
            dns_records: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Changes {
    pub add_reservations: Vec<Reservation>,
    pub remove_reservations: Vec<Reservation>,
    pub add_dns_records: Vec<DnsRecord>,
    pub remove_dns_records: Vec<DnsRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub mode: String,
    pub basis: String,
    pub desired: Snapshot,
    pub changes: Changes,
}

/// Produce an abstract review manifest without reading or changing any provider.
///
/// No snapshot means desired state only, never an assumption that providers are empty.
/// An explicit snapshot may contain only exact resources derived from the complete
/// assignment history; retired assignments authorize removal, not arbitrary ownership tags.
pub fn plan(
    config: &ServiceConfig,
    assignments: &[Assignment],
    observed: Option<&Snapshot>,
) -> Result<Plan, ServiceError> {
    config.validate()?;
    validate_assignments(config, assignments)?;

    let mut known = Resources::default();
    let mut desired = Resources::default();
    for assignment in assignments {
        known.insert(assignment, config.dns_ttl_seconds);
        if assignment.state == AssignmentState::Active {
            desired.insert(assignment, config.dns_ttl_seconds);
        }
    }

    let changes = match observed {
        None => Changes::default(),
        Some(snapshot) => {
            let observed = validate_snapshot(snapshot, &known, config.dns_ttl_seconds)?;
            Changes {
                add_reservations: desired
                    .reservations
                    .difference(&observed.reservations)
                    .cloned()
                    .collect(),
                remove_reservations: observed
                    .reservations
                    .difference(&desired.reservations)
                    .cloned()
                    .collect(),
                add_dns_records: desired
                    .dns_records
                    .difference(&observed.dns_records)
                    .cloned()
                    .collect(),
                remove_dns_records: observed
                    .dns_records
                    .difference(&desired.dns_records)
                    .cloned()
                    .collect(),
            }
        }
    };

    Ok(Plan {
        mode: "dry_run".into(),
        basis: if observed.is_some() {
            "owned_snapshot"
        } else {
            "desired_only"
        }
        .into(),
        desired: Snapshot {
            reservations: desired.reservations.into_iter().collect(),
            dns_records: desired.dns_records.into_iter().collect(),
            ..Snapshot::empty()
        },
        changes,
    })
}

/// Return all 32 reversed IPv6 nibbles with an absolute `ip6.arpa.` suffix.
pub fn reverse_name(address: Ipv6Addr) -> String {
    let mut name = String::with_capacity(73);
    for byte in address.octets().into_iter().rev() {
        for nibble in [byte & 0xf, byte >> 4] {
            name.push(b"0123456789abcdef"[usize::from(nibble)] as char);
            name.push('.');
        }
    }
    name.push_str("ip6.arpa.");
    name
}

#[derive(Default)]
struct Resources {
    reservations: BTreeSet<Reservation>,
    dns_records: BTreeSet<DnsRecord>,
}

impl Resources {
    fn insert(&mut self, assignment: &Assignment, ttl: u32) {
        self.reservations.insert(Reservation {
            asset_id: assignment.asset_id.clone(),
            link: assignment.link.clone(),
            duid: assignment.duid.clone(),
            iaid: assignment.iaid,
            address: assignment.address,
            fqdn: assignment.fqdn.clone(),
        });
        self.dns_records.insert(DnsRecord::Aaaa {
            name: assignment.fqdn.clone(),
            value: assignment.address,
            ttl,
        });
        self.dns_records.insert(DnsRecord::Ptr {
            name: reverse_name(assignment.address),
            value: assignment.fqdn.clone(),
            ttl,
        });
    }
}

fn require_unique<T: Ord>(
    keys: &mut BTreeSet<T>,
    key: T,
    description: &str,
) -> Result<(), ServiceError> {
    if !keys.insert(key) {
        return Err(ServiceError::Conflict(format!(
            "duplicate {description}; manual review required"
        )));
    }
    Ok(())
}

fn validate_assignments(
    config: &ServiceConfig,
    assignments: &[Assignment],
) -> Result<(), ServiceError> {
    let mut assets = BTreeSet::new();
    let mut duids = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut slots = BTreeSet::new();
    let address_config = config.address_config();
    let suffix = format!(".{}.", config.dns_zone);

    for assignment in assignments {
        let invalid = |detail: &str| {
            ServiceError::Validation(format!("assignment `{}`: {detail}", assignment.asset_id))
        };
        validate_dns_label(&assignment.asset_id)?;
        let label = assignment.fqdn.strip_suffix(&suffix).ok_or_else(|| {
            invalid("FQDN must be an absolute direct child of the configured DNS zone")
        })?;
        config.fqdn(label)?;

        let link = config
            .links
            .get(&assignment.link)
            .ok_or_else(|| invalid("unknown trusted link"))?;
        if !config.profiles.contains_key(&assignment.profile) {
            return Err(invalid("unknown address profile"));
        }
        if assignment.profile != link.profile || assignment.subnet != link.subnet {
            return Err(invalid("profile/subnet does not match the trusted link"));
        }
        if !(link.pool.first..=link.pool.last).contains(&assignment.device) {
            return Err(invalid("device number is outside the trusted link pool"));
        }
        if link.reserved.contains(&assignment.device) {
            return Err(invalid("device number is reserved on the trusted link"));
        }
        let rule = config
            .rules
            .iter()
            .find(|rule| rule.name == assignment.policy_rule)
            .ok_or_else(|| invalid("unknown policy rule"))?;
        if rule.profile != assignment.profile || !rule.links.contains(&assignment.link) {
            return Err(invalid("policy rule does not authorize this link/profile"));
        }
        let expected = address_config.resolve(&Alias {
            profile: assignment.profile.clone(),
            subnet: Some(assignment.subnet),
            device: assignment.device,
        })?;
        if assignment.address != expected {
            return Err(invalid(&format!(
                "address {} does not match resolved alias address {expected}",
                assignment.address
            )));
        }

        require_unique(&mut assets, &assignment.asset_id, "assignment asset ID")?;
        require_unique(&mut duids, &assignment.duid, "assignment DUID")?;
        require_unique(&mut addresses, assignment.address, "assignment address")?;
        require_unique(&mut names, &assignment.fqdn, "assignment FQDN")?;
        require_unique(
            &mut slots,
            (&assignment.profile, assignment.subnet, assignment.device),
            "assignment profile/subnet/device",
        )?;
    }
    Ok(())
}

fn validate_snapshot(
    snapshot: &Snapshot,
    known: &Resources,
    ttl: u32,
) -> Result<Resources, ServiceError> {
    if snapshot.schema_version != SCHEMA_VERSION {
        return Err(ServiceError::Conflict(format!(
            "unsupported snapshot schema version {}; expected {SCHEMA_VERSION}; manual review required",
            snapshot.schema_version
        )));
    }
    if snapshot.owner != OWNER {
        return Err(ServiceError::Conflict(format!(
            "snapshot owner `{}` is not `{OWNER}`; manual review required",
            snapshot.owner
        )));
    }
    let mut assets = BTreeSet::new();
    let mut duids = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut dns_keys = BTreeSet::new();
    let mut observed = Resources::default();
    for reservation in &snapshot.reservations {
        require_unique(
            &mut assets,
            &reservation.asset_id,
            "snapshot reservation asset ID",
        )?;
        require_unique(&mut duids, &reservation.duid, "snapshot reservation DUID")?;
        require_unique(
            &mut addresses,
            reservation.address,
            "snapshot reservation address",
        )?;
        require_unique(&mut names, &reservation.fqdn, "snapshot reservation FQDN")?;
        if !known.reservations.contains(reservation) {
            return Err(ServiceError::Conflict(format!(
                "snapshot reservation `{}` is unknown or drifted from the exact assignment history; manual review required",
                reservation.asset_id
            )));
        }
        observed.reservations.insert(reservation.clone());
    }
    for record in &snapshot.dns_records {
        let (kind, name) = record.key();
        require_unique(&mut dns_keys, record.key(), "snapshot DNS type/name")?;
        if record.ttl() != ttl {
            return Err(ServiceError::Conflict(format!(
                "snapshot {kind} `{name}` has TTL {}; expected {ttl}; manual review required",
                record.ttl()
            )));
        }
        if !known.dns_records.contains(record) {
            return Err(ServiceError::Conflict(format!(
                "snapshot {kind} `{name}` is unknown or drifted from the exact assignment history; manual review required"
            )));
        }
        observed.dns_records.insert(record.clone());
    }
    Ok(observed)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn config() -> ServiceConfig {
        ServiceConfig::from_yaml(include_str!("../../../service.example.yaml")).unwrap()
    }

    fn assignment(config: &ServiceConfig, device: u16) -> Assignment {
        let link = &config.links["corp-link"];
        Assignment {
            asset_id: format!("asset-{device}"),
            duid: format!("0001{device:04x}").parse().unwrap(),
            iaid: u32::from(device),
            link: "corp-link".into(),
            profile: link.profile.clone(),
            subnet: link.subnet,
            device,
            address: config
                .address_config()
                .resolve(&Alias {
                    profile: link.profile.clone(),
                    subnet: Some(link.subnet),
                    device,
                })
                .unwrap(),
            fqdn: format!("host-{device}.{}.", config.dns_zone),
            state: AssignmentState::Active,
            policy_rule: "managed-corporate".into(),
        }
    }

    fn assert_conflict(result: Result<Plan, ServiceError>) {
        assert!(
            matches!(result, Err(ServiceError::Conflict(_))),
            "{result:?}"
        );
    }

    #[test]
    fn selected_ttl_drives_both_dns_types_and_observed_validation() {
        let mut config = config();
        let assignments = [assignment(&config, 2)];
        let legacy = plan(&config, &assignments, None).unwrap().desired;
        config.dns_ttl_seconds = 3600;
        let selected = plan(&config, &assignments, None).unwrap().desired;
        assert_eq!(selected.dns_records.len(), 2);
        assert!(selected.dns_records.iter().all(|r| r.ttl() == 3600));
        assert_eq!(
            plan(&config, &assignments, Some(&selected))
                .unwrap()
                .changes,
            Changes::default()
        );
        assert!(plan(&config, &assignments, Some(&legacy)).is_err());
        for index in 0..2 {
            let mut stale = selected.clone();
            match &mut stale.dns_records[index] {
                DnsRecord::Aaaa { ttl, .. } | DnsRecord::Ptr { ttl, .. } => *ttl = 300,
            }
            assert!(plan(&config, &assignments, Some(&stale)).is_err());
        }
    }

    #[test]
    fn reverse_name_matches_all_32_nibbles_exactly() {
        assert_eq!(
            reverse_name("2001:db8::1".parse().unwrap()),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
        );
        assert_eq!(
            reverse_name("0123:4567:89ab:cdef:0123:4567:89ab:cdef".parse().unwrap()),
            "f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.0.f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.0.ip6.arpa."
        );
        assert_eq!(
            reverse_name(Ipv6Addr::UNSPECIFIED),
            format!("{}ip6.arpa.", "0.".repeat(32))
        );
        assert_eq!(
            reverse_name(Ipv6Addr::from(u128::MAX)),
            format!("{}ip6.arpa.", "f.".repeat(32))
        );
    }

    #[test]
    fn no_snapshot_has_desired_state_but_no_delta() {
        let config = config();
        let input = assignment(&config, 2);
        let output = plan(&config, std::slice::from_ref(&input), None).unwrap();
        assert_eq!(output.mode, "dry_run");
        assert_eq!(output.basis, "desired_only");
        assert_eq!(output.changes, Changes::default());
        assert_eq!(output.desired.reservations.len(), 1);
        assert_eq!(
            output.desired.dns_records,
            vec![
                DnsRecord::Aaaa {
                    name: input.fqdn.clone(),
                    value: input.address,
                    ttl: 300,
                },
                DnsRecord::Ptr {
                    name: reverse_name(input.address),
                    value: input.fqdn,
                    ttl: 300,
                },
            ]
        );
    }

    #[test]
    fn explicit_empty_snapshot_adds_and_desired_snapshot_is_idempotent() {
        let config = config();
        let inputs = [assignment(&config, 2), assignment(&config, 3)];
        let output = plan(&config, &inputs, Some(&Snapshot::empty())).unwrap();
        assert_eq!(output.basis, "owned_snapshot");
        assert_eq!(output.changes.add_reservations, output.desired.reservations);
        assert_eq!(output.changes.add_dns_records, output.desired.dns_records);
        assert!(output.changes.remove_reservations.is_empty());
        assert!(output.changes.remove_dns_records.is_empty());
        let snapshot: Snapshot =
            serde_json::from_str(&serde_json::to_string(&output.desired).unwrap()).unwrap();
        let repeated = plan(&config, &inputs, Some(&snapshot)).unwrap();
        assert_eq!(repeated.desired, output.desired);
        assert_eq!(repeated.changes, Changes::default());
    }

    #[test]
    fn retirement_removes_only_exact_observed_owned_resources_and_preserves_active() {
        let config = config();
        let mut inputs = [assignment(&config, 2), assignment(&config, 3)];
        let before = plan(&config, &inputs, None).unwrap().desired;
        let retired = plan(&config, &inputs[..1], None).unwrap().desired;
        inputs[0].state = AssignmentState::Retired;
        let output = plan(&config, &inputs, Some(&before)).unwrap();
        assert_eq!(output.desired.reservations.len(), 1);
        assert_eq!(output.desired.reservations[0].asset_id, inputs[1].asset_id);
        assert_eq!(output.desired.dns_records.len(), 2);
        assert!(output.changes.add_reservations.is_empty());
        assert!(output.changes.add_dns_records.is_empty());
        assert_eq!(output.changes.remove_reservations, retired.reservations);
        assert_eq!(output.changes.remove_dns_records, retired.dns_records);
        assert_eq!(
            plan(&config, &inputs, None).unwrap().changes,
            Changes::default()
        );
        let absent_retired = plan(&config, &inputs, Some(&output.desired)).unwrap();
        assert_eq!(absent_retired.changes, Changes::default());
    }

    #[test]
    fn partial_snapshots_only_change_resources_actually_missing_or_present() {
        let config = config();
        let mut inputs = [assignment(&config, 2), assignment(&config, 3)];
        let before = plan(&config, &inputs, None).unwrap().desired;
        inputs[0].state = AssignmentState::Retired;
        let retired_ptr = before
            .dns_records
            .iter()
            .find(
                |record| matches!(record, DnsRecord::Ptr { value, .. } if value == &inputs[0].fqdn),
            )
            .unwrap()
            .clone();
        let observed = Snapshot {
            dns_records: vec![retired_ptr.clone()],
            ..Snapshot::empty()
        };
        let output = plan(&config, &inputs, Some(&observed)).unwrap();
        assert_eq!(output.changes.add_reservations, output.desired.reservations);
        assert_eq!(output.changes.add_dns_records, output.desired.dns_records);
        assert!(output.changes.remove_reservations.is_empty());
        assert_eq!(output.changes.remove_dns_records, vec![retired_ptr]);
    }

    #[test]
    fn ordering_is_deterministic_for_desired_and_all_four_delta_lists() {
        let config = config();
        let mut inputs = (2..8).map(|n| assignment(&config, n)).collect::<Vec<_>>();
        let mut observed = plan(&config, &inputs[..4], None).unwrap().desired;
        inputs[0].state = AssignmentState::Retired;
        inputs[1].state = AssignmentState::Retired;
        let expected = plan(&config, &inputs, Some(&observed)).unwrap();
        assert_eq!(expected.changes.add_reservations.len(), 2);
        assert_eq!(expected.changes.remove_reservations.len(), 2);
        assert_eq!(expected.changes.add_dns_records.len(), 4);
        assert_eq!(expected.changes.remove_dns_records.len(), 4);
        let desired_only = serde_json::to_string(&plan(&config, &inputs, None).unwrap()).unwrap();
        inputs.reverse();
        observed.reservations.reverse();
        observed.dns_records.reverse();
        let reversed = plan(&config, &inputs, Some(&observed)).unwrap();
        assert_eq!(
            serde_json::to_string(&expected).unwrap(),
            serde_json::to_string(&reversed).unwrap()
        );
        assert_eq!(
            desired_only,
            serde_json::to_string(&plan(&config, &inputs, None).unwrap()).unwrap()
        );
    }

    #[test]
    fn wrong_owner_or_schema_never_authorizes_a_delta() {
        let config = config();
        for owner in ["", "kea", "V6Alias", "v6alias "] {
            let observed = Snapshot {
                owner: owner.into(),
                ..Snapshot::empty()
            };
            assert_conflict(plan(&config, &[], Some(&observed)));
        }
        for schema_version in [0, 2, u32::MAX] {
            let observed = Snapshot {
                schema_version,
                ..Snapshot::empty()
            };
            assert_conflict(plan(&config, &[], Some(&observed)));
        }
    }

    #[test]
    fn every_reservation_field_must_match_assignment_history_exactly() {
        let config = config();
        let inputs = [assignment(&config, 2)];
        let observed = plan(&config, &inputs, None).unwrap().desired;
        let original = serde_json::to_value(&observed).unwrap();
        for (field, value) in [
            ("asset_id", json!("foreign")),
            ("link", json!("lab-link")),
            ("duid", json!("ffff")),
            ("iaid", json!(u32::MAX)),
            ("address", json!("fd7a:115c:a1e0:17::3")),
            ("fqdn", json!("foreign.v6alias.home.arpa.")),
        ] {
            let mut changed = original.clone();
            changed["reservations"][0][field] = value;
            let snapshot: Snapshot = serde_json::from_value(changed).unwrap();
            assert_conflict(plan(&config, &inputs, Some(&snapshot)));
            let mut retired = inputs.clone();
            retired[0].state = AssignmentState::Retired;
            assert_conflict(plan(&config, &retired, Some(&snapshot)));
        }
        assert_conflict(plan(&config, &[], Some(&observed)));
    }

    #[test]
    fn every_dns_field_must_match_and_ttl_is_explicitly_validated() {
        let config = config();
        let inputs = [assignment(&config, 2)];
        let original = serde_json::to_value(plan(&config, &inputs, None).unwrap().desired).unwrap();
        for index in 0..2 {
            for (field, value) in [
                ("name", json!("foreign.example.")),
                (
                    "value",
                    if index == 0 {
                        json!("fd7a:115c:a1e0:17::3")
                    } else {
                        json!("foreign.v6alias.home.arpa.")
                    },
                ),
                ("ttl", json!(0)),
                ("ttl", json!(301)),
                ("ttl", json!(u32::MAX)),
            ] {
                let mut changed = original.clone();
                changed["dns_records"][index][field] = value;
                let snapshot: Snapshot = serde_json::from_value(changed).unwrap();
                let error = plan(&config, &inputs, Some(&snapshot)).unwrap_err();
                assert!(matches!(error, ServiceError::Conflict(_)));
                if field == "ttl" {
                    assert!(error.to_string().contains("expected 300"));
                }
            }
        }
        let mut malformed = original.clone();
        malformed["dns_records"][1]["name"] = json!("0.ip6.arpa.");
        assert_conflict(plan(
            &config,
            &inputs,
            Some(&serde_json::from_value(malformed).unwrap()),
        ));
        let mut uppercase = original;
        uppercase["dns_records"][1]["value"] = json!("HOST-2.v6alias.home.arpa.");
        assert_conflict(plan(
            &config,
            &inputs,
            Some(&serde_json::from_value(uppercase).unwrap()),
        ));
    }

    #[test]
    fn duplicate_assignments_are_rejected_even_across_active_and_retired() {
        let config = config();
        let first = assignment(&config, 2);
        for field in ["exact", "asset_id", "duid", "fqdn", "address-and-slot"] {
            let mut second = assignment(&config, 3);
            match field {
                "exact" => second = first.clone(),
                "asset_id" => second.asset_id = first.asset_id.clone(),
                "duid" => second.duid = first.duid.clone(),
                "fqdn" => second.fqdn = first.fqdn.clone(),
                "address-and-slot" => {
                    second.device = first.device;
                    second.address = first.address;
                }
                _ => unreachable!(),
            }
            assert_conflict(plan(&config, &[first.clone(), second.clone()], None));
            second.state = AssignmentState::Retired;
            assert_conflict(plan(&config, &[first.clone(), second], None));
        }
    }

    #[test]
    fn duplicate_snapshot_records_and_drifted_natural_keys_are_errors() {
        let config = config();
        let inputs = [assignment(&config, 2), assignment(&config, 3)];
        let original = plan(&config, &inputs, None).unwrap().desired;
        let mut snapshot = original.clone();
        snapshot.reservations.push(snapshot.reservations[0].clone());
        assert_conflict(plan(&config, &inputs, Some(&snapshot)));
        for index in 0..original.dns_records.len() {
            let mut snapshot = original.clone();
            snapshot
                .dns_records
                .push(snapshot.dns_records[index].clone());
            assert_conflict(plan(&config, &inputs, Some(&snapshot)));
            match snapshot.dns_records.last_mut().unwrap() {
                DnsRecord::Aaaa { ttl, .. } | DnsRecord::Ptr { ttl, .. } => *ttl = 301,
            }
            assert_conflict(plan(&config, &inputs, Some(&snapshot)));
        }
        for field in ["asset_id", "duid", "address", "fqdn"] {
            let mut snapshot = serde_json::to_value(&original).unwrap();
            snapshot["reservations"][1][field] = snapshot["reservations"][0][field].clone();
            assert_conflict(plan(
                &config,
                &inputs,
                Some(&serde_json::from_value(snapshot).unwrap()),
            ));
        }
    }

    #[test]
    fn forged_assignment_placement_names_and_policy_are_rejected_in_both_states() {
        let config = config();
        let original = serde_json::to_value(assignment(&config, 2)).unwrap();
        for (field, value) in [
            ("address", json!("fd7a:115c:a1e0:17::3")),
            ("address", json!("::1")),
            ("link", json!("unknown")),
            ("profile", json!("unknown")),
            ("profile", json!("lab")),
            ("subnet", json!(7)),
            ("device", json!(0)),
            ("device", json!(1)),
            ("device", json!(53)),
            ("device", json!(4096)),
            ("device", json!(u16::MAX)),
            ("policy_rule", json!("unknown")),
            ("policy_rule", json!("inventoried-lab")),
            ("asset_id", json!("Bad")),
            ("asset_id", json!("a.b")),
            ("asset_id", json!("")),
            ("asset_id", json!("a".repeat(64))),
            ("fqdn", json!("host-2.evil.example.")),
            ("fqdn", json!("host-2.notv6alias.home.arpa.")),
            ("fqdn", json!("host-2.v6alias.home.arpa")),
            ("fqdn", json!("v6alias.home.arpa.")),
            ("fqdn", json!(".v6alias.home.arpa.")),
            ("fqdn", json!("nested.host.v6alias.home.arpa.")),
            ("fqdn", json!("Host.v6alias.home.arpa.")),
            ("fqdn", json!("host.V6alias.home.arpa.")),
            ("fqdn", json!("*.v6alias.home.arpa.")),
            ("fqdn", json!("-host.v6alias.home.arpa.")),
            ("fqdn", json!("host-.v6alias.home.arpa.")),
            ("fqdn", json!("höst.v6alias.home.arpa.")),
            ("fqdn", json!("host\nAAAA.v6alias.home.arpa.")),
            (
                "fqdn",
                json!(format!("{}.v6alias.home.arpa.", "a".repeat(64))),
            ),
        ] {
            for state in ["active", "retired"] {
                let mut changed = original.clone();
                changed[field] = value.clone();
                changed["state"] = json!(state);
                let input: Assignment = serde_json::from_value(changed).unwrap();
                assert!(
                    matches!(
                        plan(&config, &[input], None),
                        Err(ServiceError::Validation(_))
                    ),
                    "{state} {field}={value}"
                );
            }
        }
    }

    #[test]
    fn validates_config_even_when_desired_is_empty() {
        let mut config = config();
        config.links.get_mut("corp-link").unwrap().pool.first = 0;
        assert!(plan(&config, &[], None).is_err());
        assert!(plan(&config, &[], Some(&Snapshot::empty())).is_err());
    }

    #[test]
    fn empty_and_fully_retired_desired_are_safe() {
        let config = config();
        for observed in [None, Some(Snapshot::empty())] {
            let output = plan(&config, &[], observed.as_ref()).unwrap();
            assert_eq!(output.desired, Snapshot::empty());
            assert_eq!(output.changes, Changes::default());
        }
        let mut input = assignment(&config, 2);
        let before = plan(&config, std::slice::from_ref(&input), None)
            .unwrap()
            .desired;
        input.state = AssignmentState::Retired;
        let output = plan(&config, &[input], Some(&before)).unwrap();
        assert_eq!(output.desired, Snapshot::empty());
        assert_eq!(output.changes.remove_reservations, before.reservations);
        assert_eq!(output.changes.remove_dns_records, before.dns_records);
        assert!(output.changes.add_reservations.is_empty());
        assert!(output.changes.add_dns_records.is_empty());
    }

    #[test]
    fn full_pool_and_largest_supported_scalar_values_are_bounded() {
        let mut config = config();
        config.links.get_mut("corp-link").unwrap().subnet = u16::MAX;
        let mut inputs = (2..=4095)
            .filter(|n| !config.links["corp-link"].reserved.contains(n))
            .map(|n| assignment(&config, n))
            .collect::<Vec<_>>();
        inputs[0].iaid = u32::MAX;
        inputs[0].duid = "ab".repeat(128).parse().unwrap();
        inputs[0].asset_id = "a".repeat(63);
        inputs[0].fqdn = format!("{}.{}.", "h".repeat(63), config.dns_zone);
        let output = plan(&config, &inputs, Some(&Snapshot::empty())).unwrap();
        assert_eq!(output.desired.reservations.len(), 4093);
        assert_eq!(output.desired.dns_records.len(), 8186);
        assert_eq!(
            plan(&config, &inputs, Some(&output.desired))
                .unwrap()
                .changes,
            Changes::default()
        );
    }

    #[test]
    fn total_dns_name_length_limit_is_checked() {
        let mut config = config();
        config.dns_zone = format!("{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(62));
        config.validate().unwrap();
        let mut input = assignment(&config, 2);
        input.fqdn = format!("{}.{}.", "h".repeat(62), config.dns_zone);
        assert_eq!(input.fqdn.len(), 254);
        assert!(plan(&config, std::slice::from_ref(&input), None).is_ok());
        input.fqdn = format!("{}.{}.", "h".repeat(63), config.dns_zone);
        assert_eq!(input.fqdn.len(), 255);
        assert!(plan(&config, &[input], None).is_err());
    }

    #[test]
    fn unknown_fields_record_types_and_untyped_values_cannot_be_deserialized() {
        let config = config();
        let output = plan(&config, &[assignment(&config, 2)], None).unwrap();
        let original = serde_json::to_value(&output.desired).unwrap();
        for pointer in ["", "/reservations/0", "/dns_records/0", "/dns_records/1"] {
            let mut changed = original.clone();
            changed.pointer_mut(pointer).unwrap()["hostname"] = json!("untrusted");
            assert!(
                serde_json::from_value::<Snapshot>(changed).is_err(),
                "{pointer}"
            );
        }
        for (field, value) in [
            ("type", json!("A")),
            ("type", json!("CNAME")),
            ("type", json!("aaaa")),
            ("value", json!("192.0.2.1")),
            ("value", json!("not-an-address")),
            ("value", json!(42)),
            ("ttl", json!(-1)),
            ("ttl", json!(u64::from(u32::MAX) + 1)),
        ] {
            let mut changed = original.clone();
            changed["dns_records"][0][field] = value;
            assert!(serde_json::from_value::<Snapshot>(changed).is_err());
        }
        let mut changed = original;
        changed["reservations"][0]["duid"] = Value::Null;
        assert!(serde_json::from_value::<Snapshot>(changed).is_err());
    }

    #[test]
    fn manifest_uses_authoritative_assignment_names_not_hostname_hints() {
        let mut config = config();
        config.rules[0].hostname_prefix = Some("untrusted-hint".into());
        let mut input = assignment(&config, 2);
        input.fqdn = "inventory-name.v6alias.home.arpa.".into();
        let output = plan(&config, std::slice::from_ref(&input), None).unwrap();
        assert_eq!(output.desired.reservations[0].fqdn, input.fqdn);
        assert!(
            output
                .desired
                .dns_records
                .iter()
                .all(|record| match record {
                    DnsRecord::Aaaa { name, .. } => name == &input.fqdn,
                    DnsRecord::Ptr { value, .. } => value == &input.fqdn,
                })
        );
        let serialized = serde_json::to_string(&output).unwrap();
        assert!(!serialized.contains("hostname"));
        assert!(!serialized.contains("untrusted-hint"));
    }
}
