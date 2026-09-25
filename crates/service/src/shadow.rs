//! Strict normalized file contract, not a DHCP backend or proof of network placement.

use std::{
    collections::BTreeSet,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{Assignment, Decision, Duid, Observation, ServiceError, reconcile, validate_dns_label};

pub const MAX_OBSERVATIONS: usize = 4096;
pub const MAX_INPUT_BYTES: u64 = 1024 * 1024;
pub const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;

pub struct SourceBinding<'a> {
    pub source: &'a str,
    pub trusted_link: &'a str,
    pub max_age_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSnapshot {
    pub schema_version: u32,
    pub source: String,
    pub captured_at_unix_secs: u64,
    pub observations: Vec<Observation>,
}

impl ObservationSnapshot {
    pub fn validate(
        &self,
        expected_source: &str,
        now_unix_secs: u64,
        max_age_secs: u64,
    ) -> Result<(), ServiceError> {
        if self.schema_version != 1 {
            return Err(ServiceError::Validation(
                "unsupported observation schema version".into(),
            ));
        }
        validate_dns_label(expected_source)?;
        validate_dns_label(&self.source)?;
        if self.source != expected_source {
            return Err(ServiceError::Validation(
                "observation source does not match operator binding".into(),
            ));
        }
        validate_capture_time(
            "observation",
            self.captured_at_unix_secs,
            now_unix_secs,
            max_age_secs,
        )?;
        validate_observations(&self.observations)
    }
}

/// Daemon-only envelope; the offline reconciliation snapshot contract is unchanged.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendSnapshot {
    pub schema_version: u32,
    pub captured_at_unix_secs: u64,
    pub snapshot: reconcile::Snapshot,
}

impl BackendSnapshot {
    pub fn validate(&self, now_unix_secs: u64, max_age_secs: u64) -> Result<(), ServiceError> {
        if self.schema_version != 1 {
            return Err(ServiceError::Validation(
                "unsupported backend envelope schema version".into(),
            ));
        }
        validate_capture_time(
            "backend",
            self.captured_at_unix_secs,
            now_unix_secs,
            max_age_secs,
        )
    }
}

pub(crate) fn validate_capture_time(
    kind: &str,
    captured_at_unix_secs: u64,
    now_unix_secs: u64,
    max_age_secs: u64,
) -> Result<(), ServiceError> {
    if !(1..=86400).contains(&max_age_secs) {
        return Err(ServiceError::Validation(
            "max age must be 1..86400 seconds".into(),
        ));
    }
    let age = now_unix_secs
        .checked_sub(captured_at_unix_secs)
        .ok_or_else(|| ServiceError::Validation(format!("{kind} capture time is in the future")))?;
    if age > max_age_secs {
        return Err(ServiceError::Validation(format!(
            "{kind} snapshot is stale"
        )));
    }
    Ok(())
}

pub(crate) fn validate_current(
    observations: &ObservationSnapshot,
    backend: Option<&BackendSnapshot>,
    binding: &SourceBinding<'_>,
) -> Result<(), ServiceError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ServiceError::Validation("system clock is before Unix epoch".into()))?
        .as_secs();
    observations.validate(binding.source, now, binding.max_age_secs)?;
    if let Some(backend) = backend {
        backend.validate(now, binding.max_age_secs)?;
    }
    Ok(())
}

pub(crate) fn validate_observations(observations: &[Observation]) -> Result<(), ServiceError> {
    if observations.len() > MAX_OBSERVATIONS {
        return Err(ServiceError::Validation(
            "observation count exceeds 4096".into(),
        ));
    }
    let mut duids = BTreeSet::new();
    for observation in observations {
        if !duids.insert(&observation.duid) {
            return Err(ServiceError::Validation(
                "duplicate DUID (including multiple IAIDs) in observation snapshot".into(),
            ));
        }
        if let Some(hostname) = &observation.hostname {
            validate_dns_label(hostname)?;
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct Outcome {
    pub duid: Duid,
    pub iaid: u32,
    pub decision: Decision,
    pub assignment: Option<Assignment>,
    pub alias: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Cycle {
    pub outcomes: Vec<Outcome>,
    pub plan: reconcile::Plan,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InventoryDevice, ServiceConfig, Store};

    fn snapshot() -> ObservationSnapshot {
        ObservationSnapshot {
            schema_version: 1,
            source: "synthetic-corp".into(),
            captured_at_unix_secs: 100,
            observations: vec![Observation {
                duid: "0001abcd".parse().unwrap(),
                iaid: 1,
                hostname: Some("untrusted-hint".into()),
            }],
        }
    }

    #[test]
    fn freshness_and_provenance_boundaries() {
        let snapshot = snapshot();
        assert!(snapshot.validate("synthetic-corp", 100, 1).is_ok());
        assert!(snapshot.validate("synthetic-corp", 101, 1).is_ok());
        assert!(snapshot.validate("synthetic-corp", 102, 1).is_err());
        assert!(snapshot.validate("synthetic-corp", 99, 1).is_err());
        assert!(snapshot.validate("wrong-source", 100, 1).is_err());
        for age in [0, 86401, u64::MAX] {
            assert!(snapshot.validate("synthetic-corp", 100, age).is_err());
        }
    }

    #[test]
    fn backend_envelope_freshness_and_strict_contract() {
        let mut backend = BackendSnapshot {
            schema_version: 1,
            captured_at_unix_secs: 100,
            snapshot: reconcile::Snapshot::empty(),
        };
        assert!(backend.validate(100, 1).is_ok());
        assert!(backend.validate(101, 1).is_ok());
        for (now, age) in [(102, 1), (99, 1), (100, 0), (100, 86401)] {
            assert!(backend.validate(now, age).is_err());
        }
        backend.schema_version = 2;
        assert!(backend.validate(100, 1).is_err());
        let mut value = serde_json::to_value(&backend).unwrap();
        value["source"] = "unbound-source".into();
        assert!(serde_json::from_value::<BackendSnapshot>(value).is_err());
        assert!(
            serde_json::from_value::<BackendSnapshot>(
                serde_json::to_value(reconcile::Snapshot::empty()).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn strict_fields_versions_identity_and_hostname() {
        let original = snapshot();
        let mut value = serde_json::to_value(&original).unwrap();
        value["trusted_link"] = "corp-link".into();
        assert!(serde_json::from_value::<ObservationSnapshot>(value).is_err());
        let mut snapshot = original;
        snapshot.schema_version = 2;
        assert!(snapshot.validate("synthetic-corp", 100, 1).is_err());
        snapshot.schema_version = 1;
        snapshot.observations.push(snapshot.observations[0].clone());
        snapshot.observations[1].iaid = 2;
        assert!(snapshot.validate("synthetic-corp", 100, 1).is_err());
        snapshot.observations.pop();
        snapshot.observations[0].hostname = Some("evil.example".into());
        assert!(snapshot.validate("synthetic-corp", 100, 1).is_err());
    }

    #[test]
    fn count_limit_accepts_exact_boundary() {
        let observations: Vec<_> = (0..MAX_OBSERVATIONS)
            .map(|i| Observation {
                duid: format!("{i:08x}").parse().unwrap(),
                iaid: 0,
                hostname: None,
            })
            .collect();
        assert!(validate_observations(&observations).is_ok());
        let mut too_many = observations;
        too_many.push(snapshot().observations.remove(0));
        assert!(validate_observations(&too_many).is_err());
        assert!(validate_observations(&[]).is_ok());
    }

    #[test]
    fn batch_exhaustion_rolls_back_allocations_and_config_pin() {
        let mut store = Store::in_memory().unwrap();
        let mut config =
            ServiceConfig::from_yaml(include_str!("../../../service.example.yaml")).unwrap();
        config.links.get_mut("corp-link").unwrap().pool.last = 2;
        let mut observations = Vec::new();
        for i in 1..=2 {
            let device = InventoryDevice {
                asset_id: format!("asset-{i}"),
                duid: format!("000{i}").parse().unwrap(),
                iaid: i,
                managed: true,
                dns_label: format!("host-{i}"),
            };
            store.register(&device).unwrap();
            observations.push(Observation {
                duid: device.duid,
                iaid: i,
                hostname: None,
            });
        }
        let snapshot = ObservationSnapshot {
            observations,
            captured_at_unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ..snapshot()
        };
        let binding = SourceBinding {
            source: "synthetic-corp",
            trusted_link: "corp-link",
            max_age_secs: 300,
        };
        assert!(matches!(
            store.shadow_cycle(&config, &snapshot, &binding, None),
            Err(ServiceError::Exhausted(_))
        ));
        assert!(store.assignments(&config).unwrap().is_empty());
        config.links.get_mut("corp-link").unwrap().pool.last = 3;
        let result = store
            .shadow_cycle(&config, &snapshot, &binding, None)
            .unwrap();
        assert_eq!(result.outcomes[0].assignment.as_ref().unwrap().device, 2);
        assert_eq!(result.outcomes[1].assignment.as_ref().unwrap().device, 3);
    }

    #[test]
    fn snapshot_expiring_during_database_lock_wait_cannot_allocate() {
        expires_while_locked("BEGIN IMMEDIATE", false);
    }

    #[test]
    fn snapshot_expiring_behind_shared_reader_cannot_commit() {
        expires_while_locked("BEGIN; SELECT * FROM inventory", false);
    }

    #[test]
    fn backend_expiring_behind_shared_reader_cannot_commit() {
        expires_while_locked("BEGIN; SELECT * FROM inventory", true);
    }

    fn expires_while_locked(lock_sql: &str, expire_backend: bool) {
        let directory = tempfile::Builder::new()
            .prefix(".shadow-lock-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        let path = directory.path().join("inventory.sqlite");
        let mut store = Store::open(&path).unwrap();
        let config =
            ServiceConfig::from_yaml(include_str!("../../../service.example.yaml")).unwrap();
        store
            .register(&InventoryDevice {
                asset_id: "test-asset".into(),
                duid: "0001abcd".parse().unwrap(),
                iaid: 1,
                managed: true,
                dns_label: "test-asset".into(),
            })
            .unwrap();
        let lock = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(
            lock.pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))
                .unwrap(),
            "delete"
        );
        lock.execute_batch(lock_sql).unwrap();
        let snapshot = ObservationSnapshot {
            captured_at_unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ..snapshot()
        };
        let backend = BackendSnapshot {
            schema_version: 1,
            captured_at_unix_secs: snapshot.captured_at_unix_secs - 300,
            snapshot: reconcile::Snapshot::empty(),
        };
        let (sender, started) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let binding = SourceBinding {
                source: "synthetic-corp",
                trusted_link: "corp-link",
                max_age_secs: if expire_backend { 300 } else { 1 },
            };
            sender.send(()).unwrap();
            let result = store.shadow_cycle(
                &config,
                &snapshot,
                &binding,
                expire_backend.then_some(&backend),
            );
            let expected = if expire_backend {
                "backend snapshot is stale"
            } else {
                "observation snapshot is stale"
            };
            assert!(
                matches!(result, Err(ServiceError::Validation(message)) if message == expected)
            );
            assert!(store.assignments(&config).unwrap().is_empty());
            let mut changed = config;
            changed.links.get_mut("corp-link").unwrap().pool.last -= 1;
            assert!(store.assignments(&changed).unwrap().is_empty());
        });
        started
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        std::thread::sleep(std::time::Duration::from_secs(2));
        lock.execute_batch("ROLLBACK").unwrap();
        worker.join().unwrap();
    }
}
