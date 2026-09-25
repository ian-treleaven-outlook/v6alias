use std::{collections::BTreeSet, path::Path, time::Duration};

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Row, TransactionBehavior, config::DbConfig, params,
};
use v6alias_core::Alias;

use crate::{
    Assignment, AssignmentState, Decision, InventoryDevice, Observation, ServiceConfig,
    ServiceError, policy, validate_dns_label,
};

const APPLICATION_ID: i64 = 0x56364153; // V6AS
const SCHEMA_VERSION: i64 = 1;
const SCHEMA: &[(&str, &str, &str)] = &[
    (
        "table",
        "inventory",
        "CREATE TABLE inventory (
            asset_id TEXT PRIMARY KEY NOT NULL
                CHECK(length(asset_id) BETWEEN 1 AND 63
                    AND asset_id NOT GLOB '*[^a-z0-9-]*'
                    AND asset_id NOT GLOB '-*' AND asset_id NOT GLOB '*-'
                    AND instr(asset_id, char(0)) = 0),
            duid TEXT NOT NULL UNIQUE
                CHECK(length(duid) BETWEEN 4 AND 256 AND length(duid) % 2 = 0
                    AND duid NOT GLOB '*[^0-9a-f]*' AND instr(duid, char(0)) = 0),
            iaid INTEGER NOT NULL CHECK(iaid BETWEEN 0 AND 4294967295),
            managed INTEGER NOT NULL CHECK(managed IN (0, 1)),
            dns_label TEXT NOT NULL UNIQUE
                CHECK(length(dns_label) BETWEEN 1 AND 63
                    AND dns_label NOT GLOB '*[^a-z0-9-]*'
                    AND dns_label NOT GLOB '-*' AND dns_label NOT GLOB '*-'
                    AND instr(dns_label, char(0)) = 0)
        ) STRICT",
    ),
    (
        "table",
        "assignments",
        "CREATE TABLE assignments (
            asset_id TEXT PRIMARY KEY NOT NULL REFERENCES inventory(asset_id)
                ON UPDATE RESTRICT ON DELETE RESTRICT,
            link TEXT NOT NULL CHECK(length(link) > 0),
            profile TEXT NOT NULL CHECK(length(profile) > 0),
            subnet INTEGER NOT NULL CHECK(subnet BETWEEN 0 AND 65535),
            device INTEGER NOT NULL CHECK(device BETWEEN 2 AND 4095),
            address TEXT NOT NULL UNIQUE CHECK(length(address) BETWEEN 2 AND 39),
            fqdn TEXT NOT NULL UNIQUE
                CHECK(length(fqdn) BETWEEN 3 AND 255 AND substr(fqdn, -1) = '.'),
            state TEXT NOT NULL CHECK(state IN ('active', 'retired')),
            policy_rule TEXT NOT NULL CHECK(length(policy_rule) > 0),
            UNIQUE(profile, subnet, device)
        ) STRICT",
    ),
    (
        "table",
        "metadata",
        "CREATE TABLE metadata (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            config_identity TEXT NOT NULL CHECK(length(config_identity) > 0)
        ) STRICT",
    ),
    (
        "trigger",
        "inventory_no_update",
        "CREATE TRIGGER inventory_no_update BEFORE UPDATE ON inventory
         BEGIN SELECT RAISE(ABORT, 'inventory is immutable'); END",
    ),
    (
        "trigger",
        "inventory_no_delete",
        "CREATE TRIGGER inventory_no_delete BEFORE DELETE ON inventory
         BEGIN SELECT RAISE(ABORT, 'inventory is permanent'); END",
    ),
    (
        "trigger",
        "assignments_no_delete",
        "CREATE TRIGGER assignments_no_delete BEFORE DELETE ON assignments
         BEGIN SELECT RAISE(ABORT, 'assignment tombstones are permanent'); END",
    ),
    (
        "trigger",
        "assignments_only_retire",
        "CREATE TRIGGER assignments_only_retire BEFORE UPDATE ON assignments
         WHEN NEW.asset_id IS NOT OLD.asset_id OR NEW.link IS NOT OLD.link
           OR NEW.profile IS NOT OLD.profile OR NEW.subnet IS NOT OLD.subnet
           OR NEW.device IS NOT OLD.device OR NEW.address IS NOT OLD.address
           OR NEW.fqdn IS NOT OLD.fqdn OR NEW.policy_rule IS NOT OLD.policy_rule
           OR (OLD.state = 'retired' AND NEW.state != 'retired')
         BEGIN SELECT RAISE(ABORT, 'only permanent retirement is permitted'); END",
    ),
    (
        "trigger",
        "metadata_no_update",
        "CREATE TRIGGER metadata_no_update BEFORE UPDATE ON metadata
         BEGIN SELECT RAISE(ABORT, 'configuration identity is immutable'); END",
    ),
    (
        "trigger",
        "metadata_no_delete",
        "CREATE TRIGGER metadata_no_delete BEFORE DELETE ON metadata
         BEGIN SELECT RAISE(ABORT, 'configuration identity is permanent'); END",
    ),
];

const DEVICE_COLUMNS: &str = "asset_id, duid, iaid, managed, dns_label";
const ASSIGNMENT_SELECT: &str =
    "SELECT a.asset_id, i.duid, i.iaid, a.link, a.profile, a.subnet, a.device,
            a.address, a.fqdn, a.state, a.policy_rule
     FROM assignments a JOIN inventory i ON i.asset_id = a.asset_id";

pub struct Store {
    connection: Connection,
}

impl Store {
    /// Opens an explicit write connection and atomically initializes an empty database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ServiceError> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;
        Self::writable(connection)
    }

    /// Opens only an existing, recognized database, without changing SQLite pragmas.
    pub fn read_only(path: impl AsRef<Path>) -> Result<Self, ServiceError> {
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(Duration::from_secs(10))?;
        connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY, true)?;
        let transaction = connection.unchecked_transaction()?;
        verify_schema(&transaction)?;
        transaction.commit()?;
        Ok(Self { connection })
    }

    /// Opens a recognized inventory for writes without ever creating or initializing it.
    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self, ServiceError> {
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        connection.busy_timeout(Duration::from_secs(10))?;
        connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY, true)?;
        let transaction = connection.unchecked_transaction()?;
        verify_schema(&transaction)?;
        transaction.commit()?;
        Ok(Self { connection })
    }

    pub fn in_memory() -> Result<Self, ServiceError> {
        Self::writable(Connection::open_in_memory()?)
    }

    fn writable(mut connection: Connection) -> Result<Self, ServiceError> {
        connection.busy_timeout(Duration::from_secs(10))?;
        connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY, true)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (version, application) = database_identity(&transaction)?;
        if version == 0 && application == 0 {
            let objects: i64 =
                transaction.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
            if objects != 0 {
                return Err(ServiceError::Conflict(
                    "refusing to initialize an unrecognized nonempty database".into(),
                ));
            }
            for (_, _, sql) in SCHEMA {
                transaction.execute_batch(sql)?;
            }
            transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
        verify_schema(&transaction)?;
        transaction.commit()?;
        Ok(Self { connection })
    }

    pub fn register(&mut self, device: &InventoryDevice) -> Result<InventoryDevice, ServiceError> {
        device.validate()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = transaction
            .query_row(
                &format!("SELECT {DEVICE_COLUMNS} FROM inventory WHERE asset_id = ?1"),
                [&device.asset_id],
                device_from_row,
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing != *device {
                return Err(ServiceError::Conflict(
                    "asset is already registered with different identity or attributes".into(),
                ));
            }
            transaction.commit()?;
            return Ok(existing);
        }
        let collision: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM inventory WHERE duid = ?1 OR dns_label = ?2)",
            params![device.duid.as_str(), device.dns_label],
            |r| r.get(0),
        )?;
        if collision {
            return Err(ServiceError::Conflict(
                "DUID or DNS label belongs to another registered asset".into(),
            ));
        }
        transaction.execute(
            "INSERT INTO inventory (asset_id, duid, iaid, managed, dns_label)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                device.asset_id,
                device.duid.as_str(),
                device.iaid,
                device.managed,
                device.dns_label
            ],
        )?;
        transaction.commit()?;
        Ok(device.clone())
    }

    pub fn devices(&self) -> Result<Vec<InventoryDevice>, ServiceError> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT {DEVICE_COLUMNS} FROM inventory ORDER BY asset_id"
        ))?;
        Ok(statement
            .query_map([], device_from_row)?
            .collect::<Result<_, _>>()?)
    }

    pub fn explain(
        &self,
        config: &ServiceConfig,
        observation: &Observation,
        trusted_link: &str,
    ) -> Result<Decision, ServiceError> {
        let identity = config.identity()?;
        // A snapshot prevents a concurrent first allocation from bypassing the config check.
        let transaction = self.connection.unchecked_transaction()?;
        check_config(&transaction, &identity)?;
        let device = observed_device(&transaction, observation)?;
        let decision = policy::evaluate(config, observation, trusted_link, device.as_ref())?;
        transaction.commit()?;
        Ok(decision)
    }

    pub fn allocate(
        &mut self,
        config: &ServiceConfig,
        observation: &Observation,
        trusted_link: &str,
    ) -> Result<Assignment, ServiceError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let assignment = Self::allocate_in(&transaction, config, observation, trusted_link)?;
        transaction.commit()?;
        Ok(assignment)
    }

    fn allocate_in(
        transaction: &Connection,
        config: &ServiceConfig,
        observation: &Observation,
        trusted_link: &str,
    ) -> Result<Assignment, ServiceError> {
        let identity = config.identity()?;
        let pinned = check_config(transaction, &identity)?;
        let device = observed_device(transaction, observation)?;
        let decision = policy::evaluate(config, observation, trusted_link, device.as_ref())?;
        if !decision.allowed {
            return Err(ServiceError::PolicyDenied(decision.reason));
        }
        let device = device.ok_or_else(|| {
            ServiceError::PolicyDenied(
                "allocation requires an authoritative inventory record".into(),
            )
        })?;
        let policy_rule = decision
            .matched_rule
            .filter(|name| !name.is_empty())
            .ok_or_else(|| ServiceError::PolicyDenied("decision has no matching rule".into()))?;
        let profile = decision
            .profile
            .filter(|name| !name.is_empty())
            .ok_or_else(|| ServiceError::PolicyDenied("decision has no target profile".into()))?;
        let subnet = decision
            .subnet
            .ok_or_else(|| ServiceError::PolicyDenied("decision has no target subnet".into()))?;
        let link = config
            .links
            .get(trusted_link)
            .ok_or_else(|| ServiceError::PolicyDenied("unknown trusted link".into()))?;
        if link.profile != profile || link.subnet != subnet {
            return Err(ServiceError::PolicyDenied(
                "decision does not match the trusted link placement".into(),
            ));
        }

        if let Some(existing) = find_assignment(transaction, &device.asset_id)? {
            if existing.state == AssignmentState::Retired {
                return Err(ServiceError::Conflict(
                    "retired assets cannot be automatically allocated again".into(),
                ));
            }
            if existing.link != trusted_link
                || existing.profile != profile
                || existing.subnet != subnet
            {
                return Err(ServiceError::Conflict(
                    "asset already has a different permanent placement".into(),
                ));
            }
            return Ok(existing);
        }
        let used = {
            let mut statement = transaction
                .prepare("SELECT device FROM assignments WHERE profile = ?1 AND subnet = ?2")?;
            statement
                .query_map(params![profile, subnet], |r| r.get::<_, u16>(0))?
                .collect::<Result<BTreeSet<_>, _>>()?
        };
        let number = (link.pool.first..=link.pool.last)
            .find(|number| !link.reserved.contains(number) && !used.contains(number))
            .ok_or_else(|| {
                ServiceError::Exhausted(format!("no unreserved device numbers on `{trusted_link}`"))
            })?;
        let address = config.address_config().resolve(&Alias {
            profile: profile.clone(),
            subnet: Some(subnet),
            device: number,
        })?;
        let assignment = Assignment {
            asset_id: device.asset_id,
            duid: device.duid,
            iaid: device.iaid,
            link: trusted_link.into(),
            profile,
            subnet,
            device: number,
            address,
            fqdn: config.fqdn(&device.dns_label)?,
            state: AssignmentState::Active,
            policy_rule,
        };
        transaction.execute(
            "INSERT INTO assignments
                (asset_id, link, profile, subnet, device, address, fqdn, state, policy_rule)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active', ?8)",
            params![
                assignment.asset_id,
                assignment.link,
                assignment.profile,
                assignment.subnet,
                assignment.device,
                assignment.address.to_string(),
                assignment.fqdn,
                assignment.policy_rule
            ],
        )?;
        if !pinned {
            transaction.execute(
                "INSERT INTO metadata (singleton, config_identity) VALUES (1, ?1)",
                [&identity],
            )?;
        }
        Ok(assignment)
    }

    /// Validate and reconcile one complete batch under a single exclusive transaction.
    /// Denials are results; any invalid snapshot, conflict or storage failure rolls back
    /// every new assignment and configuration pin from this cycle.
    pub fn shadow_cycle(
        &mut self,
        config: &ServiceConfig,
        snapshot: &crate::shadow::ObservationSnapshot,
        binding: &crate::shadow::SourceBinding<'_>,
        backend: Option<&crate::shadow::BackendSnapshot>,
    ) -> Result<crate::shadow::Cycle, ServiceError> {
        crate::shadow::validate_current(snapshot, backend, binding)?;
        let observed = backend.map(|backend| &backend.snapshot);
        let observations = &snapshot.observations;
        let trusted_link = binding.trusted_link;
        validate_dns_label(trusted_link)?;
        if !config.links.contains_key(trusted_link) {
            return Err(ServiceError::Validation("unknown trusted link".into()));
        }
        let identity = config.identity()?;
        // In rollback-journal mode, acquire the reader-blocking commit lock before
        // checking freshness: COMMIT must not wait for existing shared readers.
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Exclusive)?;
        crate::shadow::validate_current(snapshot, backend, binding)?;
        check_config(&transaction, &identity)?;
        let assignments = Self::assignments_in(&transaction)?;
        crate::reconcile::plan(config, &assignments, observed)?;
        let mut outcomes = Vec::with_capacity(observations.len());
        // Input order must not affect which of several new assets receives the lowest ID.
        let mut ordered: Vec<_> = observations.iter().collect();
        ordered.sort_by(|a, b| (&a.duid, a.iaid).cmp(&(&b.duid, b.iaid)));
        for observation in ordered {
            let device = observed_device(&transaction, observation)?;
            let decision = policy::evaluate(config, observation, trusted_link, device.as_ref())?;
            let assignment = if decision.allowed {
                Some(Self::allocate_in(
                    &transaction,
                    config,
                    observation,
                    trusted_link,
                )?)
            } else {
                None
            };
            let alias = assignment
                .as_ref()
                .map(|a| {
                    config
                        .address_config()
                        .reverse(a.address)
                        .map(|a| a.to_string())
                })
                .transpose()?;
            outcomes.push(crate::shadow::Outcome {
                duid: observation.duid.clone(),
                iaid: observation.iaid,
                decision,
                assignment,
                alias,
            });
        }
        let plan = crate::reconcile::plan(config, &Self::assignments_in(&transaction)?, observed)?;
        crate::shadow::validate_current(snapshot, backend, binding)?;
        transaction.commit()?;
        Ok(crate::shadow::Cycle { outcomes, plan })
    }

    fn assignments_in(connection: &Connection) -> Result<Vec<Assignment>, ServiceError> {
        let mut statement =
            connection.prepare(&format!("{ASSIGNMENT_SELECT} ORDER BY a.asset_id"))?;
        Ok(statement
            .query_map([], assignment_from_row)?
            .collect::<Result<_, _>>()?)
    }

    /// Includes permanent retired tombstones, ordered by stable asset identifier.
    pub fn assignments(&self, config: &ServiceConfig) -> Result<Vec<Assignment>, ServiceError> {
        let identity = config.identity()?;
        let transaction = self.connection.unchecked_transaction()?;
        check_config(&transaction, &identity)?;
        let assignments = Self::assignments_in(&transaction)?;
        transaction.commit()?;
        Ok(assignments)
    }

    pub fn retire(
        &mut self,
        config: &ServiceConfig,
        asset_id: &str,
    ) -> Result<Assignment, ServiceError> {
        validate_dns_label(asset_id)?;
        let identity = config.identity()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_config(&transaction, &identity)?;
        let mut assignment = find_assignment(&transaction, asset_id)?
            .ok_or_else(|| ServiceError::NotFound(format!("assignment for asset `{asset_id}`")))?;
        if assignment.state == AssignmentState::Active {
            transaction.execute(
                "UPDATE assignments SET state = 'retired' WHERE asset_id = ?1",
                [asset_id],
            )?;
            assignment.state = AssignmentState::Retired;
        }
        transaction.commit()?;
        Ok(assignment)
    }
}

fn database_identity(connection: &Connection) -> Result<(i64, i64), ServiceError> {
    Ok((
        connection.pragma_query_value(None, "user_version", |r| r.get(0))?,
        connection.pragma_query_value(None, "application_id", |r| r.get(0))?,
    ))
}

fn verify_schema(connection: &Connection) -> Result<(), ServiceError> {
    let (version, application) = database_identity(connection)?;
    if application != APPLICATION_ID || version != SCHEMA_VERSION {
        return Err(ServiceError::Conflict(format!(
            "unrecognized or unsupported inventory database (schema version {version})"
        )));
    }
    let mut statement = connection.prepare(
        "SELECT type, name, sql FROM sqlite_schema
         WHERE name NOT GLOB 'sqlite_*' ORDER BY type, name",
    )?;
    let objects = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    // Verify the complete versioned DDL, not just names that an unrelated DB may share.
    if objects.len() != SCHEMA.len()
        || SCHEMA.iter().any(|(kind, name, sql)| {
            !objects
                .iter()
                .any(|object| object.0 == *kind && object.1 == *name && object.2 == *sql)
        })
    {
        return Err(ServiceError::Conflict(
            "inventory database schema does not match its declared version".into(),
        ));
    }
    let violations: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
        [],
        |r| r.get(0),
    )?;
    if violations {
        return Err(ServiceError::Conflict(
            "inventory database has broken foreign key relationships".into(),
        ));
    }
    Ok(())
}

fn check_config(connection: &Connection, identity: &str) -> Result<bool, ServiceError> {
    let pinned: Option<String> = connection
        .query_row(
            "SELECT config_identity FROM metadata WHERE singleton = 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    match pinned {
        Some(pinned) if pinned == identity => Ok(true),
        Some(_) => Err(ServiceError::Conflict(
            "configuration differs from the permanently pinned allocation configuration".into(),
        )),
        None => {
            let allocated: bool =
                connection
                    .query_row("SELECT EXISTS(SELECT 1 FROM assignments)", [], |r| r.get(0))?;
            if allocated {
                Err(ServiceError::Conflict(
                    "assignments exist without a pinned configuration".into(),
                ))
            } else {
                Ok(false)
            }
        }
    }
}

fn observed_device(
    connection: &Connection,
    observation: &Observation,
) -> Result<Option<InventoryDevice>, ServiceError> {
    // Deliberately match DUID alone: policy must see and reject an IAID mismatch.
    Ok(connection
        .query_row(
            &format!("SELECT {DEVICE_COLUMNS} FROM inventory WHERE duid = ?1"),
            [observation.duid.as_str()],
            device_from_row,
        )
        .optional()?)
}

fn find_assignment(
    connection: &Connection,
    asset_id: &str,
) -> Result<Option<Assignment>, ServiceError> {
    Ok(connection
        .query_row(
            &format!("{ASSIGNMENT_SELECT} WHERE a.asset_id = ?1"),
            [asset_id],
            assignment_from_row,
        )
        .optional()?)
}

fn parse_column<T>(row: &Row<'_>, index: usize) -> rusqlite::Result<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    row.get::<_, String>(index)?.parse().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn device_from_row(row: &Row<'_>) -> rusqlite::Result<InventoryDevice> {
    Ok(InventoryDevice {
        asset_id: row.get(0)?,
        duid: parse_column(row, 1)?,
        iaid: row.get(2)?,
        managed: row.get(3)?,
        dns_label: row.get(4)?,
    })
}

fn assignment_from_row(row: &Row<'_>) -> rusqlite::Result<Assignment> {
    let state = match row.get::<_, String>(9)?.as_str() {
        "active" => AssignmentState::Active,
        "retired" => AssignmentState::Retired,
        _ => {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                9,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unknown assignment state",
                )),
            ));
        }
    };
    Ok(Assignment {
        asset_id: row.get(0)?,
        duid: parse_column(row, 1)?,
        iaid: row.get(2)?,
        link: row.get(3)?,
        profile: row.get(4)?,
        subnet: row.get(5)?,
        device: row.get(6)?,
        address: parse_column(row, 7)?,
        fqdn: row.get(8)?,
        state,
        policy_rule: row.get(10)?,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;

    fn config() -> ServiceConfig {
        ServiceConfig::from_yaml(include_str!("../../../service.example.yaml")).unwrap()
    }

    fn device(number: u32) -> InventoryDevice {
        InventoryDevice {
            asset_id: format!("asset-{number}"),
            duid: format!("0001{number:08x}").parse().unwrap(),
            iaid: number,
            managed: true,
            dns_label: format!("host-{number}"),
        }
    }

    fn observation(device: &InventoryDevice) -> Observation {
        Observation {
            duid: device.duid.clone(),
            iaid: device.iaid,
            hostname: None,
        }
    }

    fn directory() -> tempfile::TempDir {
        // Keep test artifacts in the project, not the host's shared temporary directory.
        tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap()
    }

    fn count(store: &Store, table: &str) -> i64 {
        store
            .connection
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn migration_and_reopen_are_recognized_without_wal() {
        let memory = Store::in_memory().unwrap();
        assert_eq!(
            database_identity(&memory.connection).unwrap(),
            (SCHEMA_VERSION, APPLICATION_ID)
        );
        let dir = directory();
        let path = dir.path().join("inventory.sqlite");
        let first = Store::open(&path).unwrap();
        assert_eq!(count(&first, "inventory"), 0);
        let journal: String = first
            .connection
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        assert_eq!(journal, "delete");
        drop(first);
        assert!(Store::open(&path).is_ok());
        assert!(Store::read_only(&path).is_ok());
    }

    #[test]
    fn unrecognized_databases_are_rejected_without_modification() {
        let dir = directory();
        for (name, sql) in [
            (
                "unrelated",
                "CREATE TABLE other (value TEXT); INSERT INTO other VALUES ('keep')",
            ),
            (
                "future",
                "PRAGMA application_id = 1446396243; PRAGMA user_version = 2",
            ),
            (
                "wrong-app",
                "PRAGMA application_id = 17; PRAGMA user_version = 1",
            ),
            (
                "forged",
                "PRAGMA application_id = 1446396243; PRAGMA user_version = 1",
            ),
            ("unknown-version", "PRAGMA user_version = 1"),
        ] {
            let path = dir.path().join(format!("{name}.sqlite"));
            let connection = Connection::open(&path).unwrap();
            connection.execute_batch(sql).unwrap();
            drop(connection);
            let bytes = std::fs::read(&path).unwrap();
            assert!(
                matches!(Store::open(&path), Err(ServiceError::Conflict(_))),
                "{name}"
            );
            assert!(
                matches!(Store::read_only(&path), Err(ServiceError::Conflict(_))),
                "{name}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), bytes, "{name}");
        }
    }

    #[test]
    fn read_only_never_creates_migrates_or_pins() {
        let dir = directory();
        let path = dir.path().join("inventory.sqlite");
        assert!(Store::read_only(&path).is_err());
        assert!(!path.exists());
        Connection::open(&path).unwrap();
        let empty = std::fs::read(&path).unwrap();
        assert!(Store::read_only(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), empty);
        let mut writer = Store::open(&path).unwrap();
        let known = device(1);
        writer.register(&known).unwrap();
        drop(writer);
        let before = std::fs::read(&path).unwrap();
        let mut reader = Store::read_only(&path).unwrap();
        assert!(
            reader
                .connection
                .db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY)
                .unwrap()
        );
        assert!(
            reader
                .explain(&config(), &observation(&known), "corp-link")
                .unwrap()
                .allowed
        );
        assert!(reader.assignments(&config()).unwrap().is_empty());
        assert_eq!(reader.devices().unwrap(), vec![known.clone()]);
        assert_eq!(count(&reader, "metadata"), 0);
        assert!(
            reader
                .allocate(&config(), &observation(&known), "corp-link")
                .is_err()
        );
        assert!(reader.register(&device(2)).is_err());
        drop(reader);
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn actual_legacy_metadata_bytes_survive_reads_replay_and_ttl_refusal() {
        // Literal pre-TTL serialization, including field order and explicit nulls.
        const LEGACY: &str = r#"{"profiles":{"corp":{"prefix":"fd12:3456:789a::/48","default_subnet":23,"require_managed":true}},"links":{"corp-link":{"profile":"corp","subnet":23,"pool":{"first":2,"last":4095},"reserved":[]}},"dns_zone":"legacy.home.arpa","rules":[{"name":"managed-corporate","priority":100,"links":["corp-link"],"managed":true,"hostname_prefix":null,"profile":"corp"}]}"#;
        let config: ServiceConfig = serde_json::from_str(LEGACY).unwrap();
        assert_eq!(config.identity().unwrap(), LEGACY);
        let dir = directory();
        let path = dir.path().join("legacy.sqlite");
        let mut store = Store::open(&path).unwrap();
        store
            .connection
            .execute("INSERT INTO metadata VALUES (1, ?1)", [LEGACY])
            .unwrap();
        let device = device(1);
        store.register(&device).unwrap();
        let assignment = store
            .allocate(&config, &observation(&device), "corp-link")
            .unwrap();
        let mut explicit = config.clone();
        explicit.dns_ttl_seconds = 300;
        assert_eq!(
            store
                .allocate(&explicit, &observation(&device), "corp-link")
                .unwrap(),
            assignment
        );
        drop(store);
        let bytes = std::fs::read(&path).unwrap();
        let reader = Store::read_only(&path).unwrap();
        assert_eq!(reader.assignments(&explicit).unwrap(), vec![assignment]);
        let pinned: String = reader
            .connection
            .query_row("SELECT config_identity FROM metadata", [], |row| row.get(0))
            .unwrap();
        assert_eq!(pinned, LEGACY);
        explicit.dns_ttl_seconds = 3600;
        assert!(reader.assignments(&explicit).is_err());
        drop(reader);
        let mut writer = Store::open_existing(&path).unwrap();
        assert!(
            writer
                .allocate(&explicit, &observation(&device), "corp-link")
                .is_err()
        );
        assert!(writer.retire(&explicit, &device.asset_id).is_err());
        drop(writer);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn known_version_with_changed_schema_is_rejected_without_repair() {
        let dir = directory();
        let path = dir.path().join("inventory.sqlite");
        let store = Store::open(&path).unwrap();
        store
            .connection
            .execute_batch("DROP TRIGGER assignments_no_delete")
            .unwrap();
        drop(store);
        let bytes = std::fs::read(&path).unwrap();
        assert!(matches!(Store::open(&path), Err(ServiceError::Conflict(_))));
        assert!(matches!(
            Store::read_only(&path),
            Err(ServiceError::Conflict(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn registration_is_exact_idempotent_and_rejects_every_collision() {
        let mut store = Store::in_memory().unwrap();
        let original = device(1);
        assert_eq!(store.register(&original).unwrap(), original);
        assert_eq!(store.register(&original).unwrap(), original);
        let mut changes = Vec::new();
        let mut changed = original.clone();
        changed.iaid += 1;
        changes.push(changed);
        let mut changed = original.clone();
        changed.duid = device(2).duid;
        changes.push(changed);
        let mut changed = original.clone();
        changed.managed = false;
        changes.push(changed);
        let mut changed = original.clone();
        changed.dns_label = "new-name".into();
        changes.push(changed);
        let mut collision = device(2);
        collision.duid = original.duid.clone();
        changes.push(collision.clone());
        collision.iaid = original.iaid;
        changes.push(collision);
        let mut collision = device(2);
        collision.dns_label = original.dns_label.clone();
        changes.push(collision);
        for changed in changes {
            assert!(matches!(
                store.register(&changed),
                Err(ServiceError::Conflict(_))
            ));
            assert_eq!(store.devices().unwrap(), vec![original.clone()]);
        }
        let mut canonical = original.clone();
        canonical.duid = "00:01:00:00:00:01".parse().unwrap();
        assert_eq!(store.register(&canonical).unwrap(), original);
        let mut invalid = device(2);
        invalid.asset_id = "Bad.Asset".into();
        assert!(matches!(
            store.register(&invalid),
            Err(ServiceError::Validation(_))
        ));
        store.register(&device(2)).unwrap();
        assert_eq!(count(&store, "inventory"), 2);
    }

    #[test]
    fn allocation_uses_lowest_unreserved_ids_and_explicit_subnet() {
        let mut store = Store::in_memory().unwrap();
        let mut config = config();
        let link = config.links.get_mut("corp-link").unwrap();
        link.pool.first = 2;
        link.pool.last = 6;
        link.reserved = BTreeSet::from([2, 4]);
        config.profiles.get_mut("corp").unwrap().default_subnet = 99;
        for (asset, expected) in [(3, 3), (1, 5), (2, 6)] {
            let device = device(asset);
            store.register(&device).unwrap();
            let assignment = store
                .allocate(&config, &observation(&device), "corp-link")
                .unwrap();
            assert_eq!(assignment.device, expected);
            assert_eq!(assignment.subnet, 23);
            assert_eq!(assignment.address.segments()[3], 23);
            assert_eq!(assignment.address.segments()[7], expected);
            assert_eq!(assignment.fqdn, format!("host-{asset}.v6alias.home.arpa."));
            assert_eq!(assignment.policy_rule, "managed-corporate");
            assert_eq!(assignment.state, AssignmentState::Active);
            assert_eq!(
                store
                    .allocate(&config, &observation(&device), "corp-link")
                    .unwrap(),
                assignment
            );
        }
        assert_eq!(
            store
                .assignments(&config)
                .unwrap()
                .into_iter()
                .map(|a| a.asset_id)
                .collect::<Vec<_>>(),
            ["asset-1", "asset-2", "asset-3"]
        );
        assert_eq!(count(&store, "metadata"), 1);
    }

    #[test]
    fn upper_pool_boundary_is_inclusive_and_reservations_are_not_hardcoded() {
        let mut store = Store::in_memory().unwrap();
        let mut config = config();
        let link = config.links.get_mut("corp-link").unwrap();
        link.pool.first = 4095;
        link.pool.last = 4095;
        let device = device(1);
        store.register(&device).unwrap();
        assert_eq!(
            store
                .allocate(&config, &observation(&device), "corp-link")
                .unwrap()
                .device,
            4095
        );

        let mut store = Store::in_memory().unwrap();
        let link = config.links.get_mut("corp-link").unwrap();
        link.pool.first = 53;
        link.pool.last = 53;
        link.reserved.clear();
        store.register(&device).unwrap();
        assert_eq!(
            store
                .allocate(&config, &observation(&device), "corp-link")
                .unwrap()
                .device,
            53
        );
    }

    #[test]
    fn assignments_survive_restart_and_retirement_is_permanent() {
        let dir = directory();
        let path = dir.path().join("inventory.sqlite");
        let config = config();
        let first = device(1);
        let mut store = Store::open(&path).unwrap();
        store.register(&first).unwrap();
        let active = store
            .allocate(&config, &observation(&first), "corp-link")
            .unwrap();
        drop(store);
        let mut store = Store::open(&path).unwrap();
        assert_eq!(
            store
                .allocate(&config, &observation(&first), "corp-link")
                .unwrap(),
            active
        );
        let retired = store.retire(&config, &first.asset_id).unwrap();
        assert_eq!(retired.state, AssignmentState::Retired);
        assert_eq!(store.retire(&config, &first.asset_id).unwrap(), retired);
        assert!(matches!(
            store.retire(&config, "missing"),
            Err(ServiceError::NotFound(_))
        ));
        drop(store);
        let mut store = Store::open(&path).unwrap();
        assert!(matches!(
            store.allocate(&config, &observation(&first), "corp-link"),
            Err(ServiceError::Conflict(_))
        ));
        store.register(&first).unwrap();
        let second = device(2);
        store.register(&second).unwrap();
        let next = store
            .allocate(&config, &observation(&second), "corp-link")
            .unwrap();
        assert_eq!(next.device, active.device + 1);
        assert_ne!(next.fqdn, retired.fqdn);
        assert_eq!(store.assignments(&config).unwrap(), vec![retired, next]);
        let mut stolen = device(3);
        stolen.dns_label = first.dns_label;
        assert!(matches!(
            store.register(&stolen),
            Err(ServiceError::Conflict(_))
        ));
        stolen.dns_label = "unused".into();
        stolen.duid = first.duid;
        assert!(matches!(
            store.register(&stolen),
            Err(ServiceError::Conflict(_))
        ));
    }

    #[test]
    fn exhaustion_rolls_back_and_does_not_pin_a_failed_first_allocation() {
        let mut store = Store::in_memory().unwrap();
        let mut config = config();
        let link = config.links.get_mut("corp-link").unwrap();
        link.pool.first = 2;
        link.pool.last = 2;
        link.reserved = BTreeSet::from([2]);
        let first = device(1);
        store.register(&first).unwrap();
        assert!(matches!(
            store.allocate(&config, &observation(&first), "corp-link"),
            Err(ServiceError::Exhausted(_))
        ));
        assert_eq!(count(&store, "metadata"), 0);
        assert_eq!(count(&store, "assignments"), 0);
        config.links.get_mut("corp-link").unwrap().reserved.clear();
        store
            .allocate(&config, &observation(&first), "corp-link")
            .unwrap();
        let second = device(2);
        store.register(&second).unwrap();
        assert!(matches!(
            store.allocate(&config, &observation(&second), "corp-link"),
            Err(ServiceError::Exhausted(_))
        ));
        store.retire(&config, &first.asset_id).unwrap();
        assert!(matches!(
            store.allocate(&config, &observation(&second), "corp-link"),
            Err(ServiceError::Exhausted(_))
        ));
        assert_eq!(count(&store, "assignments"), 1);
        assert_eq!(count(&store, "metadata"), 1);
        assert_eq!(count(&store, "inventory"), 2);
    }

    #[test]
    fn overlong_dns_names_never_allocate_or_pin() {
        let mut config = config();
        config.dns_zone = format!("{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(62));
        config.validate().unwrap();
        let mut store = Store::in_memory().unwrap();
        let mut device = device(1);
        device.dns_label = "h".repeat(63);
        store.register(&device).unwrap();
        assert!(matches!(
            store.allocate(&config, &observation(&device), "corp-link"),
            Err(ServiceError::Validation(_))
        ));
        assert_eq!(count(&store, "assignments"), 0);
        assert_eq!(count(&store, "metadata"), 0);
    }

    #[test]
    fn policy_denials_never_write_or_pin_and_iaid_is_checked() {
        let mut store = Store::in_memory().unwrap();
        let config = config();
        let known = device(1);
        let unknown = device(2);
        let mut unmanaged = device(3);
        unmanaged.managed = false;
        store.register(&known).unwrap();
        store.register(&unmanaged).unwrap();
        let mut wrong_iaid = observation(&known);
        wrong_iaid.iaid += 10;
        for (observation, link) in [
            (observation(&unknown), "corp-link"),
            (observation(&unmanaged), "corp-link"),
            (wrong_iaid, "corp-link"),
            (observation(&known), "unknown-link"),
        ] {
            let decision = store.explain(&config, &observation, link).unwrap();
            assert!(!decision.allowed);
            assert!(matches!(
                store.allocate(&config, &observation, link),
                Err(ServiceError::PolicyDenied(_))
            ));
            assert_eq!(count(&store, "metadata"), 0);
            assert_eq!(count(&store, "assignments"), 0);
            assert!(store.connection.is_autocommit());
        }
        assert!(
            store
                .allocate(&config, &observation(&known), "corp-link")
                .is_ok()
        );
    }

    #[test]
    fn configuration_is_pinned_only_on_success_and_survives_retirement() {
        let mut store = Store::in_memory().unwrap();
        let config = config();
        let first = device(1);
        store.register(&first).unwrap();
        assert!(
            store
                .explain(&config, &observation(&first), "corp-link")
                .unwrap()
                .allowed
        );
        let mut alternate = config.clone();
        alternate.dns_zone = "other.home.arpa".into();
        assert!(
            store
                .explain(&alternate, &observation(&first), "corp-link")
                .unwrap()
                .allowed
        );
        assert_eq!(count(&store, "metadata"), 0);
        store
            .allocate(&config, &observation(&first), "corp-link")
            .unwrap();
        for retired in [false, true] {
            if retired {
                store.retire(&config, &first.asset_id).unwrap();
            }
            let mut prefix = config.clone();
            prefix.profiles.get_mut("corp").unwrap().prefix = "fd7a:115c:a1e1::/48".into();
            let mut pool = config.clone();
            pool.links.get_mut("corp-link").unwrap().pool.last = 10;
            let mut rules = config.clone();
            rules.rules[0].priority += 1;
            for changed in [&alternate, &prefix, &pool, &rules] {
                assert!(matches!(
                    store.assignments(changed),
                    Err(ServiceError::Conflict(_))
                ));
                assert!(matches!(
                    store.explain(changed, &observation(&first), "corp-link"),
                    Err(ServiceError::Conflict(_))
                ));
                let error = store
                    .allocate(changed, &observation(&first), "corp-link")
                    .unwrap_err();
                assert!(matches!(error, ServiceError::Conflict(_)));
                assert!(!error.to_string().contains(&changed.dns_zone));
            }
        }
        assert_eq!(store.assignments(&config).unwrap().len(), 1);
    }

    #[test]
    fn changed_placement_is_rejected_even_when_policy_allows_it() {
        let mut store = Store::in_memory().unwrap();
        let config = config();
        let device = device(1);
        store.register(&device).unwrap();
        let assignment = store
            .allocate(&config, &observation(&device), "corp-link")
            .unwrap();
        assert!(
            store
                .explain(&config, &observation(&device), "lab-link")
                .unwrap()
                .allowed
        );
        assert!(matches!(
            store.allocate(&config, &observation(&device), "lab-link"),
            Err(ServiceError::Conflict(_))
        ));
        assert_eq!(store.assignments(&config).unwrap(), vec![assignment]);
    }

    #[test]
    fn failed_late_write_rolls_back_assignment_and_pin_then_can_retry() {
        let mut store = Store::in_memory().unwrap();
        let device = device(1);
        let config = config();
        store.register(&device).unwrap();
        store
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER fail_pin BEFORE INSERT ON main.metadata
             BEGIN SELECT RAISE(ABORT, 'injected pin failure'); END",
            )
            .unwrap();
        assert!(
            store
                .allocate(&config, &observation(&device), "corp-link")
                .is_err()
        );
        assert_eq!(count(&store, "metadata"), 0);
        assert_eq!(count(&store, "assignments"), 0);
        assert_eq!(count(&store, "inventory"), 1);
        assert!(store.connection.is_autocommit());
        store
            .connection
            .execute_batch("DROP TRIGGER fail_pin")
            .unwrap();
        assert_eq!(
            store
                .allocate(&config, &observation(&device), "corp-link")
                .unwrap()
                .device,
            2
        );
    }

    #[test]
    fn failed_registration_and_retirement_leave_no_partial_state() {
        let mut store = Store::in_memory().unwrap();
        let first = device(1);
        store
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER fail_register AFTER INSERT ON main.inventory
             BEGIN SELECT RAISE(ABORT, 'injected registration failure'); END",
            )
            .unwrap();
        assert!(store.register(&first).is_err());
        assert_eq!(count(&store, "inventory"), 0);
        assert!(store.connection.is_autocommit());
        store
            .connection
            .execute_batch("DROP TRIGGER fail_register")
            .unwrap();
        store.register(&first).unwrap();
        let active = store
            .allocate(&config(), &observation(&first), "corp-link")
            .unwrap();
        store
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER fail_retire AFTER UPDATE ON main.assignments
             BEGIN SELECT RAISE(ABORT, 'injected retirement failure'); END",
            )
            .unwrap();
        assert!(store.retire(&config(), &first.asset_id).is_err());
        assert!(store.connection.is_autocommit());
        assert_eq!(store.assignments(&config()).unwrap(), vec![active]);
        store
            .connection
            .execute_batch("DROP TRIGGER fail_retire")
            .unwrap();
        assert_eq!(
            store.retire(&config(), &first.asset_id).unwrap().state,
            AssignmentState::Retired
        );
    }

    #[test]
    fn schema_constraints_preserve_identity_ranges_and_tombstones() {
        let mut store = Store::in_memory().unwrap();
        let first = device(1);
        store.register(&first).unwrap();
        store
            .allocate(&config(), &observation(&first), "corp-link")
            .unwrap();
        store.retire(&config(), &first.asset_id).unwrap();
        for sql in [
            "UPDATE inventory SET iaid = 2",
            "DELETE FROM inventory",
            "DELETE FROM assignments",
            "UPDATE assignments SET state = 'active'",
            "UPDATE assignments SET device = 3",
            "UPDATE metadata SET config_identity = 'other'",
            "DELETE FROM metadata",
            "INSERT INTO inventory VALUES ('other', '0002', -1, 1, 'other')",
            "INSERT INTO inventory VALUES ('other', '0002', 4294967296, 1, 'other')",
            "INSERT INTO inventory VALUES ('other', '0002', 1, 2, 'other')",
            "INSERT INTO inventory VALUES ('other', 'ABCD', 1, 1, 'other')",
            "INSERT INTO inventory VALUES ('Bad', '0002', 1, 1, 'other')",
            "INSERT INTO assignments VALUES ('missing', 'corp-link', 'corp', 23, 3, 'fd00::3', 'x.home.arpa.', 'active', 'rule')",
        ] {
            assert!(store.connection.execute_batch(sql).is_err(), "{sql}");
        }
        let second = device(2);
        store.register(&second).unwrap();
        for (profile, subnet, number, address, fqdn) in [
            ("corp", 23, 2, "fd00::3", "x.home.arpa."),
            ("corp", 23, 3, "fd7a:115c:a1e0:17::2", "x.home.arpa."),
            ("corp", 23, 3, "fd00::3", "host-1.v6alias.home.arpa."),
            ("corp", 23, 0, "fd00::3", "x.home.arpa."),
            ("corp", 23, 1, "fd00::3", "x.home.arpa."),
            ("corp", 23, 4096, "fd00::3", "x.home.arpa."),
            ("corp", -1, 3, "fd00::3", "x.home.arpa."),
            ("corp", 65536, 3, "fd00::3", "x.home.arpa."),
        ] {
            assert!(store.connection.execute(
                "INSERT INTO assignments VALUES ('asset-2', 'corp-link', ?1, ?2, ?3, ?4, ?5, 'active', 'rule')",
                params![profile, subnet, number, address, fqdn],
            ).is_err());
        }
        assert_eq!(count(&store, "assignments"), 1);
        assert_eq!(count(&store, "metadata"), 1);
    }

    #[test]
    fn simultaneous_connections_allocate_unique_and_idempotent_assignments() {
        for same_device in [false, true] {
            let dir = directory();
            let path = dir.path().join("inventory.sqlite");
            let mut store = Store::open(&path).unwrap();
            let first = device(1);
            let second = if same_device {
                first.clone()
            } else {
                device(2)
            };
            store.register(&first).unwrap();
            store.register(&second).unwrap();
            drop(store);
            let barrier = Arc::new(Barrier::new(2));
            let handles = [first, second].map(|device| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let mut store = Store::open(path).unwrap();
                    barrier.wait();
                    store
                        .allocate(&config(), &observation(&device), "corp-link")
                        .unwrap()
                })
            });
            let [left, right] = handles.map(|h| h.join().unwrap());
            let store = Store::read_only(&path).unwrap();
            if same_device {
                assert_eq!(left, right);
                assert_eq!(store.assignments(&config()).unwrap().len(), 1);
            } else {
                assert_ne!(left.device, right.device);
                assert_ne!(left.address, right.address);
                assert_ne!(left.fqdn, right.fqdn);
                assert_eq!(
                    BTreeSet::from([left.device, right.device]),
                    BTreeSet::from([2, 3])
                );
                assert_eq!(store.assignments(&config()).unwrap().len(), 2);
            }
        }
    }

    #[test]
    fn concurrent_first_allocations_cannot_pin_different_configs() {
        let dir = directory();
        let path = dir.path().join("inventory.sqlite");
        let mut store = Store::open(&path).unwrap();
        store.register(&device(1)).unwrap();
        store.register(&device(2)).unwrap();
        drop(store);
        let barrier = Arc::new(Barrier::new(2));
        let handles = [1, 2].map(|number| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut config = config();
                config.dns_zone = format!("zone-{number}.home.arpa");
                let mut store = Store::open(path).unwrap();
                barrier.wait();
                let result = store.allocate(&config, &observation(&device(number)), "corp-link");
                (config, result)
            })
        });
        let results = handles.map(|handle| handle.join().unwrap());
        assert_eq!(
            results.iter().filter(|(_, result)| result.is_ok()).count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|(_, result)| matches!(result, Err(ServiceError::Conflict(_))))
                .count(),
            1
        );
        let store = Store::read_only(path).unwrap();
        let winning_config = &results.iter().find(|(_, result)| result.is_ok()).unwrap().0;
        assert_eq!(store.assignments(winning_config).unwrap().len(), 1);
        assert_eq!(count(&store, "metadata"), 1);
    }

    #[test]
    fn concurrent_initialization_produces_one_complete_schema() {
        let dir = directory();
        let path = dir.path().join("inventory.sqlite");
        let barrier = Arc::new(Barrier::new(2));
        let handles = [1, 2].map(|number| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                let mut store = Store::open(path).unwrap();
                store.register(&device(number)).unwrap()
            })
        });
        for handle in handles {
            handle.join().unwrap();
        }
        let store = Store::read_only(path).unwrap();
        assert_eq!(store.devices().unwrap(), vec![device(1), device(2)]);
        assert_eq!(count(&store, "metadata"), 0);
    }

    #[test]
    fn retirement_rechecks_config_after_a_concurrent_first_allocation() {
        let dir = directory();
        let path = dir.path().join("retire-race.sqlite");
        let mut first = Store::open(&path).unwrap();
        let known = device(1);
        first.register(&known).unwrap();
        let original = config();
        assert!(first.assignments(&original).unwrap().is_empty());
        let mut other = original.clone();
        other.dns_zone = "other.home.arpa".into();
        let mut second = Store::open(&path).unwrap();
        let assignment = second
            .allocate(&other, &observation(&known), "corp-link")
            .unwrap();
        assert!(matches!(
            first.retire(&original, &known.asset_id),
            Err(ServiceError::Conflict(_))
        ));
        assert_eq!(first.assignments(&other).unwrap(), vec![assignment]);
        assert_eq!(
            first.retire(&other, &known.asset_id).unwrap().state,
            AssignmentState::Retired
        );
    }
}
