//! Explicit offline, additive configuration expansion into a NEW database.
//! The source and both parent directories must be trusted local paths, quiescent
//! for the operation. This is not cutover, an in-place migration or a WAL backup.

use std::{
    collections::BTreeMap,
    fs::{self, File, Metadata},
    io::Read,
    path::{Component, Path, PathBuf},
};

use serde::Serialize;

use crate::{
    AssignmentState, InventoryDevice, Observation, Rule, ServiceConfig, ServiceError, Store,
    pfsense::digest::sha256, policy, reconcile, store::RetainedRecords, validate_dns_label,
};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const SIDECARS: [&str; 3] = ["-journal", "-wal", "-shm"];

#[derive(Debug, Serialize)]
pub struct Receipt {
    pub schema_version: u32,
    pub operation: &'static str,
    pub before_config_identity_sha256: String,
    pub after_config_identity_sha256: String,
    /// SHA256 of compact JSON RetainedRecords, with both arrays ordered by asset_id.
    pub retained_records_sha256: String,
    pub devices: usize,
    pub active_assignments: usize,
    pub retired_assignments: usize,
    pub all_retained_records_verified: bool,
    pub source_unchanged: bool,
    pub source_verification: &'static str,
    pub needs_operator_cutover: bool,
}

fn conflict(message: &str) -> ServiceError {
    ServiceError::Conflict(message.into())
}

/// Read bounded regular YAML without following symlinks/reparse points.
pub fn read_config(path: &Path) -> Result<ServiceConfig, ServiceError> {
    let mut input = Input::open(path)?;
    let mut bytes = Vec::new();
    (&mut input.file)
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(conflict("service configuration exceeds 1 MiB"));
    }
    input.verify()?;
    let yaml =
        std::str::from_utf8(&bytes).map_err(|_| conflict("service configuration must be UTF-8"))?;
    ServiceConfig::from_yaml(yaml)
}

/// Preserve inventory and every assignment/tombstone exactly under a new pin.
/// No existing database or configuration file is ever opened for writing.
pub fn expand(
    source: &Path,
    old: &ServiceConfig,
    new: &ServiceConfig,
    destination: &Path,
) -> Result<Receipt, ServiceError> {
    expand_with(source, old, new, destination, || Ok(()))
}

fn expand_with(
    source: &Path,
    old: &ServiceConfig,
    new: &ServiceConfig,
    destination: &Path,
    before_publish: impl FnOnce() -> Result<(), ServiceError>,
) -> Result<Receipt, ServiceError> {
    old.validate_expansion(new)?;
    let mut input = Input::open(source)?;
    require_no_sidecars(&input.path)?;
    // Opening a WAL database read-only can create SHM. Reject the persistent WAL
    // header BEFORE SQLite opens it, even when its sidecars are currently absent.
    let mut header = [0; 100];
    input.file.read_exact(&mut header)?;
    if &header[..16] != b"SQLite format 3\0" || header[18..20] != [1, 1] {
        return Err(conflict(
            "source must be a quiescent DELETE-journal SQLite database",
        ));
    }
    input.verify()?;
    let destination = new_path(destination)?;
    if SIDECARS
        .iter()
        .any(|suffix| paths_equal(&destination, &sidecar(&input.path, suffix)))
    {
        return Err(conflict(
            "destination collides with a source SQLite sidecar",
        ));
    }
    require_no_sidecars(&destination)?;
    let store = Store::read_only(&input.path)?;
    store.with_expansion_snapshot(old, |records| {
        input.verify()?;
        require_no_sidecars(&input.path)?;
        validate_history(old, records)?;
        validate_history(new, records)?;
        let receipt = Receipt {
            schema_version: 1,
            operation: "additive_config_expansion",
            before_config_identity_sha256: sha256(old.identity()?.as_bytes()),
            after_config_identity_sha256: sha256(new.identity()?.as_bytes()),
            retained_records_sha256: sha256(&serde_json::to_vec(records)?),
            devices: records.devices.len(),
            active_assignments: records
                .assignments
                .iter()
                .filter(|a| a.state == AssignmentState::Active)
                .count(),
            retired_assignments: records
                .assignments
                .iter()
                .filter(|a| a.state == AssignmentState::Retired)
                .count(),
            all_retained_records_verified: true,
            source_unchanged: true,
            source_verification: "locked_read_snapshot_and_file_metadata_through_publication",
            needs_operator_cutover: true,
        };
        let parent = destination
            .parent()
            .ok_or_else(|| conflict("destination needs a parent"))?;
        // Private same-filesystem directory owns all staging SQLite sidecars, so
        // every ordinary failure cleans up only our files, never an operator's.
        let staging = tempfile::Builder::new()
            .prefix(".v6alias-expand-")
            .tempdir_in(parent)?;
        let file = tempfile::NamedTempFile::new_in(staging.path())?;
        Store::write_expanded(file.path(), new, records)?;
        {
            let copied = Store::read_only(file.path())?;
            copied.with_expansion_snapshot(new, |actual| {
                if actual != records {
                    return Err(conflict(
                        "reopened destination differs from retained history",
                    ));
                }
                Ok(())
            })?;
        }
        require_no_sidecars(file.path())?;
        file.as_file().sync_all()?;
        before_publish()?;
        input.verify()?;
        require_no_sidecars(&input.path)?;
        new_path(&destination)?;
        require_no_sidecars(&destination)?;
        // Close every destination handle before an atomic no-replace publication.
        file.into_temp_path()
            .persist_noclobber(&destination)
            .map_err(|error| ServiceError::Io(error.error))?;
        Ok(receipt)
    })
}

fn validate_history(config: &ServiceConfig, records: &RetainedRecords) -> Result<(), ServiceError> {
    reconcile::plan(config, &records.assignments, None)?;
    let devices: BTreeMap<_, _> = records.devices.iter().map(|d| (&d.asset_id, d)).collect();
    for device in &records.devices {
        device.validate()?;
    }
    for assignment in &records.assignments {
        let device = devices
            .get(&assignment.asset_id)
            .ok_or_else(|| conflict("assignment has no inventory identity"))?;
        if device.duid != assignment.duid
            || device.iaid != assignment.iaid
            || config.fqdn(&device.dns_label)? != assignment.fqdn
        {
            return Err(conflict("assignment differs from authoritative inventory"));
        }
        let rule = config
            .rules
            .iter()
            .find(|r| r.name == assignment.policy_rule)
            .ok_or_else(|| conflict("assignment has no original policy rule"))?;
        if !policy_witness(config, device, &assignment.link, rule)? {
            return Err(conflict(
                "assignment could not have been authorized by its recorded policy",
            ));
        }
    }
    Ok(())
}

// Historical hostname hints were intentionally never persisted. Prove that SOME
// valid hint could uniquely select the recorded rule, without inventing history.
fn policy_witness(
    config: &ServiceConfig,
    device: &InventoryDevice,
    link: &str,
    rule: &Rule,
) -> Result<bool, ServiceError> {
    let mut observation = Observation {
        duid: device.duid.clone(),
        iaid: device.iaid,
        hostname: None,
    };
    let decision = policy::evaluate(config, &observation, link, Some(device))?;
    if decision.allowed && decision.matched_rule.as_deref() == Some(&rule.name) {
        return Ok(true);
    }
    if rule
        .managed
        .is_some_and(|managed| managed != device.managed)
        || (config.profiles[&rule.profile].require_managed && !device.managed)
    {
        return Ok(false);
    }
    let blockers: Vec<_> = config
        .rules
        .iter()
        .filter(|other| {
            other.name != rule.name
                && other.priority >= rule.priority
                && other.links.contains(link)
                && other
                    .managed
                    .is_none_or(|managed| managed == device.managed)
        })
        .collect();
    if blockers.iter().any(|r| r.hostname_prefix.is_none()) {
        return Ok(false);
    }
    let prefixes: Vec<_> = blockers
        .iter()
        .filter_map(|r| r.hostname_prefix.as_deref())
        .collect();
    let Some(hint) = unblocked_hint(rule.hostname_prefix.as_deref().unwrap_or(""), &prefixes)
    else {
        return Ok(false);
    };
    observation.hostname = Some(hint);
    let decision = policy::evaluate(config, &observation, link, Some(device))?;
    Ok(decision.allowed && decision.matched_rule.as_deref() == Some(&rule.name))
}

fn unblocked_hint(prefix: &str, blockers: &[&str]) -> Option<String> {
    if blockers.iter().any(|blocked| prefix.starts_with(blocked)) {
        return None;
    }
    if validate_dns_label(prefix).is_ok() {
        return Some(prefix.into());
    }
    if prefix.len() >= 63 || prefix.starts_with('-') {
        return None;
    }
    // Only a prefix ending in '-' (or the empty prefix) needs extension. Any
    // occupied branch is pruned at its blocking prefix; work is bounded by input.
    for next in b"abcdefghijklmnopqrstuvwxyz0123456789-" {
        let candidate = format!("{prefix}{}", char::from(*next));
        if let Some(hint) = unblocked_hint(&candidate, blockers) {
            return Some(hint);
        }
    }
    None
}

struct Input {
    path: PathBuf,
    file: File,
    before: Metadata,
}

impl Input {
    fn open(path: &Path) -> Result<Self, ServiceError> {
        let path = existing_path(path)?;
        let before = fs::symlink_metadata(&path)?;
        if !before.is_file() || is_link(&before) {
            return Err(conflict("input must be a regular non-symlink file"));
        }
        let file = File::open(&path)?;
        let input = Self { path, file, before };
        input.verify()?;
        Ok(input)
    }

    fn verify(&self) -> Result<(), ServiceError> {
        existing_path(&self.path)?;
        for after in [self.file.metadata()?, fs::symlink_metadata(&self.path)?] {
            if !after.is_file()
                || is_link(&after)
                || !same_file(&self.before, &after)
                || self.before.len() != after.len()
                || self.before.modified()? != after.modified()?
                || self.before.created().ok() != after.created().ok()
            {
                return Err(conflict("source/input changed during expansion"));
            }
        }
        Ok(())
    }
}

fn existing_path(path: &Path) -> Result<PathBuf, ServiceError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut checked = PathBuf::new();
    for component in absolute.components() {
        if matches!(component, Component::ParentDir) {
            return Err(conflict("parent traversal is not permitted"));
        }
        #[cfg(windows)]
        if let Component::Prefix(prefix) = component {
            use std::path::Prefix;
            if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) {
                return Err(conflict("only local disk paths are permitted"));
            }
        }
        #[cfg(windows)]
        if let Component::Normal(name) = component
            && name.to_string_lossy().contains(':')
        {
            return Err(conflict("alternate data streams are not permitted"));
        }
        checked.push(component);
        // A bare Windows drive prefix (especially \\?\D:) is not a directory.
        // Inspect it only once the following RootDir has formed the drive root.
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        if is_link(&fs::symlink_metadata(&checked)?) {
            return Err(conflict("symlinks and reparse points are not permitted"));
        }
    }
    Ok(fs::canonicalize(absolute)?)
}

fn new_path(path: &Path) -> Result<PathBuf, ServiceError> {
    let name = path
        .file_name()
        .ok_or_else(|| conflict("destination needs a filename"))?;
    #[cfg(windows)]
    if name.to_string_lossy().contains(':') {
        return Err(conflict("alternate data streams are not permitted"));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = existing_path(parent)?;
    if !parent.is_dir() {
        return Err(conflict(
            "destination parent must be an existing trusted local directory",
        ));
    }
    let path = parent.join(name);
    require_absent(&path)?;
    Ok(path)
}

fn require_absent(path: &Path) -> Result<(), ServiceError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(conflict(
            "destination or SQLite sidecar already exists; never overwrite",
        )),
    }
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    name.into()
}

fn require_no_sidecars(path: &Path) -> Result<(), ServiceError> {
    for suffix in SIDECARS {
        require_absent(&sidecar(path, suffix))?;
    }
    Ok(())
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    {
        left.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

fn is_link(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn same_file(before: &Metadata, after: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        before.dev() == after.dev() && before.ino() == after.ino()
    }
    #[cfg(not(unix))]
    {
        // Stable Windows metadata lacks file IDs; path components, retained
        // handles, times and size are checked. Trusted directories are required.
        let _ = (before, after);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{Connection, params};
    use std::{sync::mpsc, thread, time::Duration};

    fn configs() -> (ServiceConfig, ServiceConfig) {
        let old = ServiceConfig::from_yaml(include_str!(
            "../../../examples/offline/service-corporate.yaml"
        ))
        .unwrap();
        let new = ServiceConfig::from_yaml(include_str!("../../../service.example.yaml")).unwrap();
        (old, new)
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

    struct Fixture {
        directory: tempfile::TempDir,
        source: PathBuf,
        destination: PathBuf,
        old: ServiceConfig,
        new: ServiceConfig,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
            let source = directory.path().join("source.sqlite");
            let destination = directory.path().join("expanded.sqlite");
            let (mut old, mut new) = configs();
            old.dns_ttl_seconds = 3600;
            new.dns_ttl_seconds = 3600;
            // A reserved gap makes replay/reallocation observably incorrect.
            old.links.get_mut("corp-link").unwrap().reserved.insert(4);
            new.links.get_mut("corp-link").unwrap().reserved.insert(4);
            let mut store = Store::open(&source).unwrap();
            for number in 1..=4 {
                store.register(&device(number)).unwrap();
            }
            for number in [1, 2] {
                store
                    .allocate(&old, &observation(&device(number)), "corp-link")
                    .unwrap();
            }
            store.retire(&old, "asset-2").unwrap();
            drop(store);
            Self {
                directory,
                source,
                destination,
                old,
                new,
            }
        }

        fn expand(&self) -> Result<Receipt, ServiceError> {
            expand(&self.source, &self.old, &self.new, &self.destination)
        }

        fn assert_failure(&self) {
            let before = fs::read(&self.source).unwrap();
            assert!(self.expand().is_err());
            assert_eq!(before, fs::read(&self.source).unwrap());
            assert!(!self.destination.exists());
            assert!(!fs::read_dir(self.directory.path()).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".v6alias-expand-")
            }));
        }
    }

    #[test]
    fn expansion_retains_exact_records_pins_and_permanent_tombstones() {
        let fixture = Fixture::new();
        let before = fs::read(&fixture.source).unwrap();
        let old = Store::read_only(&fixture.source).unwrap();
        let inventory = old.devices().unwrap();
        let history = old.assignments(&fixture.old).unwrap();
        drop(old);
        let receipt = fixture.expand().unwrap();
        assert_eq!(receipt.devices, 4);
        assert_eq!(receipt.active_assignments, 1);
        assert_eq!(receipt.retired_assignments, 1);
        assert!(
            receipt.all_retained_records_verified
                && receipt.source_unchanged
                && receipt.needs_operator_cutover
        );
        assert_ne!(
            receipt.before_config_identity_sha256,
            receipt.after_config_identity_sha256
        );
        assert_eq!(receipt.retained_records_sha256.len(), 64);
        let mut new = Store::open_existing(&fixture.destination).unwrap();
        assert_eq!(new.devices().unwrap(), inventory);
        assert_eq!(new.assignments(&fixture.new).unwrap(), history);
        assert!(new.assignments(&fixture.old).is_err());
        assert_eq!(
            new.allocate(&fixture.new, &observation(&device(3)), "corp-link")
                .unwrap()
                .device,
            5
        );
        assert_eq!(
            new.allocate(&fixture.new, &observation(&device(4)), "lab-link")
                .unwrap()
                .device,
            2
        );
        assert!(
            new.allocate(&fixture.new, &observation(&device(2)), "corp-link")
                .is_err()
        );
        assert_eq!(before, fs::read(&fixture.source).unwrap());
        let old = Store::read_only(&fixture.source).unwrap();
        assert_eq!(old.assignments(&fixture.old).unwrap(), history);
        assert!(old.assignments(&fixture.new).is_err());
        drop(new);
        let connection = Connection::open(&fixture.destination).unwrap();
        for sql in [
            "UPDATE metadata SET config_identity = 'changed'",
            "DELETE FROM metadata",
            "DELETE FROM inventory",
            "UPDATE inventory SET iaid = 20",
            "DELETE FROM assignments",
            "UPDATE assignments SET state = 'active' WHERE state = 'retired'",
        ] {
            assert!(connection.execute_batch(sql).is_err(), "{sql}");
        }
    }

    #[test]
    fn additive_validation_rejects_every_old_semantic_change() {
        let (old, new) = configs();
        type Mutation = fn(&mut ServiceConfig);
        let mutations: &[Mutation] = &[
            |c| c.dns_zone = "other.home.arpa".into(),
            |c| c.dns_ttl_seconds = 3600,
            |c| {
                c.profiles.remove("corp");
            },
            |c| c.profiles.get_mut("corp").unwrap().prefix = "fd12:3456:789a::/48".into(),
            |c| c.profiles.get_mut("corp").unwrap().default_subnet = 24,
            |c| c.profiles.get_mut("corp").unwrap().require_managed = false,
            |c| {
                c.links.remove("corp-link");
            },
            |c| c.links.get_mut("corp-link").unwrap().subnet = 24,
            |c| c.links.get_mut("corp-link").unwrap().profile = "lab".into(),
            |c| c.links.get_mut("corp-link").unwrap().pool.first = 3,
            |c| c.links.get_mut("corp-link").unwrap().pool.last = 4094,
            |c| {
                c.links.get_mut("corp-link").unwrap().reserved.insert(4);
            },
            |c| {
                c.links.get_mut("corp-link").unwrap().reserved.remove(&53);
            },
            |c| c.rules[0].priority = 90,
            |c| c.rules[0].name = "renamed".into(),
            |c| c.rules[0].managed = None,
            |c| c.rules[0].hostname_prefix = Some("host".into()),
            |c| c.rules.swap(0, 1),
            |c| {
                c.rules.remove(0);
            },
            |c| {
                let mut rule = c.rules[0].clone();
                rule.name = "old-promotion".into();
                c.rules.push(rule);
            },
            |c| c.rules[1].name = c.rules[0].name.clone(),
            |c| c.profiles.get_mut("lab").unwrap().prefix = c.profiles["corp"].prefix.clone(),
            |c| {
                let link = c.links["corp-link"].clone();
                c.links.insert("alias-link".into(), link);
            },
        ];
        for (index, mutation) in mutations.iter().enumerate() {
            let mut invalid = new.clone();
            mutation(&mut invalid);
            assert!(
                old.validate_expansion(&invalid).is_err(),
                "mutation {index}"
            );
        }
        assert!(old.validate_expansion(&old).is_err());
    }

    #[test]
    fn new_subnet_of_existing_profile_is_additive_but_old_decisions_cannot_change() {
        let (old, _) = configs();
        let mut new = old.clone();
        let mut link = old.links["corp-link"].clone();
        link.subnet += 1;
        new.links.insert("second-corp".into(), link);
        let mut rule = old.rules[0].clone();
        rule.name = "second-rule".into();
        rule.links = ["second-corp".into()].into();
        rule.priority = i32::MAX;
        new.rules.push(rule);
        old.validate_expansion(&new).unwrap();
        for managed in [false, true] {
            let mut device = device(1);
            device.managed = managed;
            for hint in [None, Some("corp-host"), Some("lab-host"), Some("-invalid")] {
                let mut observation = observation(&device);
                observation.hostname = hint.map(str::to_owned);
                for inventory in [None, Some(&device)] {
                    let before =
                        policy::evaluate(&old, &observation, "corp-link", inventory).unwrap();
                    let after =
                        policy::evaluate(&new, &observation, "corp-link", inventory).unwrap();
                    assert_eq!(before.allowed, after.allowed);
                    assert_eq!(before.matched_rule, after.matched_rule);
                    assert_eq!(before.reason, after.reason);
                }
            }
        }
    }

    #[test]
    fn rule_order_is_retained_even_when_priority_order_would_be_equivalent() {
        let (_, old) = configs();
        let mut new = old.clone();
        let mut profile = old.profiles["corp"].clone();
        profile.prefix = "fd12:3456:789a::/48".into();
        new.profiles.insert("unused".into(), profile);
        old.validate_expansion(&new).unwrap();
        new.rules.swap(0, 1);
        assert!(old.validate_expansion(&new).is_err());
    }

    #[test]
    fn source_must_exist_be_recognized_and_be_pinned_to_old_config() {
        let fixture = Fixture::new();
        assert!(
            expand(
                &fixture.directory.path().join("missing"),
                &fixture.old,
                &fixture.new,
                &fixture.destination
            )
            .is_err()
        );
        let unpinned = fixture.directory.path().join("unpinned.sqlite");
        drop(Store::open(&unpinned).unwrap());
        assert!(expand(&unpinned, &fixture.old, &fixture.new, &fixture.destination).is_err());
        let mut wrong = fixture.old.clone();
        wrong.dns_ttl_seconds = 42;
        let mut wrong_new = fixture.new.clone();
        wrong_new.dns_ttl_seconds = 42;
        assert!(expand(&fixture.source, &wrong, &wrong_new, &fixture.destination).is_err());
        let unrelated = fixture.directory.path().join("unrelated.sqlite");
        Connection::open(&unrelated)
            .unwrap()
            .execute_batch("CREATE TABLE unrelated (x)")
            .unwrap();
        assert!(expand(&unrelated, &fixture.old, &fixture.new, &fixture.destination).is_err());
        let broken = fixture.directory.path().join("broken.sqlite");
        fs::write(&broken, b"not sqlite").unwrap();
        assert!(expand(&broken, &fixture.old, &fixture.new, &fixture.destination).is_err());
        assert!(!fixture.destination.exists());
    }

    #[test]
    fn an_explicitly_pinned_empty_history_still_pins_the_new_database() {
        let fixture = Fixture::new();
        let empty = fixture.directory.path().join("empty.sqlite");
        drop(Store::open(&empty).unwrap());
        let connection = Connection::open(&empty).unwrap();
        connection
            .execute(
                "INSERT INTO metadata VALUES (1, ?1)",
                [fixture.old.identity().unwrap()],
            )
            .unwrap();
        drop(connection);
        let receipt = expand(&empty, &fixture.old, &fixture.new, &fixture.destination).unwrap();
        assert_eq!(receipt.active_assignments + receipt.retired_assignments, 0);
        let store = Store::read_only(&fixture.destination).unwrap();
        assert!(store.assignments(&fixture.new).unwrap().is_empty());
        assert!(store.assignments(&fixture.old).is_err());
    }

    #[test]
    fn corrupt_history_is_not_hidden_by_join_normalization_or_retirement() {
        for corruption in [
            "fqdn",
            "policy",
            "address",
            "noncanonical",
            "orphan",
            "schema",
            "unmanaged",
            "unpin",
            "check",
        ] {
            let fixture = Fixture::new();
            let connection = Connection::open(&fixture.source).unwrap();
            // Deliberately forge new rows without weakening any production trigger.
            if corruption == "orphan" {
                connection
                    .pragma_update(None, "foreign_keys", false)
                    .unwrap();
            }
            if corruption == "schema" {
                connection
                    .execute_batch("CREATE TABLE unexpected (x)")
                    .unwrap();
            } else if corruption == "unpin" {
                // Recreate a recognized source without metadata using a fresh fixture.
                drop(connection);
                let path = fixture.directory.path().join("missing-pin.sqlite");
                drop(Store::open(&path).unwrap());
                let connection = Connection::open(&path).unwrap();
                connection.execute_batch("INSERT INTO inventory VALUES ('x', '0011', 1, 1, 'x');
                        INSERT INTO assignments VALUES ('x','corp-link','corp',23,7,'fd7a:115c:a1e0:17::7','x.v6alias.home.arpa.','retired','managed-corporate')").unwrap();
                drop(connection);
                assert!(expand(&path, &fixture.old, &fixture.new, &fixture.destination).is_err());
                continue;
            } else {
                if corruption != "orphan" {
                    connection
                        .execute(
                            "INSERT INTO inventory VALUES ('bad', '0011', 1, ?1, 'bad')",
                            [corruption != "unmanaged"],
                        )
                        .unwrap();
                }
                if corruption == "check" {
                    connection
                        .pragma_update(None, "ignore_check_constraints", true)
                        .unwrap();
                }
                let address = match corruption {
                    "address" => "fd7a:115c:a1e0:17::8",
                    "noncanonical" => "fd7a:115c:a1e0:17:0:0:0:7",
                    _ => "fd7a:115c:a1e0:17::7",
                };
                connection.execute(
                        "INSERT INTO assignments VALUES ('bad','corp-link','corp',23,?1,?2,?3,'retired',?4)",
                        params![
                            if corruption == "check" { 1 } else { 7 }, address,
                            if corruption == "fqdn" { "other.v6alias.home.arpa." } else { "bad.v6alias.home.arpa." },
                            if corruption == "policy" { "nonexistent" } else { "managed-corporate" }
                        ],
                    ).unwrap();
            }
            drop(connection);
            fixture.assert_failure();
        }
    }

    #[test]
    fn historical_hostname_rule_needs_a_possible_unique_winner_not_a_fabricated_hint() {
        let (mut config, _) = configs();
        let device = device(1);
        config.rules[0].hostname_prefix = Some("corp-".into());
        let recorded = config.rules[0].clone();
        assert!(policy_witness(&config, &device, "corp-link", &recorded).unwrap());
        let mut blocker = recorded.clone();
        blocker.name = "blocker".into();
        blocker.hostname_prefix = Some("corp-a".into());
        config.rules.push(blocker);
        assert!(policy_witness(&config, &device, "corp-link", &recorded).unwrap());
        config.rules[1].hostname_prefix = Some("corp-".into());
        assert!(!policy_witness(&config, &device, "corp-link", &recorded).unwrap());
        config.rules[1].priority -= 1;
        assert!(policy_witness(&config, &device, "corp-link", &recorded).unwrap());
        config.rules[0].hostname_prefix = Some(format!("{}-", "a".repeat(62)));
        assert!(!policy_witness(&config, &device, "corp-link", &config.rules[0]).unwrap());
    }

    #[test]
    fn source_and_destination_sidecars_and_wal_headers_fail_without_writes() {
        for suffix in SIDECARS {
            let fixture = Fixture::new();
            fs::write(sidecar(&fixture.source, suffix), b"foreign").unwrap();
            fixture.assert_failure();
            assert_eq!(
                fs::read(sidecar(&fixture.source, suffix)).unwrap(),
                b"foreign"
            );
            fs::remove_file(sidecar(&fixture.source, suffix)).unwrap();
            fs::write(sidecar(&fixture.destination, suffix), b"foreign").unwrap();
            fixture.assert_failure();
            assert_eq!(
                fs::read(sidecar(&fixture.destination, suffix)).unwrap(),
                b"foreign"
            );
        }
        let fixture = Fixture::new();
        let connection = Connection::open(&fixture.source).unwrap();
        connection
            .pragma_update(None, "journal_mode", "wal")
            .unwrap();
        drop(connection);
        require_no_sidecars(&fixture.source).unwrap();
        fixture.assert_failure();
        require_no_sidecars(&fixture.source).unwrap();
    }

    #[test]
    fn destination_collisions_never_replace_files_or_directories() {
        let fixture = Fixture::new();
        let bytes = fs::read(&fixture.source).unwrap();
        for path in [&fixture.source, fixture.directory.path()] {
            assert!(expand(&fixture.source, &fixture.old, &fixture.new, path).is_err());
        }
        for suffix in SIDECARS {
            let path = sidecar(&fixture.source, suffix);
            assert!(expand(&fixture.source, &fixture.old, &fixture.new, &path).is_err());
            assert!(!path.exists());
        }
        fs::hard_link(&fixture.source, &fixture.destination).unwrap();
        assert!(fixture.expand().is_err());
        assert_eq!(fs::read(&fixture.destination).unwrap(), bytes);
        assert_eq!(fs::read(&fixture.source).unwrap(), bytes);
        fs::remove_file(&fixture.destination).unwrap();
        fs::write(&fixture.destination, b"foreign").unwrap();
        assert!(fixture.expand().is_err());
        assert_eq!(fs::read(&fixture.destination).unwrap(), b"foreign");
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_and_parent_symlinks_are_never_followed() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new();
        let source_link = fixture.directory.path().join("source-link");
        symlink(&fixture.source, &source_link).unwrap();
        assert!(
            expand(
                &source_link,
                &fixture.old,
                &fixture.new,
                &fixture.destination
            )
            .is_err()
        );
        symlink(&fixture.source, &fixture.destination).unwrap();
        assert!(fixture.expand().is_err());
        fs::remove_file(&fixture.destination).unwrap();
        symlink("missing", &fixture.destination).unwrap();
        assert!(fixture.expand().is_err());
        fs::remove_file(&fixture.destination).unwrap();
        let parent_link = fixture.directory.path().join("parent-link");
        symlink(fixture.directory.path(), &parent_link).unwrap();
        assert!(
            expand(
                &fixture.source,
                &fixture.old,
                &fixture.new,
                &parent_link.join("new.sqlite")
            )
            .is_err()
        );
        assert!(
            expand(
                &parent_link.join("source.sqlite"),
                &fixture.old,
                &fixture.new,
                &fixture.destination
            )
            .is_err()
        );
        assert!(!fixture.destination.exists());
    }

    #[test]
    fn failure_after_copy_cleans_staging_and_no_clobber_publication_wins_race() {
        let fixture = Fixture::new();
        let bytes = fs::read(&fixture.source).unwrap();
        let result = expand_with(
            &fixture.source,
            &fixture.old,
            &fixture.new,
            &fixture.destination,
            || {
                assert!(!fixture.destination.exists());
                Err(conflict("injected pre-publication failure"))
            },
        );
        assert!(result.is_err());
        assert!(!fixture.destination.exists());
        assert_eq!(fs::read_dir(fixture.directory.path()).unwrap().count(), 1);
        let result = expand_with(
            &fixture.source,
            &fixture.old,
            &fixture.new,
            &fixture.destination,
            || {
                fs::write(&fixture.destination, b"competitor")?;
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(fs::read(&fixture.destination).unwrap(), b"competitor");
        assert_eq!(fs::read(&fixture.source).unwrap(), bytes);
        assert_eq!(fs::read_dir(fixture.directory.path()).unwrap().count(), 2);
    }

    #[test]
    fn concurrent_writer_cannot_commit_during_snapshot_or_publish_incomplete_history() {
        let fixture = Fixture::new();
        let (start_tx, start_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let source = fixture.source.clone();
        let writer = thread::spawn(move || {
            let connection = Connection::open(source).unwrap();
            connection.busy_timeout(Duration::from_millis(50)).unwrap();
            start_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            let result = connection.execute_batch("BEGIN IMMEDIATE; INSERT INTO inventory VALUES ('writer', '0011', 1, 1, 'writer'); COMMIT;");
            assert!(result.is_err());
            connection.execute_batch("ROLLBACK").unwrap();
            result_tx.send(()).unwrap();
        });
        let before = fs::read(&fixture.source).unwrap();
        expand_with(
            &fixture.source,
            &fixture.old,
            &fixture.new,
            &fixture.destination,
            || {
                assert!(!fixture.destination.exists());
                start_tx.send(()).unwrap();
                result_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                Ok(())
            },
        )
        .unwrap();
        writer.join().unwrap();
        assert_eq!(fs::read(&fixture.source).unwrap(), before);
        assert_eq!(
            Store::read_only(&fixture.destination)
                .unwrap()
                .devices()
                .unwrap()
                .len(),
            4
        );
    }
}
