//! Read-only, strict ISC DHCP 4.4.x IA_NA normalization. No inventory or network I/O.

mod parser;

use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use v6alias_core::UlaPrefix;

use crate::{
    Duid, Observation, ServiceConfig, ServiceError,
    shadow::{MAX_INPUT_BYTES, MAX_OBSERVATIONS, ObservationSnapshot, validate_capture_time},
    validate_dns_label,
};

pub const MAX_CAPTURE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_LEASE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_TOKEN_BYTES: usize = 4096;
pub const MAX_TOKENS: usize = 4_000_000;
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;
pub const MAX_ASSOCIATIONS: usize = 65_536;
pub const MAX_ADDRESSES: usize = 262_144;

type Result<T> = std::result::Result<T, ServiceError>;

fn invalid(message: impl Into<String>) -> ServiceError {
    ServiceError::Validation(message.into())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub schema_version: u32,
    pub source: String,
    pub captured_at_unix_secs: u64,
    pub lease_file: String,
}

impl Capture {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > MAX_CAPTURE_BYTES {
            return Err(invalid("ISC capture envelope exceeds 67108864 bytes"));
        }
        Ok(serde_json::from_slice(bytes)?)
    }

    fn validate(&self, source: &str, now: u64, max_age: u64) -> Result<()> {
        if self.schema_version != 1 {
            return Err(invalid("unsupported ISC capture schema version"));
        }
        // Do not reflect an envelope-sized untrusted label into diagnostics.
        if self.source.len() > 63 {
            return Err(invalid("ISC capture source exceeds 63 bytes"));
        }
        validate_dns_label(source)?;
        validate_dns_label(&self.source)?;
        if self.source != source {
            return Err(invalid(
                "ISC capture source does not match operator binding",
            ));
        }
        validate_capture_time("ISC", self.captured_at_unix_secs, now, max_age)?;
        if self.lease_file.len() > MAX_LEASE_BYTES {
            return Err(invalid("ISC decoded lease file exceeds 67108864 bytes"));
        }
        Ok(())
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Counts {
    pub association_records: usize,
    pub address_records: usize,
    pub replaced_associations: usize,
    pub latest_associations: usize,
    pub inactive_addresses: usize,
    pub expired_addresses: usize,
    pub live_addresses: usize,
    pub filtered_other_link_associations: usize,
    pub observations: usize,
    pub authoring_byte_order: Option<&'static str>,
    pub server_duid_present: bool,
}

#[derive(Debug)]
pub struct Collection {
    pub snapshot: ObservationSnapshot,
    pub counts: Counts,
}

impl Collection {
    /// The daemon's exact envelope, with a newline and its complete input-size bound.
    pub fn snapshot_json(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec(&self.snapshot)?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_INPUT_BYTES {
            return Err(invalid(
                "normalized observation output exceeds 1048576 bytes",
            ));
        }
        Ok(bytes)
    }
}

/// Validates the entire capture before filtering the selected operator-configured /64.
/// Uses the real clock; there is deliberately no production clock-override flag.
pub fn collect(
    capture: &Capture,
    config: &ServiceConfig,
    source: &str,
    trusted_link: &str,
    max_age_secs: u64,
) -> Result<Collection> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("system clock is before Unix epoch"))?
        .as_secs();
    collect_at(capture, config, source, trusted_link, max_age_secs, now)
}

fn collect_at(
    capture: &Capture,
    config: &ServiceConfig,
    source: &str,
    trusted_link: &str,
    max_age_secs: u64,
    now: u64,
) -> Result<Collection> {
    capture.validate(source, now, max_age_secs)?;
    config.validate()?;
    validate_dns_label(trusted_link)?;
    if !config.links.contains_key(trusted_link) {
        return Err(invalid("unknown --trusted-link in service configuration"));
    }
    let mut networks = BTreeMap::new();
    for (name, link) in &config.links {
        let prefix = config.profiles[&link.profile]
            .prefix
            .parse::<UlaPrefix>()
            .map_err(|e| invalid(e.to_string()))?;
        let [a, b, c] = prefix.segments();
        if networks.insert([a, b, c, link.subnet], name).is_some() {
            return Err(invalid("ambiguous trusted-link /64 mapping"));
        }
    }
    let (associations, mut counts) = parser::parse(capture.lease_file.as_bytes())?;
    let mut owners = BTreeMap::new();
    let mut live_duids: BTreeMap<&Duid, u32> = BTreeMap::new();
    let mut observations = Vec::new();
    for ((duid, iaid), addresses) in &associations {
        let mut scope = None;
        for lease in addresses {
            if !lease.active {
                counts.inactive_addresses += 1;
                continue;
            }
            // Evaluate at collection time, not cltt+max-life or the older capture time.
            if !lease.ends.live_at(now) {
                counts.expired_addresses += 1;
                continue;
            }
            counts.live_addresses += 1;
            if owners.insert(lease.address, (duid, iaid)).is_some() {
                return Err(invalid("conflicting live address owners in ISC capture"));
            }
            let segments = lease.address.segments();
            let network = [segments[0], segments[1], segments[2], segments[3]];
            let link = networks
                .get(&network)
                .ok_or_else(|| invalid("live ISC address has no configured trusted-link /64"))?;
            if scope.is_some_and(|previous| previous != *link) {
                return Err(invalid("live ISC association spans multiple trusted links"));
            }
            scope = Some(*link);
        }
        if let Some(link) = scope {
            if live_duids.insert(duid, *iaid).is_some() {
                return Err(invalid("multiple live IAIDs for one DUID are unsupported"));
            }
            if link == trusted_link {
                if observations.len() == MAX_OBSERVATIONS {
                    return Err(invalid("normalized observation count exceeds 4096"));
                }
                observations.push(Observation {
                    duid: duid.clone(),
                    iaid: *iaid,
                    hostname: None,
                });
            } else {
                counts.filtered_other_link_associations += 1;
            }
        }
    }
    counts.observations = observations.len();
    let snapshot = ObservationSnapshot {
        schema_version: 1,
        source: capture.source.clone(),
        captured_at_unix_secs: capture.captured_at_unix_secs,
        observations,
    };
    snapshot.validate(source, now, max_age_secs)?;
    let result = Collection { snapshot, counts };
    result.snapshot_json()?;
    Ok(result)
}

#[cfg(test)]
mod tests;
