use std::{fmt, net::Ipv6Addr, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Duid(String);

impl FromStr for Duid {
    type Err = ServiceError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.contains(':')
            && input
                .split(':')
                .any(|part| part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(ServiceError::Validation(
                "DUID must contain hexadecimal byte pairs".into(),
            ));
        }
        let compact = input.replace(':', "");
        if !(4..=256).contains(&compact.len())
            || !compact.len().is_multiple_of(2)
            || !compact.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ServiceError::Validation(
                "DUID must contain 2 to 128 hexadecimal bytes".into(),
            ));
        }
        Ok(Self(compact.to_ascii_lowercase()))
    }
}

impl TryFrom<String> for Duid {
    type Error = ServiceError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Duid> for String {
    fn from(value: Duid) -> Self {
        value.0
    }
}

impl fmt::Display for Duid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Duid {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryDevice {
    pub asset_id: String,
    pub duid: Duid,
    pub iaid: u32,
    pub managed: bool,
    pub dns_label: String,
}

impl InventoryDevice {
    pub fn validate(&self) -> Result<(), ServiceError> {
        validate_dns_label(&self.asset_id)?;
        validate_dns_label(&self.dns_label)
    }
}

pub fn validate_dns_label(value: &str) -> Result<(), ServiceError> {
    if value.is_empty()
        || value.len() > 63
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(ServiceError::Validation(format!(
            "`{value}` must be a lowercase ASCII DNS label (1-63 characters, no edge hyphens)"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub duid: Duid,
    pub iaid: u32,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentState {
    Active,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    pub asset_id: String,
    pub duid: Duid,
    pub iaid: u32,
    pub link: String,
    pub profile: String,
    pub subnet: u16,
    pub device: u16,
    pub address: Ipv6Addr,
    pub fqdn: String,
    pub state: AssignmentState,
    pub policy_rule: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Decision {
    pub allowed: bool,
    pub reason: String,
    pub matched_rule: Option<String>,
    pub profile: Option<String>,
    pub subnet: Option<u16>,
    pub trace: Vec<RuleTrace>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleTrace {
    pub rule: String,
    pub priority: i32,
    pub matched: bool,
    pub reason: String,
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("invalid service configuration: {0}")]
    Config(String),
    #[error("invalid input: {0}")]
    Validation(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("allocation exhausted: {0}")]
    Exhausted(String),
    #[error("SQLite: {0}")]
    Storage(#[from] rusqlite::Error),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("address configuration: {0}")]
    Address(#[from] v6alias_core::ConfigError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duids_are_canonical_and_bounded() {
        assert_eq!("00:01:AB:CD".parse::<Duid>().unwrap().as_str(), "0001abcd");
        for invalid in ["", "000", "00::01", "0:001", "00-01", "zzzz", " 0001"] {
            assert!(invalid.parse::<Duid>().is_err(), "{invalid}");
        }
        assert!("ab".repeat(128).parse::<Duid>().is_ok());
        assert!("ab".repeat(129).parse::<Duid>().is_err());
    }

    #[test]
    fn dns_labels_cannot_inject_names_or_records() {
        for invalid in ["", "-host", "host-", "Host", "a.b", "a\nAAAA", "*"] {
            assert!(validate_dns_label(invalid).is_err());
        }
        assert!(validate_dns_label(&"a".repeat(64)).is_err());
        assert!(validate_dns_label("device-42").is_ok());
    }
}
