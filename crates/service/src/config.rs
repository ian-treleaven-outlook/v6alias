use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use serde::{Deserialize, Serialize};
use v6alias_core::{Config, Profile, UlaPrefix};

use crate::{ServiceError, validate_dns_label};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub profiles: BTreeMap<String, ServiceProfile>,
    pub links: BTreeMap<String, Link>,
    pub dns_zone: String,
    pub rules: Vec<Rule>,
    // Keep the legacy serialized identity byte-for-byte when TTL is omitted or 300.
    #[serde(
        default = "default_dns_ttl",
        skip_serializing_if = "is_default_dns_ttl"
    )]
    pub dns_ttl_seconds: u32,
}

fn default_dns_ttl() -> u32 {
    300
}

fn is_default_dns_ttl(value: &u32) -> bool {
    *value == default_dns_ttl()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceProfile {
    pub prefix: String,
    pub default_subnet: u16,
    #[serde(default = "require_managed")]
    pub require_managed: bool,
}

fn require_managed() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Link {
    pub profile: String,
    pub subnet: u16,
    pub pool: Pool,
    #[serde(default)]
    pub reserved: BTreeSet<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pool {
    pub first: u16,
    pub last: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    pub priority: i32,
    pub links: BTreeSet<String>,
    pub managed: Option<bool>,
    pub hostname_prefix: Option<String>,
    pub profile: String,
}

impl ServiceConfig {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ServiceError> {
        Self::from_yaml(&std::fs::read_to_string(path)?)
    }

    pub fn from_yaml(yaml: &str) -> Result<Self, ServiceError> {
        let config: Self = serde_yaml::from_str(yaml)?;
        config.validate()?;
        Ok(config)
    }

    pub fn address_config(&self) -> Config {
        Config {
            profiles: self
                .profiles
                .iter()
                .map(|(name, profile)| {
                    (
                        name.clone(),
                        Profile {
                            prefix: profile.prefix.clone(),
                            default_subnet: Some(profile.default_subnet),
                        },
                    )
                })
                .collect(),
        }
    }

    pub fn validate(&self) -> Result<(), ServiceError> {
        self.address_config().validate()?;
        if !(1..=86400).contains(&self.dns_ttl_seconds) {
            return Err(ServiceError::Config(
                "DNS TTL must be 1..86400 seconds".into(),
            ));
        }
        for profile in self.profiles.values() {
            let prefix = profile
                .prefix
                .parse::<UlaPrefix>()
                .map_err(|err| ServiceError::Config(err.to_string()))?;
            if prefix.to_string() != profile.prefix {
                return Err(ServiceError::Config(
                    "service prefixes must use canonical IPv6 spelling".into(),
                ));
            }
        }
        if self.dns_zone.len() > 190 || !self.dns_zone.contains('.') {
            return Err(ServiceError::Config(
                "private DNS zone must have at least two labels and be at most 190 characters"
                    .into(),
            ));
        }
        for label in self.dns_zone.split('.') {
            validate_dns_label(label)?;
        }
        if self.links.is_empty() || self.rules.is_empty() {
            return Err(ServiceError::Config(
                "at least one trusted link and policy rule is required".into(),
            ));
        }
        let mut subnets = BTreeSet::new();
        for (name, link) in &self.links {
            validate_dns_label(name)?;
            if !self.profiles.contains_key(&link.profile) {
                return Err(ServiceError::Config(format!(
                    "link `{name}` uses an unknown profile"
                )));
            }
            if !subnets.insert((&link.profile, link.subnet)) {
                return Err(ServiceError::Config(
                    "each profile/subnet must belong to only one trusted link".into(),
                ));
            }
            if link.pool.first < 2 || link.pool.first > link.pool.last || link.pool.last >= 0x1000 {
                return Err(ServiceError::Config(format!(
                    "link `{name}` pool must be within decimal 2..4095; zero, router 1, and bootstrap 4096..65535 are excluded"
                )));
            }
        }
        let mut names = BTreeSet::new();
        for rule in &self.rules {
            validate_dns_label(&rule.name)?;
            if !names.insert(&rule.name) || rule.links.is_empty() {
                return Err(ServiceError::Config(
                    "rule names must be unique and every rule must constrain trusted links".into(),
                ));
            }
            if !self.profiles.contains_key(&rule.profile) {
                return Err(ServiceError::Config(format!(
                    "rule `{}` uses an unknown profile",
                    rule.name
                )));
            }
            for name in &rule.links {
                let link = self.links.get(name).ok_or_else(|| {
                    ServiceError::Config(format!("rule `{}` uses unknown link `{name}`", rule.name))
                })?;
                if link.profile != rule.profile {
                    return Err(ServiceError::Config(format!(
                        "rule `{}` would assign outside trusted link `{name}`",
                        rule.name
                    )));
                }
            }
            if let Some(prefix) = &rule.hostname_prefix
                && (prefix.is_empty()
                    || prefix.len() > 63
                    || !prefix
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
            {
                return Err(ServiceError::Config(
                    "hostname hints must be bounded lowercase ASCII prefixes".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn identity(&self) -> Result<String, ServiceError> {
        self.validate()?;
        Ok(serde_json::to_string(self)?)
    }

    /// Existing placements and every possible old-link policy decision must be unchanged.
    pub fn validate_expansion(&self, new: &Self) -> Result<(), ServiceError> {
        self.validate()?;
        new.validate()?;
        if self.dns_zone != new.dns_zone || self.dns_ttl_seconds != new.dns_ttl_seconds {
            return Err(ServiceError::Config(
                "expansion cannot change DNS zone or TTL".into(),
            ));
        }
        if self
            .profiles
            .iter()
            .any(|(key, value)| new.profiles.get(key) != Some(value))
            || self
                .links
                .iter()
                .any(|(key, value)| new.links.get(key) != Some(value))
        {
            return Err(ServiceError::Config(
                "expansion must retain every old profile and link exactly".into(),
            ));
        }
        if !new.rules.starts_with(&self.rules)
            || new.rules[self.rules.len()..]
                .iter()
                .any(|rule| rule.links.iter().any(|link| self.links.contains_key(link)))
        {
            return Err(ServiceError::Config(
                "expansion must retain the ordered rule prefix and append rules only for new links"
                    .into(),
            ));
        }
        // validate() rejects aliased /48s and duplicate profile/subnet pairs. Thus
        // new links, including new subnets of an old profile, have disjoint /64s.
        if self.profiles.len() == new.profiles.len() && self.links.len() == new.links.len() {
            return Err(ServiceError::Config(
                "expansion must add at least one profile or trusted link".into(),
            ));
        }
        Ok(())
    }

    pub fn fqdn(&self, label: &str) -> Result<String, ServiceError> {
        validate_dns_label(label)?;
        let fqdn = format!("{label}.{}.", self.dns_zone);
        if fqdn.len() > 254 {
            return Err(ServiceError::Validation(
                "absolute FQDN exceeds the DNS name length limit".into(),
            ));
        }
        Ok(fqdn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const EXAMPLE: &str = include_str!("../../../service.example.yaml");

    #[test]
    fn dns_ttl_default_identity_and_bounds() {
        let legacy = ServiceConfig::from_yaml(EXAMPLE).unwrap();
        assert_eq!(legacy.dns_ttl_seconds, 300);
        assert!(!legacy.identity().unwrap().contains("dns_ttl_seconds"));
        let explicit =
            ServiceConfig::from_yaml(&format!("{EXAMPLE}\ndns_ttl_seconds: 300\n")).unwrap();
        assert_eq!(legacy.identity().unwrap(), explicit.identity().unwrap());
        for ttl in [1, 3600, 86400] {
            let config =
                ServiceConfig::from_yaml(&format!("{EXAMPLE}\ndns_ttl_seconds: {ttl}\n")).unwrap();
            assert_ne!(config.identity().unwrap(), legacy.identity().unwrap());
            assert_eq!(config.dns_ttl_seconds, ttl);
        }
        for ttl in ["0", "86401", "4294967296", "-1", "null", "1.5"] {
            assert!(
                ServiceConfig::from_yaml(&format!("{EXAMPLE}\ndns_ttl_seconds: {ttl}\n")).is_err()
            );
        }
    }

    #[test]
    fn service_configuration_validates_trusted_placement_and_pools() {
        let config = ServiceConfig::from_yaml(EXAMPLE).unwrap();
        for (first, last) in [(0, 2), (1, 2), (2, 4096), (10, 9)] {
            let mut bad = config.clone();
            bad.links.get_mut("corp-link").unwrap().pool = Pool { first, last };
            assert!(bad.validate().is_err());
        }
        let mut bad = config.clone();
        bad.rules[0].profile = "lab".into();
        assert!(bad.validate().is_err());
        let mut bad = config.clone();
        bad.links
            .insert("duplicate".into(), bad.links["corp-link"].clone());
        assert!(bad.validate().is_err());
        let mut bad = config;
        bad.profiles.get_mut("lab").unwrap().prefix = bad.profiles["corp"].prefix.clone();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn typoed_fields_are_errors() {
        assert!(
            ServiceConfig::from_yaml(&EXAMPLE.replace("require_managed:", "managed_required:"))
                .is_err()
        );
        let config = ServiceConfig::from_yaml(EXAMPLE).unwrap();
        assert_eq!(
            ServiceConfig::from_yaml(&serde_yaml::to_string(&config).unwrap())
                .unwrap()
                .identity()
                .unwrap(),
            config.identity().unwrap()
        );
    }
}
