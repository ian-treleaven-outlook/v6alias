use std::{collections::BTreeMap, net::Ipv6Addr, path::Path, str::FromStr};

use serde::Deserialize;
use thiserror::Error;

use crate::Alias;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub profiles: BTreeMap<String, Profile>,
}

impl Config {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(ConfigError::Read)?;
        Self::from_yaml(&contents)
    }

    pub fn from_yaml(contents: &str) -> Result<Self, ConfigError> {
        let config: Self = serde_yaml::from_str(contents).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.profiles.is_empty() {
            return Err(ConfigError::NoProfiles);
        }

        let mut prefixes = BTreeMap::new();
        for (name, profile) in &self.profiles {
            validate_profile_name(name)?;
            let prefix = profile.prefix_segments()?;
            if let Some(first) = prefixes.insert(prefix, name) {
                return Err(ConfigError::DuplicateProfilePrefix {
                    prefix: profile.prefix.clone(),
                    first: first.clone(),
                    second: name.clone(),
                });
            }
        }

        Ok(())
    }

    pub fn resolve(&self, alias: &Alias) -> Result<Ipv6Addr, ConfigError> {
        let profile = self
            .profiles
            .get(&alias.profile)
            .ok_or_else(|| ConfigError::UnknownProfile(alias.profile.clone()))?;
        let subnet = alias
            .subnet
            .or(profile.default_subnet)
            .ok_or_else(|| ConfigError::MissingDefaultSubnet(alias.profile.clone()))?;
        let prefix = profile.prefix_segments()?;

        Ok(Ipv6Addr::new(
            prefix[0],
            prefix[1],
            prefix[2],
            subnet,
            0,
            0,
            0,
            alias.device,
        ))
    }

    pub fn reverse(&self, address: Ipv6Addr) -> Result<Alias, ConfigError> {
        let segments = address.segments();
        if segments[4..7] != [0, 0, 0] || segments[7] == 0 {
            return Err(ConfigError::AddressNotManaged(address));
        }

        let mut matches = self.profiles.iter().filter(|(_, profile)| {
            profile
                .prefix_segments()
                .is_ok_and(|prefix| segments[..3] == prefix)
        });
        let Some((name, profile)) = matches.next() else {
            return Err(ConfigError::AddressNotManaged(address));
        };
        if matches.next().is_some() {
            return Err(ConfigError::DuplicatePrefix(address));
        }

        let subnet = segments[3];
        Ok(Alias {
            profile: name.clone(),
            subnet: (profile.default_subnet != Some(subnet)).then_some(subnet),
            device: segments[7],
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub prefix: String,
    pub default_subnet: Option<u16>,
}

impl Profile {
    fn prefix_segments(&self) -> Result<[u16; 3], ConfigError> {
        let (address, length) = self
            .prefix
            .split_once('/')
            .ok_or_else(|| ConfigError::InvalidPrefix(self.prefix.clone()))?;
        if length != "48" {
            return Err(ConfigError::InvalidPrefix(self.prefix.clone()));
        }

        let address = Ipv6Addr::from_str(address)
            .map_err(|_| ConfigError::InvalidPrefix(self.prefix.clone()))?;
        let segments = address.segments();
        if segments[0] & 0xff00 != 0xfd00
            || segments[..3] == [0xfd00, 0, 0]
            || segments[3..] != [0, 0, 0, 0, 0]
        {
            return Err(ConfigError::InvalidPrefix(self.prefix.clone()));
        }

        Ok([segments[0], segments[1], segments[2]])
    }
}

fn validate_profile_name(name: &str) -> Result<(), ConfigError> {
    if name.is_empty()
        || !name.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
    {
        return Err(ConfigError::InvalidProfileName(name.to_owned()));
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read configuration: {0}")]
    Read(std::io::Error),
    #[error("failed to parse configuration: {0}")]
    Parse(serde_yaml::Error),
    #[error("configuration must define at least one profile")]
    NoProfiles,
    #[error("invalid profile name `{0}`")]
    InvalidProfileName(String),
    #[error("`{0}` must be a canonical locally assigned ULA /48 prefix")]
    InvalidPrefix(String),
    #[error("profiles `{first}` and `{second}` use duplicate ULA prefix `{prefix}`")]
    DuplicateProfilePrefix {
        prefix: String,
        first: String,
        second: String,
    },
    #[error("unknown profile `{0}`")]
    UnknownProfile(String),
    #[error("profile `{0}` has no default subnet; use an explicit alias")]
    MissingDefaultSubnet(String),
    #[error("address `{0}` is not owned by a configured V6Alias profile")]
    AddressNotManaged(Ipv6Addr),
    #[error("address `{0}` matches more than one configured profile")]
    DuplicatePrefix(Ipv6Addr),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            profiles: BTreeMap::from([
                (
                    "corp".into(),
                    Profile {
                        prefix: "fd7a:115c:a1e0::/48".into(),
                        default_subnet: Some(23),
                    },
                ),
                (
                    "lab".into(),
                    Profile {
                        prefix: "fdb4:82d1:930c::/48".into(),
                        default_subnet: None,
                    },
                ),
            ]),
        }
    }

    #[test]
    fn resolves_decimal_aliases_to_ipv6() {
        let config = config();
        let address = config.resolve(&"corp:23.42".parse().unwrap()).unwrap();
        assert_eq!(
            address,
            "fd7a:115c:a1e0:17::2a".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            config.resolve(&"corp:42".parse().unwrap()).unwrap(),
            address
        );
    }

    #[test]
    fn explicit_subnet_overrides_the_profile_default() {
        let address = config()
            .resolve(&"corp:65535.65535".parse().unwrap())
            .unwrap();

        assert_eq!(
            address,
            "fd7a:115c:a1e0:ffff::ffff".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn reverses_to_shortest_alias() {
        let config = config();
        let address = "fd7a:115c:a1e0:17::2a".parse().unwrap();
        assert_eq!(config.reverse(address).unwrap().to_string(), "corp:42");
    }

    #[test]
    fn explicit_nondefault_subnet_survives_round_trip() {
        let config = config();
        let alias: Alias = "corp:7.42".parse().unwrap();
        let address = config.resolve(&alias).unwrap();

        assert_eq!(config.reverse(address).unwrap(), alias);
    }

    #[test]
    fn requires_default_for_short_alias() {
        assert!(matches!(
            config().resolve(&"lab:15".parse().unwrap()),
            Err(ConfigError::MissingDefaultSubnet(_))
        ));
    }

    #[test]
    fn rejects_noncanonical_or_reserved_prefixes() {
        for prefix in [
            "fd00::/48",
            "fd7a:115c:a1e0:1::/48",
            "2001:db8::/48",
            "fd7a:115c:a1e0::/64",
        ] {
            let profile = Profile {
                prefix: prefix.into(),
                default_subnet: None,
            };
            assert!(profile.prefix_segments().is_err(), "{prefix}");
        }
    }

    #[test]
    fn rejects_duplicate_profile_prefixes() {
        let config = Config {
            profiles: BTreeMap::from([
                (
                    "corp".into(),
                    Profile {
                        prefix: "fd7a:115c:a1e0::/48".into(),
                        default_subnet: Some(1),
                    },
                ),
                (
                    "lab".into(),
                    Profile {
                        prefix: "fd7a:115c:a1e0::/48".into(),
                        default_subnet: Some(2),
                    },
                ),
            ]),
        };

        assert!(matches!(
            config.validate(),
            Err(ConfigError::DuplicateProfilePrefix { .. })
        ));
    }

    #[test]
    fn parses_yaml_independently_of_the_filesystem() {
        let config = Config::from_yaml(
            r#"
profiles:
  corp:
    prefix: "fd7a:115c:a1e0::/48"
    default_subnet: 23
"#,
        )
        .unwrap();

        assert_eq!(
            config.resolve(&"corp:42".parse().unwrap()).unwrap(),
            "fd7a:115c:a1e0:17::2a".parse::<Ipv6Addr>().unwrap()
        );
    }
}
