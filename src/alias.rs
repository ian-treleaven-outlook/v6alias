use std::{fmt, str::FromStr};

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alias {
    pub profile: String,
    pub subnet: Option<u16>,
    pub device: u16,
}

impl FromStr for Alias {
    type Err = AliasError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (profile, address) = input
            .split_once(':')
            .ok_or(AliasError::MissingProfileSeparator)?;

        if profile.is_empty()
            || !profile.chars().all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
            })
        {
            return Err(AliasError::InvalidProfile(profile.to_owned()));
        }

        let parts: Vec<_> = address.split('.').collect();
        let (subnet, device) = match parts.as_slice() {
            [device] => (None, parse_decimal("device", device)?),
            [subnet, device] => (
                Some(parse_decimal("subnet", subnet)?),
                parse_decimal("device", device)?,
            ),
            _ => return Err(AliasError::InvalidShape),
        };

        if device == 0 {
            return Err(AliasError::DeviceZero);
        }

        Ok(Self {
            profile: profile.to_owned(),
            subnet,
            device,
        })
    }
}

impl fmt::Display for Alias {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.subnet {
            Some(subnet) => write!(formatter, "{}:{subnet}.{}", self.profile, self.device),
            None => write!(formatter, "{}:{}", self.profile, self.device),
        }
    }
}

fn parse_decimal(field: &'static str, value: &str) -> Result<u16, AliasError> {
    if value.is_empty()
        || !value.chars().all(|character| character.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(AliasError::InvalidDecimal {
            field,
            value: value.to_owned(),
        });
    }

    value.parse().map_err(|_| AliasError::OutOfRange {
        field,
        value: value.to_owned(),
    })
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AliasError {
    #[error("alias must contain a profile separator (`corp:42`)")]
    MissingProfileSeparator,
    #[error("profile `{0}` must contain only lowercase ASCII letters, digits, or hyphens")]
    InvalidProfile(String),
    #[error("alias must have the form `profile:device` or `profile:subnet.device`")]
    InvalidShape,
    #[error("{field} `{value}` must be unpadded decimal")]
    InvalidDecimal { field: &'static str, value: String },
    #[error("{field} `{value}` must be between 0 and 65535")]
    OutOfRange { field: &'static str, value: String },
    #[error("device number 0 is reserved")]
    DeviceZero,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_short_and_explicit_aliases() {
        assert_eq!(
            "corp:42".parse(),
            Ok(Alias {
                profile: "corp".into(),
                subnet: None,
                device: 42,
            })
        );
        assert_eq!(
            "lab:7.15".parse(),
            Ok(Alias {
                profile: "lab".into(),
                subnet: Some(7),
                device: 15,
            })
        );
    }

    #[test]
    fn rejects_ambiguous_decimal_and_invalid_ranges() {
        assert!(matches!(
            "corp:07.15".parse::<Alias>(),
            Err(AliasError::InvalidDecimal { .. })
        ));
        assert!(matches!(
            "corp:70000.15".parse::<Alias>(),
            Err(AliasError::OutOfRange { .. })
        ));
        assert_eq!("corp:0".parse::<Alias>(), Err(AliasError::DeviceZero));
    }
}
