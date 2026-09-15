use std::{fmt, net::Ipv6Addr, str::FromStr};

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UlaPrefix {
    global_id: [u8; 5],
}

impl UlaPrefix {
    pub fn generate() -> Result<Self, getrandom::Error> {
        loop {
            let mut global_id = [0_u8; 5];
            getrandom::fill(&mut global_id)?;
            if global_id != [0; 5] {
                return Ok(Self { global_id });
            }
        }
    }

    pub fn from_global_id(global_id: [u8; 5]) -> Result<Self, UlaPrefixError> {
        if global_id == [0; 5] {
            return Err(UlaPrefixError::ReservedZeroGlobalId);
        }
        Ok(Self { global_id })
    }

    pub fn segments(self) -> [u16; 3] {
        [
            u16::from_be_bytes([0xfd, self.global_id[0]]),
            u16::from_be_bytes([self.global_id[1], self.global_id[2]]),
            u16::from_be_bytes([self.global_id[3], self.global_id[4]]),
        ]
    }

    pub fn network_address(self) -> Ipv6Addr {
        let segments = self.segments();
        Ipv6Addr::new(segments[0], segments[1], segments[2], 0, 0, 0, 0, 0)
    }
}

impl FromStr for UlaPrefix {
    type Err = UlaPrefixError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, length) = value
            .split_once('/')
            .ok_or_else(|| UlaPrefixError::Invalid(value.to_owned()))?;
        if length != "48" {
            return Err(UlaPrefixError::Invalid(value.to_owned()));
        }

        let address = address
            .parse::<Ipv6Addr>()
            .map_err(|_| UlaPrefixError::Invalid(value.to_owned()))?;
        let segments = address.segments();
        if segments[0] & 0xff00 != 0xfd00 || segments[3..] != [0, 0, 0, 0, 0] {
            return Err(UlaPrefixError::Invalid(value.to_owned()));
        }

        Self::from_global_id([
            (segments[0] & 0x00ff) as u8,
            (segments[1] >> 8) as u8,
            segments[1] as u8,
            (segments[2] >> 8) as u8,
            segments[2] as u8,
        ])
    }
}

impl fmt::Display for UlaPrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/48", self.network_address())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UlaPrefixError {
    #[error("`{0}` must be a canonical locally assigned ULA /48 prefix")]
    Invalid(String),
    #[error("the all-zero ULA Global ID is reserved by V6Alias")]
    ReservedZeroGlobalId,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_all_global_id_bits_into_the_prefix() {
        let prefix = UlaPrefix::from_global_id([0x7a, 0x11, 0x5c, 0xa1, 0xe0]).unwrap();

        assert_eq!(prefix.to_string(), "fd7a:115c:a1e0::/48");
        assert_eq!(prefix.segments(), [0xfd7a, 0x115c, 0xa1e0]);
    }

    #[test]
    fn parses_and_formats_canonical_prefixes() {
        let prefix: UlaPrefix = "fdb4:82d1:930c::/48".parse().unwrap();

        assert_eq!(prefix.to_string(), "fdb4:82d1:930c::/48");
    }

    #[test]
    fn rejects_non_ula_non_network_and_zero_prefixes() {
        for value in [
            "2001:db8::/48",
            "fd7a:115c:a1e0:1::/48",
            "fd7a:115c:a1e0::/64",
            "fd00::/48",
        ] {
            assert!(value.parse::<UlaPrefix>().is_err(), "{value}");
        }
    }
}
