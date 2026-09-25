use std::{fmt::Write, net::IpAddr};

use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use serde::Serialize;
use thiserror::Error;

use crate::{Config, ConfigError};

/// A local address snapshot. Discovery is separate from alias presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalInterface {
    pub name: String,
    pub index: u32,
    pub addresses: Vec<LocalAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAddress {
    pub address: IpAddr,
    pub prefix_length: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InterfaceView {
    pub name: String,
    pub index: u32,
    pub addresses: Vec<AddressView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressView {
    pub address: IpAddr,
    pub prefix_length: Option<u8>,
    pub alias: Option<String>,
}

#[derive(Debug, Error)]
pub enum InterfaceError {
    #[error("cannot enumerate local interfaces: {0}")]
    Enumeration(#[from] network_interface::Error),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("interface `{0}` was not found")]
    NotFound(String),
    #[error("invalid prefix length or netmask for address `{0}`")]
    InvalidPrefix(IpAddr),
}

/// Read OS interface metadata; never probe addresses or invoke network commands.
pub fn local_interfaces() -> Result<Vec<LocalInterface>, InterfaceError> {
    NetworkInterface::show()?
        .into_iter()
        .map(|interface| {
            Ok(LocalInterface {
                name: interface.name,
                index: interface.index,
                addresses: interface
                    .addr
                    .into_iter()
                    .map(|address| {
                        Ok(LocalAddress {
                            address: address.ip(),
                            prefix_length: prefix_length(address.ip(), address.netmask())?,
                        })
                    })
                    .collect::<Result<_, InterfaceError>>()?,
            })
        })
        .collect()
}

fn prefix_length(address: IpAddr, netmask: Option<IpAddr>) -> Result<Option<u8>, InterfaceError> {
    let (leading, total) = match (address, netmask) {
        (_, None) => return Ok(None),
        (IpAddr::V4(_), Some(IpAddr::V4(mask))) => {
            let bits = u32::from(mask);
            (bits.leading_ones(), bits.count_ones())
        }
        (IpAddr::V6(_), Some(IpAddr::V6(mask))) => {
            let bits = u128::from(mask);
            (bits.leading_ones(), bits.count_ones())
        }
        _ => return Err(InterfaceError::InvalidPrefix(address)),
    };
    if leading != total {
        return Err(InterfaceError::InvalidPrefix(address));
    }
    Ok(Some(
        leading
            .try_into()
            .map_err(|_| InterfaceError::InvalidPrefix(address))?,
    ))
}

/// Annotate only addresses accepted by the configured managed-address grammar.
/// `None` requests raw display and does not require a configuration file.
pub fn interface_views(
    interfaces: Vec<LocalInterface>,
    config: Option<&Config>,
    selected: Option<&str>,
) -> Result<Vec<InterfaceView>, InterfaceError> {
    if let Some(config) = config {
        config.validate()?;
    }
    if let Some(name) = selected
        && !interfaces.iter().any(|interface| interface.name == name)
    {
        return Err(InterfaceError::NotFound(name.into()));
    }
    let mut views = Vec::new();
    for interface in interfaces {
        if selected.is_some_and(|name| name != interface.name) {
            continue;
        }
        let mut addresses = Vec::new();
        for item in interface.addresses {
            let max_prefix = if item.address.is_ipv4() { 32 } else { 128 };
            if item.prefix_length.is_some_and(|length| length > max_prefix) {
                return Err(InterfaceError::InvalidPrefix(item.address));
            }
            let alias = match (config, item.address) {
                (Some(config), IpAddr::V6(address)) => match config.reverse(address) {
                    Ok(alias) => Some(alias.to_string()),
                    Err(ConfigError::AddressNotManaged(_)) => None,
                    Err(error) => return Err(error.into()),
                },
                _ => None,
            };
            addresses.push(AddressView {
                address: item.address,
                prefix_length: item.prefix_length,
                alias,
            });
        }
        addresses.sort_by_key(|item| (item.address, item.prefix_length));
        views.push(InterfaceView {
            name: interface.name,
            index: interface.index,
            addresses,
        });
    }
    views.sort_by(|a, b| (&a.name, a.index).cmp(&(&b.name, b.index)));
    Ok(views)
}

/// Render an ifconfig-like listing, retaining the real IP beside each alias.
pub fn write_interfaces(output: &mut impl Write, interfaces: &[InterfaceView]) -> std::fmt::Result {
    write_interfaces_colored(output, interfaces, false)
}

/// Coloring changes presentation only; aliases, addresses and ordering stay identical.
pub fn write_interfaces_colored(
    output: &mut impl Write,
    interfaces: &[InterfaceView],
    color: bool,
) -> std::fmt::Result {
    let reset = if color { "\x1b[0m" } else { "" };
    let heading = if color { "\x1b[1;96m" } else { "" };
    if interfaces.is_empty() {
        return writeln!(output, "No interfaces reported by the operating system.");
    }
    for interface in interfaces {
        writeln!(
            output,
            "{heading}{}{reset} (index {})",
            interface.name.escape_debug(),
            interface.index
        )?;
        if interface.addresses.is_empty() {
            writeln!(output, "  No IP addresses reported.")?;
        }
        for item in &interface.addresses {
            let family = if item.address.is_ipv4() {
                "inet "
            } else {
                "inet6"
            };
            write!(output, "  {family} ")?;
            if let Some(alias) = &item.alias {
                let accent = if color {
                    match alias.split_once(':').map(|(profile, _)| profile) {
                        Some("corp") => "\x1b[1;92m",
                        Some("lab") => "\x1b[1;95m",
                        Some("quarantine" | "quar") => "\x1b[1;93m",
                        _ => "\x1b[1;96m",
                    }
                } else {
                    ""
                };
                write!(output, "{accent}{alias}{reset}  (")?;
            }
            write!(output, "{}", item.address)?;
            if let Some(prefix) = item.prefix_length {
                write!(output, "/{prefix}")?;
            }
            if item.alias.is_some() {
                write!(output, ")")?;
            }
            writeln!(output)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config::from_yaml(include_str!("../v6alias.example.yaml")).unwrap()
    }

    fn address(ip: &str, prefix_length: Option<u8>) -> LocalAddress {
        LocalAddress {
            address: ip.parse().unwrap(),
            prefix_length,
        }
    }

    fn interface(name: &str, ips: &[&str]) -> LocalInterface {
        LocalInterface {
            name: name.into(),
            index: 7,
            addresses: ips.iter().map(|ip| address(ip, Some(64))).collect(),
        }
    }

    fn text(views: &[InterfaceView]) -> String {
        let mut text = String::new();
        write_interfaces(&mut text, views).unwrap();
        text
    }

    #[test]
    fn multiple_profiles_and_addresses_on_one_interface_are_all_retained() {
        let source = interface(
            "Ethernet",
            &[
                "fd7a:115c:a1e0:17::2a",
                "fd7a:115c:a1e0:18::2b",
                "fdb4:82d1:930c:7::f",
                "fd12:3456:789a:7::f",
                "fd7a:115c:a1e0:17:1234:5678:abcd:2a",
                "2001:db8:1234:17::2a",
                "fe80::2a",
            ],
        );
        let views = interface_views(vec![source.clone()], Some(&config()), None).unwrap();
        assert_eq!(views[0].addresses.len(), source.addresses.len());
        let aliases: Vec<_> = views[0]
            .addresses
            .iter()
            .filter_map(|item| item.alias.as_deref())
            .collect();
        assert_eq!(aliases, ["corp:42", "corp:24.43", "lab:15"]);
        for original in &source.addresses {
            let view = views[0]
                .addresses
                .iter()
                .find(|view| view.address == original.address)
                .unwrap();
            assert_eq!(view.prefix_length, original.prefix_length);
        }
        let rendered = text(&views);
        assert!(rendered.contains("inet6 corp:42  (fd7a:115c:a1e0:17::2a/64)"));
        assert!(rendered.contains("inet6 corp:24.43  (fd7a:115c:a1e0:18::2b/64)"));
        assert!(rendered.contains("inet6 lab:15  (fdb4:82d1:930c:7::f/64)"));
        assert!(rendered.contains("inet6 fd12:3456:789a:7::f/64\n"));
        assert!(rendered.contains("inet6 fd7a:115c:a1e0:17:1234:5678:abcd:2a/64\n"));
        assert!(rendered.contains("inet6 2001:db8:1234:17::2a/64\n"));
        assert!(rendered.contains("inet6 fe80::2a/64\n"));
    }

    #[test]
    fn raw_mode_retains_mixed_addresses_without_config_or_aliases() {
        let mut input = interface("eth0", &["fd7a:115c:a1e0:17::2a", "fe80::42", "::1"]);
        input.addresses.extend([
            address("10.23.0.42", Some(24)),
            address("127.0.0.1", Some(8)),
        ]);
        let views = interface_views(vec![input], None, None).unwrap();
        assert_eq!(
            text(&views),
            concat!(
                "eth0 (index 7)\n",
                "  inet  10.23.0.42/24\n",
                "  inet  127.0.0.1/8\n",
                "  inet6 ::1/64\n",
                "  inet6 fd7a:115c:a1e0:17::2a/64\n",
                "  inet6 fe80::42/64\n",
            )
        );
        assert!(views[0].addresses.iter().all(|item| item.alias.is_none()));
    }

    #[test]
    fn prefix_match_must_be_exact_and_iid_must_be_representable() {
        let ips = [
            "fd7a:115c:a1e1:17::2a",
            "fd7a:115c:a1e0:17::",
            "fd7a:115c:a1e0:17::1:2a",
            "fc7a:115c:a1e0:17::2a",
            "::ffff:10.23.0.42",
            "fd00::42",
            "ff02::1",
        ];
        let views = interface_views(vec![interface("eth0", &ips)], Some(&config()), None).unwrap();
        assert!(views[0].addresses.iter().all(|item| item.alias.is_none()));
    }

    #[test]
    fn defaults_missing_defaults_and_numeric_boundaries_use_existing_reverse_rules() {
        let mut config = config();
        config.profiles.get_mut("lab").unwrap().default_subnet = None;
        let ips = [
            "fdb4:82d1:930c:7::f",
            "fd7a:115c:a1e0::1",
            "fd7a:115c:a1e0:ffff::ffff",
        ];
        let views = interface_views(vec![interface("eth0", &ips)], Some(&config), None).unwrap();
        let aliases: Vec<_> = views[0]
            .addresses
            .iter()
            .filter_map(|item| item.alias.as_deref())
            .collect();
        assert_eq!(aliases, ["corp:0.1", "corp:65535.65535", "lab:7.15"]);
        for item in &views[0].addresses {
            let alias = item.alias.as_ref().unwrap().parse().unwrap();
            assert_eq!(IpAddr::V6(config.resolve(&alias).unwrap()), item.address);
        }
    }

    #[test]
    fn same_link_local_address_on_different_interfaces_remains_separate() {
        let mut second = interface("Wi-Fi", &["fe80::42"]);
        second.index = 9;
        let views = interface_views(
            vec![second, interface("Ethernet", &["fe80::42"])],
            Some(&config()),
            None,
        )
        .unwrap();
        assert_eq!(views.len(), 2);
        assert_eq!((views[0].index, views[1].index), (7, 9));
        assert_eq!(views[0].addresses[0].address, views[1].addresses[0].address);
        assert_eq!(views[0].addresses[0].alias, None);
    }

    #[test]
    fn invalid_or_duplicate_configuration_is_not_silently_ignored() {
        let mut config = config();
        config.profiles.get_mut("corp").unwrap().prefix = "2001:db8::/48".into();
        assert!(interface_views(vec![], Some(&config), None).is_err());
        config.profiles.get_mut("corp").unwrap().prefix = config.profiles["lab"].prefix.clone();
        assert!(matches!(
            interface_views(vec![], Some(&config), None),
            Err(InterfaceError::Config(
                ConfigError::DuplicateProfilePrefix { .. }
            ))
        ));
    }

    #[test]
    fn selection_and_ordering_are_deterministic_without_dropping_duplicate_ips() {
        let a = interface("a", &["fe80::2", "fe80::1", "fe80::1"]);
        let b = interface("b", &[]);
        let expected = interface_views(vec![a.clone(), b.clone()], None, None).unwrap();
        let mut reversed = a.clone();
        reversed.addresses.reverse();
        assert_eq!(
            interface_views(vec![b.clone(), reversed], None, None).unwrap(),
            expected
        );
        assert_eq!(expected[0].addresses.len(), 3);
        assert_eq!(
            interface_views(vec![a, b.clone()], None, Some("b"))
                .unwrap()
                .len(),
            1
        );
        assert!(
            text(&interface_views(vec![b], None, None).unwrap())
                .contains("No IP addresses reported.")
        );
        assert!(matches!(
            interface_views(vec![], None, Some("missing")),
            Err(InterfaceError::NotFound(_))
        ));
        assert_eq!(
            text(&[]),
            "No interfaces reported by the operating system.\n"
        );
    }

    #[test]
    fn unknown_masks_are_not_guessed_and_invalid_masks_fail() {
        let ipv4 = "10.0.0.2".parse().unwrap();
        let ipv6 = "fd7a:115c:a1e0:17::2a".parse().unwrap();
        assert_eq!(prefix_length(ipv6, None).unwrap(), None);
        assert_eq!(
            prefix_length(ipv4, Some("255.255.255.0".parse().unwrap())).unwrap(),
            Some(24)
        );
        assert_eq!(
            prefix_length(ipv4, Some("0.0.0.0".parse().unwrap())).unwrap(),
            Some(0)
        );
        assert_eq!(
            prefix_length(ipv4, Some("255.255.255.255".parse().unwrap())).unwrap(),
            Some(32)
        );
        assert_eq!(
            prefix_length(ipv6, Some("ffff:ffff:ffff:ffff::".parse().unwrap())).unwrap(),
            Some(64)
        );
        assert_eq!(
            prefix_length(
                ipv6,
                Some("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap())
            )
            .unwrap(),
            Some(128)
        );
        assert!(prefix_length(ipv4, Some("255.0.255.0".parse().unwrap())).is_err());
        assert!(prefix_length(ipv6, Some("255.255.255.0".parse().unwrap())).is_err());
        let mut input = interface("Ethernet", &[]);
        input.addresses.push(LocalAddress {
            address: ipv6,
            prefix_length: None,
        });
        let views = interface_views(vec![input], Some(&config()), None).unwrap();
        assert!(text(&views).contains("corp:42  (fd7a:115c:a1e0:17::2a)\n"));
        let json = serde_json::to_value(&views).unwrap();
        assert!(json[0]["addresses"][0]["prefix_length"].is_null());
        assert_eq!(json[0]["addresses"][0]["address"], "fd7a:115c:a1e0:17::2a");
        assert_eq!(json[0]["addresses"][0]["alias"], "corp:42");
        for (ip, length) in [("10.0.0.2", 33), ("::1", 129)] {
            let input = LocalInterface {
                name: "a".into(),
                index: 1,
                addresses: vec![address(ip, Some(length))],
            };
            assert!(interface_views(vec![input], None, None).is_err());
        }
    }

    #[test]
    fn display_cannot_interpret_control_characters_in_interface_names() {
        let views =
            interface_views(vec![interface("Ethernet\n\u{1b}[31m", &[])], None, None).unwrap();
        let output = text(&views);
        assert!(output.starts_with("Ethernet\\n\\u{1b}[31m (index 7)\n"));
    }

    #[test]
    fn color_highlights_only_headings_and_aliases_without_changing_addresses() {
        let views = interface_views(
            vec![interface(
                "demo",
                &["fd7a:115c:a1e0:17::2a", "fdb4:82d1:930c:7::f", "fe80::1"],
            )],
            Some(&config()),
            None,
        )
        .unwrap();
        let mut colored = String::new();
        write_interfaces_colored(&mut colored, &views, true).unwrap();
        assert!(colored.contains("\x1b[1;96mdemo\x1b[0m"));
        assert!(colored.contains("\x1b[1;92mcorp:42\x1b[0m"));
        assert!(colored.contains("\x1b[1;95mlab:15\x1b[0m"));
        assert!(colored.contains("inet6 fe80::1/64"));
        let plain = ["\x1b[0m", "\x1b[1;96m", "\x1b[1;92m", "\x1b[1;95m"]
            .into_iter()
            .fold(colored, |value, escape| value.replace(escape, ""));
        assert_eq!(plain, text(&views));
    }
}
