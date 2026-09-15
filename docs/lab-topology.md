# Isolated KVM lab topology

The canonical V6Alias protocol lab runs on an Ubuntu 24.04 KVM/libvirt host.
Every VM and network owned by this project is named `scout-*`. None of the
virtual networks has libvirt forwarding, a host IP, or a physical interface.

## Networks

| Profile | libvirt network | Bridge | IPv4 bootstrap | ULA router address |
|---|---|---|---|---|
| Simulated WAN | `scout-wan` | `virbr-scoutwan` | None | None |
| Corporate | `scout-lan` | `virbr-scoutlan` | `10.50.0.0/24` | `<corp-prefix>:17::1/64` |
| Lab | `scout-lab` | `virbr-scoutlab` | `10.51.0.0/25` | `<lab-prefix>:7::1/64` |
| Quarantine | `scout-quar` | `virbr-scoutq` | `10.51.0.128/25` | `<quarantine-prefix>:1::1/64` |

The hexadecimal IPv6 subnet IDs correspond to decimal V6Alias defaults:
corporate `23` becomes `0x17`; lab `7` and quarantine `1` are unchanged.
Generate and persist the three RFC 4193 `/48` values in an ignored
`lab/v6alias.lab.local.yaml` file. Never regenerate an active profile prefix.

## Virtual machines

| VM | Purpose | Interfaces |
|---|---|---|
| `scout-pfsense` | Routing, firewall, RA, and DHCP services | All four networks |
| `scout-admin` | Sealed management and diagnostics | Corporate |
| `scout-corp-client` | Corporate policy test client | Corporate |
| `scout-lab-client` | Lab policy test client | Lab |
| `scout-quar-client` | Unknown-device and quarantine test client | Quarantine |
| `scout-v6alias` | Rust daemon, inventory, policy, and DNS | Corporate initially |

## Containment requirements

- No network XML contains a `<forward>` element or `<ip>` element.
- No domain uses a physical bridge, macvtap, host device, or non-`scout-*`
  network.
- `ip route get 192.168.1.1` on the host must use `enp0s31f6`.
- Captures on the physical NIC must contain no scout DHCP, DHCPv6, RA, or ULA
  packets.
- The simulated WAN remains unanswered until a separate, approved
  `scout-isp` VM is created.
- Snapshot every VM before each configuration experiment.

## Current validated baseline

- pfSense 2.8.1 boots from a pristine post-install clone.
- Corporate IPv4 is `10.50.0.1/24`, pool `10.50.0.100-199`.
- Lab IPv4 is `10.51.0.1/25`, pool `10.51.0.32-99`.
- Quarantine IPv4 is `10.51.0.129/25`, pool `10.51.0.160-223`.
- `scout-admin` receives `10.50.0.100`, reaches pfSense over ICMP and HTTPS,
  and has a captured DHCP Discover/Offer/Request/ACK exchange.
- IPv6 addresses and Router Advertisements are intentionally not configured
  until the profile prefixes above are persisted and reviewed.
