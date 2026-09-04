# V6Alias

V6Alias is a standards-compliant usability and address-management layer for
managed IPv6 Unique Local Addresses (ULAs). It turns addresses such as
`fd7a:115c:a1e0:17::2a` into memorable decimal aliases such as `corp:23.42`.

```text
corp:42       -> default corporate subnet, device 42
corp:23.42    -> corporate subnet 23, device 42
lab:7.15      -> lab subnet 7, device 15
```

V6Alias is an early Microsoft Hackathon project. It is a policy and tooling
layer, not a new IPv6 literal syntax, DHCPv6 extension, or security boundary.

## Why

IPv6 addresses remain difficult to read, transcribe, and communicate during
diagnostics and recovery. V6Alias hides an organization's stable RFC 4193
ULA `/48` behind a named profile while preserving normal IPv6 `/64` subnets.
Users enter decimal values; the tool handles hexadecimal representation.

## Current prototype

The initial Rust CLI validates profile configuration and supports deterministic
expansion and reverse formatting:

```powershell
Copy-Item v6alias.example.yaml v6alias.yaml
cargo run -- resolve corp:42
# fd7a:115c:a1e0:17::2a

cargo run -- reverse fd7a:115c:a1e0:17::2a
# corp:42
```

It can also resolve an alias and invoke familiar networking tools without
replacing or shadowing their executables:

```powershell
cargo run -- ping corp:42 --dry-run -- -n 5
# Resolved: corp:42 -> fd7a:115c:a1e0:17::2a
# Command:  ping -6 -n 5 fd7a:115c:a1e0:17::2a

cargo run -- trace corp:42 --dry-run
cargo run -- ssh corp:42 --dry-run -- -l administrator
```

Arguments after `--` are passed directly to the underlying command before the
resolved address. V6Alias launches the executable without a shell, displays the
exact invocation, and returns its exit code. `--dry-run` performs resolution
and prints the command without executing it.

Configuration:

```yaml
profiles:
  corp:
    prefix: "fd7a:115c:a1e0::/48"
    default_subnet: 23
  lab:
    prefix: "fdb4:82d1:930c::/48"
    default_subnet: 7
```

The example prefixes are illustrative. Generate and permanently register a
random RFC 4193 `/48` before deployment. Do not use `fd00::/48` as a shared
organizational prefix.

## Planned architecture

- Stable sequential allocation of small managed device numbers
- Named `corp`, `lab`, `quarantine`, and custom profiles
- Policy selection from trusted VLAN/link placement and asset inventory
- DHCPv6 reservation integration without changing the DHCPv6 protocol
- Private AAAA and `ip6.arpa` PTR synchronization
- An isolated Hyper-V demonstration using pfSense
- An external service deployment model that does not modify pfSense internals
- A packaged C++/WinRT WinUI 3 configuration app over a narrow Rust FFI

Unknown or conflicting devices must enter quarantine or be rejected. An
address assignment never grants authorization; VLAN, NAC, firewall, and
application controls remain authoritative.

All operational components—including the library, allocator, policy engine,
artifact generators, daemon, and command-line tools—remain pure Rust. C++ is
limited to the replaceable WinUI 3/XAML presentation layer so future web and
non-Windows interfaces can reuse the same Rust APIs.

## Development

```powershell
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

The first milestone is intentionally small: establish and test the address
grammar before adding persistence, allocation, policy, DHCPv6, and DNS.

## Standards

- [RFC 4193: Unique Local IPv6 Unicast Addresses](https://www.rfc-editor.org/rfc/rfc4193.html)
- [RFC 9915: DHCPv6](https://www.rfc-editor.org/rfc/rfc9915.html)
- [RFC 4861: Neighbor Discovery for IPv6](https://www.rfc-editor.org/rfc/rfc4861.html)
- [RFC 4862: IPv6 Stateless Address Autoconfiguration](https://www.rfc-editor.org/rfc/rfc4862.html)

## License

No license has been selected yet. All rights are reserved until the project
owner adds a license.
