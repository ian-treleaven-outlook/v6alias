# Testing strategy

Core logic is the highest-confidence boundary in V6Alias. Address generation,
allocation, policy, and artifact rendering must be testable without WinUI,
pfSense, DHCP, DNS, a network interface, or elevated privileges.

## Principles

- Every domain invariant and error variant has a direct unit test.
- Pure logic accepts data as values or text; filesystem and network I/O stay in
  adapters.
- Tests use injected clocks and random-number sources where behavior would
  otherwise be nondeterministic.
- Invalid and ambiguous inputs fail closed; tests must not assert
  success-shaped fallbacks.
- Every fixed bug receives a regression test.
- Generated deployment artifacts are deterministic and reviewable.
- Unit tests never invoke `ping`, `tracert`, `traceroute`, `ssh`, DHCP, DNS, or
  pfSense.

## Core unit-test matrix

| Component | Required coverage |
|---|---|
| Alias grammar | Short and explicit forms, decimal boundaries, leading zeros, invalid profiles, malformed separators, reserved device zero |
| ULA profiles | Valid locally assigned `/48`, canonical network boundary, reserved `fd00::/48`, duplicate prefixes, unknown fields, missing defaults |
| Resolution | Default and explicit subnets, numeric decimal-to-hex conversion, minimum and maximum values |
| Reverse formatting | Shortest canonical alias, nondefault subnet preservation, unknown prefix, unmanaged IID shape, duplicate ownership |
| ULA generation | Correct `fd` layout, 40 generated bits, deterministic seeded tests, collision retry, persisted-prefix reuse |
| Subnet allocator | Lowest-free allocation, exhaustion, reserved ranges, concurrency, idempotency, retirement and tombstones |
| Device allocator | Stable reassignment to the same asset, uniqueness, range boundaries, quarantine before reuse |
| Policy engine | Rule precedence, trusted-input requirements, explain output, conflicts, unknown devices, fail-closed quarantine |
| Artifact model | Escaping, ordering, exact addresses, duplicate prevention, unsupported capability errors |
| Command invocation | Platform executable selection, IPv6 flags, argument boundaries, display quoting, dry run, exit-code propagation |

Round-trip invariants must be exercised across representative boundaries:

```text
reverse(resolve(alias)) == canonical(alias)
resolve(reverse(address)) == address
```

Property-based tests should cover the complete `u16` subnet and managed-device
domains once the core crate is split from the CLI.

## Persistence tests

SQLite tests use an isolated temporary database and real transactions:

- schema creation and forward migrations;
- uniqueness under concurrent allocation attempts;
- rollback after interrupted writes;
- restart and reconciliation;
- asset, DUID, and IAID conflicts;
- tombstone retention and prohibited reuse;
- import/export round trips.

No test shares a database or relies on execution order.

## Artifact tests

Generators produce structured models before serialization. Tests then compare
canonical output with reviewed golden files for:

- V6Alias YAML;
- pfSense change manifests;
- Kea DHCPv6 reservations;
- private AAAA and `ip6.arpa` PTR records;
- Unbound forwarding configuration;
- Hyper-V and deployment manifests.

Golden-file changes must be intentional and reviewed as deployment changes.
Secrets, machine-specific paths, timestamps, and unstable identifiers are
excluded.

## FFI tests

The Rust FFI crate requires tests from both sides of the ABI:

- Rust tests for every exported operation and status code;
- a small C++ harness that creates and frees every opaque handle and buffer;
- malformed UTF-8, null-pointer, length, and use-after-free defenses;
- panic containment so unwinding never crosses the ABI;
- API-version compatibility checks;
- x64 and ARM64 builds.

The WinUI application tests the FFI service wrapper rather than duplicating
domain assertions in C++.

## CLI and integration tests

CLI tests run the compiled binary with temporary configuration and assert
stdout, stderr, and exit codes. Networking wrappers use a fake executable
placed on a test-only `PATH` to capture arguments without sending traffic.

Adapter contract tests use local fakes for DHCPv6, DNS, and pfSense. Tests
against real services run separately in containers or the Hyper-V lab and are
never required for the core unit-test job.

## WinUI tests

The native application requires:

- view-model and FFI-wrapper unit tests;
- launch and navigation smoke tests;
- profile creation and validation workflows;
- artifact preview and save workflows;
- keyboard-only operation;
- Narrator names and logical focus order;
- Light, Dark, and High Contrast themes;
- 100%, 150%, and 200% display scaling.

Domain correctness remains in Rust tests.

## Hyper-V acceptance tests

The isolated lab verifies behavior that unit tests cannot:

- Router Advertisement and DHCPv6 exchange;
- profile selection from trusted virtual-network placement;
- `corp`, `lab`, and `quarantine` firewall policy;
- AAAA/PTR publication and containment;
- client, service, and pfSense restart recovery;
- DUID reset and duplicate-client handling;
- no ULA traffic or private DNS leakage to the dead WAN.

## Continuous-integration gates

Every pull request must pass:

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
```

As crates are added, CI expands with:

1. Rust tests on Windows and Linux.
2. C ABI harness builds on Windows x64 and ARM64.
3. C++/WinRT build and package validation.
4. Deterministic artifact golden tests.
5. Dependency and security auditing.

Coverage reports are initially informational. Merge gates focus on explicit
invariant, error-path, and regression coverage rather than a misleading global
line percentage.
