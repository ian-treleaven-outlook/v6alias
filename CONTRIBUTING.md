# Contributing

V6Alias is currently an early hackathon prototype. Open an issue before making
large changes so the address model and standards guardrails remain coherent.

## Local checks

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --locked
```

The configured CI matrix runs these gates on Windows and Linux; do not report
CI success without an actual run. For disconnected local checks, Rust, a C
toolchain, and dependencies must already be installed/cached. Set
`$env:CARGO_NET_OFFLINE = "true"` to prevent Cargo downloads.

## Offline service boundary

The workspace separates `crates\core` (pure Rust address logic),
`crates\service` (operational Rust inventory/policy/allocation/reconciliation),
and the root CLI. The service uses `rusqlite` with bundled SQLite, whose C
engine is compiled as a dependency. Rust application logic does not imply
that every dependency is pure Rust.

Keep the core library deterministic and independent of DHCP or DNS providers.
Invalid, ambiguous, or unauthorized inputs must fail explicitly rather than
falling back to a privileged profile.

Use the [README walkthrough](README.md#offline-service-stage) and
`examples\offline` JSON fixtures for manual checks. Always supply `--database`;
keep local databases/snapshots in ignored `state`. The service's
`--service-config service.example.yaml` is not the resolver's `--config`.
Read/list commands must not initialize a database. Successful commands return
JSON; policy denial returns JSON with exit 2, while denied writes and
operational/input errors use stderr and exit 1.

Preserve these phase-one invariants:

- One asset binds one canonical DUID and IAID; identifiers are not
  authentication. Inventory is immutable except for exact canonical replay.
  Multi-IA, updates, and re-enrollment are deferred.
- Trusted links come from the operator, never observation JSON. Unknown or
  mismatched inventory and unmanaged corporate requests fail closed. Managed
  inventory is required by default; explicit lab/quarantine opt-out still
  requires known inventory and policy for that link.
- Hostname hints are single lowercase ASCII labels, never DNS authority or
  standalone privilege. DNS names come from inventory; plans use TTL 300.
- Allocate the lowest unreserved ID in decimal 2–4095; exclude 0/1 and
  bootstrap `0x1000`–`0xffff`. Keep retired tombstones forever, without automatic
  reuse, reactivation, or cross-link reassignment.
- Pin the entire service configuration only after the first successful
  allocation. Later configuration changes require a future explicit migration;
  never suggest ad hoc database edits.
- No observed snapshot means desired-only output with empty deltas. Explicit
  snapshots may contain only exact known active/retired owned resources;
  reject unknown/drifted records rather than trusting an owner string.

There is no live daemon/listener, DHCP lease observer, Kea/pfSense adapter, or
DNS updater yet. Plans are provider-neutral review models, not executable
configuration, and never apply changes. Keep network, guest installation,
deployment, packet captures, live provider/version checks, and live rollback
exercises outside offline validation and behind explicit approval. See the
[testing strategy](docs/testing.md) for implemented coverage and future gates.

Command wrappers must launch executables directly rather than through a shell,
show the resolved address and exact invocation, and preserve the child process
exit code. C++ code is restricted to the WinUI presentation adapter.
