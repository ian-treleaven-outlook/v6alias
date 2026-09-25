# Testing strategy

Core logic is the highest-confidence boundary in V6Alias. Address generation,
allocation, policy, and artifact rendering must be testable without WinUI,
pfSense, DHCP, DNS, a network interface, or elevated privileges.

## Current offline coverage

The workspace has a pure Rust address crate (`crates\core`), an operational
Rust service crate (`crates\service`), and the root CLI. Service persistence
tests exercise real bundled SQLite through `rusqlite`; the SQLite engine is
compiled C, not Rust application logic.

Existing local tests cover these layers without live network services:

| Layer | Covered behavior |
|---|---|
| Address core | Alias and ULA validation, resolution, reverse formatting, numeric boundaries, ULA generation |
| Service input/configuration | Canonical bounded DUIDs, strict fields, ASCII DNS labels, trusted-link/profile consistency, pool bounds and reservations |
| Policy | Known inventory and matching DUID/IAID, managed-by-default profiles, explicit lab/quarantine opt-out, link confinement, deterministic precedence/traces, tie denial, malformed hostname rejection, no hostname-only authority |
| SQLite store | Schema recognition and rejection of foreign/changed databases, exact inventory replay and conflicts, lowest unreserved allocation, exhaustion, restart persistence, transactional rollback, concurrent allocation/initialization, successful-first-allocation config pinning, permanent placement and tombstones |
| Reconciliation | Desired-only output with empty deltas, explicit empty/partial/matching snapshots, exact active/retired ownership checks, safe proposed removals, duplicate/drift rejection, deterministic ordering, private AAAA/PTR names and configured bounded TTL (default 300) |
| Native pfSense compiler | Source/version/ISC/TTL 3600 capability pins, global native conflicts, complete capture and independent address approvals, exact owned replay/removal, raw unmanaged preservation, full-projection/revision CAS, actual offline transformations and exact guarded rollback |
| CLI | JSON workflow across process restarts, policy denial and failed writes, strict/oversized inputs, guest-field rejection, changed configuration, read-only commands that do not create databases/sidecars, original resolver and wrapper dry runs |
| Shadow daemon | Real foreground binary once/loop execution, strict normalized-file schema/provenance/freshness/counts, whole-cycle rollback, explicit denials, stable restart/concurrent replay, reserved/tombstone allocation, owned-snapshot semantics, capped retry errors, recovery and Linux interrupt/shutdown |
| Interface display | Synthetic mixed IPv4/IPv6 and multiple configured/unconfigured ULAs per interface, exact prefix and managed-IID matching, decimal/default-subnet rules, raw/JSON output, retained interface context and masks, deterministic ordering, invalid configuration and exact-filter errors |

Run the local gates from the repository root:

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
```

Rust, the native C compiler needed for bundled SQLite, and dependencies must
already be available for a disconnected run. Set
`$env:CARGO_NET_OFFLINE = "true"` to prevent Cargo from downloading dependencies.
No lab, guest installation, or deployment is needed. The
[README walkthrough](../README.md#offline-service-stage) exercises the same
workflow manually with `service.example.yaml`, `examples\offline` fixtures,
and an explicit database under the ignored `state` directory.

Interface formatting tests use values only and do not require assigned test
addresses. Separate `interfaces_cli` integration tests exercise read-only OS
enumeration through `interfaces` and `ifconfig`, including raw mode without a
config file. They do not send packets, alter interfaces, invoke native network
tools, or require a lab. Platform address/mask availability follows the native
enumeration adapter; unknown masks must never be guessed.

These fixtures are not DHCP observations. The operator supplies
`--trusted-link`; a DUID is an identifier, not authentication. A successful
policy explanation does not reserve an address. Policy denial produces JSON
and exit 2; denied writes and operational/input failures produce stderr and
exit 1 (CLI argument parsing has its own errors).

No snapshot means `basis: "desired_only"` with empty changes, not an assumption
that a provider is empty. Capturing a plan's `desired` as an observed fixture
and replaying it yields no changes; retiring its asset then proposes only the
known reservation/AAAA/PTR removals. Plans never apply those changes. Unknown
or drifted snapshot records fail even when their owner string is `v6alias`.

## Principles

The `Demo.ps1` five-VM routed-demo controller has an independent mocked guard
suite covering exact resource allowlists, active/persistent XML, bridge
membership, disk metadata, forbidden host-directory mounts, command deadlines,
controller serialization, and partial-start cleanup. PowerShell tests verify
schema validation, menu/WhatIf behavior, and console dispatch without SSH.

The manually staged live demo is distinct from the offline allocator tests.
Its in-guest rehearsal verifies actual source/target aliases, absence of default
routes, bounded IPv6 ping replies, dedicated-key/strict-host-key SSH, remote
hostname/prompt identity, and return to the original guest. All traffic stays
on the isolated scout networks; it is not a live DHCPv6/DNS reconciliation
acceptance test. The routed extension checks explicit opposite-subnet gateways,
no default routes on source and lab target, and three actual replies from
`lab:7.15`, followed by the existing corporate ping/SSH regression.

- Every domain invariant and error variant has a direct unit test.
- Pure logic accepts data as values or text; filesystem and network I/O stay in
  adapters.
- Tests use injected clocks and random-number sources where behavior would
  otherwise be nondeterministic.
- Invalid and ambiguous inputs fail closed; tests must not assert
  success-shaped fallbacks.
- Every fixed bug receives a regression test.
- Generated deployment artifacts are deterministic and reviewable.
- Unit tests never invoke `ping`, `tracert`, `traceroute`, `ssh`, DHCP, real DNS
  services, or pfSense. The helper's UDP wire tests contact only their own
  ephemeral IPv6-loopback fixture server.

## Domain test matrix

This matrix guides current and future coverage; it is not a claim that every
planned component exists. The implemented layers are listed above.

| Component | Required coverage |
|---|---|
| Alias grammar | Short and explicit forms, decimal boundaries, leading zeros, invalid profiles, malformed separators, reserved device zero |
| ULA profiles | Valid locally assigned `/48`, canonical network boundary, reserved `fd00::/48`, duplicate prefixes, unknown fields, missing defaults |
| Resolution | Default and explicit subnets, numeric decimal-to-hex conversion, minimum and maximum values |
| Reverse formatting | Shortest canonical alias, nondefault subnet preservation, unknown prefix, unmanaged IID shape, duplicate ownership |
| ULA generation | Correct `fd` layout, 40 generated bits, deterministic seeded tests, collision retry, persisted-prefix reuse |
| Subnet allocator (future) | Lowest-free allocation, exhaustion, reserved ranges, concurrency, idempotency, retirement and tombstones; current service links have configured subnets |
| Device allocator | Stable replay at the same placement, uniqueness, decimal 2–4095 boundaries, exclusion of 0/1 and bootstrap IDs, reserved skips, permanent tombstones with no automatic reuse |
| Policy engine | Rule precedence, trusted-input requirements, explain output, conflicts, unknown/mismatched/unmanaged corporate denial, explicit inventoried quarantine placement |
| Artifact model | Escaping, ordering, exact addresses, duplicate prevention, unsupported capability errors |
| Command invocation | Platform executable selection, IPv6 flags, argument boundaries, display quoting, dry run, exit-code propagation |

Round-trip invariants must be exercised across representative boundaries:

```text
reverse(resolve(alias)) == canonical(alias)
resolve(reverse(address)) == address
```

Property-based tests over the complete `u16` subnet and managed-device domains
remain a future addition; the address core is already split from the CLI.

## Persistence tests

SQLite tests use isolated disposable databases under the repository and real
transactions. Current coverage includes:

- schema creation, version recognition, and rejection of incompatible schemas;
- uniqueness under concurrent allocation attempts;
- rollback after injected write failures, including failed config pinning;
- restart persistence and reconciliation against retained history;
- asset, DUID, and IAID conflicts;
- immutable inventory with exact canonical replay only;
- full configuration pinning on the first successful allocation, including
  concurrent first-allocation conflicts;
- tombstone retention and prohibited reuse or cross-link reassignment.

No test shares a database or relies on execution order. General forward
migrations and import/export round trips are future work, as are multi-IA,
inventory updates, and re-enrollment. Configuration changes after pinning need
a future explicit migration, never ad hoc database edits.

## Artifact tests

Current reconciliation tests assert structured, provider-neutral review
models before serialization. They validate exact assignment-derived resources,
authoritative inventory names, private AAAA/PTR records, explicit TTL policy, and
deterministic deltas. These are not executable Kea/pfSense configurations, and
an owner label alone cannot authorize changing an unknown record.

Future generators should compare canonical output with reviewed golden files
for:

- V6Alias YAML;
- broader pfSense provider contracts beyond the implemented pinned native subset;
- Kea DHCPv6 reservations;
- private AAAA and `ip6.arpa` PTR records;
- Unbound forwarding configuration;
- Hyper-V and deployment manifests.

Golden-file changes must be intentional and reviewed as deployment changes.
Secrets, machine-specific paths, timestamps, and unstable identifiers are
excluded.

## Future FFI tests

When the Rust FFI crate is implemented, it will require tests from both sides
of the ABI:

- Rust tests for every exported operation and status code;
- a small C++ harness that creates and frees every opaque handle and buffer;
- malformed UTF-8, null-pointer, length, and use-after-free defenses;
- panic containment so unwinding never crosses the ABI;
- API-version compatibility checks;
- x64 and ARM64 builds.

The future WinUI application should test the FFI service wrapper rather than
duplicating domain assertions in C++.

## CLI and integration tests

Current CLI tests run the compiled binary with disposable local configuration
and assert stdout, stderr, exit codes, and persistence across process restarts.
Networking wrappers are exercised through argument-construction tests and
dry runs without sending traffic. Future child-process integration tests should
use a fake executable on a test-only `PATH`, not a live networking tool.

The foreground `v6aliasd` and read-only `v6alias-collect-isc` capture normalizer
exist, alongside the native pfSense offline compiler/application engine, but no
listener, installed privileged executor, Kea adapter, or live DNS updater exists
at this stage. The normalizer consumes an operator-supplied capture;
it does not continuously capture pfSense or contact guests.
Future backend adapter contract tests should use local fakes.
Tests against real services must run separately in an explicitly approved
isolated environment, never as a requirement of the offline unit-test job.

### Shadow daemon gates

`tests\daemon_cli.rs` launches the real daemon against disposable synthetic
inventory under ignored `state`, using the original CLI to initialize/register.
It checks versioned JSON lines, exit codes, repeated polling, recovery from
malformed input, retry exhaustion, concurrent processes, forced-stop/restart
replay, and no inferred retirement on observation disappearance. Reserved IDs
and permanent tombstones remain unavailable. Invalid whole snapshots and
managed-record inputs produce no stdout plan or new assignment; service unit
tests verify batch exhaustion rolls back both allocations and config pinning.
Source mismatch, future/stale timestamps, malformed/unknown fields, duplicate
identities, size/count limits, nonregular files, nonexistent/unrecognized DBs,
config conflicts, and unsupported `--apply` are rejection cases.
Backend-envelope tests independently reject stale/future captures, missing/unknown
fields, unsupported versions, raw snapshots and invalid later managed records,
without committing new allocations or pinning configuration. Loop tests keep
observations fresh while the backend ages out. Offline CLI raw-snapshot acceptance
remains a separate regression.

Unix-only process tests send SIGTERM/SIGINT to the specific owned child, checking
interruptible polling and failed-cycle backoff. Linux pipe tests hold non-draining
stdout/stderr consumers open, send both signals during publication, and require
bounded nonzero exits. They also cover blocked fatal diagnostics and broken pipes.
Cross-platform publisher unit tests gate writes/flushes to check timeouts,
cancellation, sticky shutdown state, errors, acknowledgements, and no stalled-stream
retry. Every long-running test child has
bounded waits and cleanup on assertion failure. These Unix tests do not establish
Windows console Ctrl-C behavior. Cross-compilation alone also does not establish
runtime behavior; run the Windows binary against the same synthetic workflow
locally. No test needs a listener, elevated privileges, networking, or a guest.

Freshness unit tests inject integer times for exact boundaries. The daemon checks
the actual clock for both capture envelopes before locking, after acquiring the
exclusive transaction, and immediately before commit. Real rollback-journal reader
transactions (`BEGIN; SELECT ...`) and writer locks are held while captures expire;
both reader tests require rejection with no allocations/config pin. This closes the
shared-reader COMMIT wait gap, not arbitrary filesystem/fsync stalls. Atomic
collector publication and trustworthy link filtering are operator responsibilities,
not something synthetic tests prove. The daemon-only backend envelope nests the
unchanged offline reconciliation snapshot; tests use explicit simulated captures.
Store commit precedes plan output; restart is idempotent, not exactly-once delivery.

```powershell
cargo test --test daemon_cli --locked
cargo build --release --locked --target x86_64-unknown-linux-musl -p v6alias --bins
cargo build --release --locked --target x86_64-pc-windows-gnu -p v6alias --bins
```

These target builds require the corresponding preinstalled compilers/targets.
See the [shadow walkthrough](../README.md#foreground-shadow-daemon) for a fresh
synthetic fixture, explicit trusted source/link binding, flags, and failure semantics.

### Read-only ISC collector gates

`crates\service\src\isc` unit tests cover byte-preserving quoted/octal and
colon-hex identifiers, both writing-server byte orders, all 256 octets, identifier
reader limits, strict headers/scalars/braces, and truncation at every association
byte. Tests verify latest-whole-record file-order replacement, empty/inactive
suppression, finite UTC/epoch/never expiration, invalid calendars/weekday/timezone
suffixes, unsigned lifetime overflow, inert binding constants, and explicit
rejection of expressions, handlers, IA_TA/IA_PD, and unknown grammar.
Identical repeated server-DUID headers are accepted after byte decoding, including
equivalent quoted/hex spellings. Conflicting identities, missing delimiters, and
late server-DUID declarations remain errors. The synthetic empty fixture mirrors
the repeated-header shape found in the actual pfSense capture without copying its ID.

Scope tests check configured `/64` selection, same-scope deduplication, unknown
or ambiguous mappings, cross-scope associations, conflicting live address owners,
and multiple live IAIDs even on filtered-out known links. They independently
exercise envelope, decoded-input, token, token-count, record-byte, record-count,
address-count, observation-count, and serialized-output limits. Small private
test limits exercise exact parser boundaries; production has no limit bypass.
Freshness boundary tests use a private integer-clock helper; the production
collector has no clock override and preserves the original source capture time.

`tests\isc_collector_cli.rs` runs the real collector -> snapshot file -> real
`v6aliasd --once` pipeline against explicitly initialized/registered disposable
synthetic inventory under ignored `state`. It verifies stable `corp:2` replay,
inventory-owned DNS, null hostnames, denied unknown identities without registration,
and no retirement on disappearance. Capture/config/DB are not modified by collection;
invalid late syntax, stale/future/source-mismatched envelopes and size/nonregular
inputs produce no stdout snapshot or DB writes. Unix tests reject symlinks/devices
before open and bound a non-draining stdout consumer. The shared publication
module retains its existing cross-platform cancellation/write/flush/error tests.

Fixtures `examples\isc\synthetic-active.leases` and `synthetic-empty.leases` are
**synthetic**, not private pfSense captures or evidence of actual arrivals.
Integration tests generate fresh capture timestamps and realistic finite epoch
ends. A real header-only capture can establish parsing of an empty database,
not active client collection, stable-address delivery, or reservation/DNS writes.
`v6aliasd` chooses the stable address; pfSense DHCPv6 delivery remains later
approval-gated integration, never a direct address assignment by the collector.

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --release --locked --target x86_64-unknown-linux-musl -p v6alias --bins
cargo build --release --locked --target x86_64-pc-windows-gnu -p v6alias --bins
```

Crossbuilds are not native runtime tests. Run the Windows GNU executables locally
against a unique synthetic directory: initialize/register, collect to a separate
snapshot only after successful exit, run the daemon twice, then reject stale and
malformed captures with empty stdout. Delete only that owned directory afterward.
The repeatable PowerShell smoke is:

```powershell
.\scripts\tests\Test-IscCollector.ps1
# Or pass -BinaryDirectory pointing at another native Windows build directory.
```

The collector-stage local validation on 2026-09-23 passed its Rust tests,
formatting, strict workspace Clippy, and Linux musl/Windows GNU crossbuilds.
The native Windows smoke passed stable `corp:2` replay, unknown denial without
registration, stale/future/malformed rejection with empty stdout, and synthetic
header-only zero observations. These results are synthetic/local, not real
pfSense arrival or DHCP-delivery acceptance.

Separately, a one-shot read-only capture of the actual pfSense ISC lease file
passed collector-to-shadow-daemon processing for corporate, lab, and quarantine
scope mappings. The capture had zero associations and repeated identical server-DUID
headers. Its capture timestamp was preserved; an explicit 3600-second maximum age
was used for this retained development input. No active client arrivals or address
delivery were claimed. Private evidence remains in ignored local `state`.

No automated test requires a VM, SSH, client/static ULA changes, DHCP reservations,
DNS writes, or an installed service. Protect capture directories and atomically replace
downstream files; tests cannot authenticate a source label or make unsafe shell
redirection (including input hardlink collisions) safe. See the
[collector contract](../README.md#read-only-isc-dhcpv6-collector) for precise limits.

## Native pfSense compiler and offline transaction gates

`crates\service\src\pfsense.rs` is executable native configuration translation,
not just a provider-neutral manifest. It uses concrete DHCPv6 staticmap and
Unbound host objects, with pure CAS-guarded application/rollback over complete
secret-free projections. These Rust tests do not write config.xml, call privileged PHP,
reloads services, contacts a router, or changes client addresses.

Coverage includes:

- Literal pre-TTL canonical metadata is inserted into actual SQLite, then read,
  allocated and replayed with default/explicit 300. TTL 3600 changes are rejected
  atomically without changing database bytes; both AAAA/PTR use the selected TTL,
  and stale observed TTL fails.
- Full foreign baseline append/preservation, native lowercase colon DUIDs with
  no fictional IAID field, no native TTL field, exact owned replay, exact retired
  removals and rollback backed by retained history. Tags never authorize unknown
  or modified objects.
- Conflict checks across all native interfaces and all host IPs/aliases/external
  CNAME/PTR owners, one-DUID/one-IAID history, duplicate identities, unsupported
  alias/delegation/pool/tracked-scope shapes, wrong/lookalike /64s, protected router
  and external static addresses, independently approved reservation addresses.
  Interface mode/address validation uses the real `config.interfaces` subtree,
  not the DHCPv6 subtree; missing, tracked, dynamic and mismatched interface
  addresses/prefixes are rejected.
- Versions, backend, source/capability/coverage/freshness, strict unknown and
  duplicate JSON fields, byte/count limits and unsupported paths/program fields.
- Real local transformations, deterministic newly appended order, object-order
  preservation and deliberate canonical-key hashing; revision AND whole-state
  preconditions, forged request/token/candidate rejection, exact rollback,
  concurrent unrelated-edit preservation by refusal and rejected rollback retry.
  SHA256 has empty/abc/multiblock/million-byte known-answer vectors.
  Opaque JSON numbers cannot be rounded before hashing: out-of-range integers
  and floating-point forms are rejected. Exact integer extremes round-trip,
  and distinct integers above the floating-point exactness boundary change CAS.

`tests\pfsense_cli.rs` launches the real original and native helper binaries for
init/register/allocate/plan/simulate/replay/rollback, stable read-only inventory
bytes, stale/revision/conflict/tamper rejection with empty stdout, missing DB
noninitialization, input non-overwrite, 3600 AAAA/PTR, and unavailable live flags.
The Unix-only nonregular/symlink check complements the shared bounded publisher
tests; protected directory permissions remain necessary.

```powershell
$env:CARGO_NET_OFFLINE = "true"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo build --release --locked --target x86_64-unknown-linux-musl -p v6alias --bins
cargo build --release --locked --target x86_64-pc-windows-gnu -p v6alias --bins
.\scripts\tests\Test-PfsenseNative.ps1
.\scripts\tests\Test-IscCollector.ps1
```

The native Windows pfSense smoke creates and removes only a unique synthetic
directory. It checks actual CLI outputs, inventory SHA256 stability, foreign
preservation, exact replay, rollback/retry/concurrent-edit/revision/stale refusal
and 3600 AAAA/PTR. Crossbuilds alone are not Windows runtime evidence. Synthetic
fixture timestamps are explicitly refreshed; **real captures must never be
retimestamped** to bypass freshness.

Local validation on 2026-09-23 passed **204 Rust tests** (the 165-test prior
baseline plus 39 TTL/native tests), formatting, strict all-target/all-feature
workspace Clippy, and release builds of all four binaries for Linux musl and
Windows GNU. The actual native Windows pfSense smoke passed **30 assertions**,
the README PowerShell workflow ran successfully, and the existing
`Test-IscCollector.ps1` regression passed. These are offline proofs, not router
persistence or live DHCPv6/DNS acceptance.

The separate PHP helper implements actual DOM collection and bounded durable
XML persistence/rollback, with **offline** integration tests below. Its versioned
live helper also completed the separately approved one-client persistence trial.
Source labels/hashes do not authenticate a
capture. No fake persistence/reload orchestration is presented as live acceptance.
The helper implements cold-restart runtime acceptance and symmetric rollback
verification. Actual DHCPv6/Unbound acceptance used separately approved external
router restarts; service-only hot reload is not implemented.
See the [native contract and walkthrough](../README.md#native-pfsense-adapter-local-compiler-and-offline-transactions).

### Root-local PHP collector/writer gates

With an already available 64-bit PHP 8.3+ CLI, DOM and POSIX (no framework or
router installation), run from the repository root in a local Linux shell:

```text
php scripts/tests/test_pfsense.php --rust-bin-dir target/debug
```

The Rust binaries must already be built. Omitting `--rust-bin-dir` runs only the
PHP tests and explicitly reports that the cross-language pipeline did not run.
On 2026-09-23, an unprivileged extracted PHP 8.5.4 runtime with DOM/POSIX passed
**83 tests including the actual Rust-to-PHP pipeline**; the existing **96 Python
tests** also passed. No packages were installed on a router or into the local OS.
After actual-router compatibility fixes on September 24, the suite passes
**87 tests**. New cases cover the root-level/default ISC backend, managed RA
metadata, dormant tracking preferences on fixed interfaces, and repeated private
system groups without leaking their contents or accepting duplicate DNS identities.
The subsequent local lock/evidence milestone passed **118 PHP tests including
the real Rust-to-PHP pipeline**, all five PHP files pass syntax checks, and all
**204 Rust workspace regressions** pass using the existing WSL toolchain/cache.
No Rust, PowerShell bundle or CI code changed. The milestone preserves the
earlier cases and adds
explicit stock-lock initialization and immutable schema-2 activation evidence
coverage. The cold-restart acceptance milestone adds real production runtime
parsers/probes and durable activation/rollback states, tested through offline
synthetic command/file responses. The original suite passed **179 PHP tests
including the Rust-to-PHP pipeline**; all six PHP files (five deployment files
plus the test) pass syntax checks with the extracted PHP 8.5 runtime. All
**204 cached Rust test-harness tests** pass directly without rebuilding or
changing Rust. Actual FreeBSD 8.3 runtime probes remain unexecuted.
The boot-identity/served-DNS and native executable fixes expand this to **248 PHP tests including the
Rust-to-PHP pipeline**, with seven syntax-checked PHP files (six deployment
files plus the test). The new PHP code uses PHP 8.3-compatible syntax; local
execution/lint uses the extracted PHP 8.5 runtime, not a FreeBSD compatibility
claim. These changes do not alter the shared Rust schema or sources.

The tests exercise real DOM parsing, actual files, short writes, flock contention,
fsync, atomic rename, readback, private preimages, journals and exact rollback
under a unique `v6alias-php-helper-test-*` directory on native Linux working
storage (`TMPDIR` set to the local validation working directory), removed
afterward. This avoids inconsistent post-rename metadata on Windows-mounted
DrvFS without weakening production checks. Synthetic
XML includes noncredential secret sentinels; projection/results must not expose
them, and unrelated nodes/comments/CDATA/foreign entries must survive persistence.
Coverage includes strict duplicate-key/number/Unicode canonical JSON, unsafe XML,
all native counterparts including alias A/AAAA and primary PTR TTL/target drift,
unsupported extensions and registration, source/version pins, approval/hash/
revision/freshness/path/foreign/ownership refusals, capture races, final CAS,
write/fsync/rename/cache failures, absent caches, lock timeouts, unsafe file types/
owners/permissions/links, corrupted backups and concurrent-edit rollback refusal.
Injected crashes before/after commit and rollback are recovered from exact full
hashes, not guessed partial state. Exact approved retirement is exercised too.
Complete multi-interface captures are tested with a smaller managed-interface
subset, including a real Rust-generated subset request. Unpublished preparations
are fault-injected after directory, backup and journal creation and at atomic
publication; a subsequent persistence attempt safely cleans them and succeeds.
Published prepared transactions still require explicit recovery, and unexpected
staging contents are never deleted. Evidence-file preparation is fault-injected
before journal publication too. The retained canonical request is replayed against
the raw preimage and private DNS baseline before rollback/recovery. Delayed
preparation expiry still permits abort recovery without reapproving an old request.
Corrupt evidence, mismatched source/policy identity and legacy schema-1/2 journals
fail closed; no silent migration is allowed.

Lock tests use actual O_EXCL/flock/fsync and a fixture-owned sticky directory:
idempotent creation/adoption, unchanged inode/contents, racing stock or symlink
creators, symlink/hardlink/directory/foreign-owner/unsafe-mode refusal, bounded
contention, same-object reentry, inode substitution, fsync failure and interruption
at open/chmod/durability boundaries. A failed initialization never deletes the
stock inode. Production metadata checks are retained on opened descriptors.
Capture with an absent stock lock still makes exactly two DNS-data reads and
creates nothing; ordinary persistence refuses rather than initializes it.

The cross-language test initializes/registers/allocates with the real Rust CLI,
feeds a PHP-collected synthetic baseline through the native Rust compiler and
simulator, compares all canonical hashes (including Unicode/slash/line separator),
persists the actual reviewed request with PHP, verifies the native DOM projection,
then restores the full preimage without changing Rust inventory bytes.

The fixture backend adapts owner/mode checks for unprivileged execution;
the production checks receive independent adversarial
metadata tests. Capture-only acceptance on actual FreeBSD/PHP 8.3.19 established
root-private installation, fixed source pins and read-only collection. The genuine
three-scope projection also passed the Windows native compiler and private no-op
review-bundle workflow, retaining its capture timestamp and approving no changes.
The subsequent approved trial exercised real standard-lock initialization,
directory durability, journaled persistence and post-restart activation acceptance.
The stock lock was recreated explicitly after each boot, never implicitly through
capture or persistence. Live failure recovery/rollback was not needed and remains
distinct from the successful persistence path.
The production CLI has **no fixture-root, environment,
clock, arbitrary subprocess, or privilege bypass**. Linux production invocation
fails closed. Tests do not exercise live DHCP/RA activation. `activate` validates
approval/revision/policy/source/evidence, then durably prepares an external cold
restart; invalid preflight still leaves journal/config/evidence unchanged.
`verify-activation` alone can record accepted runtime after a changed boot and
actual health probes. A changed boot with stale DNS fails. Tests cover durable
preparation/verification/finalization faults, immutable boot identity on retry,
foreign edits during health/final save, re-verification failure clearing prior
proof, historical-versus-fresh status, old rollback versus a newer transaction,
rollback crash recovery and a second cold boot restoring baseline runtime.
Rollback cannot silently rebaseline damaged IPv4/RA configuration.

The production `RuntimeHealth` implementation is also run directly against
synthetic pfSense-format command and file fixtures: full native map/subnet/range
parsing; PID/executable/chroot/jail/family/interface/config argument checks;
UDP6:547 listener; Unbound status and DNSSEC validator; native AAAA/PTR TTL and
foreign DNS coverage; stable repeated boot/PID/process/config/DNS reads.
Adversarial cases include comment-only/missing/duplicate/wrong reservations,
wrong subnet/range, injected include, truncation, zombies, PID reuse, wrong
executable/chroot/argv, absent listener, stale listener PID, stopped Unbound,
disabled validator, changed IPv4/RA files, TTL/PTR drift, native-file
owner/type/link/mode violations, unapproved physical interfaces, late source/
dirty/fsync failures and command failures.

The v2 boot proof hashes exactly 16 raw `kern.boot_id` bytes, including leading/
trailing whitespace or NULs. Bad lengths and legacy v1 contracts refuse. Forward
and backward wall-clock/NTP steps with the same ID cannot satisfy activation or
rollback, and retries retain their frozen preboot identity. A changed ID still
needs all health checks; it cannot distinguish a warm reboot from cold power
cycling or RAM-snapshot restoration. External libvirt off/start evidence remains
separate, and actual FreeBSD 15-CURRENT router availability is not tested here.

DNS tests retain independent native/control provenance checks, then exercise
all owned/foreign host A/AAAA/PTR and alias queries on every exact policy ULA.
A healthy control table cannot hide a dead listener, stale served address,
wrong PTR or TTL. Empty rollback must serve a known baseline (10800 TTL is
accepted only when that is its exact control-data TTL). Missing probes,
unknown baseline names, public/link-local/hostname targets, excessive inventory,
aggregate monotonic deadline exhaustion and incomplete proof fields refuse.
The wire parser tests cover normalized complete RRsets, ordinary compression
and compressed PTRs; bad IDs/questions/class/owner/type/flags, REFUSED/NXDOMAIN,
CNAMEs, unrelated/extra/missing/duplicate answers, malformed lengths/counts,
trailing bytes, compression loops and oversized packets all refuse.
Actual connected IPv6 UDP tests run against a fixture subprocess bound only to
an owned ephemeral `[::1]` port: AAAA/PTR replies, wrong-source datagrams and
bounded timeout. They never contact the machine's real DNS listener or router.
Production has no port override, fixture server or resolver fallback. It uses
one attempt, a 2-second exchange cap, a 30-second aggregate DNS cap, and bounded
query/packet/answer counts. Proofs include served count and answer-set hash only
after every query succeeds; failures leave failed/verifying state, not accepted
activation. No new test framework or extension is required.

Mock success is **only offline evidence of these code paths**, never a claim of
live DHCP delivery, RA packets, DNS serving or production readiness.

`services_dhcp.inc` is now captured and pinned at its resolved
`/usr/local/pfSense/include/www/services_dhcp.inc` path. Its mandatory
`config.gui.inc` dependency (plus `Net/IPv6.php`, `ipsec.inc`, `vpn.inc`,
`syslog.inc` edges elsewhere) remains outside the captured include closure.
Cold-restart acceptance executes **no native includes** and needs no
`write_config`, name-based kill, reload, anchor or service wrapper. The helper
does not perform the external restart. IPv4 DHCP, RA, firewall and DNS services
are untouched by local tests. Before deployment, review the six-file package
(`core.php`, `storage.php`, `platform.php`, `runtime.php`, `dns.php`,
`v6alias-local.php`), schema-3/v2-runtime contract and exact [cold-restart protocol](../README.md#cold-restart-activation-acceptance-local-implementation-not-live-acceptance),
then separately approve router-only restart and live read-only probe/rollback
acceptance. Native boot may perform ordinary background network attempts; the
lab isolation guard, not these unit tests, must enforce the no-upstream boundary.

Full router XML/backups must never become test fixtures. Only synthetic
`scripts/tests/fixtures/pfsense-config.xml` and `pfsense-policy.json` are checked
in; source pins are hashes, not copied pfSense implementation files.

The Windows-only `scripts/tests/Test-PfsenseChangeBundle.ps1` runs 133 assertions
against real planner/simulator binaries: private ACLs, atomic publication,
preserved integer values, input identity/hash stability, expiry, non-approval,
collision/reparse/hardlink rejection, output limits and owned-child timeouts.
CI runs these Windows workflows and the PHP/Rust fixture pipeline independently;
neither step performs router operations.

## Future WinUI tests

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

## Future Hyper-V acceptance tests

The isolated lab will verify behavior that unit tests cannot, only after
explicit approval of the topology and each live integration stage:

- Router Advertisement and DHCPv6 exchange;
- profile selection from trusted virtual-network placement;
- `corp`, `lab`, and `quarantine` firewall policy;
- AAAA/PTR publication and containment;
- client, service, and pfSense restart recovery;
- DUID reset and duplicate-client handling;
- no ULA traffic or private DNS leakage to the dead WAN.

Live provider apply/rollback exercises, provider/version compatibility checks,
and packet captures are also future, approval-gated acceptance work. Local
transaction rollback tests do not establish live provider rollback safety.
Do not infer deployment readiness or lab results from an offline test pass.

## Continuous-integration gates

Every pull request must pass:

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --locked
```

The current CI workflow configures these workspace gates on both Windows and
Linux. This describes the checked-in matrix, not a claim that CI has run or
passed. Future CI additions include:

1. C ABI harness builds on Windows x64 and ARM64.
2. C++/WinRT build and package validation.
3. Provider-specific deterministic artifact golden tests.
4. Dependency and security auditing.

Coverage reports are initially informational. Merge gates focus on explicit
invariant, error-path, and regression coverage rather than a misleading global
line percentage.
