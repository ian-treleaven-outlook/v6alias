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

## Resolver and command wrappers

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

```powershell
cargo run -- ula generate
# fdxx:xxxx:xxxx::/48
```

Generation uses 40 cryptographically random Global ID bits and rejects the
reserved all-zero value. Persist the generated prefix rather than generating a
new one on each run.

### Local interface addresses

`v6alias interfaces` (also `v6alias ifconfig`) is a read-only, ifconfig-like IP
listing. Unlike the `ping`, `trace`, and `ssh` wrappers, it reads the operating
system's interface metadata directly; it does not execute native `ifconfig`,
probe addresses, query DNS, or configure networking.

```powershell
cargo run -- --config v6alias.example.yaml interfaces
cargo run -- --config v6alias.example.yaml ifconfig --interface "Ethernet"
cargo run -- --config v6alias.example.yaml interfaces --json
cargo run -- interfaces --raw
```

Use the existing resolver profile configuration, not `service.example.yaml`.
With the example profile configuration, illustrative output for an interface
with multiple IPv6 addresses is:

```text
Ethernet (index 7)
  inet  10.23.0.42/24
  inet6 2001:db8::42/64
  inet6 fd12:3456:789a:7::f/64
  inet6 corp:42  (fd7a:115c:a1e0:17::2a/64)
  inet6 corp:24.43  (fd7a:115c:a1e0:18::2b/64)
  inet6 lab:15  (fdb4:82d1:930c:7::f/64)
  inet6 fe80::42/64
```

Every reported address is retained, including multiple addresses from the same
profile or different profiles on one interface. Only an exact configured ULA
`/48` **and** a representable managed interface identifier (`::1` through
`::ffff` within that subnet) receive an alias. Random/temporary interface
identifiers within a matching prefix remain IPv6 literals; no bits are
discarded to manufacture an alias. Unknown ULAs, GUA, link-local IPv6, and IPv4
are never aliased. Decimal conversion and omission of the configured default
subnet use the same rules as `reverse`.

The actual IPv6 address remains beside the alias. Prefix lengths are shown
when supplied by the enumeration API, not guessed; for example, its Windows
IPv6 enumeration currently reports no netmask, so those rows omit `/length`.
Link-local addresses remain associated with their interface name/index; these
are listings, not standalone scoped command targets. Interfaces and addresses
are sorted deterministically without collapsing multi-address entries.

`--raw` disables alias annotations and does not read a configuration file.
Otherwise, missing or invalid configuration is an error, rather than silently
showing potentially misleading results. `--interface` selects an exact OS name;
an unknown name is an error. JSON retains the numeric `address`, nullable
`prefix_length`, and nullable `alias` as separate fields.

This is a display convenience, not proof that SQLite assigned an address or
that its owner is trusted. It does not emulate native ifconfig's configuration
flags. It lists the machine where the binary runs: inside WSL, that means WSL,
not the Windows host or a remote guest.

### Color and opt-in demo command names

Human-readable interface headings and wrapper previews use color on interactive
terminals. Configured `corp` aliases are green, `lab` aliases magenta, and
`quarantine` aliases yellow; labels still identify profiles without color.
Actual numeric addresses are retained. `--color always` explicitly enables ANSI
color for Windows Terminal serial consoles; `--color never` disables it.
Automatic mode respects `NO_COLOR`, `TERM=dumb`, and redirected stdout.
JSON, `resolve`, and `reverse` output always remain plain.

```powershell
.\v6alias.exe --color always ifconfig
.\v6alias.exe --color never ping corp:42 --dry-run
```

Adding a binary directory to `PATH` does not enable color. A serial guest may
have conservative terminal settings, and console automation may leave a plain
prompt. These demo helpers do not edit `PATH`, `TERM`, `.bashrc`, or PowerShell
profiles. The normal CLI continues to use subcommands and never replaces native
executables.

For an **explicit, temporary opt-in** on PowerShell 7.3+:

```powershell
Import-Module D:\v6alias\scripts\V6AliasDemo.psm1
Enable-V6AliasDemo -Color
ping corp:42 --dry-run -n 3
ssh corp:42 --dry-run -l scout-user
ifconfig
Disable-V6AliasDemo
```

Inside a Bash guest, once the updated package is installed:

```bash
source ~/v6alias/demo-shell.bash
v6alias-demo-on --color
ifconfig
ping corp:42 --dry-run -c 3
ssh corp:42 --dry-run -l scout-user
v6alias-demo-off
```

`--color` also installs a readable cyan `user@host` Bash prompt for the current
shell, without a `[DEMO]` tag; disabling restores the previous prompt. File-list colors are separate:
use `ls --color=auto` when supported. Existing `ls` aliases are not changed.
The narrated `demo.py` also supports `--color auto|always|never` for headings.

The shortcuts require the **alias first**, followed by native options. They
translate `ping corp:42 -c 3` to `v6alias ping corp:42 -- -c 3` on Linux.
For ordinary IPs/hostnames use `native-ping`, `native-trace`, `native-ssh`, or
disable demo mode. PowerShell users can also explicitly call `ping.exe`/`ssh.exe`.
Existing aliases/functions with these names cause activation to fail rather than
being overwritten; removing demo mode preserves replacements made by the user.
Functions are not installed as executables, so V6Alias's native child process
cannot recursively invoke the shortcut.

Only `--dry-run` **before** an optional `--` separator controls V6Alias. Following
arguments are native tool arguments. PowerShell arrays should be splatted
(`ping @arguments`); nested array arguments are rejected. When combining
PowerShell splatting and a separator, put `'--'` inside the argument array or
quote it. These are alias-first demo shortcuts, not complete native command-line
emulators; SSH remote-command syntax is not supported by the wrapper yet.

Omit `--dry-run` only when intentionally connecting to an approved, reachable
destination. No addresses, firewall access, or SSH trust are created by enabling
shortcuts, and unknown aliases never fall back to native networking.

## Offline service stage

The Cargo workspace now contains:

- `crates\core` (`v6alias-core`): the pure Rust address library for aliases,
  ULA profiles, resolution, reverse formatting, and ULA generation.
- `crates\service` (`v6alias-service`): the operational Rust library for
  inventory, policy, transactional allocation, and provider-neutral plans.
  It uses `rusqlite` with bundled SQLite: the SQLite **C engine is compiled as
  a dependency**. Application and policy logic is Rust, not C++; this is not
  a claim that every dependency is pure Rust.
- The root `v6alias` CLI: the original resolver/wrappers plus local offline
  `inventory`, `policy`, and `service` commands.
- The root `v6aliasd` binary: a portable foreground, file-fed shadow observer
  with bounded polling/retries and transactional local allocation.
- `v6alias-collect-isc`: a portable read-only ISC DHCPv6 capture normalizer,
  producing the daemon's existing source-bound observation envelope.
- `v6alias-pfsense`: a native ISC+Unbound persistent-configuration request
  compiler and guarded **offline projection** application/rollback engine.
- `scripts\pfsense\v6alias-local.php`: a separate root-local read-only projection
  collector and approval-gated XML persistence/recovery helper. It is installed
  in the isolated lab and has completed one approved live reservation/DNS
  transaction with externally controlled cold-restart acceptance. Service-only
  hot reload remains unavailable.

There is **no live listener/API, Kea adapter, or unattended arrival-to-writer
loop**. `service plan` remains provider-neutral; the separate
native compiler below emits concrete configuration collection replacements,
but cannot install or activate them. The collector reads an explicitly supplied
capture file; it does not contact pfSense or a guest. Shadow mode **can write
local SQLite assignments**; it is not globally read-only.

**First live client accepted, September 24, 2026:** `scout-admin` now acquires
`corp:2` by DHCPv6 instead of its former static `corp:43`. Its private
`scout-admin.v6alias.home.arpa.` AAAA/PTR records use native TTL 3600.
The address, identity and DNS behavior persisted across router and client cold
restarts, without IPv4, SLAAC addresses or a default Internet route. This was a
pre-enrolled, pre-reserved client trial, not autonomous discovery/provisioning.
The other clients and user recordings were unchanged. The legacy demonstration's
`ping corp:43` target now needs `corp:2`; its installed recording script has not
been rewritten.

### Local PowerShell walkthrough

Run from `D:\v6alias` with Rust and build dependencies already installed/cached.
For disconnected builds, set `$env:CARGO_NET_OFFLINE = "true"`; Cargo then fails
rather than downloading missing dependencies. PowerShell 7 is recommended,
especially for writing BOM-free UTF-8 JSON.

Every service-stage command requires an explicit `--database` path.
`--service-config service.example.yaml` is separate from the resolver's
`--config v6alias.yaml`; these are different configuration schemas.
Use a new demo database for the complete walkthrough, since retirement below
is permanent. `state` is ignored by the repository.

```powershell
Set-Location D:\v6alias
New-Item -ItemType Directory -Force state | Out-Null

cargo run -- inventory --database state\demo.sqlite init
cargo run -- inventory --database state\demo.sqlite register --device examples\offline\device.json
cargo run -- inventory --database state\demo.sqlite list

cargo run -- policy --database state\demo.sqlite --service-config service.example.yaml explain --observation examples\offline\observation.json --trusted-link corp-link
cargo run -- service --database state\demo.sqlite --service-config service.example.yaml allocate --observation examples\offline\observation.json --trusted-link corp-link
cargo run -- service --database state\demo.sqlite --service-config service.example.yaml assignments
cargo run -- service --database state\demo.sqlite --service-config service.example.yaml plan
```

Successful commands emit JSON on stdout. The fixture's first assignment is
device **2**, address `fd7a:115c:a1e0:17::2` (alias `corp:2`), not device 42:
allocation chooses the lowest unreserved free number. Repeating allocation
returns the same active assignment. Its private authoritative name is
`demo-workstation.v6alias.home.arpa.`, derived from inventory, not the
observation's `untrusted-hint` hostname. Planned AAAA/PTR records use
`dns_ttl_seconds`, default **300 seconds**. The inclusive bound is 1–86400:
positive, no more than one day, so retention is explicit and bounded.
Omitted TTL and explicit 300 retain the exact old serialized configuration
identity (including field order); nondefault TTL is part of that identity.
Switching an allocated database to 3600 fails, including after retirement;
additive expansion deliberately cannot change TTL. Stale observed TTL is a conflict, not
permission to rewrite records. `service.example.yaml` remains unchanged.

Read commands (`inventory list`, `policy explain`, `service assignments`,
`service plan`) require an existing initialized database; they do not create,
initialize, migrate, or pin one. Policy denial emits a JSON explanation and
exits 2:

```powershell
cargo run -- policy --database state\demo.sqlite --service-config service.example.yaml explain --observation examples\offline\unknown.json --trusted-link corp-link
$LASTEXITCODE # 2
```

Denied writes, including `service allocate`, and operational/input errors exit
1 with an error on stderr, not a success-shaped JSON result. Missing or invalid
CLI arguments are parser errors.

Device, observation, and configuration inputs are limited to 1 MiB. Owned
snapshots have a separate 64 MiB limit so a complete low-number pool can be
round-tripped. Larger inventories need a future streaming/batched adapter;
the current CLI rejects oversized input rather than truncating it.

### Review a simulated reconciliation

Without `--observed`, a plan has `basis: "desired_only"` and **empty change
lists**. It does not assume an empty provider. To simulate a matching baseline,
save only the plan's `desired` snapshot (not the whole plan):

```powershell
$plan = cargo run -- service --database state\demo.sqlite --service-config service.example.yaml plan | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "Plan failed" }
$plan.desired | ConvertTo-Json -Depth 20 | Set-Content -Encoding utf8 state\observed.json

cargo run -- service --database state\demo.sqlite --service-config service.example.yaml plan --observed state\observed.json
# basis: owned_snapshot; all change lists are empty

cargo run -- service --database state\demo.sqlite --service-config service.example.yaml retire --asset-id demo-workstation
cargo run -- service --database state\demo.sqlite --service-config service.example.yaml plan --observed state\observed.json
# Proposes removal of the known reservation and its AAAA/PTR records; applies nothing
```

Use PowerShell 7 for the `Set-Content -Encoding utf8` command: Windows PowerShell
5.1 writes a BOM that the strict JSON reader does not accept. These files are
**fixtures, not actual observations**. An explicit observed snapshot may contain
only an owned subset of exact known active/retired records. Unknown records,
duplicates, or drifted fields are rejected; an `owner: "v6alias"` string alone
does not establish authority. Only exact records backed by retained assignment
history can be proposed for removal.

### Phase-one invariants and limitations

- Unknown inventory, mismatched DUID/IAID, and unmanaged corporate requests
  fail closed. `--trusted-link` is operator-supplied placement, not a field
  accepted from observation JSON and not evidence of a live link observation.
- One asset binds one DUID and one IAID. DUIDs are canonicalized to lowercase
  hexadecimal without colons, but are identifiers, **not authentication**.
  Inventory is immutable: only an exact replay after canonicalization is
  idempotent. Multi-IA support, updates, and re-enrollment are deferred.
- Profiles default to `require_managed: true`. The example explicitly opts
  `lab` and `quarantine` out, but both still require known inventory, their
  configured trusted link, and matching policy. Unknown devices do not
  automatically receive a quarantine assignment.
- An optional hostname must be a single lowercase ASCII label, 1–63 characters,
  using letters, digits, or hyphens with no edge hyphens. It is never DNS
  authority or sufficient for privilege. Invalid hints deny the request;
  there is no hostname-only promotion or reassignment across trusted links.
- Managed device IDs are decimal 2–4095. IDs 0/1 and the bootstrap range
  `0x1000`–`0xffff` are excluded; configured reservations are skipped
  (`53` on `corp-link` in the example). Retired assignments remain tombstones
  forever, with no automatic address reuse or reactivation.
- The **full service configuration is pinned after the first successful
  allocation**, not after initialization, explanation, or a failed allocation.
  Existing configuration values cannot change. Strictly additive expansion into
  a **new** database is available below; do not edit the database ad hoc.
  Retirement does not unpin it.

### Explicit additive configuration expansion (offline preparation only)

```powershell
v6alias service --database SOURCE.sqlite --service-config OLD.yaml expand-config --new-service-config NEW.yaml --destination NEW.sqlite
```

This command **writes a new database**, not a dry run, and performs **no cutover**.
It never replaces an existing file, switches a service, edits either YAML file,
contacts a provider, or changes infrastructure. The source must be recognized,
already pinned to `OLD.yaml`, and offline in SQLite **DELETE journal mode**.
Stop all source writers before starting and keep them stopped through separately
reviewed cutover. WAL mode (even without sidecars), any source/destination
`-journal`, `-wal`, or `-shm`, symlinks/reparse points in inputs or parents,
missing destination parents, existing destinations (including hard links and
Windows case aliases), invalid history, and unpinned sources are refused.
No mode converts a source journal, deletes a sidecar, or bypasses the pin.

Additive means:

- Retain every old profile and link **exactly**, including /48, default subnet,
  managed requirement, subnet, pool and reserved numbers. Keep DNS zone and TTL.
- Retain the entire ordered old rule vector as an identical prefix. Append rules
  only for wholly new links; no appended rule may match any old link.
- Add at least one profile or link; a no-op creates no file. New profiles require
  disjoint /48s. New links may use a new subnet of an old profile, but actual /64
  networks cannot overlap. All ordinary configuration validation still applies.

Both YAML inputs are bounded to 1 MiB. Under one source read transaction, the
command verifies schema, integrity, pin, immutable inventory and complete
active/**retired** history against both configurations and reconciliation rules.
Since original hostname hints are not stored, policy verification proves the
recorded rule could have uniquely authorized the inventory identity for some
valid hint; it does not reconstruct or authenticate a historical observation.
Old-link allowed/denied decisions remain unchanged for **all** possible requests,
not merely currently assigned devices.

The destination is built in private same-filesystem staging: schema, unchanged
inventory/history and the new permanent pin are committed together. No assignment
is reallocated or replayed into the next free slot. The copy is reopened and
compared, SQLite handles are closed, data is synced, and a no-overwrite operation
publishes it. Ordinary failures remove owned staging files and leave no new final
database. Do not remove unrelated files to retry; investigate them first.

JSON receipt fields include `before_config_identity_sha256`,
`after_config_identity_sha256`, `retained_records_sha256`, device/active/retired
counts, `all_retained_records_verified`, `source_unchanged`, and
`needs_operator_cutover: true`. Config hashes are SHA256 of the exact canonical
identity strings, not YAML bytes. The retained digest hashes compact JSON with
`devices` then `assignments`, each ordered by asset ID. It is a semantic history
digest, **not a database-file hash or an authorization signature**.
The source proof combines read-only SQLite, a locked snapshot and unchanged
file metadata through publication; it does not freeze later source writes.
Paths must be on trusted local filesystems with operator-controlled directories.
Path checks do not defend against malicious concurrent directory replacement;
portable Windows metadata does not provide file IDs. Publication is atomic,
but crash/power-loss durability of directory entries remains filesystem-dependent.

Synthetic example (use a fresh directory; never an accepted inventory):

```powershell
New-Item -ItemType Directory state\expansion-demo | Out-Null
cargo run -- inventory --database state\expansion-demo\corporate.sqlite register --device examples\offline\device.json
cargo run -- service --database state\expansion-demo\corporate.sqlite --service-config examples\offline\service-corporate.yaml allocate --observation examples\offline\observation.json --trusted-link corp-link
cargo run -- service --database state\expansion-demo\corporate.sqlite --service-config examples\offline\service-corporate.yaml expand-config --new-service-config service.example.yaml --destination state\expansion-demo\expanded.sqlite
cargo run -- service --database state\expansion-demo\expanded.sqlite --service-config service.example.yaml assignments
```

The corporate-only fixture and expanded example both use TTL 300. For a source
already pinned to TTL 3600, both reviewed configurations must retain 3600.
`SOURCE + OLD` and `NEW database + NEW config` continue working independently;
the opposite combinations fail the pin. Review the receipt and retained records
before any separately authorized service/file cutover. Never merge subsequent
writes into either database by hand.

### Foreground shadow daemon

`v6aliasd` consumes an explicit normalized JSON **file**, not an ISC leases file,
Kea CSV, or a REST endpoint. Read-only lab discovery found pfSense 2.8.1 running
ISC DHCP 4.4.3P1_5 and Unbound 1.24.2; installed Kea 2.6.2 was not running.
An installed package does not establish an available Control Agent or API.
This milestone neither reads nor modifies generated pfSense configuration.

The operator or the [ISC collector](#read-only-isc-dhcpv6-collector) must
**normalize and filter network placement using trusted configuration** before
publishing a file. One file/source is bound by operator flags to exactly one
configured trusted link. Never mix links, infer placement from a hostname or
an address without a trusted source and scope mapping, or let clients write this
file. `source` is a checked provenance label, not a signature or authentication.
The daemon cannot prove the claimed origin or placement. DUID/IAID and hostname
remain untrusted hints checked against immutable registered inventory and policy;
unknown/denied devices are never registered automatically.

The strict version-1 file has exactly these envelope fields:

```json
{
  "schema_version": 1,
  "source": "synthetic-corp",
  "captured_at_unix_secs": 0,
  "observations": [
    {"duid": "000400112233445566778899aabbccddeeff", "iaid": 1, "hostname": "untrusted-hint"}
  ]
}
```

Timestamp `0` deliberately makes the checked-in fixture stale. Capture timestamps
are integer Unix UTC seconds: future values are rejected, and age must be at most
`--max-age-secs` (default 300). Never refresh a stale live capture's timestamp
without actually recapturing it. A missing file is an error, not an empty snapshot.
An explicitly empty `observations` array is valid and **does not retire anything**.
Observations/configuration are limited to 1 MiB; observations to 4096 entries.
Unknown fields (including guest-supplied placement), duplicate JSON fields,
duplicate canonical DUIDs (even with different IAIDs), and malformed identity or
hostname fields reject the whole cycle before assignments are committed.

Synthetic PowerShell 7 walkthrough (use a fresh database, not the retired one
from the earlier walkthrough):

```powershell
New-Item -ItemType Directory -Force state | Out-Null
cargo run -- inventory --database state\shadow-demo.sqlite init
cargo run -- inventory --database state\shadow-demo.sqlite register --device examples\offline\device.json
$capture = Get-Content examples\offline\observation-snapshot.json -Raw | ConvertFrom-Json
$capture.captured_at_unix_secs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$capture | ConvertTo-Json -Depth 10 | Set-Content -Encoding utf8 state\shadow-observations.json

cargo run --bin v6aliasd -- --database state\shadow-demo.sqlite --service-config service.example.yaml --observations state\shadow-observations.json --source synthetic-corp --trusted-link corp-link --once
# Run again within the freshness window: same corp:2 / fd7a:115c:a1e0:17::2, one assignment.

# Optional synthetic empty backend: daemon --observed requires a timestamped envelope,
# unlike the original offline `service plan --observed` raw snapshot shown above.
$backend = Get-Content examples\offline\backend-snapshot.json -Raw | ConvertFrom-Json
$backend.captured_at_unix_secs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$backend | ConvertTo-Json -Depth 20 | Set-Content -Encoding utf8 state\shadow-backend.json
cargo run --bin v6aliasd -- --database state\shadow-demo.sqlite --service-config service.example.yaml --observations state\shadow-observations.json --source synthetic-corp --trusted-link corp-link --observed state\shadow-backend.json --once

# Foreground loop; Ctrl-C stops it. Refresh synthetic captures deliberately as needed.
cargo run --bin v6aliasd -- --database state\shadow-demo.sqlite --service-config service.example.yaml --observations state\shadow-observations.json --source synthetic-corp --trusted-link corp-link --poll-ms 5000
```

All five path/binding flags above are required. The daemon opens only an existing,
recognized inventory database; it never initializes or registers inventory.
Configuration is loaded at startup, not hot-reloaded. `cargo run -- ...` still
defaults to the original `v6alias` CLI. These executables are foreground programs;
no service is installed, autostart configured, listener opened, or endpoint contacted.

Each successful cycle emits one compact versioned JSON line to stdout with
`event: "cycle"`, `mode: "shadow"`, provenance/timestamps, operator trusted link,
explicit per-identity policy decisions, nullable assignments/aliases, and a plan.
Plans retain `mode: "dry_run"`. Without `--observed PATH`, their basis is
`desired_only` and **all deltas are empty**, not an assumed empty DHCP/DNS backend.
The optional managed-record file is a strict, versioned **backend envelope**,
limited to 64 MiB including its nested reconciliation snapshot:

```json
{
  "schema_version": 1,
  "captured_at_unix_secs": 0,
  "snapshot": {
    "schema_version": 1,
    "owner": "v6alias",
    "reservations": [],
    "dns_records": []
  }
}
```

Both files are reread each cycle. Each timestamp independently must be nonfuture
and no older than `--max-age-secs`; refreshing observations cannot keep an old
backend snapshot usable. Output includes `backend_captured_at_unix_secs` (null
when omitted). The nested snapshot retains exact retained-history ownership
validation. Its `owner` is not provenance or authentication; no live adapter or
backend source is inferred. The operator must capture the appropriate managed
DHCP/DNS state, not simply re-date an old file. The checked-in empty example is
synthetic and stale, not evidence that a real backend is empty. Original offline
`v6alias service plan --observed` continues accepting the **raw** nested snapshot.
Desired state includes all active database assignments, not just this file's
current observations. Only explicit retirement can propose removal.

Operational diagnostics are versioned JSON lines on stderr (`started`,
`cycle_error`, `shutdown`, `fatal`, or `argument_error`). Policy denials are
explicit successful-cycle outcomes (exit 0 for `--once`), unlike the existing
CLI's `policy explain` exit 2. Invalid input, conflicts, storage/output failures,
and exhausted retries exit 1; invalid arguments exit 2. Failed cycles emit **no
success plan**, and old output is not re-emitted as fresh. Consumers must check
timestamps and diagnostics rather than treating the last plan as continuously valid.

| Flag | Default | Bounds / semantics |
|---|---|---|
| `--once` | off | Exactly one attempt, no retry |
| `--poll-ms` | 5000 | 100–3600000; delay after each successful cycle |
| `--max-age-secs` | 300 | 1–86400; both captures checked before/after DB locking and before commit |
| `--max-retries` | 3 | 0–20 additional attempts per consecutive failure run |
| `--retry-ms` | 1000 | 100–60000; initial exponential retry delay |
| `--max-retry-ms` | 30000 | 100–300000; cap, at least `--retry-ms` |

A successful cycle resets the retry counter. Startup/configuration/database-open
errors and stdout/stderr publication failures are fatal, not retried. Linux SIGINT/SIGTERM and
Windows console Ctrl-C request shutdown; polling/backoff waits are interruptible.
A cycle in progress finishes or rolls back first; SQLite lock waits retain the
Store's 10-second timeout. Interrupted recovery from an unresolved failed cycle
exits 1 rather than reporting healthy shutdown. Windows service-manager control
and forced console/process termination are not graceful-shutdown guarantees.
Stdout and stderr each have one bounded writer with write/flush acknowledgement.
Publication times out after 5 seconds and is interruptible even if a consumer
keeps a full pipe open without draining it. Final/shutdown diagnostics receive
at most 100 ms; failed streams are never retried or joined. Interrupted, timed-out,
or broken publication exits nonzero, possibly with a partial JSON line. Only an
acknowledged complete cycle can be followed by a healthy interrupt (exit 0).
Diagnostics remain structured where deliverable; no final diagnostic is guaranteed
on a blocked/broken stderr.

All cycle allocations and config pinning share one exclusive SQLite transaction;
exhaustion, retired-asset conflicts, invalid managed records, or any later failure
roll back the whole cycle. Concurrent daemons serialize under the existing Store
contract. New identities are allocated in canonical DUID order, not file order.
In rollback-journal mode, existing shared readers must release their locks before
the post-lock freshness check: they cannot delay COMMIT past the last check.
This does not guarantee wall-clock freshness across arbitrary filesystem/fsync
stalls or clock changes. Other Store allocation/retirement transactions are unchanged.
Commit precedes stdout publication: a crash or broken pipe may leave committed
assignments without a delivered plan. Restart/retry safely reuses those assignments;
output is **at-least-once**, not an exactly-once event log. No checkpoint or lease
disappearance garbage collector is used.

Use operator-controlled local directories for the database and capture files.
Collectors should publish a complete file by atomic replacement, not mutate it
in place; readers reject partial/malformed captures and retry within bounds.
Protect directory permissions and synchronize clocks. Symlink/hostile replacement
races in writable directories are not a supported trust boundary. There is no
output-file option: avoid shell redirection onto the database, config, captures,
or any alias of them. Downstream consumers own durable/atomic output storage.

### Read-only ISC DHCPv6 collector

`v6alias-collect-isc` performs **one finite read/validate/normalize operation**,
with or without `--once`. It reads no inventory, opens no network connections,
and writes no files, DHCP reservations, DNS, client configuration, or static ULAs.
`v6aliasd` chooses and persists a stable managed address; **pfSense DHCPv6 would
deliver it later**, after a separately approved DHCP-writing integration.
Neither component directly assigns an address to a client. This milestone has
no DHCP service-writing adapter, daemon installation, listener/API, or Kea switch.

Input is a bounded JSON **capture envelope**, not a naked lease file:

```json
{
  "schema_version": 1,
  "source": "scout-pfsense-isc",
  "captured_at_unix_secs": 0,
  "lease_file": "authoring-byte-order little-endian;\nserver-duid 00:01:aa;\n"
}
```

These are the **exact four fields**. The example is synthetic and deliberately
stale, not private router state. The timestamp belongs to the actual source
capture, not the time an old copy was wrapped, copied, or normalized. The operator
must freshly capture the approved ISC database and retain its original timestamp.
Future/stale captures, source mismatch, missing/unknown/duplicate JSON fields,
and unsupported schema versions fail closed. `--max-age-secs` defaults to 300
and allows 1–86400, matching the daemon; there is no clock override.

Read-only discovery identified pfSense 2.8.1's active ISC 4.4.3P1_5 database as
`/var/dhcpd/var/db/dhcpd6.leases`; installed Kea was inactive. The discovered
database had no IA_NA/IA_PD records. Header-only captures normalize to zero
observations: **not evidence of real client arrivals**. Files under
`examples\isc` are explicitly synthetic parser/pipeline fixtures.

Given a fresh operator-produced capture in an operator-protected directory:

```powershell
# PowerShell 7; build or use an already validated native binary.
cargo build --locked --bins
$normalized = & .\target\debug\v6alias-collect-isc.exe --capture state\isc-capture.json --service-config service.example.yaml --source scout-pfsense-isc --trusted-link corp-link --max-age-secs 300 --once
if ($LASTEXITCODE -ne 0) { throw "ISC capture rejected; do not publish" }

# Use unique, noncolliding staging and destination paths in the same protected directory.
$destination = [IO.Path]::GetFullPath("state\isc-corp-observations.json")
$staged = $destination + "." + [Guid]::NewGuid().ToString("N") + ".new"
[IO.File]::WriteAllText($staged, ($normalized -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
[IO.File]::Move($staged, $destination, $true)

# Existing explicitly initialized/registered inventory only:
.\target\debug\v6aliasd.exe --database state\shadow-demo.sqlite --service-config service.example.yaml --observations $destination --source scout-pfsense-isc --trusted-link corp-link --once
```

Use an atomic same-filesystem replacement supported by the destination filesystem
and check every exit status. Never redirect stdout onto an input, config, DB, or
any hardlink/alias of them: **the shell can truncate it before the program starts**.
Do not publish partial stdout after failure. Consumers still validate freshness.
The collector preserves capture time, so rerunning it cannot refresh an old capture.
There is no deployed continuous pfSense collector: source capture refresh, protected
files, clock synchronization, and per-link daemon wiring remain operator duties.
The source label and DUID are **not authentication**.

#### Supported ISC subset and fail-closed behavior

- A byte-level lexer handles comments only outside strings. Quoted identifiers
  accept printable ASCII, escaped quote/backslash, and exactly three octal digits
  `\000`–`\377`; NUL/high bytes are preserved, never lossily decoded as UTF-8.
  Colon-separated hex byte pairs are also accepted.
- The first four identifier bytes are IAID in the **writing server's native
  endian order**, from a unique `authoring-byte-order little-endian;` or
  `big-endian;` header before associations. No host/network-endian guess is made.
  A header-only database (including server-DUID-only) is allowed; a blank file is not.
  Identical `server-duid` headers before associations may repeat, as observed on
  pfSense; comparison uses decoded bytes. Conflicting or late identities fail closed.
  IAID+DUID lengths: quoted 6–131 bytes, hex 6–132; server-DUID metadata:
  quoted 3–127, hex 3–128. DUID output uses the service's canonical lowercase hex.
- Only IA_NA is supported. IA_TA, IA_PD, `on` handlers, unknown statements,
  expressions, malformed/duplicate fields/children, and unsupported syntax reject
  the **whole file**, even after valid earlier records. Nothing is executed.
  `set` string, signed 32-bit `%number`, and boolean constants are syntax-checked
  then ignored. Hostname is always JSON `null`; inventory owns private DNS names.
- The latest **whole association in file order** replaces its predecessor,
  including empty, inactive, and expired replacements; `cltt` never sorts updates.
  Only `binding state active` with explicit `ends` later than collection time
  (or `never`) is live. Free, released, expired, and abandoned states are ignored.
  Preferred/max lifetimes are unsigned 32-bit, preferred <= max, not expiration
  calculations. Both lifetimes, binding state, and explicit ends are required.
- Finite times support strict UTC `weekday YYYY/MM/DD HH:MM:SS` in 1970–2037,
  with valid calendar/time/weekday, or `epoch 0`–`2147483646`. `cltt` is optional
  but finite; only `ends` accepts `never`. ISC's numeric MAX_TIME/year-2038 sentinel,
  numeric timezone suffixes, leap seconds, and guessed local times are rejected.
- Every live address maps to exactly one configured profile `/48` plus link subnet
  `/64`. Unknown/ambiguous scopes, cross-scope associations, cross-owner active
  address conflicts, and multiple live IAIDs for one DUID reject the entire capture,
  **including other known links before filtering**. Multiple same-scope addresses
  deduplicate to one observation. Selection is not limited to the managed low-ID pool:
  bootstrap addresses can identify known devices, but cannot authorize them.
  No registration, reclaim, or retirement is inferred.

| Bound | Maximum |
|---|---:|
| Capture JSON / decoded lease bytes | 64 MiB each |
| Service configuration / complete normalized stdout including newline | 1 MiB each |
| Raw token bytes (including quotes/escapes) | 4096 |
| Tokens | 4,000,000 |
| Association bytes (including internal comments/whitespace) | 1 MiB |
| Association records / address records, including superseded records | 65,536 / 262,144 |
| Block nesting | 2 (IA_NA and iaaddr; no recursive grammar) |
| Selected observations | 4096 |

Limits reject instead of truncating. Inputs must be regular non-symlink files;
pre/post metadata checks catch common mutation/replacement races (including inode
checks on Unix), not hostile writable-directory races or arbitrary filesystem stalls.
Normalization completes before stdout publication. Success emits **only the exact
ObservationSnapshot** to stdout; stderr has bounded JSON `validated` counts or
`fatal`/`argument_error` diagnostics, with no raw lease identifiers in counts.
`validated` means validation completed, **not that stdout was delivered**.
Publication reuses the daemon's shutdown-aware writer: stdout deadline 5 seconds,
diagnostics 100 ms. Failures exit 1 (arguments 2), possibly with partial stdout for
an output failure; only successful exit permits downstream publication.

Format references: ISC [IA key construction](https://sources.debian.org/src/isc-dhcp/4.4.3-P1-2/server/mdb6.c/#L310),
[byte-order parser](https://sources.debian.org/src/isc-dhcp/4.4.3-P1-2/server/confpars.c/#L6370),
[lease writer and bindings](https://github.com/isc-projects/dhcp/blob/v4_4_3/server/db.c#L563),
[escaping / time / lease-ID formatting](https://sources.debian.org/src/isc-dhcp/4.4.3-P1-2/common/print.c/),
and [date / quoted-ID readers](https://sources.debian.org/src/isc-dhcp/4.4.3-P1-2/common/parse.c/).
This is a deliberately narrow fail-closed reader, not general ISC configuration
evaluation or a claim of support for every historic lease database.

### Native pfSense adapter: local compiler and offline transactions

This is working native-specific Rust translation/application, **not live
integration** and not a verified public pfSense API package. The supported
contract is deliberately pinned to **pfSense 2.8.1-RELEASE, ISC 4.4.3P1,
Unbound 1.24.2**, fixed /64 scopes and operator-bound `lan`, `opt1`, `opt2`.
Different versions/backend/projection capability fail closed; Kea stays untouched.
The Rust executable has no PHP bridge, XML writer, shell command, SSH transport,
router installation, service reload, firewall change, or client static ULA change.
The separate [root-local PHP helper](#root-local-pfsense-helper-capture-only-installation)
implements collection and durable persistence; it does not install or activate itself.
`cargo run` still defaults to the original `v6alias`.

**TTL 3600 is mandatory here.** Native `unbound/hosts` has no per-host TTL field.
Installed `unbound.inc` lines 760–791 emit local-data/local-data-ptr without a
TTL; the approved Unbound 1.24.2 local-zone defaults are 3600. The source/capability
declaration must also exclude TTL overrides. The compiler never invents a
native TTL or IAID field. ISC maps only DUID; the complete immutable inventory
and assignment/tombstone history must enforce one DUID/one IAID globally.

Inputs are explicit `--database` (existing, read-only), `--service-config`,
`--bindings`, and `--capture`, followed by `plan`, `simulate`, or `rollback`.
See the complete synthetic JSON/YAML shapes in `examples\pfsense`:

- Bindings: strict version/source, link -> interface and
  `approved_reservation_addresses`. These addresses require an independent
  operator inventory/audit, **not absence in a capture**. Synthetic `::2`/`::3`
  assert nothing about availability in a real lab.
- Projection: strict version/source/original capture time, source contract,
  backend/version/TTL capability, `complete: true`, exact coverage declaration,
  full-configuration `config_revision_sha256`, `offline_generation`, all native
  scopes, `external_dns`, and raw `config` object. The hash must come from a
  trusted on-router helper; it is not a hash of this secret-free projection.
  The PHP collector has passed capture-only acceptance on the isolated router;
  live persistence and activation remain separate approval-gated work.
- Every scope declares its exact /64, router address and externally inventoried
  static addresses. The projection must also include its actual
  `config.interfaces.{interface}.ipaddrv6` and `subnetv6`: a fixed IPv6 address
  matching the declared router and the native string `"64"`. Tracked/dynamic
  modes, tracking settings, missing interfaces, and mismatched addresses fail closed.
  All native DHCPv6 scopes/staticmaps and Unbound hosts/aliases
  must be present, even on interfaces without a managed link. Primary
  `range/from`–`range/to` must be `::1000`–`::ffff`. Additional pools,
  delegated/tracked scopes and custom Unbound/backend configuration are rejected.
  Other effective DNS records (including automatic hosts, CNAME owners, PTR
  owners and addresses outside host overrides) must be represented in
  `external_dns`, without duplicating the native host records. Partial captures
  cannot establish absence of conflicts.
- Each owned native DHCPv6 object uses
  `dhcpdv6/{interface}/staticmap`: lowercase colon-separated `duid`, `ipaddrv6`,
  `hostname`, `descr`, `earlydnsregpolicy: "disable"`, empty `filename`/`rootpath`.
  One `unbound/hosts` object uses `host`, `domain`, one IPv6 `ip`, `descr` and
  `aliases: {"item":[]}`; native generation supplies AAAA/PTR.
- All unmanaged IPs (including comma-separated IPv4/IPv6 lists), host/domain
  names and aliases are inspected globally. Unmanaged conflicting DUID, IP,
  FQDN or PTR owner is never adopted. `descr: "v6alias:<asset>"` alone is not
  authority: the **entire** native object and path must derive exactly from
  retained active/retired history; altered owned objects fail closed.

`plan` emits `mode: "native_plan"`, explicit fixed allowed paths, deterministic
changes with whole `before`/`after` collections, original full-config revision,
baseline/candidate projection SHA256 and authority SHA256, plus remaining
activation requirements. `simulate [--request PATH]` recompiles from the Store
and capture (never trusts caller-supplied paths/desired objects), verifies the
reviewed request, actually transforms the supplied projection, and emits
`mode: "offline_simulation"`, `request`, `projection`, and `rollback` token.
Both modes carry `mutation_scope`, `network_writes: false`,
`approval_required: true`. There is **no live `--apply` flag**.

The output projection uses exactly the input projection schema. Existing foreign
array/object order and opaque fields are retained; only new owned entries are
sorted before appending. JSON numbers must be exact signed/unsigned 64-bit
integers; floating-point/exponent forms and out-of-range integers are rejected
throughout the document, including opaque fields, rather than rounded before
preservation or hashing. Native numeric strings remain strings.
Exact owned replay is a no-op; retirement removes only
exact matches. Hashing deliberately sorts object keys recursively, not arrays,
so equivalent JSON key order is accepted. The dependency-free SHA256 used for
state comparison has standard known-answer tests; hashes/source labels are
**not authentication**. No full router configuration or secret material is output.

`rollback --simulation PATH --current PATH` also needs the **original** capture
and unchanged authoritative configuration/history. It recompiles and verifies the
request/token and exact whole poststate/revision before reversing only those
compiled collections. Any unrelated edit, changed revision, retirement since
planning, altered token/candidate, or rollback replay fails rather than discarding
external changes. `offline_generation` advances on nonempty local transactions;
the original router hash/time are retained, never relabeled as a persisted
router revision or fresh capture. No filesystem persistence or reload orchestrator
is claimed: this is a pure value transformation with guarded rollback.

#### Synthetic PowerShell walkthrough

Use PowerShell 7 and an already built native Windows release. This makes a
unique disposable directory; successful stdout is saved only to separate files.

```powershell
Set-Location D:\v6alias
$bin = ".\target\x86_64-pc-windows-gnu\release"
$cli = Join-Path $bin "v6alias.exe"
$native = Join-Path $bin "v6alias-pfsense.exe"
$work = Join-Path $PWD ("state\native-example-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory $work | Out-Null
$db = Join-Path $work "inventory.sqlite"
$capture = Join-Path $work "capture.json"
$config = "examples\pfsense\service.yaml" # explicit TTL 3600, NEW database
$utf8 = [Text.UTF8Encoding]::new($false)
function Save-NativeJson($Path, $Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 80), $utf8)
}
function Invoke-NativeJson($Exe, [string[]]$Arguments) {
    $text = & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Rejected; do not publish partial output" }
    ($text -join "`n") | ConvertFrom-Json
}

try {
    Invoke-NativeJson $cli @("inventory", "--database", $db, "init") | Out-Null
    Invoke-NativeJson $cli @("inventory", "--database", $db, "register", "--device", "examples\pfsense\device.json") | Out-Null
    Invoke-NativeJson $cli @("service", "--database", $db, "--service-config", $config, "allocate", "--observation", "examples\pfsense\observation.json", "--trusted-link", "demo-link") | Out-Null
    $baseline = Get-Content -Raw examples\pfsense\native-foreign.json | ConvertFrom-Json
    # ONLY synthetic fixtures may be refreshed this way. NEVER retimestamp real captures.
    $baseline.captured_at_unix_secs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    Save-NativeJson $capture $baseline
    $common = @("--database", $db, "--service-config", $config,
        "--bindings", "examples\pfsense\bindings.json", "--capture", $capture)
    $request = Join-Path $work "request.json"
    Save-NativeJson $request (Invoke-NativeJson $native ($common + @("plan")))
    $sim = Invoke-NativeJson $native ($common + @("simulate", "--request", $request))
    $simulation = Join-Path $work "simulation.json"
    $current = Join-Path $work "current.json"
    Save-NativeJson $simulation $sim
    Save-NativeJson $current $sim.projection
    $rollbackArgs = $common + @("rollback", "--simulation", $simulation, "--current", $current)
    $rolled = Invoke-NativeJson $native $rollbackArgs
    $rolled.projection.config.unbound.hosts.Count # 1: original foreign host retained
    $sim.projection.config.opaque_synthetic_note.z = "concurrent external edit"
    Save-NativeJson $current $sim.projection
    $discard = & $native @rollbackArgs
    if ($LASTEXITCODE -eq 0 -or $discard) { throw "Expected drift rejection" }
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force
}
# Repeats this flow plus stale/revision/replay checks and inventory SHA256 comparison:
.\scripts\tests\Test-PfsenseNative.ps1
```

Freshness defaults to 300 seconds, with finite `--max-age-secs` 1–86400 and a
final authority/freshness recheck before publication. Inputs and output are
limited to 16 MiB (service config 1 MiB), combined native/external DNS records
to 4096, per-host IPs and aliases to 128, bindings/external static address lists
to 4096. Unknown envelope fields, duplicate JSON keys and unsupported relevant
shapes are rejected; opaque native fields are preserved, not executed.
Protected regular non-symlink local inputs are required; hostile writable-directory
races are not a supported security boundary. Stdout uses the shared bounded
5-second publisher, diagnostics 100 ms. Errors exit 1 with bounded payload-free
stderr and no plan (publication failure may leave partial stdout).
Never redirect over inputs or their aliases: the shell can truncate them before
startup. Only successful complete output may be saved by the caller.

### Remaining-fleet preparation

The accepted `scout-admin` assignment remains `corp:2`. Preparation for the
remaining clients uses an **additive expansion into a separate inventory**,
not an in-place rewrite of the accepted database. Proposed reservations, Linux
network files and native pfSense changes are review artifacts until the operator
approves a fresh, snapshot-backed rollout.

`scripts\Set-ServerCoreDhcpv6.ps1` is a console-only helper restricted to the
prepared `CORP-44` Server Core guest. Its default `Inspect` action is read-only;
`Apply` requires an explicit plan, a new private state directory and confirmation.
The helper preserves the existing native DUID/IAID, enables default-route rejection
before Router Discovery, pins IPv6 DNS, disables RA-based DNS and removes only
the planned old manual ULA. IPv4 bindings, firewall and management services are
never enabled or changed. `Verify` checks native DHCPv6 origin and exact private
DNS answers; `-WhatIf` issues no configuration commands.

The actual guest reports persistent RA-DNS as `Default`, which has no verified
exact guest-level restoration API. Its plan must therefore explicitly select
`"RollbackStrategy": "VmSnapshot"` and name an independently approved cold
`RecoverySnapshot`. The helper retains `Default` in evidence, never substitutes
`Enabled`, and never claims guest rollback succeeded for that strategy. On an
approved failure-recovery attempt, it can stop only its journaled acquisition
and report `VM_SNAPSHOT_RESTORE_REQUIRED`; the operator performs the separately
approved hypervisor restore after clean shutdown. A snapshot name in JSON is an
attestation, not proof that a snapshot exists.

Windows persistent interface metadata may also contain empty inherited
Advertising/Forwarding values. These are accepted only when the active values
are disabled, are recorded unchanged, and cannot be altered without refusal.
DNS ownership includes both effective addresses and persistent `NameServer`
contents. Failure-journal errors are reported separately and do not mask the
original failure or silently suppress approved, durably journaled recovery.

The isolation guard retains its normal five-VM demo lifecycle and keeps
quarantine off by default. A separate, explicitly approved migration caller can
request read-only observation with `allow_quarantine=True`; that still verifies
the exact quarantine disk, dedicated network, bridge membership and isolation.
It does not add quarantine to `Demo.ps1` startup/shutdown ownership.

#### Root-local pfSense helper (capture-only installation)

`scripts\pfsense\v6alias-local.php` is a finite, custom root CLI, not a REST
endpoint, listener, daemon, remote-login client, or pfSense core patch. PHP is
limited to native DOM/projection validation and filesystem operations; Rust
remains authoritative for inventory, policy, allocation, retained history, and
request compilation. No router installation or live persistence was performed
by the offline helper tests.

On September 24, 2026, the approved capture-only installation completed on
`scout-pfsense`, after cold snapshot `before-capture-helper-20260924`.
The helper resides at canonical `/cf/conf/v6alias-helper` (the router's `/conf`
is a verified alias). Files are root-owned 0600 in a 0700 directory. Its policy
approves **zero reservation addresses**. PHP 8.3.19 captured all three scopes
and 108 external DNS owners with the raw configuration hash unchanged; no
persistence journal was created. The router was cleanly stopped afterward.
No DHCP/DNS configuration or client static address changed.

Production invocation requires FreeBSD, effective UID 0, 64-bit PHP 8.3+ with
DOM/POSIX/fsync, the exact installed source hashes in `platform.php`, pfSense
2.8.1-RELEASE, ISC 4.4.3-P1, and Unbound 1.24.2. It never includes `config.inc`
(which can recover configuration, write caches, and invoke plugins merely on
include), calls `write_config`, or runs service configuration hooks. Source hashes
are from the inspected installed build, not an assumed public release tag.

**Policy is independent operator authorization.** The strict, root-owned 0600
policy has `schema_version: 1`, a DNS-label `source`, an `audit_id`,
`audited_at_unix_secs`, `max_age_secs` (1–300), `dns_zone`,
`globals_sha256`, `standard_lock_path: "/tmp/config.lock"`, `scopes`, and
`managed_interfaces`.
Every enabled native scope must be included, with its fixed `router_address`
(`::1`), complete audited `external_static_addresses`, and independently
`approved_reservation_addresses` (only managed IDs 2–4095, never router/external
addresses). Those addresses must agree with the Rust bindings. The policy's
source/zone must agree with Rust configuration. The fixture policy under
`scripts\tests\fixtures` is **not deployment authorization**.
`scopes` is complete capture/conflict coverage; `managed_interfaces` is a
nonempty, duplicate-free subset authorizing changes. A captured unmanaged
interface does not become a permitted mutation path. The subset must match the
Rust bindings; every requested change is checked against both allowlists.

The `globals_sha256` pin and lock-path declaration attest an **independent source
review** of the actual installed `globals.inc`: `tmp_path=/tmp`,
`varrun_path=/var/run`, standard config lock, and cache locations. The helper
hash-checks that file but does not execute it. These installation-specific
assumptions still need on-router read-only verification before approving a real
policy; do not substitute a freshly computed hash without reviewing its meaning.
Unsupported config-directory aliases, permissions, source changes, absent locks
outside explicit initialization, or directory-fsync support fail closed.

Command syntax below is a contract, **not approval to execute or install it**:

```text
php v6alias-local.php capture --policy FILE
php v6alias-local.php initialize-lock --policy FILE --maintenance-window
php v6alias-local.php persist --policy FILE --baseline FILE --request FILE --approve-request-sha256 HEX --maintenance-window
php v6alias-local.php status --policy FILE --transaction ID
php v6alias-local.php recover --policy FILE --transaction ID --maintenance-window
php v6alias-local.php rollback --policy FILE --transaction ID --expected-current-revision HEX --maintenance-window
php v6alias-local.php activate --policy FILE --transaction ID --expected-current-revision HEX --approve-request-sha256 HEX --maintenance-window
php v6alias-local.php verify-activation --policy FILE --transaction ID --expected-current-revision HEX --approve-request-sha256 HEX --maintenance-window
php v6alias-local.php activate-rollback --policy FILE --transaction ID --expected-current-revision HEX --approve-request-sha256 HEX --maintenance-window
php v6alias-local.php verify-rollback --policy FILE --transaction ID --expected-current-revision HEX --approve-request-sha256 HEX --maintenance-window
```

**Local-only lock milestone (not installed or executed on the router):**
`initialize-lock` is the sole operation allowed to create the exact stock
`/tmp/config.lock`. It requires the policy/source/root gates, the private helper
lock and the maintenance acknowledgement. The parent must be root-owned sticky
01777; creation is exclusive, initially 0600, then changed to the stock-compatible
0666 while holding a bounded exclusive flock. The regular root-owned single-link
inode is checked against its pathname before/after locking, chmod and fsync;
the directory is fsynced too. Existing 0666 files, or 0600 files from interrupted
initialization, are adopted without truncation or inode replacement. A racing
stock creator is verified identically; symlinks, hardlinks, foreign owners, other
modes and replaced inodes refuse. No lock is ever unlinked. Failure can leave the
same inode requiring an explicitly approved retry; it is not evidence of no
filesystem changes. The command also creates private helper state if needed.
It never writes config, invalidates caches or runs service hooks. Capture still
does not initialize any lock; ordinary persistence still refuses an absent lock.

`capture` only reads the fixed config/version/source paths and runs fixed,
bounded version commands plus local `unbound-control list_local_data` against
127.0.0.1:953. It does not make upstream DNS queries or change caches, flags,
configuration, services, or files. DOM prohibits DTDs/entities/external resolution,
namespaces/attributes and excessive depth/size. Only allowlisted native fields
are exported; raw config, keys, passwords and arbitrary extensions are not.
The initial supported subset accepts the root `dhcpbackend` value `isc`, or
the omitted/empty value that the additionally pinned `pfsense-utils.inc`
defaults to ISC. Explicit Kea and unrecognized values refuse. It requires fixed
/64s with `::1000`–`::ffff` pools, enabled Unbound, no registrations, custom
options, Python modules, domain overrides, added pools, delegation, or packages.
Unknown relevant fields refuse rather than silently disappear. DNSSEC may be
enabled because the helper never executes a restart or anchor command.
Managed RA metadata is preserved. The additionally pinned `interfaces.inc`
selects tracking only when `ipaddrv6` is `track6`; dormant tracking preferences
on an actual fixed-address interface are ignored in the projection and retained
untouched in XML. Active tracking/dynamic modes still refuse. Repeated private
system user/group entries are not exported or mistaken for duplicate DNS identity.

All native maps, hosts and aliases are projected. Runtime records matching native
A/AAAA/PTR counterparts are excluded **only on exact owner/type/address or PTR
target and TTL 3600**; missing, extra or changed native records refuse capture.
Other runtime A/AAAA addresses, PTR/CNAME and other owners become external
conflict evidence. Runtime records and raw config are reread around capture;
dirty flags and independent extension caches refuse. A successful projection
proves this bounded collection contract, **not DHCP/RA health or future address
availability**. Canonical native aliases use `{"item":[]}` even for empty XML.

`persist` requires an independently supplied approval hash of the **reviewed
canonical Rust request** (for example `simulation.rollback.request_sha256`
after operator review). Never automatically approve a file by hashing that same
unreviewed file. This is different from `request_file_sha256`, the raw-file audit
checksum. Canonical hashing recursively sorts object keys, preserves array order,
uses UTF-8 without escaping Unicode/slashes, and rejects duplicate keys/floats/
exponents/overflow. PHP deliberately accepts only signed 64-bit integers, a
safe subset of Rust's integer domain. Requests cannot supply executable commands,
filesystem destinations, or arbitrary XML paths. The helper independently checks
native fields, approved addresses, paired ownership, foreign preservation,
freshness, exact full-config revision and baseline/candidate hashes; the approved
request hash authorizes the Rust history decision, not an ownership description.

Persistence uses only the fixed `/conf/config.xml` (or verified `/cf/conf`
alias), private `/conf/v6alias` state, and standard config lock/cache. It locks
the private helper lock then the existing pfSense config flock, with bounded
nonblocking waits. Lock files are never unlinked. Private directories/files are
0700/0600, root-owned, regular and single-link; symlinks/untrusted parents refuse.
It preserves unrelated DOM nodes and existing foreign records, writes a durable
private full preimage, immutable `activation.json` evidence and schema-3
`prepared` journal in a private `.prepare-*` directory.
The complete transaction directory is atomically published and fsynced before
configuration can be replaced. It then uses same-directory exclusive
staging, full-byte CAS, file/directory fsync, atomic rename and readback. Cache
invalidation happens only after commit. The result carries the **actual new raw
revision**, `network_writes: true`, and `activation: "not_activated"`, never the
simulator's original revision mislabeled as a live result. `config_persisted`
indicates whether that command wrote config; status/recovery still identify a
committed transaction as having network-configuration writes.

The private backup contains **all router secrets**. It must stay on-router,
root-private: never stdout, source control, laptop artifacts, or transported
evidence. Journals contain only hashes/status/IDs, not config or credentials.
The evidence file retains the approved canonical request, secret-free baseline
projection and private local-DNS snapshot, not another full XML copy. Keep it
root-private/on-router too: resolver data can contain internal or sensitive names.
The journal binds its exact bytes, policy and complete current source-pin identity.
Request replay validates reservation/host ownership, DNS counterparts and exact
candidate raw hash against the private preimage before rollback/recovery or an
activation attempt. Request object keys are normalized before XML serialization
so replay is deterministic. Schema-1/2 journals explicitly require manual recovery;
there is no silent migration or guessed missing evidence. No genuine persistence
journals existed at the capture-only installation.
On failure, do not assume no write occurred. `status`, then explicitly approved
`recover`, compares the entire current config with the prepared pre/post hashes.
Recovery reconciles the journal/cache, never rewrites configuration. `rollback`
requires the exact journal postimage hash and operator-supplied expected current
revision; it restores only the verified private preimage. Foreign changes, missing
or corrupt journals/backups, or unknown states require manual investigation,
never forced rollback. `status` also checks the transaction's policy/source
identity. `runtime_health_verified: false` distinguishes configuration restoration
from service restoration. Neither `rolled_back` nor successful `recover` proves
DHCP/DNS runtime state. A crash before transaction publication leaves only an
unpublished preparation: the next persistence attempt removes its precisely
allowlisted private files, without touching configuration. Unexpected contents,
permissions or links refuse cleanup. New transactions are blocked while
an earlier transaction remains unresolved. Verified `activated` and
`rollback_verified` transactions permit the next request; old rollback still
requires the entire current config to equal that old transaction's postimage.
There is deliberately no
automatic backup pruning or activation-completion override.

`scripts\Prepare-PfsenseChange.ps1` packages a fresh projection, bindings,
service configuration, native request, simulation and review summary into a
private local directory. It includes artifact hashes and the canonical request
hash but **does not grant approval** or copy the inventory database. Its output
must be reviewed and separately approved before a root-local persistence call.
Expired captures must be recaptured, not retimestamped.

**Maintenance window is mandatory:** no UI or other configuration writers,
unrelated service restarts or reboot. The explicitly approved cold restart below
is the sole planned exception. Stock writers can retain stale in-memory configs
before acquiring their final lock; neither flock nor CAS prevents a later stale
UI write after this helper releases its lock. No atomicity across services is
claimed. Persisted changes could become active on a later reboot or unrelated
apply, so persistence is itself a live configuration change requiring approval.

#### Cold-restart activation acceptance

`activate` now **prepares durable cold-restart acceptance**, rather than always
refusing or pretending to reload. It requires the committed transaction, full
current raw revision, the independently approved canonical request hash, policy
and maintenance acknowledgement. It validates immutable request/baseline/source
evidence without requiring the not-yet-activated candidate DNS records. Under
the private helper and standard configuration locks it records
`awaiting_cold_boot`, the SHA256 of the kernel's raw `kern.boot_id` and preservation hashes of
native IPv4 DHCP/RA configurations. It never edits services or config, signals
daemons, clears dirty flags, includes native PHP, or reboots. This lab runtime
contract requires exactly the enabled fixed interfaces `em1`, `em2`, `em3`.

The v2 runtime contract reads exactly `/sbin/sysctl -b kern.boot_id`: successful
exit, no stderr, exactly 16 opaque bytes, hashed without trimming. FreeBSD's
random per-kernel-boot ID is immutable across NTP/wall-clock corrections; there
is no `kern.boottime`, host UUID or elapsed-time fallback. The
[kernel implementation](https://github.com/freebsd/freebsd-src/blob/release/14.0.0/sys/kern/kern_mib.c#L499-L523)
is present in FreeBSD 13/14/15; pfSense 2.8 uses FreeBSD 15-CURRENT, not 14.
Actual-router availability still requires read-only confirmation. A changed ID
proves a different kernel boot, **not cold versus warm restart or RAM-snapshot
restoration**. The separately approved libvirt off/start workflow supplies the
power-state evidence; the helper does not attest that evidence.

The explicit protocol, **only after exact installation/write/cutover approval**:

1. Preserve the independently approved cold snapshot and isolation guard.
   Initialize the stock lock if needed; persist the reviewed request.
2. Run `activate` with the returned transaction/postimage hash and approval.
   Confirm `awaiting_cold_boot`; the router is **not yet accepted as activated**.
3. The operator performs the separately approved router-only cold restart
   through the existing lab controller. There is no helper reboot command.
   If volatile `/tmp/config.lock` disappeared, explicitly run the separately
   approved `initialize-lock` again; verification never creates it implicitly.
4. Run `verify-activation` with the same arguments. Only changed boot identity
   **and all actual runtime checks** produce durable `activated`.

Verification uses fixed bounded argv, numeric checked PIDs and no shell:
`sysctl -b kern.boot_id`, `ps`, `procstat`, `sockstat`,
`dhcpd -6 -t -cf /var/dhcpd/etc/dhcpdv6.conf`,
`unbound-checkconf /var/unbound/unbound.conf`, and loopback-only
`unbound-control status/list_local_data` at 127.0.0.1:953. It checks all native
DHCP static-map DUID/address pairs, generated subnet/ranges and host identities;
the DHCPv6 PID, executable, family, chroot, config/interface argv and UDP6:547
listener; Unbound executable/argv, status and DNSSEC validator presence; all
native/foreign host A/AAAA/PTR counterparts and TTL 3600; and preserved external
DNS coverage. Boot, config, PID/process identities, generated DHCP bytes and DNS
data are reread to detect races. Native daemon-owned files are read through a
separate fixed-path, owner/type/link/permission-checked adapter.

Control status/local-data alone cannot pass verification. A bounded DNS wire
reader also queries UDP port 53 on **every exact policy scope `router_address`**,
requiring literal ULA targets, never a hostname, public address or OS resolver.
Each native host override (owned and foreign), alias A/AAAA and primary PTR
RRset must actually be served with exact values and TTL 3600. Questions are
permitted only after their expected name/type is verified in local-data;
recursion is disabled (`RD=0`), and CNAMEs/referrals are not followed. Even an
empty rollback must query a known local-data baseline (prefer `localhost.`
AAAA, otherwise a known system AAAA/A), with that baseline's exact TTL, including
the built-in 10800. External conflict coverage remains independently checked.
Connected literal UDP sockets restrict peers. IDs, echoed questions, flags,
compressed names and complete answer sets are validated; malformed, stale,
extra, partial, refused, truncated or timed-out answers fail closed.
There is one attempt per question, at most 2 seconds per exchange, a monotonic
30-second aggregate DNS budget, 4096 queries total, 4096 bytes per response and
256 answers per query. Oversized inventories fail explicitly, not partially.
Only complete success yields `served_query_count` and `served_answers_sha256`
in the strict v2 proof. No listener probe means no accepted proof.

IPv4 DHCP and radvd must retain their native configuration hashes and healthy
process identities. PIDs naturally change across cold boots; they must remain
stable **within verification**, not equal the preboot PIDs. DNSSEC remains
configured and its validator must be present. The helper makes no upstream
queries and never invokes `unbound-anchor`; ordinary native boot may attempt its
existing background traffic, so the external isolation guard remains mandatory.
These checks do **not** prove client lease acquisition, RA packet delivery,
client-to-router DNS connectivity or continuous production integration. Client acceptance
and packet/isolation evidence remain a separate milestone.

`activation_verifying` is durable before probes. Failures record
`activation_failed` with `recovery_required: true` (a hard interruption may leave
`activation_verifying`). Retry verification probes again; `activate` retries
never reset the original boot/preservation contract. `recover` reconciles only
known config/cache states, never invents health or overwrites a foreign edit.
Only the verification command returns `runtime_health_verified: true`.
`status`/`recover` expose historical proof as
`runtime_health_previously_verified` and hashes/counts/timestamp, not fresh health.
`runtime_activation_performed` remains false: the operator, not the helper,
caused the restart. No raw config, DNS names, DUIDs or process arguments appear
in the runtime proof.

**Rollback is explicitly two-stage:** `rollback` performs the existing full-hash
CAS restoration and records `rolled_back` / `rollback_required`, not restored
runtime. Then run `activate-rollback` with the original request approval and
the restored **before** revision, perform another separately approved cold
restart, and run `verify-rollback` with those same arguments. Baseline DHCP/DNS,
including absence of stale candidate records, must verify before
`rollback_verified`. The original IPv4/RA preservation hash cannot be rebaselined
after damage. Failed rollback verification remains `rollback_failed` and blocks
new transactions. There is no automatic compensating write on error.

**Hot reload remains future work.** The September 24 source capture resolved
`services_dhcp.inc` to `/usr/local/pfSense/include/www/services_dhcp.inc`,
SHA256 `f8caec631c20bfb0b47e20d5a3d52d03273a627d2e3a88d33a2a271efb44d282`;
this is now an explicit path/hash pin, not an assumed `/etc/inc` file. Mandatory
uncaptured include edges still include `services_dhcp.inc → config.gui.inc`,
`util.inc → Net/IPv6.php`, `interfaces.inc → ipsec.inc/vpn.inc`, and
`system.inc → syslog.inc`. The acceptance implementation needs none of these
includes. It does not substitute `write_config`, name-based kills,
`services_dhcpd_configure('inet6')` (also changes RA), or full Unbound restarts.
No native source is patched.

**Deployment boundary:** deliver the consistent six-file set `core.php`,
`storage.php`, `platform.php`, **`runtime.php`**, **`dns.php`**, `v6alias-local.php` plus the
independently reviewed private policy. Recompute/review delivery hashes. Native
pins remain in `SourceGate::PINS` and the globals pin in policy; source identity
now binds the explicit path mapping and runtime contract too. Existing four-file
capture-only installation remains untouched. Schema-1/2 journals and v1
wall-clock/control-only runtime proofs are deliberately manual-only, not silently
migrated. The PHP runtime-proof fields do not change the Rust request/projection
schema. Before client cutover, separately approve
deployment, snapshot/maintenance, exact request writes, external router-only
restart, live read-only probe compatibility and rollback acceptance. The approved
one-client trial used the separate versioned directory
`/cf/conf/v6alias-helper-live-20260924`; the original capture helper remains intact.
Actual initialization, persistence, two router boots and served-DNS acceptance
succeeded. Live rollback was not needed or exercised; its fault paths remain
covered by offline tests. The temporary client boot-report unit was disabled
after acceptance. Both trial VMs were shut down with their accepted configuration
retained and cold snapshots saved.

### WSL and a local Linux build

From Windows PowerShell, enter an already configured Ubuntu WSL installation:

```powershell
wsl --distribution Ubuntu --cd D:\v6alias
```

Then, in the WSL shell, use POSIX paths:

```bash
. "$HOME/.cargo/env"
cargo test --workspace --locked
mkdir -p state
cargo run -- inventory --database state/demo-wsl.sqlite init
cargo run -- inventory --database state/demo-wsl.sqlite register --device examples/offline/device.json
cargo run -- service --database state/demo-wsl.sqlite --service-config service.example.yaml allocate --observation examples/offline/observation.json --trusted-link corp-link
```

With the `x86_64-unknown-linux-musl` Rust target, `musl-tools`, and dependencies
already installed locally, build the static Linux CLI in WSL:

```bash
cargo build --release --target x86_64-unknown-linux-musl -p v6alias
```

Results include `target/x86_64-unknown-linux-musl/release/v6alias`, `v6aliasd`,
`v6alias-collect-isc`, and `v6alias-pfsense`.
With the Windows GNU Rust target and MinGW compiler installed, the equivalent
`cargo build --release --locked --target x86_64-pc-windows-gnu -p v6alias --bins`
produces all four `.exe` files. These are local builds only: they do not install
anything in a guest, deploy, or start a service.

## Planned architecture

- Live trusted VLAN/link observation feeding the offline policy model
- DHCPv6 reservation integration without changing the DHCPv6 protocol
- Private AAAA and `ip6.arpa` PTR synchronization
- An isolated Hyper-V demonstration using pfSense
- An external service deployment model that does not modify pfSense internals
- A packaged C++/WinRT WinUI 3 configuration app over a narrow Rust FFI

Unknown or conflicting devices must enter quarantine or be rejected. An
address assignment never grants authorization; VLAN, NAC, firewall, and
application controls remain authoritative.

Application logic for operational components—including the allocator, policy
engine, artifact models, command-line tools, and shadow daemon—is Rust. Native
dependencies such as SQLite are distinct from that application boundary. C++ is
limited to the replaceable WinUI 3/XAML presentation layer so future web and
non-Windows interfaces can reuse the same Rust APIs.

## Development

### Trying a local release build

Local development builds may be placed under ignored `dist\windows-x64` and
`dist\linux-x64` folders. The Windows x64 executable is standalone on Windows
11: neither Rust nor WSL is needed to run it. These are unsigned development
builds, not installers or published releases.

```powershell
Set-Location D:\v6alias\dist\windows-x64
.\v6alias.exe ifconfig --raw
.\v6alias.exe ifconfig
.\v6alias.exe interfaces --json
.\v6alias.exe ping corp:42 --dry-run
```

The supplied `v6alias.yaml` contains **illustrative profiles**, not your real
network configuration. Change its profile prefixes/default subnets to match
the ULAs you intend to label; this changes display/resolution only, not network
addresses. `--raw` works without any profile configuration. The accompanying
`service.example.yaml` and `examples\offline` fixtures are for offline service
experiments, never automatically applied to DHCPv6 or DNS.

The Linux executable runs on the Linux machine where it is launched. WSL
enumerates WSL's adapters, while the `.exe` above enumerates Windows adapters.
Do not assume the two machines have the same addresses.

### Rebuilding

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --locked
```

Bundled SQLite needs a local C toolchain (for example, MSVC Build Tools for
native Windows builds). The CI workflow is configured for Windows and Linux;
that configuration is not evidence of a completed CI run.

With the `x86_64-pc-windows-gnu` Rust target and MinGW-w64 cross compiler
installed in the local Ubuntu WSL build environment, a Windows build can also
be produced without installing Rust on Windows:

```bash
. "$HOME/.cargo/env"
cargo build --locked --release --target x86_64-pc-windows-gnu -p v6alias
```

Run the resulting `target\x86_64-pc-windows-gnu\release\v6alias.exe` on Windows.
Cross-compilation alone is not a runtime test; exercise the produced executable
on its target OS before distributing it.

### Guided test-lab helpers (PowerShell 7)

For this configured scout lab, start with one command from Windows:

```powershell
Set-Location D:\v6alias
.\Lab.ps1
```

The commented script displays a simple menu: **1 Open**, **2 Status**,
**3 Stop**, **4 Help**, **0 Exit**. Each action explains its steps:

- **Open** checks isolation, starts only `scout-v6alias` if it is off, then opens
  its serial console through `labagent@labhost`. Log in as `scout-user` using
  your privately chosen password. Press Enter if the console screen is blank.
- **Status** reports the service VM state and verifies isolation without
  changing anything.
- **Stop** requests a clean service-VM shutdown and waits for confirmation.
  It never force-stops a VM, even on timeout.
- **Help** explains the commands and console controls without connecting.

Use **Ctrl+]** to detach from the console and return to the menu. Detaching
does **not** log the guest out or power it off; choose **3 Stop** when finished.
No script starts pfSense, changes network settings, enables guest Internet, or
handles your guest password. A console already in use is never forcibly taken.

Direct commands are available when you do not need the menu:

```powershell
.\Lab.ps1 -Action Open
.\Lab.ps1 -Action Status
.\Lab.ps1 -Action Stop
.\Lab.ps1 -Action Open -WhatIf
```

`-WhatIf` makes no SSH connection. `-Confirm` requests confirmation before an
action. These helpers depend on the already-installed host isolation guard and
dedicated SSH setup; they fail closed if either is missing. They intentionally
cannot be pointed at another VM or host. SSH reaches the **host**; the guest
console is not a network connection into the isolated guest.

Once logged into the prepared guest, run the commented, narrated walkthrough:

```bash
python3 ~/v6alias/demo.py --pause
```

Press Enter after each of its 12 stages. It shows interface addresses, expands
an example alias, previews ping without sending traffic, creates fictional
inventory, explains policy, allocates and replays a stable number, compares a
**simulated** DNS/reservation snapshot, rejects an unknown device, and retires
only its own fictional assignment. Omit `--pause` to run continuously.

Every run creates a new `state/demo-*` scratch directory and prints its report
path. Existing databases and configuration files are untouched. Only synthetic
service output is saved; real interface addresses remain console-only. The
demo uses `v6alias.example.yaml` when packaged, leaving your display mapping in
`v6alias.yaml` alone. Live DHCPv6/DNS integration is not applied.

You can also run the same walkthrough on Windows without connecting to the lab:

```powershell
py -3 scripts\demo.py --tools dist\windows-x64 --pause
```

Python 3.10+ and the packaged native executable are required. Comments and
printed commands show precisely what is happening. For the helper-only,
offline regression suite:

```powershell
py -3 -B -m unittest discover -s scripts\tests -p "test_*.py"
.\scripts\tests\Test-LabHelpers.ps1
```

See the [testing strategy](docs/testing.md) for the core unit-test matrix,
persistence and artifact tests, FFI validation, WinUI checks, and Hyper-V
acceptance plan.

The current milestone adds offline persistence, allocation, policy, and review
plans to the tested address grammar. Live integration remains a later,
explicitly approved stage.

### Two-minute presentation outline

Keep setup out of the recording. Use only the title and final solution slides,
then one visible console. The approved routed demo uses four existing Linux
guests and pfSense. Three Linux guests stay on isolated `scout-lan`, while the
lab target uses isolated `scout-lab`. Only specific routes between those two
demo `/64`s are installed; the Linux guests have no default route or Internet
access. The quarantine client stays off, and no physical network uplink is attached.

| Guest VM (unchanged libvirt name) | Guest hostname | Alias | Role |
|---|---|---|---|
| `scout-v6alias` | `corp-10` | `corp:10` | Starting console |
| `scout-admin` | `corp-43` | `corp:43` | Ping destination |
| `scout-corp-client` | `corp-42` | `corp:42` | SSH destination |
| `scout-lab-client` | `lab-7-15` | `lab:7.15` | Cross-subnet ping destination |
| `scout-pfsense` | Existing router hostname | Not needed on screen | Routes between the isolated subnets |

The guest hostnames deliberately match the alias numbers, using DNS-compatible
hyphens. The colored prompt changes from `scout-user@corp-10` to
`scout-user@corp-42` during SSH, and changes back when you exit.

From PowerShell 7, use the **routed-demo** menu:

```powershell
Set-Location D:\v6alias
.\Demo.ps1
```

Choose **1 Open** to start/reuse the five approved guests and open the source
console. Log in as `scout-user` with your existing guest password before
recording; then prepare the shell. On a cold start, allow pfSense a few minutes
to finish booting before recording; "running" is a VM power state, not guest
network readiness.

```bash
source ~/v6alias/live-demo.bash
```

The short commands for the video are:

```bash
ifconfig
ping corp:43 -c 3
ping lab:7.15 -c 3
ssh corp:42 -l scout-user
hostname
exit
```

For key-by-key recording, save `scripts/record-demo.bash` as
`~/v6alias/record-demo.bash` in the guest, then run
`bash ~/v6alias/record-demo.bash`. It loads the live shortcuts, waits for a key,
runs `clear`, visibly types the next command, and executes it. The sequence is
`ifconfig`, the local YAML configuration, two three-reply pings, and interactive
SSH to `corp:42`. Each ping also has a ten-second deadline. Press `q` between
steps to quit; type `exit` inside SSH to finish. It stops on command failure
and does not change the calling shell. The configuration-display step is
intended for this demo recording and shows its real lab ULA prefixes.
Waiting is intentionally silent: there are no startup banners, step numbers,
keypress hints, or completion messages in the recording. Press Enter or Space
to advance, including the first command. Errors remain visible and stop the
sequence rather than hiding a failed command.

The SSH client uses a dedicated private key generated inside `corp-10`, and a
destination host key pinned from the offline `corp-42` image. No private keys
were copied to Windows or the host. The target allows only the standard demo
account using public-key authentication; agent, port, and X11 forwarding are
disabled. No password or first-use trust dialog should occur during this SSH
hop. If it fails, stop and investigate rather than weakening host-key checking.

At the **source** prompt, **Ctrl+]** detaches to the Windows menu. Choose
**3 Stop all five cleanly** when finished. `.\Demo.ps1 -Action Status` is
read-only; `-WhatIf` makes no SSH connection. Operations are serialized and
refuse unapproved guests, disks, network attachment, or host-directory mounts.
If starting fails, cleanup touches only guests whose start this invocation
confirmed. A timeout or unsuccessful start requires checking Status; it is not
permission to stop another invocation's guest.

`Lab.ps1` remains the earlier **single-VM** helper and intentionally refuses
while other demo guests are running. Use `Demo.ps1` for this live setup.

| Time | Screen and point |
|---|---|
| 0:00-0:15 | Title: normal IPv6 on the network, memorable names for people |
| 0:15-0:30 | Solution slide: `corp:42`, defaults, and decimal subnet/device numbers |
| 0:30-0:50 | `ifconfig` on `corp-10`: actual IPv6 address displayed alongside `corp:10` |
| 0:50-1:10 | `ping lab:7.15 -c 3`: real IPv6 traffic to a different isolated subnet; same-subnet `corp:43` is optional |
| 1:10-1:40 | `ssh corp:42 -l scout-user`, then `hostname` and `exit`: identity changes visibly |
| 1:40-1:55 | Close: standard packets; offline inventory/policy ready, live reconciliation still future work |

This setup demonstrates **real ping and SSH using manually pre-staged static
addresses**, not automatic live assignment by V6Alias. DHCPv6/RA are disabled
for all four Linux demo interfaces, and no DNS server is needed for the alias
resolution. The fictional offline allocator walkthrough remains separate.
The existing display configuration and databases under `~/v6alias` are
preserved; this live shell explicitly uses the isolated-demo package under
`/opt/v6alias-live-demo`. Do not publish its private local-prefix configuration.

Keep every guest on its existing scout-only segment: no home-network bridge,
NAT, physical interface attachment, or guest Internet access. Pre-login before
recording, clear old scrollback, use a readable terminal font size and the
opt-in demo shell, and never display passwords, private keys, or configuration
files containing private lab prefixes. Rehearse the exact ping/SSH direction
before recording. Shut down the five demo guests through the menu afterward.
The existing pfSense firewall policy is unchanged: adding a return route does
not grant new access from the lab profile to the corporate profile.
Pre-staging recovery snapshots and root-only copies of original network/hostname
files were retained; rollback is an explicit administrative operation, not
something the menu performs automatically.

### Windows Server 2025 Core test guest

`scout-win2025` is a separate, low-resource **Windows Server 2025 Standard Core**
test client for the native Windows V6Alias build. It has 2 vCPUs, 4 GiB RAM,
a 64 GiB thin-provisioned disk, Secure Boot, and an emulated TPM 2.0. No extra
server roles are required. The disk is emulated NVMe and the Ethernet adapter
is Intel-compatible, allowing installation with Windows inbox drivers rather
than unsigned/test-signed drivers.

Installation was completed with the only `scout-lan` NIC disconnected. After
offline configuration and native tests, the link was enabled **only on isolated
scout-lan**. This guest uses static `corp:44`, with IPv4 unbound, DHCPv6 and
Router Discovery disabled, no default route, and Windows Firewall enabled.
SSH and WinRM remain disabled. No guest Internet, activation bypass, or extra
server roles were introduced; product-key activation is still deferred.

PowerShell 7.6.6 and V6Alias are installed locally under `C:\V6Alias`. The
temporary installation/tools/test CDs have been ejected. Only checksum-verified
local setup/test copies were unblocked with explicit approval; the machine
execution policy remains unchanged. The 32-check native Server Core suite
passed before and after a clean restart, using fresh disposable SQLite state.

To open the signed-in or locked guest console, use PowerShell 7 on your laptop:

```powershell
Set-Location D:\v6alias
.\WinCoreConsole.ps1
```

This opens the existing guest's graphical console in your browser. It verifies
the guest and isolation, creates a local-only SSH-forwarded VNC connection,
and serves upstream noVNC only on `127.0.0.1`. Enter credentials **inside the
Windows guest screen**, never in chat. Keep the PowerShell window open while
using the console; press Enter there to close the helpers afterward. Closing
the viewer does not shut down the VM.

The console script never starts/stops the guest, opens a LAN listener, records
the screen, or reads passwords/private keys. It requires the staged local
noVNC/Node `ws` payload and the established dedicated `labhost` SSH connection.
Its first-setup guard currently requires all six original guests to remain off.

`Demo.ps1` still starts/stops only the existing five Linux/router demo guests.
Its guard recognizes and checks this optional seventh guest, but does not
silently add Windows to the demo lifecycle. Log into Windows as Administrator
with your privately chosen guest password. If needed, use noVNC's **Extra keys**
button to send Ctrl+Alt+Del. From SConfig choose **15** to exit to the command
shell, then enter:

```powershell
C:\V6Alias\PowerShell7\pwsh.exe -NoLogo -NoProfile
Set-Location C:\V6Alias
.\v6alias.exe ifconfig
.\v6alias.exe ping corp:42 --dry-run
```

The original peers are not automatically started. The command above previews
ping without sending traffic; remote SSH access to Windows is not configured.
The optional command-shortcut module is at `C:\V6Alias\V6AliasDemo.psm1`.

To rerun the guest's self-contained native test suite from its prepared PS7:

```powershell
& C:\V6Alias\Setup\Test-V6AliasServerCore.ps1
```

Reports are kept in a new `C:\V6Alias\state\core-smoke-*` directory each time.
The test suite uses interface reads and network-command previews, not network
probes. It checks alias display, OS metadata parity, SQLite inventory,
allocation/restart behavior, policy denial, tombstones, and review-only plans.
The initial setup and validation scripts are restricted to CORP-44 Server Core;
do not run them on your laptop. A cold internal disk snapshot named
`windows-tools-validated-20260922` preserves the pre-link-up recovery point.
The emulated NVMe device does not support managed save/resume; use a clean
shutdown rather than force-stopping it.

## Standards

- [RFC 4193: Unique Local IPv6 Unicast Addresses](https://www.rfc-editor.org/rfc/rfc4193.html)
- [RFC 9915: DHCPv6](https://www.rfc-editor.org/rfc/rfc9915.html)
- [RFC 4861: Neighbor Discovery for IPv6](https://www.rfc-editor.org/rfc/rfc4861.html)
- [RFC 4862: IPv6 Stateless Address Autoconfiguration](https://www.rfc-editor.org/rfc/rfc4862.html)

## License

No license has been selected yet. All rights are reserved until the project
owner adds a license.
