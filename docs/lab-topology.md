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
| `scout-win2025` | Windows Server 2025 Standard Core client-tool testing | Corporate |

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

## Original bootstrap baseline

- pfSense 2.8.1 boots from a pristine post-install clone.
- Corporate IPv4 is `10.50.0.1/24`, pool `10.50.0.100-199`.
- Lab IPv4 is `10.51.0.1/25`, pool `10.51.0.32-99`.
- Quarantine IPv4 is `10.51.0.129/25`, pool `10.51.0.160-223`.
- `scout-admin` receives `10.50.0.100`, reaches pfSense over ICMP and HTTPS,
  and has a captured DHCP Discover/Offer/Request/ACK exchange.
- IPv6 addresses and Router Advertisements are intentionally not configured
  until the profile prefixes above are persisted and reviewed.

The bootstrap baseline above records the original installation, not the
current IPv6 configuration. The later live demonstration uses manually staged
Linux ULAs and explicit inter-subnet routes, without guest default routes.
The Windows test adapter is IPv6-only, with DHCPv6 and Router Discovery disabled.

## Read-only backend discovery: September 23, 2026

Only `scout-pfsense` was temporarily started for this inspection. No guest
configuration, DHCP reservations, DNS records, firewall rules, or physical
networking were changed. It was cleanly stopped afterward; all six original
guests were off, and the previously running Windows guest remained running.

| Component | Observed state |
|---|---|
| pfSense | 2.8.1-RELEASE |
| Active DHCP backend | ISC DHCP 4.4.3P1; separate IPv4 and IPv6 `dhcpd` processes |
| Kea | 2.6.2 installed; DHCPv4, DHCPv6, and Control Agent processes not running |
| DHCPv6 scopes | Corporate, lab, and quarantine enabled; managed RA; no static mappings |
| Bootstrap pools | Each configured `/64` uses `::1000` through `::ffff` |
| ISC lease source | `/var/dhcpd/var/db/dhcpd6.leases`; no IA_NA or IA_PD records at inspection |
| Private DNS | Unbound 1.24.2; no host/domain overrides; DHCP/static registration disabled |
| Unbound control | Local TLS control on `127.0.0.1:953`; read-only status succeeded |

pfSense's installed configuration generator creates ISC DHCPv6 static mappings
using the client's DUID (`host-identifier option dhcp6.client-id`) and
`fixed-address6`. This is not proof of an external reservation-management API.
No API package was found in the package-name inspection, and no durable external
DHCPv6/DNS write contract has been verified.

The read-only `v6alias-collect-isc` normalizer derives placement from lease
addresses and operator-verified configured scope mappings: `lan`/`em1` is corporate,
`opt1`/`em2` is lab, and `opt2`/`em3` is quarantine. Do not treat the
client-supplied hostname as placement or authentication. It emits the normalized
observation-file contract accepted by `v6aliasd`.

A one-shot read-only console capture of the actual ISC lease file was processed
through the native Windows collector and shadow daemon for all three scopes.
Its original capture timestamp was retained, with an explicit one-hour maximum
age for the retained development capture. It contained no client associations,
so each scope correctly yielded zero observations and no new assignments.
Two identical server-DUID headers in that file exposed and corrected a parser
compatibility issue; conflicting server identities remain rejected.

This proves the captured-file path, not real client arrival, continuous remote
collection, or DHCPv6 address delivery. No clients or static ULAs were changed;
pfSense was cleanly stopped after capture. A continuously refreshed, trusted
capture transport is not deployed. Static-to-DHCPv6 migration remains an
explicitly approved, snapshot-backed, one-client-at-a-time step.

The existing one-DUID/one-IAID inventory restriction must remain explicit when
mapping to pfSense's DUID-based reservations. A later write adapter also needs
an approved, persistent configuration path, exact ownership checks, rollback,
and client address-reacquisition behavior. Editing generated DHCP configuration
or inserting transient Unbound records is not sufficient persistence.
Switching to Kea, exposing a management API, or applying any DHCP/DNS changes
requires separate approval.

## Persistent-adapter discovery

The installed 2.8.1 source, rather than an unverified public release branch, was
captured read-only and hash-checked for the next integration stage. No live
configuration contents were exported. pfSense was cleanly stopped afterward;
its configuration hash still matched the earlier inspection.

Native Unbound host overrides persist host/domain/address/description/aliases,
but expose no per-record TTL. The installed `unbound_generate_zone_data()` emits
AAAA and PTR data without a TTL; the matching Unbound 1.24.2 parser supplies
3600 seconds. The approved integration policy is to use these native one-hour
records, not custom DNS configuration or pfSense patches. The provider must
require an explicit matching TTL policy; legacy five-minute configurations and
previously pinned databases must not silently change.

For urgent DNS changes, reloading or restarting Unbound does not invalidate
answers already cached elsewhere. The controlled `scout-*` fleet can have its
OS resolver caches cleared individually during approved maintenance; application
caches and existing connections must also be considered. No cache flush or
resolver restart is implied by choosing the native TTL.

Configuration-file persistence and service activation are separate operations.
The installed `write_config()` returns the resulting configuration array on
success, not boolean `true`; failure can return `false` or `-1`. Its file writer
locks the final serialization/write, not the whole read-modify-write operation.
It also has optional synchronization/plugin/remote-backup side effects. A custom
privileged helper would therefore need verified revision checks, narrowly scoped
changes, explicit side-effect controls, and conflict-aware recovery. A filesystem
lock or a backup alone does not establish an atomic DHCP-and-DNS transaction.
The helper progressed from capture-only validation to the separately approved
one-client persistence and cold-restart acceptance described below.

The local `v6alias-pfsense` compiler now translates retained V6Alias assignments
into those concrete native collections and supports guarded application and
rollback over offline configuration projections. Its one-hour TTL setting is
explicit; legacy five-minute configuration identities remain compatible.
Source projections must include the actual fixed interface configuration, and
lossy JSON numeric representations are rejected before state comparisons.
These local operations are not persistent writes to the router.

The source-specific activation boundary has additional effects: calling
`services_dhcpd_configure('inet6')` also configures Router Advertisements and has
no success return value. `services_unbound_configure(false)` stops/restarts the
resolver and invokes host-file and DHCP-lease integration. Its return value
alone does not establish resolver health. Offline native-configuration planning
must therefore remain distinct from a future privileged executor, which needs
source-contract gating, post-write readback, runtime checks, and a separately
approved maintenance window before any static-to-DHCPv6 cutover.

## Capture-only helper installation: September 24, 2026

The approved installation followed cold snapshot
`before-capture-helper-20260924`. The root-private helper is located at canonical
`/cf/conf/v6alias-helper`, reached through the router's verified `/conf` alias.
Files are 0600, the directory 0700, and the installed policy approves zero
reservation addresses.

The actual PHP 8.3.19 collector successfully captured all three scopes and 108
external DNS owners, without changing the configuration hash or creating a
persistence journal. Its output was accepted by the Windows native compiler
and a zero-change review bundle using an empty local inventory. This is capture
acceptance only: no reservation, host override, reload, cache flush or client
address change occurred. All six original guests were off afterward; Windows
remained running and isolated.

Installation exposed source-specific normalization details now covered by
regressions: root-level/default ISC selection, managed RA priority `medium`,
root-owned sticky `/var/run`, dormant tracking preferences on a fixed interface,
and legitimate repeated private system groups. Active tracked IPv6 mode still
refuses. The standard config lock was absent on this boot; live persistence
cannot proceed until its safe initialization contract is separately addressed.

## First-client trial preparation

Local code now implements explicit standard-lock initialization and acceptance
after an externally controlled router restart. Runtime checks use the immutable
16-byte `kern.boot_id`, exact DHCPv6 process/configuration/listener evidence, and
bounded direct AAAA/PTR queries to the configured router ULAs. Control-channel
record listings alone cannot establish DNS service health. Service-only hot
reload remains deferred.

The first client is `scout-admin`, preserving the existing demo source
and SSH target. The approved trial replaced static `corp:43` with a
pre-enrolled DHCPv6 reservation at `corp:2`, and publishes
`scout-admin.v6alias.home.arpa.` with native one-hour AAAA/PTR TTL. It keeps the
client hostname unchanged, pins DNS to the corporate router, and suppresses
SLAAC addresses and RA default routes while accepting the on-link prefix.
Existing demo commands that ping `corp:43` need a separately reviewed target
update to `corp:2`; installed recording scripts and user videos were not rewritten.

## First-client live acceptance: September 24, 2026

Cold snapshots `before-first-live-dhcpv6-20260924` protect both `scout-pfsense`
and `scout-admin`. The versioned six-file helper and one-address policy were
installed at `/cf/conf/v6alias-helper-live-20260924`. A fresh capture and
authoritative compilation matched the reviewed change pair before persistence:
one corporate ISC DHCPv6 reservation and one native Unbound host override.

Explicit standard-lock initialization and persistence succeeded. After each of
two graceful router cold starts, the helper confirmed a changed kernel boot ID,
the exact DHCPv6 reservation, six served AAAA/PTR queries across the three router
interfaces, and unchanged IPv4 DHCP/RA configuration hashes. `scout-admin` passed
all 15 client assertions on two distinct boots, including networkd-reported
DHCPv6 origin, fixed DUID/IAID, private DNS and absence of default routes.

The read-only acceptance script initially expected wire-format DUID metadata;
systemd 255 reports `UUID:<hex>`. Only that assertion was corrected, and the
network configuration did not change during the correction. Acceptance then
passed. The temporary reporting unit is disabled; the client network configuration
remains persistent. Cold snapshots `first-dhcpv6-accepted-20260924` preserve the
accepted state. All six original VMs were off at handoff, with Windows still
running and isolation intact. No rollback or forced shutdown was required.

This establishes one pre-enrolled client's actual delivery and DNS persistence.
It does not establish unattended lease-arrival ingestion, automatic runtime
application, hot reload, or migration of the remaining static clients.
