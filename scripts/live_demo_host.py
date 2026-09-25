"""Independent, read-only isolation guard and narrowly scoped five-VM controller.

Sent to python3 over SSH stdin; importing this file performs no host operations.
Provisioning may import guard, run, require, VMs, APPROVED, and IMAGES.
Optional scout-win2025 is observed for isolation, never lifecycle-owned here.
"""

from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from types import SimpleNamespace
import xml.etree.ElementTree as ET


APPROVED = ("scout-v6alias", "scout-admin", "scout-corp-client",
            "scout-pfsense", "scout-lab-client")
BLOCKED = ("scout-quar-client",)
VMs = APPROVED + BLOCKED
IMAGES = {name: f"/var/lib/libvirt/images/scout/{name}.qcow2" for name in APPROVED}
QUARANTINE_IMAGE = "/var/lib/libvirt/images/scout/scout-quar-client.qcow2"
NETWORKS = {
    "scout-wan": "virbr-scoutwan",
    "scout-lan": "virbr-scoutlan",
    "scout-lab": "virbr-scoutlab",
    "scout-quar": "virbr-scoutq",
}
VM_NETWORKS = {
    **{name: ("scout-lan",) for name in ("scout-v6alias", "scout-admin", "scout-corp-client")},
    "scout-pfsense": tuple(NETWORKS),
    "scout-lab-client": ("scout-lab",),
    "scout-quar-client": ("scout-quar",),
}
START_ORDER = ("scout-pfsense", "scout-lab-client", "scout-admin",
               "scout-corp-client", "scout-v6alias")
STOP_ORDER = tuple(reversed(START_ORDER))
STATES = ("running", "shut off")
URI = "qemu:///system"
LOCK_PATH = "/home/labagent/work/scout-live-demo-20260918/controller.lock"
WINDOWS = "scout-win2025"
WINDOWS_IMAGE = "/var/lib/libvirt/images/scout/scout-win2025.qcow2"
WINDOWS_MEDIA = frozenset(
    f"/var/lib/libvirt/images/scout/win2025-media/{filename}"
    for filename in ("windows-server-2025.iso", "virtio-win.iso",
                     "scout-win2025-tools.iso", "scout-win2025-setup.iso")
)
WINDOWS_LOADERS = frozenset((
    "/usr/share/OVMF/OVMF_CODE_4M.ms.fd",
    "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
))
WINDOWS_TEMPLATES = frozenset((
    "/usr/share/OVMF/OVMF_VARS_4M.ms.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd",
))
WINDOWS_NVRAM = {
    "/var/lib/libvirt/qemu/nvram/scout-win2025_VARS.fd": "raw",
    "/var/lib/libvirt/qemu/nvram/scout-win2025_VARS.qcow2": "qcow2",
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


@contextmanager
def controller_lock():
    """Serialize production actions without creating or accepting another directory."""
    try:
        import fcntl
    except ImportError as error:
        raise RuntimeError("The production controller requires Linux flock.") from error

    path = Path(LOCK_PATH)
    flags = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | flags)
    try:
        descriptor = os.open(path.name, os.O_CREAT | os.O_RDWR | flags, 0o600,
                             dir_fd=directory)
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and info.st_uid == os.geteuid(),
                    "Controller lock must be a single-link regular file owned by this user.")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno in (errno.EACCES, errno.EAGAIN):
                    raise RuntimeError(
                        "Controller busy: another status/start/stop action holds the lock; "
                        "retry after it finishes."
                    ) from error
                raise
            os.fchmod(descriptor, 0o600)
            yield
        finally:
            # Closing releases flock, including on failure; never unlink the inode.
            os.close(descriptor)
    finally:
        os.close(directory)


def run(*args, timeout=30):
    """Run a bounded command, pinning every virsh invocation to system libvirt."""
    command = list(args)
    if command and command[0] == "virsh":
        command[1:1] = ["--connect", URI]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout,
            check=False, env={**os.environ, "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"Command timed out after {timeout}s: {' '.join(command)}") from error
    require(
        result.returncode == 0,
        f"Command failed ({result.returncode}): {' '.join(command)}: "
        f"{result.stderr.strip() or result.stdout.strip()}",
    )
    return result.stdout.strip()


class RouteLeakError(RuntimeError):
    """Priority handoff; never treat a lost physical route as ordinary cleanup."""


def check_route(runner):
    try:
        routes = json.loads(runner("ip", "-j", "route", "get", "192.168.1.1"))
        valid = (
            isinstance(routes, list) and len(routes) == 1
            and routes[0].get("dev") == "enp0s31f6"
            and routes[0].get("type", "unicast") == "unicast"
        )
        require(valid, "192.168.1.1 is not routed exclusively via enp0s31f6.")
    except (RuntimeError, OSError, ValueError, AttributeError, TypeError) as error:
        raise RouteLeakError(
            "PRIORITY: physical-route isolation is lost or cannot be verified. "
            "Operator handoff: stop all approved scout VMs (including optional "
            "scout-win2025 if present), including any already running before this invocation, "
            "and keep scout-quar-client off, using the approved incident procedure. Normal "
            "Demo Stop refuses an unsafe guard. No broad or forced shutdown was attempted. "
            f"Route detail: {error}"
        ) from error


def read_states(runner, *, allow_quarantine=False):
    require(type(allow_quarantine) is bool, "Quarantine allowance must be an explicit boolean.")
    states = {name: runner("virsh", "domstate", name) for name in VMs}
    require(all(state in STATES for state in states.values()),
            f"Unexpected scout guest state: {states}")
    require(allow_quarantine or all(states[name] == "shut off" for name in BLOCKED),
            "scout-quar-client must remain off.")
    return states


def windows_state(runner):
    """Discover only by exact name; lookup/list failures are never treated as absence."""
    names = runner("virsh", "list", "--all", "--name").splitlines()
    if WINDOWS not in names:
        return None
    state = runner("virsh", "domstate", WINDOWS)
    require(state in STATES, f"Unexpected {WINDOWS} guest state: {state!r}")
    return state


def xml_root(text, tag, name):
    try:
        root = ET.fromstring(text)
    except ET.ParseError as error:
        raise RuntimeError(f"Invalid {tag} XML for {name}: {error}") from error
    require(root.tag == tag and root.findtext("name") == name,
            f"XML identity does not match {name}.")
    return root


def local_tag(element):
    return element.tag.rsplit("}", 1)[-1]


def check_network(text, name):
    root = xml_root(text, "network", name)
    forbidden = {
        "forward", "ip", "nat", "interface", "pf", "hostdev", "virtualport",
        "route", "physicaluplink", "uplink",
    }
    require(not any(local_tag(node) in forbidden for node in root.iter()),
            f"{name} contains forwarding, addressing, or an uplink/device.")
    bridges = root.findall("bridge")
    require(len(bridges) == 1 and bridges[0].get("name") == NETWORKS[name],
            f"{name} has an unexpected bridge.")


def check_image(path, path_factory):
    # Compare the XML string before touching the filesystem; never follow an
    # arbitrary XML path into a home directory or inspect credential material.
    image = path_factory(path)
    require(not any(part.is_symlink() for part in (image, *image.parents)),
            f"Symlinked demo image path is forbidden: {path}")
    require(image.is_file(), f"Expected demo image is not a regular file: {path}")


def check_domain_devices(root, name):
    require(not any(
        local_tag(node) in ("hostdev", "filesystem", "shmem", "virtualport",
                            "commandline", "qemu:commandline")
        or node.tag.startswith("{http://libvirt.org/schemas/domain/qemu/")
        for node in root.iter()
    ), f"{name} contains host devices, filesystems, shared memory, virtual ports, "
       "or custom QEMU configuration.")


def check_interfaces(root, name, allowed_networks, active):
    interfaces = root.findall("./devices/interface")
    require(len(interfaces) == len(allowed_networks),
            f"{name} has an unexpected NIC count.")
    networks = []
    targets = []
    for interface in interfaces:
        sources = interface.findall("source")
        require(interface.get("type") == "network" and len(sources) == 1,
                f"{name} must use only approved libvirt network NICs.")
        source = sources[0]
        network = source.get("network")
        require(network in allowed_networks and
                set(source.attrib) <= {"network", "bridge", "portid"} and
                source.get("bridge", NETWORKS[network]) == NETWORKS[network],
                f"{name} uses a nonapproved network or uplink.")
        require(not any(local_tag(node) in ("filterref", "script", "backend")
                        for node in interface.iter()),
                f"{name} has custom NIC filtering, scripts, or backend.")
        networks.append(network)
        if active:
            target = interface.find("target")
            device = target.get("dev", "") if target is not None else ""
            require(re.fullmatch(r"vnet[0-9]+", device) is not None,
                    f"{name} has an unexpected active NIC target.")
            targets.append((NETWORKS[network], device))
    require(sorted(networks) == sorted(allowed_networks),
            f"{name} does not match its approved network assignment.")
    return targets


def check_domain(text, name, active=False, path_factory=Path):
    root = xml_root(text, "domain", name)
    check_domain_devices(root, name)
    targets = check_interfaces(root, name, VM_NETWORKS[name], active)
    if name in VMs:
        image = QUARANTINE_IMAGE if name in BLOCKED else IMAGES[name]
        disks = root.findall("./devices/disk")
        require(len(disks) == 1, f"{name} must have exactly one disk and no other disk media.")
        disk = disks[0]
        source = disk.find("source")
        driver = disk.find("driver")
        require(
            disk.get("type") == "file" and disk.get("device") == "disk"
            and driver is not None and driver.get("type") == "qcow2"
            and source is not None and source.get("file") == image
            and set(source.attrib) <= ({"file", "index"} if active else {"file"})
            and (not active or "index" not in source.attrib
                 or source.get("index", "").isdigit())
            and len(disk.findall("source")) == 1
            and disk.find(".//backingStore/source") is None
            and disk.find(".//dataStore") is None and disk.find("mirror") is None,
            f"{name} must use only its exact approved qcow2 image: {image}",
        )
        check_image(image, path_factory)
    return targets


def check_windows_source(source, allowed_paths, active):
    require(set(source.attrib) <= ({"file", "index"} if active else {"file"})
            and source.get("file") in allowed_paths and not len(source)
            and ("index" not in source.attrib or re.fullmatch(r"[0-9]+", source.get("index", ""))),
            f"{WINDOWS} has an unapproved file source.")
    return source.get("file")


def check_windows_firmware(root, active):
    systems = root.findall("os")
    require(len(systems) == 1, f"{WINDOWS} requires explicit UEFI firmware.")
    system = systems[0]
    require(all(node.tag in ("type", "loader", "nvram", "boot", "bootmenu", "smbios", "firmware")
                for node in system), f"{WINDOWS} has custom OS boot configuration.")
    loaders, stores = system.findall("loader"), system.findall("nvram")
    require(len(loaders) == len(stores) == 1, f"{WINDOWS} requires UEFI loader and NVRAM.")
    loader, store = loaders[0], stores[0]
    require(loader.text in WINDOWS_LOADERS and not len(loader)
            and set(loader.attrib) <= {"readonly", "type", "secure", "format"}
            and loader.get("readonly") == "yes" and loader.get("type") == "pflash"
            and loader.get("format", "raw") == "raw"
            and loader.get("secure", "yes") in ("yes", "no"),
            f"{WINDOWS} requires an approved readonly OVMF pflash loader.")
    require(set(store.attrib) <= {"template", "templateFormat", "type", "format"}
            and store.get("type", "file") == "file"
            and ("template" not in store.attrib or store.get("template") in WINDOWS_TEMPLATES)
            and store.get("templateFormat", "raw") == "raw",
            f"{WINDOWS} has unapproved NVRAM configuration.")
    sources = store.findall("source")
    if sources:
        require(len(store) == len(sources) == 1 and not (store.text or "").strip(),
                f"{WINDOWS} has ambiguous NVRAM sources.")
        path = check_windows_source(sources[0], WINDOWS_NVRAM, active)
    else:
        require(not len(store), f"{WINDOWS} has custom NVRAM sources.")
        path = store.text
    require(path in WINDOWS_NVRAM and store.get("format", "raw") == WINDOWS_NVRAM[path],
            f"{WINDOWS} must use its exact approved NVRAM path and format.")
    # Firmware/NVRAM paths are string-checked only; no privileged host file reads.


def check_windows_graphics(root):
    graphics = root.findall("./devices/graphics")
    require(len(graphics) <= 1, f"{WINDOWS} has extra graphics devices.")
    for device in graphics:
        require(device.get("type") in ("vnc", "spice")
                and set(device.attrib) <= {"type", "port", "tlsPort", "autoport", "listen",
                                          "socket", "keymap", "passwd", "passwdValidTo",
                                          "connected", "defaultMode"}
                and all(node.tag == "listen" for node in device),
                f"{WINDOWS} has unapproved graphics configuration.")
        require("listen" not in device.attrib or device.get("listen") == "127.0.0.1",
                f"{WINDOWS} graphics must not listen outside 127.0.0.1.")
        listeners = device.findall("listen")
        require(len(listeners) <= 1 and (listeners or "listen" in device.attrib or "socket" in device.attrib),
                f"{WINDOWS} graphics requires an explicit local listener.")
        sockets = [device.get("socket")] if "socket" in device.attrib else []
        for listener in listeners:
            kind = listener.get("type")
            require(not len(listener) and kind in ("address", "socket", "none")
                    and set(listener.attrib) <= {"type", "address", "socket", "fromConfig", "autoGenerated"},
                    f"{WINDOWS} has an unapproved graphics listener.")
            if kind == "address":
                require(listener.get("address") == "127.0.0.1" and "socket" not in listener.attrib
                        and not sockets, f"{WINDOWS} graphics must listen only on 127.0.0.1.")
            else:
                require("address" not in listener.attrib and "listen" not in device.attrib,
                        f"{WINDOWS} has conflicting graphics listeners.")
                if kind == "none":
                    require("socket" not in listener.attrib and not sockets,
                            f"{WINDOWS} has conflicting graphics sockets.")
                elif "socket" in listener.attrib:
                    sockets.append(listener.get("socket"))
        require(not sockets or "listen" not in device.attrib,
                f"{WINDOWS} has conflicting graphics listeners.")
        for socket in sockets:
            require(re.fullmatch(
                r"(?:/run/libvirt/qemu/scout-win2025\.(?:vnc|spice)\.sock"
                r"|/var/lib/libvirt/qemu/domain-[0-9]+-scout-win2025/(?:vnc|spice)\.sock)",
                socket or "") is not None, f"{WINDOWS} has an unapproved graphics socket.")


def check_windows_domain(text, active=False, path_factory=Path):
    """Validate the optional guest without expanding the controller's lifecycle allowlist."""
    root = xml_root(text, "domain", WINDOWS)
    check_domain_devices(root, WINDOWS)
    require(len(root.findall("devices")) == 1, f"{WINDOWS} requires one devices section.")
    allowed_sources = set(root.findall("./devices/disk/source") +
                          root.findall("./devices/interface/source") + root.findall("./os/nvram/source"))
    for device in root.findall("./devices/serial") + root.findall("./devices/console"):
        require(device.get("type") == "pty" and device.find("log") is None,
                f"{WINDOWS} permits only PTY serial/console devices without host logs.")
        for source in device.findall("source"):
            require(active and set(source.attrib) == {"path"} and not len(source)
                    and re.fullmatch(r"/dev/pts/[0-9]+", source.get("path", "")),
                    f"{WINDOWS} has an unapproved PTY source.")
            allowed_sources.add(source)
    require(all(node in allowed_sources for node in root.iter() if local_tag(node) == "source"),
            f"{WINDOWS} has custom host/device sources.")
    require(not any(local_tag(node) in ("lease", "rng", "redirdev", "smartcard") for node in root.iter()),
            f"{WINDOWS} has unapproved host-backed devices.")
    for emulator in root.findall("./devices/emulator"):
        require(emulator.text == "/usr/bin/qemu-system-x86_64" and not emulator.attrib and not len(emulator),
                f"{WINDOWS} has an unapproved emulator.")
    targets = check_interfaces(root, WINDOWS, ("scout-lan",), active)
    interface = root.find("./devices/interface")
    source = interface.find("source")
    models, links = interface.findall("model"), interface.findall("link")
    require(not len(source) and len(models) == 1
            and models[0].attrib in ({"type": "e1000e"}, {"type": "virtio"})
            and not len(models[0])
            and len(links) <= 1 and all(link.attrib in ({"state": "down"}, {"state": "up"})
                                        and not len(link) for link in links)
            and len(interface.findall("target")) <= 1,
            f"{WINDOWS} requires one approved scout-lan NIC model/link.")
    for target in interface.findall("target"):
        require(set(target.attrib) <= {"dev", "managed"} and target.get("managed", "yes") == "yes"
                and re.fullmatch(r"vnet[0-9]+", target.get("dev", "")) and not len(target),
                f"{WINDOWS} has an unapproved NIC target.")
    disks = root.findall("./devices/disk")
    require(sum(disk.get("device") == "disk" for disk in disks) == 1,
            f"{WINDOWS} requires exactly one root disk.")
    for disk in disks:
        kind = disk.get("device")
        drivers, sources, disk_targets = (disk.findall(tag) for tag in ("driver", "source", "target"))
        require(disk.get("type") == "file" and kind in ("disk", "cdrom")
                and len(drivers) == len(disk_targets) == 1 and len(sources) <= 1
                and all(node.tag in ("driver", "source", "target", "readonly", "boot", "alias",
                                     "address", "backingStore") for node in disk)
                and all(not len(node) and not node.attrib for node in disk.findall("backingStore")),
                f"{WINDOWS} has extra or unapproved disk media.")
        driver, target = drivers[0], disk_targets[0]
        empty_optical = kind == "cdrom" and (
            not sources or all(not source.get("file") for source in sources)
        )
        # Libvirt omits the format of an empty CD tray in cold-boot runtime XML.
        format_ok = driver.get("type") == ("qcow2" if kind == "disk" else "raw")
        format_ok = format_ok or (active and empty_optical and driver.get("type") is None)
        require(driver.get("name") == "qemu" and format_ok
                and not len(driver) and target.get("bus") in
                    (("sata", "virtio", "scsi", "nvme") if kind == "disk" else ("sata", "scsi")),
                f"{WINDOWS} has an unapproved disk driver/bus.")
        if kind == "disk":
            require(len(sources) == 1 and disk.find("readonly") is None,
                    f"{WINDOWS} requires its writable root disk.")
            path = check_windows_source(sources[0], {WINDOWS_IMAGE}, active)
        else:
            readonly = disk.findall("readonly")
            require(len(readonly) == 1 and not readonly[0].attrib and not len(readonly[0]),
                    f"{WINDOWS} CDROM media must be readonly.")
            # A live-ejected optical drive retains only its libvirt source index.
            if sources and "file" not in sources[0].attrib:
                require(active and set(sources[0].attrib) <= {"index"} and not len(sources[0])
                        and ("index" not in sources[0].attrib or sources[0].get("index", "").isdigit()),
                        f"{WINDOWS} has an invalid empty optical drive.")
                path = None
            else:
                path = check_windows_source(sources[0], WINDOWS_MEDIA | {""}, active) if sources else None
        if path:
            check_image(path, path_factory)
    check_windows_firmware(root, active)
    check_windows_graphics(root)
    tpms = root.findall("./devices/tpm")
    require(len(tpms) <= 1, f"{WINDOWS} has extra TPM devices.")
    for tpm in tpms:
        backends = tpm.findall("backend")
        require(tpm.attrib in ({"model": "tpm-tis"}, {"model": "tpm-crb"})
                and len(backends) == 1 and all(node.tag in ("backend", "alias", "address") for node in tpm)
                and len(backends[0]) <= 1
                and all(node.tag == "profile" and node.attrib == {"name": "default-v1"}
                        and not len(node) for node in backends[0])
                and backends[0].get("type") == "emulator"
                and backends[0].get("version") == "2.0"
                and set(backends[0].attrib) <= {"type", "version", "persistent_state"}
                and backends[0].get("persistent_state", "yes") in ("yes", "no"),
                f"{WINDOWS} permits only an emulated TPM 2.0 without custom sources.")
    return targets


def check_bridge(runner, bridge, expected, path_factory):
    base = path_factory("/sys/class/net") / bridge
    require((base / "bridge").is_dir(), f"Expected Linux bridge is missing: {bridge}")
    require(not (base / "master").exists(), f"{bridge} must not have a master/uplink.")
    members = {item.name for item in (base / "brif").iterdir()}
    require(members == expected, f"{bridge} membership mismatch: expected {sorted(expected)}, "
            f"found {sorted(members)}; no other or physical members are permitted.")
    links = json.loads(runner("ip", "-j", "address", "show", "dev", bridge))
    require(isinstance(links, list) and len(links) == 1 and
            links[0].get("ifname") == bridge and not links[0].get("master") and
            links[0].get("addr_info") == [],
            f"{bridge} must have no master and no host IPv4 or IPv6 addresses.")


def guard(require_off=False, *, runner=None, path_factory=Path, allow_quarantine=False):
    """Return the original six states after verifying isolation, including optional Windows.

    Quarantine remains off by default. A separately approved migration caller may
    explicitly observe it running; that does not grant lifecycle ownership to Demo.
    require_off always requires all original six guests off.
    Provisioners must separately require windows_state(runner) != "running" before edits.
    """
    require(type(allow_quarantine) is bool, "Quarantine allowance must be an explicit boolean.")
    runner = runner or run
    require(runner("hostname") == "ian-thinkpad", "Unexpected Linux host; refusing.")
    require(runner("id", "-un") == "labagent", "Expected the labagent host identity.")
    require(runner("virsh", "uri") == URI, "Expected qemu:///system.")
    check_route(runner)
    try:
        states = read_states(runner, allow_quarantine=allow_quarantine)
        optional_state = windows_state(runner)
        if require_off:
            require(all(states[name] == "shut off" for name in VMs),
                    "All six original guests must be off for this operation."
                    if allow_quarantine else
                    "All five approved demo guests must be off for this operation.")
        for network in NETWORKS:
            info = runner("virsh", "net-info", network)
            require(re.search(r"^Active:\s+yes\s*$", info, re.M) is not None and
                    re.search(r"^Persistent:\s+yes\s*$", info, re.M) is not None,
                    f"{network} must be active and persistent.")
            for suffix in ((), ("--inactive",)):
                check_network(runner("virsh", "net-dumpxml", network, *suffix), network)
        expected = {bridge: set() for bridge in NETWORKS.values()}
        observed = dict(states)
        if optional_state is not None:
            observed[WINDOWS] = optional_state
        for name, state in observed.items():
            checker = check_windows_domain if name == WINDOWS else check_domain
            arguments = () if name == WINDOWS else (name,)
            checker(runner("virsh", "dumpxml", name, "--inactive"), *arguments,
                    path_factory=path_factory)
            if state == "running":
                targets = checker(runner("virsh", "dumpxml", name), *arguments,
                                  active=True, path_factory=path_factory)
                for bridge, device in targets:
                    require(not any(device in members for members in expected.values()),
                            f"Duplicate NIC target: {device}")
                    expected[bridge].add(device)
        for bridge, members in expected.items():
            check_bridge(runner, bridge, members, path_factory)
        require(read_states(runner, allow_quarantine=allow_quarantine) == states,
                "Guest states changed during verification; retry Status.")
        require(windows_state(runner) == optional_state,
                "Optional Windows presence/state changed during verification; retry Status.")
        return states
    finally:
        # A route failure takes priority over any other guard error.
        check_route(runner)


def snapshot(safety, require_off=False):
    states = safety.guard(require_off=require_off)
    require(isinstance(states, dict) and set(states) == set(VMs),
            "Guard must return exactly the six allowlisted scout VM states.")
    require(all(value in STATES for value in states.values()) and
            all(states[name] == "shut off" for name in BLOCKED),
            "Guard returned unsafe or unexpected guest states.")
    require(not require_off or all(states[name] == "shut off" for name in APPROVED),
            "The five demo VMs are not all off.")
    return states


def clean_stop(safety, name, clock=time.monotonic, sleep=time.sleep):
    require(name in APPROVED, "Clean shutdown is restricted to the five approved VMs.")
    deadline = clock() + 120
    safety.run("virsh", "shutdown", name, timeout=30)
    while True:
        remaining = deadline - clock()
        require(remaining > 0, f"Clean shutdown of {name} exceeded 120 seconds; "
                "check Status. No force-stop was attempted.")
        state = safety.run("virsh", "domstate", name, timeout=min(30, remaining))
        if state == "shut off":
            return
        require(state == "running", f"{name} entered unexpected state {state!r}; "
                "check Status. No force-stop was attempted.")
        sleep(min(3, max(0, deadline - clock())))


def rollback(safety, started, stop):
    errors = []

    def recovery_snapshot():
        try:
            snapshot(safety)
        except RouteLeakError:
            raise
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
            errors.append(f"recovery verification: {error}")

    if not started:
        recovery_snapshot()
    for name in reversed(started):
        recovery_snapshot()
        try:
            # Isolation may be the reason startup failed. Recovery is restricted
            # to confirmed successful starts; never stop an uncertain start or a
            # pre-existing running guest.
            state = safety.run("virsh", "domstate", name)
            require(state in STATES, f"{name} has unexpected recovery state {state!r}.")
            if state == "running":
                stop(safety, name)
        except RouteLeakError:
            raise
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
            errors.append(f"{name}: {error}")
        recovery_snapshot()
    return errors


def perform(action, safety=None, *, stop=clean_stop):
    require(action in ("status", "start", "stop"), "Only status, start, or stop is supported.")
    if safety is None:
        with controller_lock():
            return _perform(action, SimpleNamespace(guard=guard, run=run), stop=stop)
    return _perform(action, safety, stop=stop)


def _perform(action, safety, *, stop):
    states = snapshot(safety)
    original_running = {name for name in APPROVED if states[name] == "running"}
    changed = []
    started = []
    pending = None
    try:
        order = START_ORDER if action == "start" else STOP_ORDER if action == "stop" else ()
        for name in order:
            states = snapshot(safety)
            if action == "start" and states[name] == "shut off":
                require(name not in original_running,
                        f"Pre-existing running guest {name} changed state; check Status.")
                pending = name
                safety.run("virsh", "start", name)
                started.append(name)
                pending = None
                changed.append(name)
                states = snapshot(safety)
                require(states[name] == "running", f"Startup of {name} was not confirmed.")
            elif action == "stop" and states[name] == "running":
                stop(safety, name)
                changed.append(name)
                states = snapshot(safety)
                require(states[name] == "shut off", f"Shutdown of {name} was not confirmed.")
        states = snapshot(safety, require_off=(action == "stop"))
        wanted = {"start": "running", "stop": "shut off"}.get(action)
        require(wanted is None or all(states[name] == wanted for name in APPROVED),
                f"Requested {action} state was not confirmed for all five VMs.")
    except RouteLeakError:
        # Do not turn an incident requiring all-scout operator intervention into
        # an ordinary rollback or hide it behind a lower-priority cleanup error.
        raise
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        if action == "start":
            uncertain = (
                f" Startup status uncertain for {pending}: virsh start did not confirm "
                "success; it may be running. Manual attention required; no shutdown "
                "was attempted for this guest."
            ) if pending is not None else ""
            try:
                errors = rollback(safety, started, stop)
            except RouteLeakError as incident:
                raise RouteLeakError(
                    f"{incident} Original start failure: {error}.{uncertain}"
                ) from error
            if errors:
                detail = "Cleanup failed: " + "; ".join(errors)
            elif started:
                detail = "Only guests with confirmed successful starts by this invocation were cleanly stopped."
            else:
                detail = "No guest was confirmed started by this invocation; no rollback shutdown was attempted."
            raise RuntimeError(f"Start failed: {error}.{uncertain} {detail} "
                               "Check Status before retrying; no force-stop was attempted.") from error
        if action == "stop":
            raise RuntimeError(f"Stop failed: {error}. Some demo VMs may already be stopped "
                               f"(confirmed changes: {changed}); check Status before retrying. "
                               "No force-stop was attempted.") from error
        raise
    return {
        "mode": "routed_demo", "action": action,
        "states": {name: states[name] for name in APPROVED},
        # Legacy flag refers to blocked quarantine, not optional observed Windows.
        "isolation": "verified", "other_vms_off": True, "changed": changed,
    }


def main():
    require(len(sys.argv) == 2 and sys.argv[1] in ("status", "start", "stop"),
            "Usage: python3 - status|start|stop")
    print(json.dumps(perform(sys.argv[1])), flush=True)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Five-VM routed demo action failed: {error}", file=sys.stderr)
        sys.exit(1)
