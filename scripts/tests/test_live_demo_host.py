"""Offline only: fake host operations; POSIX lock tests use project-local files."""

import builtins
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import unittest
from unittest.mock import patch
from uuid import uuid4
import xml.etree.ElementTree as ET


SPEC = importlib.util.spec_from_file_location(
    "live_demo_host", Path(__file__).resolve().parents[1] / "live_demo_host.py"
)
host = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(host)

EXPECTED_APPROVED = ("scout-v6alias", "scout-admin", "scout-corp-client",
                     "scout-pfsense", "scout-lab-client")
EXPECTED_NETWORKS = {
    "scout-v6alias": ("scout-lan",),
    "scout-admin": ("scout-lan",),
    "scout-corp-client": ("scout-lan",),
    "scout-pfsense": ("scout-wan", "scout-lan", "scout-lab", "scout-quar"),
    "scout-lab-client": ("scout-lab",),
    "scout-quar-client": ("scout-quar",),
}


class Safety:
    def __init__(self, running=()):
        self.states = {name: "running" if name in running else "shut off" for name in host.VMs}
        self.calls = []
        self.guards = 0
        self.fail_guard = None
        self.fail_start = None
        self.fail_shutdown = None

    def guard(self, require_off=False):
        self.guards += 1
        self.calls.append(("guard", require_off))
        if self.fail_guard:
            self.fail_guard(self)
        if require_off and any(self.states[name] != "shut off" for name in host.APPROVED):
            raise RuntimeError("must be off")
        return dict(self.states)

    def run(self, *args, timeout=30):
        self.calls.append(args)
        tool, action, name = args
        assert tool == "virsh" and name in host.APPROVED
        if action == "start":
            self.states[name] = "running"
            if name == self.fail_start:
                raise RuntimeError("original start error")
        elif action == "shutdown":
            if name == self.fail_shutdown:
                raise RuntimeError("cleanup shutdown error")
            self.states[name] = "shut off"
        elif action == "domstate":
            return self.states[name]
        else:
            raise AssertionError(args)
        return "success"

    @property
    def mutations(self):
        return [call for call in self.calls if call[0] == "virsh" and call[1] != "domstate"]


class OperationsTests(unittest.TestCase):
    def test_exact_routed_allowlist_order_images_and_shared_lock(self):
        self.assertEqual(host.APPROVED, EXPECTED_APPROVED)
        self.assertEqual(host.BLOCKED, ("scout-quar-client",))
        self.assertEqual(host.VMs, EXPECTED_APPROVED + ("scout-quar-client",))
        self.assertEqual(host.VM_NETWORKS, EXPECTED_NETWORKS)
        self.assertEqual(host.START_ORDER, ("scout-pfsense", "scout-lab-client", "scout-admin",
                                           "scout-corp-client", "scout-v6alias"))
        self.assertEqual(host.STOP_ORDER, tuple(reversed(host.START_ORDER)))
        self.assertEqual(host.IMAGES, {
            name: f"/var/lib/libvirt/images/scout/{name}.qcow2" for name in EXPECTED_APPROVED
        })
        self.assertEqual(host.LOCK_PATH,
                         "/home/labagent/work/scout-live-demo-20260918/controller.lock")

    def test_status_read_only_and_exact_schema(self):
        for running in ((), host.APPROVED, ("scout-admin",), ("scout-pfsense", "scout-lab-client")):
            safety = Safety(running)
            self.assertEqual(host.perform("status", safety), {
                "mode": "routed_demo", "action": "status",
                "states": {name: safety.states[name] for name in host.APPROVED},
                "isolation": "verified", "other_vms_off": True, "changed": [],
            })
            self.assertEqual(safety.mutations, [])

    def test_start_stop_order_and_idempotence(self):
        safety = Safety()
        self.assertEqual(host.perform("start", safety)["changed"], list(host.START_ORDER))
        self.assertEqual(host.perform("start", safety)["changed"], [])
        self.assertEqual(host.perform("stop", safety)["changed"], list(host.STOP_ORDER))
        self.assertEqual(host.perform("stop", safety)["changed"], [])
        self.assertEqual(safety.mutations,
                         [("virsh", "start", name) for name in host.START_ORDER] +
                         [("virsh", "shutdown", name) for name in host.STOP_ORDER])

    def test_guard_snapshots_surround_every_start_and_stop(self):
        safety = Safety()
        host.perform("start", safety)
        host.perform("stop", safety)
        for index, call in enumerate(safety.calls):
            if call[0] == "virsh" and call[1] == "start":
                self.assertEqual(safety.calls[index - 1][0], "guard")
                self.assertEqual(safety.calls[index + 1][0], "guard")
            elif call[0] == "virsh" and call[1] == "shutdown":
                self.assertEqual(safety.calls[index - 1][0], "guard")
                self.assertEqual(safety.calls[index + 1], ("virsh", "domstate", call[2]))
                self.assertEqual(safety.calls[index + 2][0], "guard")

    def test_invalid_action_and_failed_preflight_do_not_mutate(self):
        for action in ("destroy", "status", "start", "stop"):
            safety = Safety(host.APPROVED)
            def failure(_):
                raise RuntimeError("isolation failed")
            safety.fail_guard = failure
            with self.assertRaises(RuntimeError):
                host.perform(action, safety)
            self.assertEqual(safety.mutations, [])

    def test_invalid_guard_states_fail_before_mutation(self):
        variants = [
            {"scout-quar-client": "running"}, {"scout-admin": "paused"},
            {"scout-admin": True}, {"lab-production": "running"},
        ]
        for variant in variants:
            safety = Safety()
            safety.states.update(variant)
            with self.assertRaises(RuntimeError):
                host.perform("start", safety)
            self.assertEqual(safety.mutations, [])

    def test_guard_requires_exact_six_states_not_old_three_or_only_approved(self):
        for names in (EXPECTED_APPROVED[:3], EXPECTED_APPROVED, host.VMs + ("foo",)):
            for action in ("status", "start", "stop"):
                safety = Safety()
                safety.states = {name: "shut off" for name in names}
                with self.assertRaisesRegex(RuntimeError, "exactly the six"):
                    host.perform(action, safety)
                self.assertEqual(safety.mutations, [])

    def test_preexisting_router_and_lab_target_are_reused_not_rolled_back(self):
        safety = Safety(("scout-pfsense", "scout-lab-client"))
        safety.fail_start = "scout-v6alias"
        with self.assertRaisesRegex(RuntimeError, "status uncertain for scout-v6alias"):
            host.perform("start", safety)
        for name in ("scout-pfsense", "scout-lab-client"):
            self.assertEqual(safety.states[name], "running")
            self.assertFalse(any(call[2] == name for call in safety.mutations))
        self.assertEqual([call[2] for call in safety.mutations if call[1] == "shutdown"],
                         ["scout-corp-client", "scout-admin"])

    def test_partial_start_rollback_preserves_preexisting_running_guest(self):
        safety = Safety(("scout-admin",))
        safety.fail_start = "scout-v6alias"
        with self.assertRaisesRegex(RuntimeError, "original start error.*cleanly stopped"):
            host.perform("start", safety)
        self.assertEqual(safety.states["scout-admin"], "running")
        self.assertEqual(safety.states["scout-v6alias"], "running")
        self.assertEqual(safety.states["scout-corp-client"], "shut off")
        self.assertEqual(safety.mutations, [
            ("virsh", "start", "scout-pfsense"),
            ("virsh", "start", "scout-lab-client"),
            ("virsh", "start", "scout-corp-client"),
            ("virsh", "start", "scout-v6alias"),
            ("virsh", "shutdown", "scout-corp-client"),
            ("virsh", "shutdown", "scout-lab-client"),
            ("virsh", "shutdown", "scout-pfsense"),
        ])

    def test_failed_start_is_uncertain_and_never_owned_even_if_running(self):
        for failed in host.START_ORDER:
            with self.subTest(failed=failed):
                safety = Safety()
                safety.fail_start = failed
                with self.assertRaisesRegex(
                    RuntimeError, f"status uncertain for {failed}.*may be running.*Manual attention"
                ):
                    host.perform("start", safety)
                self.assertEqual(safety.states[failed], "running")
                self.assertNotIn(("virsh", "shutdown", failed), safety.mutations)
                confirmed = host.START_ORDER[:host.START_ORDER.index(failed)]
                self.assertEqual(
                    [call[2] for call in safety.mutations if call[1] == "shutdown"],
                    list(reversed(confirmed)),
                )
                self.assertTrue(all(safety.states[name] == "shut off" for name in confirmed))

    def test_competing_start_after_snapshot_does_not_claim_other_invocation_guest(self):
        safety = Safety(("scout-admin",))
        original = safety.run
        def competing_start(*args, **kwargs):
            if args == ("virsh", "start", "scout-v6alias"):
                self.assertEqual(safety.calls[-1][0], "guard")
                self.assertEqual(safety.states["scout-v6alias"], "shut off")
                safety.states["scout-v6alias"] = "running"
                safety.calls.append(args)
                raise RuntimeError("domain is already active: competing invocation won")
            return original(*args, **kwargs)
        with patch.object(safety, "run", side_effect=competing_start):
            with self.assertRaisesRegex(RuntimeError, "already active.*status uncertain.*Manual attention"):
                host.perform("start", safety)
        self.assertEqual(safety.states["scout-admin"], "running")
        self.assertEqual(safety.states["scout-v6alias"], "running")
        self.assertEqual(safety.states["scout-corp-client"], "shut off")
        self.assertEqual([call for call in safety.mutations if call[1] == "shutdown"],
                         [("virsh", "shutdown", name) for name in
                          ("scout-corp-client", "scout-lab-client", "scout-pfsense")])

    def test_start_command_error_types_preserve_uncertain_guest_and_roll_back_siblings(self):
        for error in (RuntimeError("command failed"), OSError("command unavailable"),
                      ValueError("invalid command"),
                      subprocess.TimeoutExpired("virsh start", 30),
                      subprocess.CalledProcessError(1, "virsh start")):
            with self.subTest(error=type(error).__name__):
                safety = Safety()
                original = safety.run
                def failing_command(*args, **kwargs):
                    result = original(*args, **kwargs)
                    if args == ("virsh", "start", "scout-corp-client"):
                        raise error
                    return result
                with patch.object(safety, "run", side_effect=failing_command):
                    with self.assertRaisesRegex(RuntimeError, "status uncertain for scout-corp-client"):
                        host.perform("start", safety)
                self.assertEqual(safety.states["scout-admin"], "shut off")
                self.assertEqual(safety.states["scout-corp-client"], "running")
                self.assertEqual(safety.states["scout-v6alias"], "shut off")
                confirmed = host.START_ORDER[:host.START_ORDER.index("scout-corp-client")]
                self.assertEqual([call[2] for call in safety.mutations if call[1] == "shutdown"],
                                 list(reversed(confirmed)))
                self.assertTrue(all(safety.states[name] == "shut off" for name in confirmed))

    def test_post_start_guard_failure_rolls_back(self):
        safety = Safety()
        def failure(s):
            if s.guards == 3:
                raise RuntimeError("post-start isolation failure")
        safety.fail_guard = failure
        with self.assertRaisesRegex(RuntimeError, "post-start isolation failure"):
            host.perform("start", safety)
        self.assertTrue(all(state == "shut off" for state in safety.states.values()))
        self.assertEqual(safety.mutations, [
            ("virsh", "start", "scout-pfsense"), ("virsh", "shutdown", "scout-pfsense")
        ])

    def test_cleanup_failure_preserves_original_and_continues_other_cleanup(self):
        safety = Safety()
        safety.fail_start = "scout-v6alias"
        safety.fail_shutdown = "scout-corp-client"
        with self.assertRaisesRegex(RuntimeError, "original start error.*Cleanup failed.*cleanup shutdown error"):
            host.perform("start", safety)
        self.assertEqual(safety.states["scout-admin"], "shut off")
        self.assertEqual(safety.states["scout-corp-client"], "running")
        self.assertEqual(safety.states["scout-v6alias"], "running")
        self.assertNotIn(("virsh", "shutdown", "scout-v6alias"), safety.mutations)
        self.assertEqual(safety.states["scout-lab-client"], "shut off")
        self.assertEqual(safety.states["scout-pfsense"], "shut off")
        self.assertEqual(safety.mutations[-1], ("virsh", "shutdown", "scout-pfsense"))

    def test_route_failure_during_cleanup_preserves_original_and_priority(self):
        safety = Safety()
        safety.fail_start = host.START_ORDER[0]
        def failure(s):
            if s.guards >= 3:
                raise host.RouteLeakError("PRIORITY: stop all approved scout VMs")
        safety.fail_guard = failure
        with self.assertRaisesRegex(host.RouteLeakError, "PRIORITY.*Original start failure: original start error"):
            host.perform("start", safety)
        self.assertEqual(safety.mutations, [("virsh", "start", host.START_ORDER[0])])

    def test_route_failure_in_sibling_cleanup_takes_priority_over_uncertain_start(self):
        safety = Safety()
        safety.fail_start = "scout-corp-client"
        def incident(*_):
            raise host.RouteLeakError("PRIORITY: stop all approved scout VMs, including already running")
        with self.assertRaisesRegex(host.RouteLeakError, "PRIORITY.*all approved.*Original start failure.*uncertain"):
            host.perform("start", safety, stop=incident)
        attempted = host.START_ORDER[:host.START_ORDER.index(safety.fail_start) + 1]
        self.assertTrue(all(safety.states[name] == "running" for name in attempted))
        self.assertFalse(any(call[1] == "shutdown" for call in safety.mutations))

    def test_stop_failure_reports_partial_state_without_starting_anything(self):
        safety = Safety(host.APPROVED)
        safety.fail_shutdown = "scout-corp-client"
        with self.assertRaisesRegex(RuntimeError, "Some demo VMs may already be stopped.*Status"):
            host.perform("stop", safety)
        self.assertEqual(safety.states["scout-v6alias"], "shut off")
        self.assertEqual(safety.states["scout-admin"], "running")
        self.assertTrue(all(call[1] == "shutdown" for call in safety.mutations))

    def test_stop_midway_guard_failure_does_not_continue(self):
        safety = Safety(host.APPROVED)
        def failure(s):
            if s.guards == 3:
                raise RuntimeError("isolation failed after shutdown")
        safety.fail_guard = failure
        with self.assertRaisesRegex(RuntimeError, "isolation failed after shutdown"):
            host.perform("stop", safety)
        self.assertEqual(safety.mutations, [("virsh", "shutdown", "scout-v6alias")])

    def test_fatal_route_failure_is_priority_operator_handoff(self):
        safety = Safety(("scout-admin",))
        def failure(s):
            if s.states["scout-corp-client"] == "running":
                raise host.RouteLeakError("PRIORITY: stop all approved scout VMs")
        safety.fail_guard = failure
        with self.assertRaisesRegex(host.RouteLeakError, "PRIORITY.*all approved"):
            host.perform("start", safety)
        self.assertEqual(safety.mutations, [("virsh", "start", name) for name in
                                          ("scout-pfsense", "scout-lab-client", "scout-corp-client")])

    def test_shutdown_deadline_and_no_force(self):
        safety = Safety(host.APPROVED)
        with patch.object(safety, "run", return_value="running") as command:
            with self.assertRaisesRegex(RuntimeError, "120 seconds.*No force-stop"):
                host.clean_stop(safety, "scout-v6alias",
                                clock=iter((0, 0, 0, 121)).__next__, sleep=lambda _: None)
        self.assertEqual(command.call_args_list[0].args, ("virsh", "shutdown", "scout-v6alias"))
        self.assertTrue(all(call.args[1] in ("shutdown", "domstate") for call in command.call_args_list))

    def test_cleanup_disallows_unapproved_names(self):
        for name in ("scout-quar-client", "scout-win2025", "foo"):
            with self.assertRaisesRegex(RuntimeError, "restricted"):
                host.clean_stop(Safety(), name)

    def test_imported_controller_default_safety_is_injectable_without_sys_modules(self):
        safety = Safety()
        with patch.object(host, "guard", side_effect=safety.guard), \
                patch.object(host, "run", side_effect=safety.run), \
                patch.object(host, "controller_lock") as lock:
            self.assertEqual(host.perform("status")["changed"], [])
        lock.assert_called_once_with()
        self.assertEqual(safety.mutations, [])

    def test_injected_safety_never_opens_production_lock_even_if_falsey(self):
        class FalseySafety(Safety):
            def __bool__(self):
                return False
        with patch.object(host, "controller_lock", side_effect=AssertionError("live lock touched")):
            safety = FalseySafety()
            for action in ("status", "start", "stop"):
                host.perform(action, safety)

    def test_production_lock_surrounds_all_snapshots_commands_and_rollback(self):
        for action, failed in (("status", False), ("start", False),
                               ("stop", False), ("start", True), ("stop", True)):
            with self.subTest(action=action, failed=failed):
                safety = Safety(host.APPROVED if action == "stop" else ())
                if failed:
                    safety.fail_start = "scout-corp-client"
                    safety.fail_shutdown = "scout-corp-client"
                held = False
                events = []
                @contextmanager
                def lock():
                    nonlocal held
                    held = True
                    events.append("entered")
                    try:
                        yield
                    finally:
                        held = False
                        events.append("released")
                def guarded_snapshot(**kwargs):
                    self.assertTrue(held)
                    return safety.guard(**kwargs)
                def guarded_command(*args, **kwargs):
                    self.assertTrue(held)
                    return safety.run(*args, **kwargs)
                with patch.object(host, "controller_lock", side_effect=lock), \
                        patch.object(host, "guard", side_effect=guarded_snapshot), \
                        patch.object(host, "run", side_effect=guarded_command):
                    if failed:
                        with self.assertRaises(RuntimeError):
                            host.perform(action)
                    else:
                        host.perform(action)
                self.assertEqual(events, ["entered", "released"])
                self.assertFalse(held)
                if action == "start" and failed:
                    self.assertEqual(safety.mutations[-1], ("virsh", "shutdown", "scout-pfsense"))

    def test_busy_lock_prevents_any_default_guard_or_command(self):
        for action in ("status", "start", "stop"):
            with patch.object(host, "controller_lock", side_effect=RuntimeError("Controller busy")), \
                    patch.object(host, "guard") as guard, patch.object(host, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "Controller busy"):
                    host.perform(action)
                guard.assert_not_called()
                run.assert_not_called()

    def test_import_does_not_require_fcntl(self):
        original = builtins.__import__
        def without_fcntl(name, *args, **kwargs):
            if name == "fcntl":
                raise ImportError("fcntl unavailable on Windows")
            return original(name, *args, **kwargs)
        with patch("builtins.__import__", side_effect=without_fcntl):
            imported = importlib.util.module_from_spec(SPEC)
            SPEC.loader.exec_module(imported)
            self.assertEqual(imported.perform("status", Safety())["changed"], [])
            with self.assertRaisesRegex(RuntimeError, "requires Linux flock"):
                with imported.controller_lock():
                    self.fail("Lock acquired without flock")


@unittest.skipUnless(os.name == "posix", "Linux flock tests; never use the production lock path")
class ControllerLockTests(unittest.TestCase):
    def setUp(self):
        self.path = Path(__file__).resolve().parent / f".controller-test-{uuid4().hex}.lock"
        self.addCleanup(self.path.unlink, missing_ok=True)
        self.path.touch(mode=0o600)
        self.path.chmod(0o600)
        self.mode_bits_supported = stat.S_IMODE(self.path.stat().st_mode) == 0o600
        self.path.unlink()
        fchmod = patch.object(host.os, "fchmod", wraps=os.fchmod)
        self.fchmod = fchmod.start()
        self.addCleanup(fchmod.stop)
        self.constant = patch.object(host, "LOCK_PATH", str(self.path))
        self.constant.start()
        self.addCleanup(self.constant.stop)

    def test_lock_is_private_nonblocking_and_persists_after_release(self):
        with host.controller_lock():
            inode = self.path.stat().st_ino
            self.assertEqual(self.fchmod.call_args.args[1], 0o600)
            # DrvFS without metadata cannot report POSIX modes; still verify the
            # real flock and required fchmod call without leaving the project.
            if self.mode_bits_supported:
                self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
            with self.assertRaisesRegex(RuntimeError, "Controller busy"):
                with host.controller_lock():
                    self.fail("A competing action acquired the lock")
        with host.controller_lock():
            self.assertEqual(self.path.stat().st_ino, inode)

    def test_existing_lock_permissions_are_restricted_and_failure_releases_it(self):
        self.path.write_text("existing lock", encoding="utf-8")
        self.path.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "action failed"):
            with host.controller_lock():
                self.assertEqual(self.fchmod.call_args.args[1], 0o600)
                if self.mode_bits_supported:
                    self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
                raise RuntimeError("action failed")
        with host.controller_lock():
            self.assertEqual(self.path.read_text(encoding="utf-8"), "existing lock")

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "O_NOFOLLOW unavailable")
    def test_symlink_lock_is_rejected_without_touching_target(self):
        target = self.path.with_suffix(".target")
        self.addCleanup(target.unlink, missing_ok=True)
        target.write_text("untouched", encoding="utf-8")
        target.chmod(0o644)
        self.path.symlink_to(target)
        with self.assertRaises(OSError):
            with host.controller_lock():
                self.fail("Followed a symlink lock")
        self.assertEqual(target.read_text(encoding="utf-8"), "untouched")
        self.fchmod.assert_not_called()
        if self.mode_bits_supported:
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)

    def test_missing_parent_directory_is_not_created(self):
        missing = self.path.with_suffix(".missing")
        with patch.object(host, "LOCK_PATH", str(missing / "controller.lock")):
            with self.assertRaises(FileNotFoundError):
                with host.controller_lock():
                    self.fail("Created a lock in a missing directory")
        self.assertFalse(missing.exists())

    def test_real_busy_lock_blocks_all_production_actions_without_guard(self):
        with host.controller_lock(), patch.object(host, "guard") as guard, \
                patch.object(host, "run") as run:
            for action in ("status", "start", "stop"):
                with self.assertRaisesRegex(RuntimeError, "Controller busy"):
                    host.perform(action)
            guard.assert_not_called()
            run.assert_not_called()


class FakePath:
    def __init__(self, fixture, value):
        self.fixture = fixture
        self.path = PurePosixPath(value)

    def __truediv__(self, name):
        return FakePath(self.fixture, self.path / name)

    @property
    def name(self):
        return self.path.name

    @property
    def parents(self):
        return [FakePath(self.fixture, parent) for parent in self.path.parents]

    def is_symlink(self):
        return str(self.path) in self.fixture.symlinks

    def is_file(self):
        return (str(self.path) in {*host.IMAGES.values(), host.WINDOWS_IMAGE, *host.WINDOWS_MEDIA}
                and str(self.path) not in self.fixture.missing)

    def is_dir(self):
        return self.name == "bridge" and str(self.path) not in self.fixture.missing

    def exists(self):
        return str(self.path) in self.fixture.existing

    def iterdir(self):
        assert self.name == "brif"
        bridge = self.path.parent.name
        members = set(self.fixture.extra_members.get(bridge, ()))
        members.update(target for (name, network), target in self.fixture.targets.items()
                       if self.fixture.states[name] == "running" and host.NETWORKS[network] == bridge)
        return iter(FakePath(self.fixture, self.path / name) for name in members)


class Fixture:
    def __init__(self, running=(), windows=None, link="down"):
        self.states = {name: "running" if name in running else "shut off" for name in host.VMs}
        profiles = [(name, network) for name, networks in EXPECTED_NETWORKS.items() for network in networks]
        if windows is not None:
            self.states[host.WINDOWS] = windows
            profiles.append((host.WINDOWS, "scout-lan"))
        self.windows_link = link
        self.targets = {profile: f"vnet{index}" for index, profile in enumerate(profiles)}
        self.calls = []
        self.hostname = "ian-thinkpad"
        self.user = "labagent"
        self.uri = host.URI
        self.route = [{"dev": "enp0s31f6"}]
        self.route_sequence = []
        self.overrides = {}
        self.extra_members = {}
        self.addresses = {}
        self.existing = set()
        self.symlinks = set()
        self.missing = set()

    def path(self, value):
        # Guard must not even stat arbitrary XML paths or private home files.
        assert str(value).startswith(("/sys/class/net", "/var/lib/libvirt/images/scout/")) \
            or str(value) in host.WINDOWS_MEDIA
        return FakePath(self, value)

    def network_xml(self, name):
        return f"<network><name>{name}</name><bridge name='{host.NETWORKS[name]}'/></network>"

    def domain_xml(self, name, active=False):
        root = ET.Element("domain", type="kvm")
        ET.SubElement(root, "name").text = name
        if name == host.WINDOWS:
            system = ET.SubElement(root, "os")
            ET.SubElement(system, "type", arch="x86_64", machine="pc-q35-10.0").text = "hvm"
            ET.SubElement(system, "loader", readonly="yes", type="pflash").text = \
                "/usr/share/OVMF/OVMF_CODE_4M.ms.fd"
            ET.SubElement(system, "nvram", template="/usr/share/OVMF/OVMF_VARS_4M.ms.fd").text = \
                "/var/lib/libvirt/qemu/nvram/scout-win2025_VARS.fd"
        devices = ET.SubElement(root, "devices")
        for network in (("scout-lan",) if name == host.WINDOWS else EXPECTED_NETWORKS[name]):
            nic = ET.SubElement(devices, "interface", type="network")
            ET.SubElement(nic, "source", network=network)
            if name == host.WINDOWS:
                ET.SubElement(nic, "model", type="e1000e")
                ET.SubElement(nic, "link", state=self.windows_link)
            if active:
                ET.SubElement(nic, "target", dev=self.targets[name, network])
        if name in host.APPROVED or name == host.WINDOWS:
            disk = ET.SubElement(devices, "disk", type="file", device="disk")
            ET.SubElement(disk, "driver", name="qemu", type="qcow2")
            ET.SubElement(disk, "source", file=host.WINDOWS_IMAGE if name == host.WINDOWS else host.IMAGES[name])
        if name == host.WINDOWS:
            ET.SubElement(disk, "target", bus="sata", dev="sda")
            for index, path in enumerate(sorted(host.WINDOWS_MEDIA)):
                cdrom = ET.SubElement(devices, "disk", type="file", device="cdrom")
                ET.SubElement(cdrom, "driver", name="qemu", type="raw")
                ET.SubElement(cdrom, "source", file=path)
                ET.SubElement(cdrom, "target", bus="sata", dev=f"sd{chr(ord('b') + index)}")
                ET.SubElement(cdrom, "readonly")
            graphics = ET.SubElement(devices, "graphics", type="vnc", port="-1",
                                     autoport="yes", listen="127.0.0.1")
            ET.SubElement(graphics, "listen", type="address", address="127.0.0.1")
            tpm = ET.SubElement(devices, "tpm", model="tpm-crb")
            ET.SubElement(tpm, "backend", type="emulator", version="2.0")
        return ET.tostring(root, encoding="unicode")

    def run(self, *args, timeout=30):
        self.calls.append(args)
        if args in self.overrides:
            return self.overrides[args]
        if args == ("hostname",):
            return self.hostname
        if args == ("id", "-un"):
            return self.user
        if args == ("virsh", "uri"):
            return self.uri
        if args == ("virsh", "list", "--all", "--name"):
            return "\n".join((*self.states, "lab-unrelated"))
        if args == ("ip", "-j", "route", "get", "192.168.1.1"):
            route = self.route_sequence.pop(0) if self.route_sequence else self.route
            return json.dumps(route)
        if args[:3] == ("ip", "-j", "address"):
            bridge = args[-1]
            return json.dumps([{"ifname": bridge, "addr_info": self.addresses.get(bridge, [])}])
        if args[0] == "virsh":
            _, command, name, *extra = args
            if command in ("dumpxml", "domstate"):
                assert name in (*host.VMs, host.WINDOWS) and name in self.states
                if command == "domstate":
                    return self.states[name]
                return self.domain_xml(name, active=not extra)
            if command in ("start", "shutdown"):
                assert name in host.APPROVED
                self.states[name] = "running" if command == "start" else "shut off"
                return "success"
            assert name in host.NETWORKS
            if command == "net-info":
                return "Active: yes\nPersistent: yes"
            if command == "net-dumpxml":
                return self.network_xml(name)
        raise AssertionError(f"Unexpected command: {args}")

    def guard(self, require_off=False):
        return host.guard(require_off, runner=self.run, path_factory=self.path)

    def domain_override(self, name, edit, active=False):
        root = ET.fromstring(self.domain_xml(name, active))
        edit(root)
        command = ("virsh", "dumpxml", name) + (() if active else ("--inactive",))
        self.overrides[command] = ET.tostring(root, encoding="unicode")


class GuardTests(unittest.TestCase):
    def test_router_has_exactly_four_distinct_scout_networks_and_own_image(self):
        fixture = Fixture(host.APPROVED)
        self.assertEqual(fixture.guard(), fixture.states)
        for active in (False, True):
            root = ET.fromstring(fixture.domain_xml("scout-pfsense", active))
            networks = [node.get("network") for node in root.findall("./devices/interface/source")]
            self.assertEqual(networks, ["scout-wan", "scout-lan", "scout-lab", "scout-quar"])
            self.assertEqual(root.find("./devices/disk/source").get("file"),
                             "/var/lib/libvirt/images/scout/scout-pfsense.qcow2")
        for network, bridge in host.NETWORKS.items():
            members = {path.name for path in (fixture.path("/sys/class/net") / bridge / "brif").iterdir()}
            self.assertIn(fixture.targets["scout-pfsense", network], members)
        self.assertEqual(fixture.states["scout-quar-client"], "shut off")
        self.assertEqual(len(host.check_domain(
            fixture.domain_xml("scout-pfsense", True), "scout-pfsense", active=True,
            path_factory=fixture.path,
        )), 4)

    def test_approved_lab_client_cannot_use_another_scout_or_default_network(self):
        for network in ("scout-lan", "scout-wan", "scout-quar", "default", "foo"):
            for active in (False, True):
                with self.subTest(network=network, active=active):
                    fixture = Fixture(host.APPROVED if active else ())
                    fixture.domain_override(
                        "scout-lab-client",
                        lambda r: r.find("./devices/interface/source").set("network", network),
                        active=active,
                    )
                    with self.assertRaisesRegex(RuntimeError, "nonapproved"):
                        fixture.guard()

    def test_router_rejects_duplicate_profiles_missing_or_extra_wan_and_external_nics(self):
        def extra_wan(root):
            nic = ET.SubElement(root.find("devices"), "interface", type="network")
            ET.SubElement(nic, "source", network="scout-wan")
        edits = (
            lambda r: r.find("./devices/interface/source").set("network", "scout-lan"),
            lambda r: r.find("devices").remove(r.find("./devices/interface")),
            extra_wan,
            lambda r: r.find("./devices/interface/source").set("network", "default"),
            lambda r: r.find("./devices/interface/source").set("bridge", "virbr0"),
            lambda r: r.find("./devices/interface").set("type", "direct"),
        )
        for active in (False, True):
            for index, edit in enumerate(edits):
                with self.subTest(active=active, edit=index):
                    fixture = Fixture(host.APPROVED if active else ())
                    fixture.domain_override("scout-pfsense", edit, active=active)
                    with self.assertRaisesRegex(RuntimeError, "NIC count|network|uplink"):
                        fixture.guard()

    def test_router_active_targets_cannot_be_shared_between_networks_or_guests(self):
        for duplicate in (("scout-pfsense", "scout-lan"), ("scout-v6alias", "scout-lan")):
            fixture = Fixture(host.APPROVED)
            fixture.domain_override(
                "scout-pfsense",
                lambda r: r.find("./devices/interface/target").set("dev", fixture.targets[duplicate]),
                active=True,
            )
            with self.assertRaisesRegex(RuntimeError, "Duplicate NIC"):
                fixture.guard()

    def test_no_default_nat_or_forwarding_on_any_scout_network_with_router_running(self):
        for network in host.NETWORKS:
            for suffix in ((), ("--inactive",)):
                fixture = Fixture(host.APPROVED)
                fixture.overrides[("virsh", "net-dumpxml", network, *suffix)] = \
                    fixture.network_xml(network).replace(
                        "</network>", "<forward mode='nat'><nat/></forward></network>"
                    )
                with self.assertRaisesRegex(RuntimeError, "forwarding"):
                    fixture.guard()
                self.assertFalse(any(call[:3] in (("virsh", "net-info", "default"),
                                                  ("virsh", "net-dumpxml", "default"))
                                     for call in fixture.calls))

    def test_all_scout_bridges_remain_without_host_ips_even_with_router_running(self):
        for bridge in host.NETWORKS.values():
            for family, local in (("inet", "10.50.0.1"), ("inet6", "fd00::1")):
                fixture = Fixture(host.APPROVED)
                fixture.addresses[bridge] = [{"family": family, "local": local}]
                with self.assertRaisesRegex(RuntimeError, "IPv4 or IPv6"):
                    fixture.guard()

    def test_active_libvirt_disk_index_is_metadata_not_an_extra_image(self):
        for name in host.APPROVED:
            for index in ("1", "7", "54321"):
                fixture = Fixture(host.APPROVED)
                fixture.domain_override(name,
                                        lambda r: r.find("./devices/disk/source").set("index", index),
                                        active=True)
                self.assertEqual(fixture.guard()[name], "running")

    def test_active_disk_index_does_not_relax_exact_image_or_source_checks(self):
        for attributes in ({"index": "-1"}, {"index": "dynamic"}, {"index": ""},
                           {"index": "2", "file": "/outside/other.qcow2"},
                           {"index": "2", "dev": "/dev/sda"}):
            fixture = Fixture(host.APPROVED)
            fixture.domain_override(
                "scout-admin", lambda r: r.find("./devices/disk/source").attrib.update(attributes),
                active=True,
            )
            with self.assertRaisesRegex(RuntimeError, "exact approved qcow2"):
                fixture.guard()

    def test_real_guard_preflight_failures_prevent_all_operation_mutations(self):
        for action in ("status", "start", "stop"):
            for fault in ("network", "image", "bridge", "state", "route", "filesystem", "shmem"):
                fixture = Fixture()
                if fault == "network":
                    fixture.overrides[("virsh", "net-dumpxml", "scout-lan", "--inactive")] = \
                        fixture.network_xml("scout-lan").replace("</network>", "<forward/></network>")
                elif fault == "image":
                    fixture.symlinks.add(host.IMAGES["scout-admin"])
                elif fault == "bridge":
                    fixture.extra_members["virbr-scoutlan"] = {"enp0s31f6"}
                elif fault == "state":
                    fixture.states["scout-quar-client"] = "running"
                elif fault in ("filesystem", "shmem"):
                    fixture.domain_override(
                        "scout-quar-client", lambda r: ET.SubElement(r.find("devices"), fault)
                    )
                else:
                    fixture.route = [{"dev": "virbr-scoutlan"}]
                with self.assertRaises(RuntimeError):
                    host.perform(action, fixture)
                self.assertFalse(any(call[:2] in (("virsh", "start"), ("virsh", "shutdown"))
                                     for call in fixture.calls))

    def test_guard_accepts_off_running_and_mixed_states(self):
        for running in ((), host.APPROVED, ("scout-admin",), ("scout-pfsense", "scout-lab-client")):
            fixture = Fixture(running)
            self.assertEqual(fixture.guard(), fixture.states)
            self.assertEqual(sum(call[:3] == ("ip", "-j", "route") for call in fixture.calls), 2)
            for network in host.NETWORKS:
                self.assertIn(("virsh", "net-dumpxml", network), fixture.calls)
                self.assertIn(("virsh", "net-dumpxml", network, "--inactive"), fixture.calls)
            detailed = {call[2] for call in fixture.calls if call[:2] == ("virsh", "dumpxml")}
            self.assertEqual(detailed, set(host.VMs))
            self.assertFalse(any(call[0] == "virsh" and call[1] in ("start", "shutdown") for call in fixture.calls))

    def test_require_off_applies_to_all_five(self):
        self.assertEqual(Fixture().guard(True), Fixture().states)
        for name in host.APPROVED:
            with self.assertRaisesRegex(RuntimeError, "must be off"):
                Fixture((name,)).guard(True)

    def test_host_user_and_uri_are_pinned(self):
        for attribute, value in (("hostname", "other"), ("user", "root"), ("uri", "qemu:///session")):
            fixture = Fixture()
            setattr(fixture, attribute, value)
            with self.assertRaises(RuntimeError):
                fixture.guard()

    def test_unexpected_or_blocked_guest_states_fail(self):
        for name in host.VMs:
            fixture = Fixture()
            fixture.states[name] = "paused"
            with self.assertRaisesRegex(RuntimeError, "Unexpected"):
                fixture.guard()
        for name in host.BLOCKED:
            with self.assertRaisesRegex(RuntimeError, "must remain off"):
                Fixture((name,)).guard()

    def test_route_checked_before_and_after_even_other_guard_failure(self):
        for routes in (([{"dev": "virbr-scoutlan"}],),
                       ([{"dev": "enp0s31f6"}], [{"dev": "virbr-scoutlan"}])):
            fixture = Fixture()
            fixture.route_sequence = list(routes)
            with self.assertRaisesRegex(host.RouteLeakError, "PRIORITY.*all approved.*scout-win2025.*already running"):
                fixture.guard()
        fixture = Fixture()
        fixture.states["scout-admin"] = "paused"
        fixture.route_sequence = [[{"dev": "enp0s31f6"}], []]
        with self.assertRaises(host.RouteLeakError):
            fixture.guard()

    def test_networks_require_live_persistent_isolated_xml(self):
        for network in host.NETWORKS:
            for suffix in ((), ("--inactive",)):
                for tag in ("forward", "ip", "nat", "interface", "pf", "hostdev", "virtualport", "route"):
                    fixture = Fixture()
                    xml = fixture.network_xml(network).replace("</network>", f"<{tag}/></network>")
                    fixture.overrides[("virsh", "net-dumpxml", network, *suffix)] = xml
                    with self.assertRaises(RuntimeError):
                        fixture.guard()
        for info in ("Active: no\nPersistent: yes", "Active: yes\nPersistent: no"):
            fixture = Fixture()
            fixture.overrides[("virsh", "net-info", "scout-lan")] = info
            with self.assertRaises(RuntimeError):
                fixture.guard()

    def test_network_bridge_and_name_must_match(self):
        for original, replacement in (("virbr-scoutlan", "br0"), ("<name>scout-lan", "<name>other")):
            fixture = Fixture()
            fixture.overrides[("virsh", "net-dumpxml", "scout-lan")] = \
                fixture.network_xml("scout-lan").replace(original, replacement)
            with self.assertRaises(RuntimeError):
                fixture.guard()

    def test_bridge_rejects_extra_ports_master_and_host_ip_including_ipv6(self):
        for bridge in host.NETWORKS.values():
            fixture = Fixture()
            fixture.extra_members[bridge] = {"enp0s31f6"}
            with self.assertRaisesRegex(RuntimeError, "membership mismatch"):
                fixture.guard()
            fixture = Fixture()
            fixture.extra_members[bridge] = {"vnet999"}
            with self.assertRaisesRegex(RuntimeError, "membership mismatch"):
                fixture.guard()
            fixture = Fixture()
            fixture.existing.add(f"/sys/class/net/{bridge}/master")
            with self.assertRaisesRegex(RuntimeError, "master"):
                fixture.guard()
            for family, local in (("inet", "10.50.0.1"), ("inet6", "fe80::1")):
                fixture = Fixture()
                fixture.addresses[bridge] = [{"family": family, "local": local}]
                with self.assertRaisesRegex(RuntimeError, "IPv4 or IPv6"):
                    fixture.guard()

    def test_active_targets_must_match_exact_bridge_members(self):
        fixture = Fixture(host.APPROVED)
        fixture.domain_override("scout-admin",
                                lambda r: r.find("./devices/interface/target").set("dev", "vnet999"),
                                active=True)
        with self.assertRaisesRegex(RuntimeError, "membership mismatch"):
            fixture.guard()
        fixture = Fixture(host.APPROVED)
        fixture.domain_override("scout-admin",
                                lambda r: r.find("./devices/interface/target").set("dev", "eth0"),
                                active=True)
        with self.assertRaisesRegex(RuntimeError, "NIC target"):
            fixture.guard()
        fixture = Fixture(host.APPROVED)
        fixture.domain_override("scout-admin",
                                lambda r: r.find("./devices/interface/target").set("dev", "vnet0"),
                                active=True)
        with self.assertRaisesRegex(RuntimeError, "Duplicate NIC"):
            fixture.guard()

    def test_missing_bridge_and_master_reported_by_ip_are_rejected(self):
        fixture = Fixture()
        fixture.missing.add("/sys/class/net/virbr-scoutlan/bridge")
        with self.assertRaisesRegex(RuntimeError, "bridge is missing"):
            fixture.guard()
        fixture = Fixture()
        fixture.overrides[("ip", "-j", "address", "show", "dev", "virbr-scoutlan")] = json.dumps([
            {"ifname": "virbr-scoutlan", "addr_info": [], "master": "br0"}
        ])
        with self.assertRaisesRegex(RuntimeError, "no master"):
            fixture.guard()

    def test_state_change_during_guard_is_not_reported_as_verified(self):
        fixture = Fixture()
        original = fixture.run
        seen = 0
        def runner(*args):
            nonlocal seen
            if args == ("virsh", "domstate", "scout-admin"):
                seen += 1
                if seen == 2:
                    return "running"
            return original(*args)
        with self.assertRaisesRegex(RuntimeError, "states changed"):
            host.guard(runner=runner, path_factory=fixture.path)

    def test_domain_identity_and_network_assignment_checked_for_every_vm(self):
        for name in host.VMs:
            fixture = Fixture()
            fixture.domain_override(name, lambda r: setattr(r.find("name"), "text", "lab-other"))
            with self.assertRaisesRegex(RuntimeError, "identity"):
                fixture.guard()
            fixture = Fixture()
            fixture.domain_override(name, lambda r: r.find("./devices/interface/source").set("network", "default"))
            with self.assertRaisesRegex(RuntimeError, "nonapproved"):
                fixture.guard()

    def test_hostdev_custom_qemu_and_bridge_nics_rejected(self):
        for edit in (
            lambda r: ET.SubElement(r.find("devices"), "hostdev"),
            lambda r: ET.SubElement(r, "{http://libvirt.org/schemas/domain/qemu/1.0}commandline"),
            lambda r: ET.SubElement(r.find("./devices/interface"), "virtualport"),
            lambda r: r.find("./devices/interface").set("type", "bridge"),
            lambda r: ET.SubElement(r.find("devices"), "interface", type="network"),
        ):
            fixture = Fixture()
            fixture.domain_override("scout-admin", edit)
            with self.assertRaises(RuntimeError):
                fixture.guard()

    def test_filesystem_and_shmem_rejected_for_all_six_including_unknown_namespaces(self):
        for name in host.VMs:
            for active in ((False, True) if name in host.APPROVED else (False,)):
                for namespace in ("", "{urn:unknown:host-backed}"):
                    for tag in ("filesystem", "shmem"):
                        for source in ("/home/labagent/outside-approved", "/var/lib/libvirt/images/scout"):
                            with self.subTest(name=name, active=active, namespace=namespace,
                                              tag=tag, source=source):
                                fixture = Fixture((name,) if active else ())
                                def host_backed(root):
                                    device = ET.SubElement(root.find("devices"), namespace + tag)
                                    if tag == "filesystem":
                                        device.set("type", "mount")
                                        ET.SubElement(device, namespace + "source", dir=source)
                                        ET.SubElement(device, namespace + "target", dir="hostshare")
                                    else:
                                        device.set("name", "hostshare")
                                        ET.SubElement(device, namespace + "server", path=source)
                                fixture.domain_override(name, host_backed, active=active)
                                with self.assertRaisesRegex(RuntimeError, "filesystems, shared memory"):
                                    fixture.guard()

    def test_standard_serial_console_pty_remains_allowed(self):
        for active in (False, True):
            fixture = Fixture(host.APPROVED if active else ())
            def pty_devices(root):
                for tag in ("serial", "console"):
                    device = ET.SubElement(root.find("devices"), tag, type="pty")
                    if active:
                        ET.SubElement(device, "source", path="/dev/pts/5")
                    ET.SubElement(device, "target", port="0")
            for name in host.VMs:
                fixture.domain_override(name, pty_devices)
                if active and name in host.APPROVED:
                    fixture.domain_override(name, pty_devices, active=True)
            self.assertEqual(fixture.guard(), fixture.states)

    def test_approved_disk_is_sole_exact_qcow2_and_never_reads_private_paths(self):
        edits = (
            lambda r: r.find("./devices/disk/source").set("file", "/home/labagent/.ssh/id_ed25519"),
            lambda r: r.find("./devices/disk/source").set("file", "/var/lib/libvirt/images/scout/../scout/scout-admin.qcow2"),
            lambda r: r.find("./devices/disk/driver").set("type", "raw"),
            lambda r: ET.SubElement(r.find("devices"), "disk", device="cdrom"),
            lambda r: ET.SubElement(r.find("devices"), "disk", device="floppy"),
            lambda r: r.find("./devices/disk").set("type", "block"),
            lambda r: r.find("devices").remove(r.find("./devices/disk")),
            lambda r: ET.SubElement(r.find("./devices/disk"), "source", file="/outside/other.qcow2"),
            lambda r: ET.SubElement(ET.SubElement(r.find("./devices/disk"), "backingStore"),
                                   "source", file="/outside/base.qcow2"),
            lambda r: ET.SubElement(r.find("./devices/disk"), "dataStore"),
            lambda r: ET.SubElement(r.find("./devices/disk"), "mirror"),
        )
        for name in host.APPROVED:
            for active in (False, True):
                for index, edit in enumerate(edits):
                    with self.subTest(name=name, active=active, edit=index):
                        fixture = Fixture(host.APPROVED if active else ())
                        fixture.domain_override(name, edit, active=active)
                        with self.assertRaises(RuntimeError):
                            fixture.guard()

    def test_each_approved_guest_requires_its_own_image_not_another_approved_image(self):
        for name in host.APPROVED:
            for other in host.APPROVED:
                if other == name:
                    continue
                for active in (False, True):
                    with self.subTest(name=name, other=other, active=active):
                        fixture = Fixture(host.APPROVED if active else ())
                        fixture.domain_override(
                            name, lambda r: r.find("./devices/disk/source").set("file", host.IMAGES[other]),
                            active=active,
                        )
                        with self.assertRaisesRegex(RuntimeError, "exact approved qcow2"):
                            fixture.guard()

    def test_image_symlinks_and_missing_files_rejected(self):
        for path in (*host.IMAGES.values(), "/var/lib/libvirt/images/scout"):
            fixture = Fixture()
            fixture.symlinks.add(path)
            with self.assertRaisesRegex(RuntimeError, "Symlink"):
                fixture.guard()
        for path in host.IMAGES.values():
            fixture = Fixture()
            fixture.missing.add(path)
            with self.assertRaisesRegex(RuntimeError, "regular file"):
                fixture.guard()

    def test_active_domain_is_checked_independently_of_persistent_xml(self):
        fixture = Fixture(host.APPROVED)
        fixture.domain_override("scout-v6alias",
                                lambda r: r.find("./devices/disk/source").set("file", "/bad"),
                                active=True)
        with self.assertRaises(RuntimeError):
            fixture.guard()

    def test_run_captures_errors_and_pins_uri_without_shell(self):
        completed = subprocess.CompletedProcess([], 0, " running\n", "")
        with patch.object(host.subprocess, "run", return_value=completed) as command:
            self.assertEqual(host.run("virsh", "domstate", "scout-admin", timeout=7), "running")
            self.assertEqual(command.call_args.args[0],
                             ["virsh", "--connect", host.URI, "domstate", "scout-admin"])
            self.assertEqual(command.call_args.kwargs["timeout"], 7)
            self.assertNotIn("shell", command.call_args.kwargs)
        with patch.object(host.subprocess, "run",
                          return_value=subprocess.CompletedProcess([], 1, "", "specific failure")):
            with self.assertRaisesRegex(RuntimeError, r"Command failed \(1\).*specific failure"):
                host.run("hostname")
        with patch.object(host.subprocess, "run", side_effect=subprocess.TimeoutExpired("hostname", 5)):
            with self.assertRaisesRegex(RuntimeError, "timed out after 5s"):
                host.run("hostname", timeout=5)


class WindowsGuardTests(unittest.TestCase):
    def test_cold_boot_empty_cdrom_may_omit_runtime_format_only(self):
        fixture = Fixture(windows="running")
        root = ET.fromstring(fixture.domain_xml(host.WINDOWS, active=True))
        disk = root.find("./devices/disk[@device='cdrom']")
        disk.remove(disk.find("source"))
        disk.find("driver").attrib.pop("type")
        host.check_windows_domain(ET.tostring(root, encoding="unicode"), active=True,
                                  path_factory=fixture.path)
        ET.SubElement(disk, "source", file=next(iter(host.WINDOWS_MEDIA)))
        with self.assertRaisesRegex(RuntimeError, "disk driver"):
            host.check_windows_domain(ET.tostring(root, encoding="unicode"), active=True,
                                      path_factory=fixture.path)

    def test_live_ejected_optical_drive_has_only_nonpath_index(self):
        fixture = Fixture(windows="running")
        root = ET.fromstring(fixture.domain_xml(host.WINDOWS, active=True))
        source = root.find("./devices/disk[@device='cdrom']/source")
        source.attrib.clear()
        source.set("index", "5")
        host.check_windows_domain(ET.tostring(root, encoding="unicode"),
                                  active=True, path_factory=fixture.path)
        source.set("dev", "/dev/cdrom")
        with self.assertRaisesRegex(RuntimeError, "invalid empty optical"):
            host.check_windows_domain(ET.tostring(root, encoding="unicode"),
                                      active=True, path_factory=fixture.path)

    def test_libvirt_default_tpm_profile_is_permitted_without_host_sources(self):
        fixture = Fixture(windows="running")
        root = ET.fromstring(fixture.domain_xml(host.WINDOWS, active=True))
        backend = root.find("./devices/tpm/backend")
        self.assertIsNotNone(backend)
        ET.SubElement(backend, "profile", name="default-v1")
        host.check_windows_domain(ET.tostring(root, encoding="unicode"),
                                  active=True, path_factory=fixture.path)

    def test_exact_optional_assets_do_not_expand_lifecycle_allowlists(self):
        self.assertEqual(host.WINDOWS, "scout-win2025")
        self.assertEqual(host.WINDOWS_IMAGE, "/var/lib/libvirt/images/scout/scout-win2025.qcow2")
        self.assertEqual(host.WINDOWS_MEDIA, {
            "/var/lib/libvirt/images/scout/win2025-media/windows-server-2025.iso",
            "/var/lib/libvirt/images/scout/win2025-media/virtio-win.iso",
            "/var/lib/libvirt/images/scout/win2025-media/scout-win2025-tools.iso",
            "/var/lib/libvirt/images/scout/win2025-media/scout-win2025-setup.iso",
        })
        self.assertNotIn(host.WINDOWS, host.VMs)
        self.assertNotIn(host.WINDOWS, host.APPROVED)
        self.assertNotIn(host.WINDOWS, host.IMAGES)
        self.assertNotIn(host.WINDOWS, host.START_ORDER + host.STOP_ORDER)

    def test_absent_guest_is_discovered_without_lookup_or_unrelated_details(self):
        fixture = Fixture()
        fixture.overrides[("virsh", "list", "--all", "--name")] = \
            "scout-win2025-old\nother-scout-win2025\nlab-unrelated\n"
        self.assertIsNone(host.windows_state(fixture.run))
        self.assertEqual(fixture.guard(), fixture.states)
        self.assertFalse(any(call[:2] in (("virsh", "domstate"), ("virsh", "dumpxml"))
                             and call[2] not in host.VMs for call in fixture.calls))
        self.assertEqual(fixture.calls.count(("virsh", "list", "--all", "--name")), 3)

    def test_discovery_and_domain_query_errors_fail_closed(self):
        for command in (("virsh", "list", "--all", "--name"),
                        ("virsh", "domstate", host.WINDOWS),
                        ("virsh", "dumpxml", host.WINDOWS, "--inactive")):
            fixture = Fixture(windows="shut off")
            original = fixture.run
            def runner(*args, **kwargs):
                if args == command:
                    raise RuntimeError("query unavailable")
                return original(*args, **kwargs)
            with patch.object(fixture, "run", side_effect=runner):
                with self.assertRaisesRegex(RuntimeError, "query unavailable"):
                    host.perform("start", fixture)
            self.assertFalse(any(call[:2] == ("virsh", "start") for call in fixture.calls))

    def test_off_and_running_up_or_down_keep_original_six_state_schema(self):
        for state in host.STATES:
            for link in ("up", "down"):
                for running in ((), host.APPROVED):
                    with self.subTest(state=state, link=link, running=running):
                        fixture = Fixture(running, windows=state, link=link)
                        expected = {name: fixture.states[name] for name in host.VMs}
                        self.assertEqual(fixture.guard(), expected)
                        self.assertEqual(host.snapshot(fixture), expected)
                        self.assertEqual(host.perform("status", fixture), {
                            "mode": "routed_demo", "action": "status",
                            "states": {name: fixture.states[name] for name in host.APPROVED},
                            "isolation": "verified", "other_vms_off": True, "changed": [],
                        })
                        self.assertIn(("virsh", "dumpxml", host.WINDOWS, "--inactive"), fixture.calls)
                        self.assertEqual(("virsh", "dumpxml", host.WINDOWS) in fixture.calls, state == "running")
                        self.assertTrue(all(call[2] in (*host.VMs, host.WINDOWS)
                                            for call in fixture.calls
                                            if call[:2] in (("virsh", "dumpxml"), ("virsh", "domstate"))))

    def test_require_off_and_start_stop_remain_scoped_to_original_five(self):
        for windows in ("shut off", "running"):
            fixture = Fixture(windows=windows)
            self.assertEqual(set(fixture.guard(True)), set(host.VMs))
            self.assertEqual(host.perform("start", fixture)["changed"], list(host.START_ORDER))
            self.assertEqual(host.perform("start", fixture)["changed"], [])
            with self.assertRaisesRegex(RuntimeError, "five approved.*off"):
                fixture.guard(True)
            self.assertEqual(host.perform("stop", fixture)["changed"], list(host.STOP_ORDER))
            self.assertEqual(host.perform("stop", fixture)["changed"], [])
            self.assertEqual(fixture.states[host.WINDOWS], windows)
            mutations = [call for call in fixture.calls if call[:2] in (("virsh", "start"), ("virsh", "shutdown"))]
            self.assertEqual(mutations, [("virsh", "start", name) for name in host.START_ORDER] +
                             [("virsh", "shutdown", name) for name in host.STOP_ORDER])

    def test_rollback_never_touches_preexisting_optional_windows(self):
        fixture = Fixture(windows="running")
        original = fixture.run
        def runner(*args, **kwargs):
            result = original(*args, **kwargs)
            if args == ("virsh", "start", "scout-corp-client"):
                raise RuntimeError("uncertain startup")
            return result
        with patch.object(fixture, "run", side_effect=runner):
            with self.assertRaisesRegex(RuntimeError, "uncertain startup.*status uncertain"):
                host.perform("start", fixture)
        self.assertEqual(fixture.states[host.WINDOWS], "running")
        self.assertEqual(fixture.states["scout-corp-client"], "running")
        self.assertEqual([call[2] for call in fixture.calls if call[:2] == ("virsh", "shutdown")],
                         ["scout-admin", "scout-lab-client", "scout-pfsense"])

    def test_windows_does_not_relax_quarantine_or_network_isolation(self):
        fixture = Fixture(("scout-quar-client",), windows="running")
        with self.assertRaisesRegex(RuntimeError, "must remain off"):
            fixture.guard()
        fixture = Fixture(windows="running")
        fixture.extra_members["virbr-scoutlan"] = {"enp0s31f6"}
        with self.assertRaisesRegex(RuntimeError, "membership mismatch"):
            fixture.guard()
        fixture = Fixture(windows="running")
        fixture.addresses["virbr-scoutlan"] = [{"family": "inet6", "local": "fe80::1"}]
        with self.assertRaisesRegex(RuntimeError, "no host IPv4 or IPv6"):
            fixture.guard()

    def test_unknown_states_and_presence_state_changes_fail_closed(self):
        for state in ("paused", "in shutdown", "crashed", "", "unknown"):
            with self.assertRaisesRegex(RuntimeError, "Unexpected scout-win2025"):
                Fixture(windows=state).guard()
        for before, after in ((None, "shut off"), ("shut off", None),
                              ("shut off", "running"), ("running", "shut off")):
            fixture = Fixture(windows=before)
            original = fixture.run
            seen = 0
            def runner(*args):
                nonlocal seen
                if args == ("virsh", "list", "--all", "--name"):
                    seen += 1
                    if seen == 2:
                        if after is None:
                            del fixture.states[host.WINDOWS]
                        else:
                            fixture.states[host.WINDOWS] = after
                return original(*args)
            with self.assertRaisesRegex(RuntimeError, "presence/state changed"):
                host.guard(runner=runner, path_factory=fixture.path)

    def test_final_optional_discovery_error_cannot_report_verified(self):
        fixture = Fixture()
        original = fixture.run
        seen = 0
        def runner(*args):
            nonlocal seen
            if args == ("virsh", "list", "--all", "--name"):
                seen += 1
                if seen == 2:
                    raise RuntimeError("final discovery failed")
            return original(*args)
        with self.assertRaisesRegex(RuntimeError, "final discovery failed"):
            host.guard(runner=runner, path_factory=fixture.path)
        self.assertEqual(sum(call[:3] == ("ip", "-j", "route") for call in fixture.calls), 2)

    def assert_bad_windows(self, edits, message=None):
        for active in (False, True):
            for index, edit in enumerate(edits):
                with self.subTest(active=active, edit=index):
                    fixture = Fixture(host.APPROVED, windows="running")
                    fixture.domain_override(host.WINDOWS, edit, active=active)
                    with self.assertRaisesRegex(RuntimeError, message or "scout-win2025|Duplicate NIC"):
                        host.perform("start", fixture)
                    self.assertFalse(any(call[:2] in (("virsh", "start"), ("virsh", "shutdown"))
                                         for call in fixture.calls))

    def test_unsafe_nics_and_duplicate_or_missing_live_targets_are_rejected(self):
        self.assert_bad_windows((
            lambda r: r.find("./devices/interface/source").set("network", "default"),
            lambda r: r.find("./devices/interface/source").set("network", "scout-quar"),
            lambda r: r.find("./devices/interface/source").set("bridge", "br0"),
            lambda r: r.find("./devices/interface/source").set("dev", "enp0s31f6"),
            lambda r: r.find("./devices/interface").set("type", "direct"),
            lambda r: r.find("./devices/interface/model").set("type", "e1000"),
            lambda r: r.find("./devices/interface/link").set("state", "unknown"),
            lambda r: ET.SubElement(r.find("./devices/interface"), "script", path="/outside/script"),
            lambda r: ET.SubElement(r.find("./devices/interface"), "backend", tap="/dev/net/tun"),
            lambda r: ET.SubElement(r.find("./devices/interface/source"), "host", name="outside"),
            lambda r: ET.SubElement(r.find("devices"), "interface", type="network"),
        ))
        for target in ("enp0s31f6", "vnet999", "vnet0", ""):
            fixture = Fixture(host.APPROVED, windows="running", link="down")
            fixture.domain_override(host.WINDOWS,
                                    lambda r: r.find("./devices/interface/target").set("dev", target),
                                    active=True)
            with self.assertRaises(RuntimeError):
                fixture.guard()
        fixture = Fixture(windows="running")
        fixture.domain_override(host.WINDOWS,
                                lambda r: r.find("./devices/interface").remove(r.find("./devices/interface/target")),
                                active=True)
        with self.assertRaisesRegex(RuntimeError, "NIC target"):
            fixture.guard()

    def test_host_mounts_devices_qemu_overrides_and_custom_sources_are_rejected(self):
        for tag in ("hostdev", "filesystem", "shmem", "virtualport", "commandline"):
            for namespace in ("", "{urn:custom}"):
                self.assert_bad_windows((lambda r: ET.SubElement(r.find("devices"), namespace + tag),))
        self.assert_bad_windows((
            lambda r: ET.SubElement(r, "{http://libvirt.org/schemas/domain/qemu/1.0}override"),
            lambda r: ET.SubElement(ET.SubElement(r.find("devices"), "channel", type="unix"),
                                   "source", path="/home/labagent/.ssh/id_ed25519"),
            lambda r: ET.SubElement(ET.SubElement(r.find("devices"), "serial", type="file"),
                                   "source", path="/home/labagent/.ssh/id_ed25519"),
            lambda r: setattr(ET.SubElement(r.find("devices"), "emulator"), "text", "/outside/qemu"),
        ))

    def test_root_image_source_media_and_bus_fail_closed_before_arbitrary_path_access(self):
        self.assert_bad_windows((
            lambda r: r.find("./devices/disk/source").set("file", "/home/labagent/.ssh/id_ed25519"),
            lambda r: r.find("./devices/disk/source").set("file", host.IMAGES["scout-admin"]),
            lambda r: r.find("./devices/disk/source").set("file", "/var/lib/libvirt/images/scout/../scout/scout-win2025.qcow2"),
            lambda r: r.find("./devices/disk/source").set("dev", "/dev/sda"),
            lambda r: r.find("./devices/disk/source").set("protocol", "rbd"),
            lambda r: r.find("./devices/disk/source").set("socket", "/outside/socket"),
            lambda r: r.find("./devices/disk/source").set("index", "invalid"),
            lambda r: r.find("./devices/disk").set("type", "block"),
            lambda r: r.find("./devices/disk/driver").set("type", "raw"),
            lambda r: r.find("./devices/disk/target").set("bus", "usb"),
            lambda r: ET.SubElement(r.find("devices"), "disk", type="file", device="disk"),
            lambda r: ET.SubElement(r.find("devices"), "disk", type="file", device="floppy"),
            lambda r: ET.SubElement(r.find("./devices/disk"), "source", file=host.WINDOWS_IMAGE),
            lambda r: ET.SubElement(ET.SubElement(r.find("./devices/disk"), "backingStore"),
                                   "source", file="/outside/base.qcow2"),
            lambda r: ET.SubElement(r.find("./devices/disk"), "mirror"),
            lambda r: ET.SubElement(r.find("./devices/disk"), "dataStore"),
            lambda r: r.find("./devices/disk[@device='cdrom']/source").set("file", "/outside/windows.iso"),
            lambda r: r.find("./devices/disk[@device='cdrom']/source").set("dev", "/dev/cdrom"),
            lambda r: r.find("./devices/disk[@device='cdrom']/driver").set("type", "qcow2"),
            lambda r: r.find("./devices/disk[@device='cdrom']").remove(
                r.find("./devices/disk[@device='cdrom']/readonly")),
        ))

    def test_missing_and_symlinked_optional_assets_are_rejected(self):
        for path in (host.WINDOWS_IMAGE, *host.WINDOWS_MEDIA):
            for fault in ("missing", "symlinks"):
                fixture = Fixture(windows="shut off")
                getattr(fixture, fault).add(path)
                with self.assertRaisesRegex(RuntimeError, "regular file|Symlink"):
                    fixture.guard()
        fixture = Fixture(windows="shut off")
        fixture.symlinks.add("/var/lib/libvirt/images/scout/win2025-media")
        with self.assertRaisesRegex(RuntimeError, "Symlink"):
            fixture.guard()

    def test_approved_models_buses_empty_cdrom_and_active_metadata(self):
        for model in ("e1000e", "virtio"):
            for bus in ("sata", "virtio", "scsi", "nvme"):
                fixture = Fixture(windows="running")
                def edit(root):
                    root.find("./devices/interface/model").set("type", model)
                    root.find("./devices/disk/target").set("bus", bus)
                    for disk in root.findall("./devices/disk[@device='cdrom']"):
                        disk.remove(disk.find("source"))
                    root.find("./devices/interface").remove(root.find("./devices/interface/link"))
                fixture.domain_override(host.WINDOWS, edit)
                def active_edit(root):
                    edit(root)
                    root.find("./devices/disk/source").set("index", "2")
                    root.find("./devices/interface/source").set("bridge", "virbr-scoutlan")
                    root.find("./devices/interface/source").set("portid", "libvirt-port-id")
                    ET.SubElement(root.find("./devices/disk"), "backingStore")
                fixture.domain_override(host.WINDOWS, active_edit, active=True)
                self.assertEqual(set(fixture.guard()), set(host.VMs))

    def test_firmware_must_be_readonly_uefi_with_exact_private_nvram_paths(self):
        self.assert_bad_windows((
            lambda r: r.remove(r.find("os")),
            lambda r: r.find("os").remove(r.find("./os/loader")),
            lambda r: r.find("./os/loader").set("readonly", "no"),
            lambda r: r.find("./os/loader").set("type", "rom"),
            lambda r: setattr(r.find("./os/loader"), "text", "/home/labagent/.ssh/id_ed25519"),
            lambda r: r.find("./os/loader").set("format", "qcow2"),
            lambda r: setattr(r.find("./os/nvram"), "text", "/var/lib/libvirt/qemu/nvram/other_VARS.fd"),
            lambda r: r.find("./os/nvram").set("template", "/home/labagent/.ssh/id_ed25519"),
            lambda r: r.find("./os/nvram").set("type", "network"),
            lambda r: r.find("./os/nvram").set("templateFormat", "qcow2"),
            lambda r: r.find("./os/nvram").set("format", "qcow2"),
            lambda r: ET.SubElement(r.find("./os/nvram"), "source", dev="/dev/sda"),
            lambda r: setattr(ET.SubElement(r.find("os"), "kernel"), "text", "/outside/kernel"),
        ))
        for loader in host.WINDOWS_LOADERS:
            for path, fmt in host.WINDOWS_NVRAM.items():
                for template in host.WINDOWS_TEMPLATES:
                    fixture = Fixture(windows="running")
                    def edit(root):
                        root.find("./os/loader").text = loader
                        nvram = root.find("./os/nvram")
                        nvram.text = None
                        nvram.attrib.update(type="file", format=fmt, template=template, templateFormat="raw")
                        ET.SubElement(nvram, "source", file=path)
                    for active in (False, True):
                        fixture.domain_override(host.WINDOWS, edit, active=active)
                    self.assertEqual(set(fixture.guard()), set(host.VMs))
        def wrong_source(root):
            nvram = root.find("./os/nvram")
            nvram.text = None
            ET.SubElement(nvram, "source", file="/var/lib/libvirt/qemu/nvram/scout-win2025_VARS.fd",
                          socket="/outside/socket")
        self.assert_bad_windows((wrong_source,))

    def test_graphics_cannot_expose_remote_tcp_or_arbitrary_host_paths(self):
        def unspecified_listener(root):
            graphics = root.find("./devices/graphics")
            graphics.attrib.pop("listen")
            graphics.remove(graphics.find("listen"))
        self.assert_bad_windows((
            unspecified_listener,
            lambda r: r.find("./devices/graphics").set("type", "sdl"),
            lambda r: r.find("./devices/graphics").set("listen", "0.0.0.0"),
            lambda r: r.find("./devices/graphics/listen").set("address", "::"),
            lambda r: r.find("./devices/graphics/listen").set("address", "192.168.1.2"),
            lambda r: r.find("./devices/graphics/listen").set("type", "network"),
            lambda r: r.find("./devices/graphics").set("socket", "/home/labagent/.ssh/id_ed25519"),
            lambda r: ET.SubElement(r.find("./devices/graphics"), "listen", type="address", address="0.0.0.0"),
            lambda r: r.find("./devices/graphics/listen").attrib.clear(),
        ))
        for kind in ("vnc", "spice"):
            for listener in ({"type": "address", "address": "127.0.0.1"}, {"type": "none"},
                             {"type": "socket"}, {"type": "socket", "socket": f"/run/libvirt/qemu/scout-win2025.{kind}.sock"}):
                fixture = Fixture(windows="running")
                def edit(root):
                    device = root.find("./devices/graphics")
                    device.attrib = {"type": kind}
                    device.find("listen").attrib = listener
                for active in (False, True):
                    fixture.domain_override(host.WINDOWS, edit, active=active)
                self.assertEqual(set(fixture.guard()), set(host.VMs))
        def unsafe_socket(root):
            graphics = root.find("./devices/graphics")
            graphics.attrib = {"type": "vnc"}
            graphics.find("listen").attrib = {"type": "socket", "socket": "/outside/vnc.sock"}
        self.assert_bad_windows((unsafe_socket,))

    def test_tpm_is_optional_but_never_passthrough_or_host_sourced(self):
        self.assert_bad_windows((
            lambda r: r.find("./devices/tpm/backend").set("type", "passthrough"),
            lambda r: r.find("./devices/tpm/backend").set("version", "1.2"),
            lambda r: r.find("./devices/tpm/backend").set("source", "/dev/tpm0"),
            lambda r: ET.SubElement(r.find("./devices/tpm/backend"), "device", path="/dev/tpm0"),
            lambda r: ET.SubElement(r.find("./devices/tpm/backend"), "source", path="/outside/tpm"),
            lambda r: ET.SubElement(r.find("devices"), "tpm", model="tpm-crb"),
        ))
        fixture = Fixture(windows="shut off")
        fixture.domain_override(host.WINDOWS, lambda r: r.find("devices").remove(r.find("./devices/tpm")))
        self.assertEqual(set(fixture.guard()), set(host.VMs))


if __name__ == "__main__":
    unittest.main()
