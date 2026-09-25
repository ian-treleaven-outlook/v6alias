import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "lab_host.py"
SPEC = importlib.util.spec_from_file_location("lab_host", SOURCE)
host = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(host)


class Safety:
    VM = "scout-v6alias"

    def __init__(self, state="shut off"):
        self.state = state
        self.calls = []
        self.fail_guard = False
        self.fail_after_start = False

    def guard(self, require_off=True):
        if self.fail_guard or (self.fail_after_start and self.state == "running"):
            raise RuntimeError("synthetic isolation failure")
        if require_off and self.state != "shut off":
            raise RuntimeError("guest must be off")
        return self.state

    def run(self, *args):
        self.calls.append(args)
        if args == ("virsh", "start", self.VM):
            self.state = "running"
        elif args == ("virsh", "shutdown", self.VM):
            self.state = "shut off"
        elif args == ("virsh", "domstate", self.VM):
            return self.state
        else:
            raise AssertionError(f"Unexpected command: {args}")
        return "mock success"


class HostTests(unittest.TestCase):
    def test_status_is_read_only_in_both_states(self):
        for state in ("running", "shut off"):
            safety = Safety(state)
            result = host.perform("status", safety)
            self.assertEqual(result, dict(vm=safety.VM, state=state, isolation="verified",
                                         other_vms_off=True, changed=False, action="status"))
            self.assertEqual(safety.calls, [])

    def test_start_and_stop_are_idempotent_and_pin_the_target(self):
        safety = Safety()
        self.assertTrue(host.perform("start", safety)["changed"])
        self.assertFalse(host.perform("start", safety)["changed"])
        self.assertTrue(host.perform("stop", safety)["changed"])
        self.assertFalse(host.perform("stop", safety)["changed"])
        self.assertEqual(safety.calls, [
            ("virsh", "start", "scout-v6alias"), ("virsh", "shutdown", "scout-v6alias"),
            ("virsh", "domstate", "scout-v6alias"),
        ])

    def test_invalid_scope_and_failed_preflight_never_mutate(self):
        safety = Safety()
        with self.assertRaises(ValueError):
            host.perform("destroy", safety)
        safety.fail_guard = True
        for action in ("status", "start", "stop"):
            with self.assertRaises(RuntimeError):
                host.perform(action, safety)
        self.assertEqual(safety.calls, [])
        safety.VM = "other-domain"
        with self.assertRaises(RuntimeError):
            host.perform("start", safety)

    def test_start_verification_failure_uses_clean_recovery(self):
        safety = Safety()
        safety.fail_after_start = True
        with self.assertRaisesRegex(RuntimeError, "cleanly stopped"):
            host.perform("start", safety)
        self.assertEqual(safety.state, "shut off")
        self.assertNotIn(("virsh", "destroy", "scout-v6alias"), safety.calls)

    def test_clean_stop_timeout_is_explicit_and_never_forces(self):
        safety = Safety("running")
        calls = []
        def never_stops(*args):
            calls.append(args)
            return "running"
        with patch.object(safety, "run", side_effect=never_stops):
            with self.assertRaisesRegex(RuntimeError, "no force-stop"):
                host.clean_stop(safety, clock=iter([0, 0, 121]).__next__, sleep=lambda _: None)
        self.assertEqual(calls[0], ("virsh", "shutdown", "scout-v6alias"))
        self.assertTrue(all(call[1] in ("shutdown", "domstate") for call in calls))


if __name__ == "__main__":
    unittest.main()
