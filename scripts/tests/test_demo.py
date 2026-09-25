"""Offline tests: native processes are mocked; scratch files stay under this directory."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("demo", ROOT / "scripts" / "demo.py")
demo = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(demo)


class DemoTests(unittest.TestCase):
    def setUp(self):
        self.home = Path(__file__).parent / f".demo-test-{uuid4().hex}"
        self.home.mkdir()
        self.addCleanup(shutil.rmtree, self.home)
        self.tools = self.home / "tools with spaces"
        self.tools.mkdir()
        files = [(Path("v6alias.example.yaml"), Path("v6alias.yaml")),
                 (Path("service.example.yaml"), Path("service.example.yaml"))]
        for name in ("device.json", "observation.json", "unknown.json"):
            path = Path("examples") / "offline" / name
            files.append((path, path))
        for source, target in files:
            destination = self.tools / target
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / source, destination)
        (self.tools / ("v6alias.exe" if demo.os.name == "nt" else "v6alias")).write_bytes(b"mock only")
        self.device = demo.load_json((self.tools / "examples" / "offline" / "device.json").read_text())
        self.device["duid"] = self.device["duid"].replace(":", "").lower()
        self.assignment = dict(asset_id="demo-workstation", duid=self.device["duid"], iaid=1,
                               link="corp-link", profile="corp", subnet=23, device=2,
                               address="fd7a:115c:a1e0:17::2", state="active",
                               policy_rule="managed-corporate", fqdn="demo-workstation.v6alias.home.arpa.")
        self.records = {
            "schema_version": 1, "owner": "v6alias",
            "reservations": [{key: self.assignment[key] for key in
                              ("asset_id", "link", "duid", "iaid", "address", "fqdn")}],
            "dns_records": [{"type": "AAAA", "name": self.assignment["fqdn"],
                             "value": self.assignment["address"], "ttl": 300},
                            {"type": "PTR", "name": "synthetic.ip6.arpa.",
                             "value": self.assignment["fqdn"], "ttl": 300}],
        }
        self.failure = None
        self.retired = False
        self.calls = []

    def native(self, args, **options):
        self.calls.append((args, options))
        self.assertIsInstance(args, list)
        self.assertFalse(options["shell"])
        self.assertEqual(options["timeout"], 30)
        self.assertEqual(Path(args[0]).parent, self.tools.resolve())
        self.assertTrue(Path(args[2]).is_relative_to(options["cwd"]))
        code, value = 0, None
        if args[3] == "ifconfig":
            self.assertIsNone(options["stdout"])
            self.assertIsNone(options["stderr"])
            if self.failure == "timeout":
                raise subprocess.TimeoutExpired(args, 30)
            return subprocess.CompletedProcess(args, 7 if self.failure == "exit" else 0,
                                               "REAL_MACHINE_IP_MUST_NOT_BE_SAVED", "")
        if args[3] == "resolve":
            return subprocess.CompletedProcess(args, 0, "fd7a:115c:a1e0:17::2a\n", "")
        if args[3] == "ping":
            self.assertIn("--dry-run", args)
            return subprocess.CompletedProcess(args, 0, "Resolved: corp:42 -> fd7a:115c:a1e0:17::2a\n"
                                                       "Command:  ping -6 fd7a:115c:a1e0:17::2a\n", "")
        if "init" in args:
            self.retired = False
            Path(args[args.index("--database") + 1]).touch(exist_ok=False)
            value = {"schema_version": 1, "initialized": True}
        elif "register" in args:
            value = self.device
        elif "explain" in args:
            allowed = Path(args[args.index("--observation") + 1]).name != "unknown.json"
            code = 0 if allowed else 2
            if not allowed and self.failure == "json":
                return subprocess.CompletedProcess(args, 2, "not JSON", "")
            value = dict(allowed=allowed, reason="synthetic reason",
                         matched_rule="managed-corporate" if allowed else None,
                         profile="corp" if allowed else None, subnet=23 if allowed else None,
                         trace=[dict(rule="managed-corporate", priority=100, matched=allowed, reason="test")])
        elif "allocate" in args:
            value = self.assignment
        elif "retire" in args:
            self.retired = True
            value = dict(self.assignment, state="retired")
        elif "assignments" in args:
            value = [dict(self.assignment, state="retired")]
        elif "plan" in args:
            changes = {key: [] for key in demo.CHANGE_FIELDS}
            records = self.records
            if self.retired:
                records = dict(self.records, reservations=[], dns_records=[])
                changes.update(remove_reservations=self.records["reservations"],
                               remove_dns_records=self.records["dns_records"])
            value = dict(mode="dry_run", basis="owned_snapshot" if "--observed" in args else "desired_only",
                         desired=records, changes=changes)
        else:
            self.fail(f"Unexpected native command: {args}")
        return subprocess.CompletedProcess(args, code, json.dumps(value), "")

    def invoke(self, *extra):
        before = set((self.tools / "state").glob("demo-*/report.json"))
        with patch.object(demo.subprocess, "run", side_effect=self.native), patch("builtins.input") as pause:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                result = demo.main(["--tools", str(self.tools), *extra])
        reports = set((self.tools / "state").glob("demo-*/report.json")) - before
        self.assertEqual(len(reports), 1)
        path = reports.pop()
        return result, json.loads(path.read_text()), path, pause.call_count

    def test_complete_runs_are_independent_and_never_save_machine_addresses(self):
        original = {path: path.read_bytes() for path in self.tools.rglob("*") if path.is_file()}
        result, report, first, pauses = self.invoke()
        self.assertEqual((result, pauses), (0, 0))
        self.assertEqual(report["status"], "passed")
        self.assertEqual(len(report["steps"]), 12)
        self.assertTrue(all(step["status"] == "passed" for step in report["steps"]))
        self.assertEqual(len(self.calls), 14)
        self.assertNotIn("REAL_MACHINE_IP", first.read_text())
        self.assertEqual(report["steps"][9]["commands"][0]["exit_code"], 2)
        result, _, second, pauses = self.invoke("--pause")
        self.assertEqual((result, pauses), (0, 12))
        self.assertNotEqual(first.parent, second.parent)
        self.assertEqual(original, {path: path.read_bytes() for path in original})
        self.assertTrue((second.parent / "simulated-observed.json").is_file())

    def test_nonzero_exit_stops_and_leaves_partial_report(self):
        self.failure = "exit"
        result, report, _, _ = self.invoke("--no-pause")
        self.assertEqual(result, 1)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["steps"][0]["status"], "failed")
        self.assertEqual(report["steps"][0]["commands"][0]["exit_code"], 7)
        self.assertTrue(all(step["status"] == "pending" for step in report["steps"][1:]))

    def test_packaged_examples_leave_user_display_mapping_untouched(self):
        example = (ROOT / "v6alias.example.yaml").read_bytes()
        (self.tools / "v6alias.example.yaml").write_bytes(example)
        user_config = b"profiles: user-managed-display-mapping\n"
        (self.tools / "v6alias.yaml").write_bytes(user_config)
        result, _, report, _ = self.invoke()
        self.assertEqual(result, 0)
        self.assertEqual((report.parent / "v6alias.yaml").read_bytes(), example)
        self.assertEqual((self.tools / "v6alias.yaml").read_bytes(), user_config)

    def test_timeout_stops_and_records_failure(self):
        self.failure = "timeout"
        result, report, _, _ = self.invoke()
        self.assertEqual(result, 1)
        self.assertEqual(report["error_type"], "TimeoutExpired")
        self.assertEqual(report["steps"][0]["commands"][0]["status"], "failed")

    def test_expected_denial_still_requires_valid_json(self):
        self.failure = "json"
        result, report, _, _ = self.invoke()
        self.assertEqual(result, 1)
        self.assertEqual(report["steps"][9]["status"], "failed")
        self.assertEqual(report["steps"][10]["status"], "pending")

    def test_json_and_plan_regressions_fail(self):
        for text in ('{"x": 1, "x": 2}', '{"x": NaN}', '{} trailing text'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                demo.load_json(text)
        with self.assertRaises(RuntimeError):
            demo.check_plan(dict(mode="dry_run", basis="owned_snapshot"), "desired_only", 1, 2, (0, 0, 0, 0))

    def test_color_is_presentation_only_and_does_not_enter_reports(self):
        with patch.object(demo.subprocess, "run", side_effect=self.native):
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                result = demo.main(["--tools", str(self.tools), "--color", "always"])
        self.assertEqual(result, 0)
        self.assertIn("\x1b[1;96m[1/12]", output.getvalue())
        reports = list((self.tools / "state").glob("demo-*/report.json"))
        self.assertEqual(len(reports), 1)
        self.assertNotIn("\\u001b", reports[0].read_text())
        self.assertNotIn("\x1b", reports[0].read_text())


if __name__ == "__main__":
    unittest.main()
