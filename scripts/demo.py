"""Guided, offline demonstration using Python 3.10+ and the packaged native tool."""

import argparse
from contextlib import contextmanager
from datetime import datetime
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from uuid import uuid4


STEPS = [
    ("Look at this computer", "Read local interface addresses only; these stay on the console, not in the report. "
     "No managed ULA address is expected if the lab router is off."),
    ("Expand an alias", "corp:42 is a friendly name for an example IPv6 address; no lookup uses the network."),
    ("Preview ping safely", "Print the ping command WITHOUT running it. No packets will be sent."),
    ("Create fictional inventory", "Create a fresh local database and register the supplied synthetic device."),
    ("Explain the allowed decision", "The trusted corp-link and registered managed device permit this request. "
     "The trace explains each rule; a device's hostname is only an untrusted hint."),
    ("Choose the first free number", "Reserve the lowest available number, 2, in this database only. "
     "This does not assign an address to a real network interface."),
    ("Prove persistence", "Run allocation in a NEW process. It must return the exact same saved assignment."),
    ("Describe desired records", "With no observed snapshot, the plan is desired_only with an empty change list. "
     "This does NOT mean that any real server is empty."),
    ("Compare a SIMULATED snapshot", "Copy desired records into our own simulated-observed.json, NOT a live observation. "
     "Comparing this fictional matching snapshot must propose no changes."),
    ("Reject an unknown device", "The unknown fixture is not registered. A JSON denial with exit code 2 is expected, "
     "not a failed demo."),
    ("Retire the fictional device", "Permanently retire this local assignment. Its saved tombstone prevents reuse "
     "of the number in this database."),
    ("Preview cleanup, never apply", "Against our simulated snapshot, propose removing one reservation and two DNS "
     "records. Verify the saved assignment is still retired; no live records are deleted."),
]
CHANGE_FIELDS = ("add_reservations", "remove_reservations", "add_dns_records", "remove_dns_records")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


# Use a JSON parser, rejecting non-JSON numbers and ambiguous duplicate keys.
def reject_constant(value):
    raise ValueError(f"Non-JSON number: {value}")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(text):
    return json.loads(text, parse_constant=reject_constant, object_pairs_hook=unique_object)


def check_plan(plan, basis, reservations, dns, changes):
    require(plan["mode"] == "dry_run" and plan["basis"] == basis, "Unexpected plan mode or basis")
    desired = plan["desired"]
    require(desired["schema_version"] == 1 and desired["owner"] == "v6alias", "Unexpected snapshot format")
    for key, count in (("reservations", reservations), ("dns_records", dns)):
        require(isinstance(desired[key], list) and len(desired[key]) == count, f"Unexpected desired {key}")
    for key, count in zip(CHANGE_FIELDS, changes):
        require(isinstance(plan["changes"][key], list) and len(plan["changes"][key]) == count,
                f"Unexpected change count: {key}")


def check_decision(decision, allowed):
    require(decision["allowed"] is allowed and isinstance(decision["reason"], str) and decision["reason"],
            "Unexpected policy decision")
    trace = decision["trace"]
    require(isinstance(trace, list) and trace, "Missing policy trace")
    require(all(isinstance(row["matched"], bool) and row["rule"] and row["reason"] for row in trace),
            "Incomplete policy trace")
    expected = ("managed-corporate", "corp", 23) if allowed else (None, None, None)
    require(tuple(decision[key] for key in ("matched_rule", "profile", "subnet")) == expected,
            "Unexpected policy placement")
    require(any(row["matched"] for row in trace) is allowed, "Unexpected rule matches")


class Demo:
    def __init__(self, tools, work, pause, color=False):
        self.binary = tools / ("v6alias.exe" if os.name == "nt" else "v6alias")
        self.work, self.pause, self.color = work, pause, color
        self.report = {"status": "failed", "offline": True, "observed_is_simulated": True,
                       "steps": [{"name": name, "status": "pending", "commands": []} for name, _ in STEPS]}
        self.current = None

    @contextmanager
    def step(self, number):
        self.current = self.report["steps"][number - 1]
        self.current["status"] = "running"
        accent, reset = ("\x1b[1;96m", "\x1b[0m") if self.color else ("", "")
        print(f"\n{accent}[{number}/{len(STEPS)}] {STEPS[number - 1][0]}{reset}\n{STEPS[number - 1][1]}", flush=True)
        yield
        self.current["status"] = "passed"
        if self.pause:
            input("Press ENTER to continue...")

    def run(self, *arguments, group=None, expected=0, text=False, console_only=False):
        args = [str(self.binary), "--config", str(self.work / "v6alias.yaml")]
        if group:
            args += [group, "--database", str(self.work / "inventory.sqlite")]
            if group != "inventory":
                args += ["--service-config", str(self.work / "service.example.yaml")]
        args += [str(arg) for arg in arguments]
        accent, reset = ("\x1b[1;94m", "\x1b[0m") if self.color else ("", "")
        print(accent + "> " + (subprocess.list2cmdline(args) if os.name == "nt" else shlex.join(args)) + reset, flush=True)
        record = {"arguments": args[1:], "expected_exit": expected, "status": "running"}
        self.current["commands"].append(record)
        # Inherit console streams for ifconfig: never capture or serialize real machine addresses.
        result = subprocess.run(args, cwd=self.work, shell=False, timeout=30, check=False,
                                stdout=None if console_only else subprocess.PIPE,
                                stderr=None if console_only else subprocess.PIPE,
                                text=True, encoding="utf-8", errors="strict")
        record["exit_code"] = result.returncode
        if not console_only:
            print(result.stdout, end="", flush=True)
            if result.stderr:
                print(result.stderr, end="", file=sys.stderr)
        require(result.returncode == expected,
                f"Native command exited {result.returncode}; expected {expected}")
        value = None if console_only else result.stdout.strip() if text else load_json(result.stdout)
        if not console_only and not text:
            record["synthetic_result"] = value
        record["status"] = "passed"
        return value

    def execute(self, tools):
        require(self.binary.is_file(), f"Missing native executable: {self.binary}")
        # Snapshot only supplied demo inputs. Every write is inside this run's fresh directory.
        for relative in (Path("v6alias.yaml"), Path("service.example.yaml"),
                         *(Path("examples") / "offline" / name
                           for name in ("device.json", "observation.json", "unknown.json"))):
            source = tools / relative
            if relative.name == "v6alias.yaml" and (tools / "v6alias.example.yaml").is_file():
                source = tools / "v6alias.example.yaml"
            with (self.work / relative.name).open("xb") as target:
                target.write(source.read_bytes())
        device = load_json((self.work / "device.json").read_text(encoding="utf-8"))
        observation = ("--observation", self.work / "observation.json", "--trusted-link", "corp-link")
        with self.step(1):
            self.run("ifconfig", console_only=True)
        with self.step(2):
            address = self.run("resolve", "corp:42", text=True)
            require(address == "fd7a:115c:a1e0:17::2a", "Unexpected example alias address")
        with self.step(3):
            preview = self.run("ping", "corp:42", "--dry-run", text=True)
            require(f"Resolved: corp:42 -> {address}" in preview and f"ping -6 {address}" in preview,
                    "Unexpected ping preview")
        with self.step(4):
            require(self.run("init", group="inventory") == {"schema_version": 1, "initialized": True},
                    "Inventory initialization did not confirm schema 1")
            require((self.work / "inventory.sqlite").is_file(), "Missing new database")
            registered = self.run("register", "--device", self.work / "device.json", group="inventory")
            require(registered == dict(device, duid=device["duid"].replace(":", "").lower()),
                    "Registered device differs from the synthetic fixture")
        with self.step(5):
            check_decision(self.run("explain", *observation, group="policy"), True)
        with self.step(6):
            assignment = self.run("allocate", *observation, group="service")
            expected = {key: registered[key] for key in ("asset_id", "duid", "iaid")}
            expected.update(link="corp-link", profile="corp", subnet=23, device=2,
                            address="fd7a:115c:a1e0:17::2", state="active", policy_rule="managed-corporate",
                            fqdn=f"{registered['dns_label']}.v6alias.home.arpa.")
            require(assignment == expected, "Unexpected first allocation or authoritative DNS name")
        with self.step(7):
            require(self.run("allocate", *observation, group="service") == assignment,
                    "Assignment changed across separate native processes")
        with self.step(8):
            desired = self.run("plan", group="service")
            check_plan(desired, "desired_only", 1, 2, (0, 0, 0, 0))
            records = desired["desired"]
            require(records["reservations"][0]["address"] == assignment["address"] and
                    {row["type"] for row in records["dns_records"]} == {"AAAA", "PTR"},
                    "Expected a reservation and forward/reverse DNS records")
        with self.step(9):
            simulated = self.work / "simulated-observed.json"
            with simulated.open("x", encoding="utf-8") as output:
                json.dump(records, output, indent=2, allow_nan=False)
            unchanged = self.run("plan", "--observed", simulated, group="service")
            check_plan(unchanged, "owned_snapshot", 1, 2, (0, 0, 0, 0))
            require(unchanged["desired"] == records, "Matching snapshot changed desired records")
        with self.step(10):
            check_decision(self.run("explain", "--observation", self.work / "unknown.json",
                                    "--trusted-link", "corp-link", group="policy", expected=2), False)
        with self.step(11):
            retired = self.run("retire", "--asset-id", registered["asset_id"], group="service")
            require(retired == dict(assignment, state="retired"), "Missing permanent retired tombstone")
        with self.step(12):
            cleanup = self.run("plan", "--observed", simulated, group="service")
            check_plan(cleanup, "owned_snapshot", 0, 0, (0, 1, 0, 2))
            require(cleanup["changes"]["remove_reservations"] == records["reservations"] and
                    cleanup["changes"]["remove_dns_records"] == records["dns_records"],
                    "Cleanup differs from our simulated records")
            require(self.run("assignments", group="service") == [retired], "Planning changed saved state")
        self.report["status"] = "passed"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    here = Path(__file__).resolve().parent
    default = here if any((here / name).is_file() for name in ("v6alias", "v6alias.exe")) else (
        here.parent / "dist" / ("windows-x64" if os.name == "nt" else "linux-x64"))
    parser.add_argument("--tools", type=Path, default=default, help="Directory containing packaged v6alias and fixtures")
    parser.add_argument("--output-root", type=Path, help="Parent for a fresh run directory (default: tools/state)")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                        help="Color step headings; JSON reports are always plain")
    pauses = parser.add_mutually_exclusive_group()
    pauses.add_argument("--pause", action="store_true", help="Wait for ENTER after each step")
    pauses.add_argument("--no-pause", action="store_true", help="Run automatically (the default)")
    args = parser.parse_args(argv)
    demo = None
    exit_code = 0
    try:
        tools = args.tools.resolve()
        root = (args.output_root or tools / "state").resolve()
        root.mkdir(parents=True, exist_ok=True)
        work = root / f"demo-{datetime.now():%Y%m%d-%H%M%S}-{uuid4().hex[:12]}"
        work.mkdir(mode=0o700)  # Exclusive creation: never reuse a previous run or its database.
        color = args.color == "always" or (
            args.color == "auto" and sys.stdout.isatty()
            and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"
        )
        demo = Demo(tools, work, args.pause, color)
        print(f"Offline guided demo. New scratch directory: {work}", flush=True)
        demo.execute(tools)
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError, KeyError, TypeError,
            EOFError, KeyboardInterrupt) as error:
        print(f"Demo stopped: {type(error).__name__}: {error}", file=sys.stderr)
        if demo:
            demo.report["error_type"] = type(error).__name__  # No raw diagnostics or machine IPs in reports.
        exit_code = 1
    finally:
        if demo:
            for step in demo.report["steps"]:
                if step["status"] == "running":
                    step["status"] = "failed"
                for command in step["commands"]:
                    if command["status"] == "running":
                        command["status"] = "failed"
            try:
                report = demo.work / "report.json"
                with report.open("x", encoding="utf-8") as output:
                    json.dump(demo.report, output, indent=2, allow_nan=False)
                print(f"\nScratch directory: {demo.work}\nReport: {report}", flush=True)
            except OSError as error:
                print(f"Could not save report: {error}", file=sys.stderr)
                exit_code = 1
    if exit_code:
        return exit_code
    print("All 12 steps verified. No network settings changed. Live DHCP/DNS integration is not implemented.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
