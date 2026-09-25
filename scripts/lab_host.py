"""Host-side safety controller, sent through SSH stdin by Lab.ps1.

It reuses the established scout isolation guard. It never discovers or accepts
arbitrary VM names, changes networking, handles passwords, or force-stops a VM.
"""
import json
from pathlib import Path
import subprocess
import sys
import time

GUARD_DIRECTORY = Path("/home/labagent/work/scout-console-access-20260917")
VM = "scout-v6alias"


def clean_stop(safety, clock=time.monotonic, sleep=time.sleep):
    safety.run("virsh", "shutdown", VM)
    deadline = clock() + 120
    while safety.run("virsh", "domstate", VM) != "shut off":
        if clock() >= deadline:
            raise RuntimeError(
                "Clean shutdown did not finish within 120 seconds. The VM may still "
                "be running; no force-stop was attempted."
            )
        sleep(3)


def perform(action, safety):
    if action not in ("status", "start", "stop"):
        raise ValueError("Only status, start, or stop is supported.")
    if safety.VM != VM:
        raise RuntimeError("Installed guard does not target the expected service VM.")

    # Every action, including read-only status, proves isolation and checks the
    # other five scout guests. Unexpected states fail rather than guessing.
    state = safety.guard(require_off=False)
    if state not in ("running", "shut off"):
        raise RuntimeError("The guest is not in an expected running or shut-off state.")
    changed = False
    if action == "start" and state == "shut off":
        safety.guard()
        safety.run("virsh", "start", VM)
        changed = True
        try:
            state = safety.guard(require_off=False)
            if state != "running":
                raise RuntimeError("Guest startup was not confirmed.")
        except (RuntimeError, OSError, subprocess.SubprocessError) as error:
            # Only undo a start made by this invocation, using clean shutdown.
            try:
                clean_stop(safety)
                safety.guard()
            except (RuntimeError, OSError, subprocess.SubprocessError) as cleanup:
                raise RuntimeError(
                    "Post-start verification failed and clean recovery could not be "
                    "confirmed. Check Status; no force-stop was attempted."
                ) from cleanup
            raise RuntimeError("Post-start verification failed; guest cleanly stopped.") from error
    elif action == "stop" and state == "running":
        clean_stop(safety)
        state = safety.guard()
        changed = True

    # A final snapshot of the safety state is needed before reporting success.
    state = safety.guard(require_off=(action == "stop"))
    expected = {"start": "running", "stop": "shut off"}.get(action)
    if expected is not None and state != expected:
        raise RuntimeError("The requested guest state was not confirmed.")
    return {
        "vm": VM, "state": state, "isolation": "verified",
        "other_vms_off": True, "changed": changed, "action": action,
    }


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("status", "start", "stop"):
        raise ValueError("Usage: python3 - status|start|stop")
    if not (GUARD_DIRECTORY / "scout_account_guard.py").is_file():
        raise RuntimeError(
            "The installed scout isolation guard is missing. Stop and restore the "
            "approved guard; do not bypass this preflight."
        )
    sys.path.insert(0, str(GUARD_DIRECTORY))
    import scout_account_guard

    print(json.dumps(perform(sys.argv[1], scout_account_guard)), flush=True)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, ImportError, subprocess.SubprocessError) as error:
        print(f"Lab action failed: {error}", file=sys.stderr)
        sys.exit(1)
