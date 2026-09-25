"""Exercise the recording script in a pseudo-terminal with all demo commands mocked."""
import errno
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "record-demo.bash"


@unittest.skipUnless(os.name == "posix", "Bash pseudo-terminal tests require POSIX")
class RecordingTests(unittest.TestCase):
    def exercise(self, *, quit_first=False, fail_ping=False):
        import pty

        with tempfile.TemporaryDirectory(prefix="v6alias-recording-") as directory:
            home = Path(directory)
            (home / "v6alias").mkdir()
            log = home / "calls"
            (home / "v6alias" / "live-demo.bash").write_text(
                "clear() { printf 'CLEAR\\n' >> \"$DEMO_TEST_LOG\"; }\n"
                "sleep() { :; }\n"
                "ifconfig() { printf 'IFCONFIG\\n' >> \"$DEMO_TEST_LOG\"; }\n"
                "cat() { printf 'CAT %s\\n' \"$*\" >> \"$DEMO_TEST_LOG\"; }\n"
                "ping() { printf 'PING %s\\n' \"$*\" >> \"$DEMO_TEST_LOG\";"
                " return \"$DEMO_TEST_PING_EXIT\"; }\n"
                "ssh() { printf 'SSH %s\\n' \"$*\" >> \"$DEMO_TEST_LOG\";"
                " printf 'MOCK_REMOTE_READY\\n'; IFS= read -r answer;"
                " [[ $answer == exit ]]; }\n",
                encoding="utf-8",
            )
            master, slave = pty.openpty()
            process = subprocess.Popen(
                ["bash", str(SCRIPT)], stdin=slave, stdout=slave, stderr=slave,
                env={**os.environ, "HOME": directory, "TERM": "xterm",
                     "DEMO_TEST_LOG": str(log), "DEMO_TEST_PING_EXIT": "7" if fail_ping else "0"},
            )
            os.close(slave)
            data = b""
            presses = 0
            exited_ssh = False
            deadline = time.monotonic() + 10
            waiting_since = time.monotonic()
            completed = 0
            try:
                while time.monotonic() < deadline:
                    if select.select([master], [], [], 0.1)[0]:
                        try:
                            chunk = os.read(master, 65536)
                        except OSError as error:
                            if error.errno == errno.EIO:
                                break
                            raise
                        if not chunk:
                            break
                        data += chunk
                    count = len(log.read_text().splitlines()) // 2 if log.exists() else 0
                    if count > completed:
                        completed = count
                        waiting_since = time.monotonic()
                    # The script must stay silent and not dispatch another command
                    # until the test supplies a key, just as a presenter would.
                    if (process.poll() is None and presses < 5 and count == presses
                            and not (fail_ping and presses == 3)
                            and time.monotonic() - waiting_since >= 0.12):
                        if presses == 0:
                            self.assertEqual(data, b"", "Startup should be completely silent")
                        os.write(master, b"q" if quit_first else b" ")
                        presses += 1
                    if b"MOCK_REMOTE_READY" in data and not exited_ssh:
                        os.write(master, b"exit\n")
                        exited_ssh = True
                code = process.wait(timeout=2)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                os.close(master)
            calls = log.read_text().splitlines() if log.exists() else []
            return code, data.decode(), calls, presses

    def test_each_key_clears_types_and_executes_one_command_then_ssh_returns(self):
        code, output, calls, presses = self.exercise()
        self.assertEqual(code, 0)
        self.assertEqual(presses, 5)
        self.assertEqual(calls, [
            "CLEAR", "IFCONFIG",
            "CLEAR", "CAT /opt/v6alias-live-demo/v6alias.local.yaml",
            "CLEAR", "PING corp:43 -c 3 -W 2 -w 10",
            "CLEAR", "PING lab:7.15 -c 3 -W 2 -w 10",
            "CLEAR", "SSH corp:42",
        ])
        for narration in ("Recording sequence complete", "Ready:", "Press Enter", "[1/5]", "[5/5]"):
            self.assertNotIn(narration, output)
        self.assertIn("ifconfig", output)

    def test_quit_does_not_clear_or_execute_any_command(self):
        code, _, calls, presses = self.exercise(quit_first=True)
        self.assertEqual((code, calls, presses), (0, [], 1))

    def test_command_failure_preserves_exit_and_stops_before_ssh(self):
        code, output, calls, presses = self.exercise(fail_ping=True)
        self.assertEqual((code, presses), (7, 3))
        self.assertNotIn("SSH corp:42", calls)
        self.assertIn("Command failed (exit 7)", output)
        self.assertNotIn("Recording sequence complete.", output)

    def test_requires_terminal_and_rejects_sourcing(self):
        result = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("interactive guest console", result.stderr)
        result = subprocess.run(["bash", "-c", 'source "$1"', "test", str(SCRIPT)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("rather than source", result.stderr)


if __name__ == "__main__":
    unittest.main()
