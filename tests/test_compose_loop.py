"""Security audit run-1 (11-10): a cycle that hangs blocks every later cycle. compose.yaml's loop bounds one cycle's
run time with coreutils `timeout`, logs a timed-out cycle as such and goes on. The cycle line runs here under sh with a
fake `python` and a 1-second limit (needs sh and coreutils, as in the image; Git for Windows has both)."""

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SH = shutil.which("sh") or next((p for p in (r"C:\Program Files\Git\usr\bin\sh.exe",) if os.path.exists(p)), None)


def cycle_line():
    """The loop's cycle line, as sh sees it ($$ is Compose's escape for $), with the limit cut to 1 second."""
    line = next(line for line in (ROOT / "compose.yaml").read_text(encoding="utf-8").splitlines()
                if "python -m collector" in line and "timeout" in line)
    return line.strip().replace("$$", "$").replace("3000", "1")


@unittest.skipUnless(SH, "needs sh with coreutils timeout")
class CycleLimitTest(unittest.TestCase):
    def run_with(self, fake):
        with tempfile.TemporaryDirectory() as tmp:
            pathlib.Path(tmp, "python").write_text(f"#!/bin/sh\n{fake}\n", newline="\n")
            os.chmod(pathlib.Path(tmp, "python"), 0o755)
            # /usr/bin first: from Windows, Git's sh would otherwise find System32's timeout.exe
            unix = subprocess.run([SH, "-c", f'PATH="/usr/bin:$PATH"; cygpath -u "{tmp}" 2>/dev/null || echo "{tmp}"'],
                                  capture_output=True, text=True).stdout.strip()
            script = f'PATH="{unix}:/usr/bin:$PATH"; chmod +x "{unix}/python"; {cycle_line()}; echo next'
            return subprocess.run([SH, "-c", script], capture_output=True, text=True, timeout=30).stdout

    def test_a_hung_cycle_is_stopped_logged_as_timed_out_and_the_loop_goes_on(self):
        out = self.run_with("exec sleep 20")
        self.assertIn("cycle timed out after 1 s", out)
        self.assertTrue(out.endswith("next\n"))

    def test_a_failed_cycle_is_still_logged_with_its_exit(self):
        out = self.run_with("exit 3")
        self.assertIn("cycle failed with exit 3", out)
        self.assertNotIn("timed out", out)

    def test_a_good_cycle_logs_nothing(self):
        self.assertEqual(self.run_with("exit 0"), "next\n")


if __name__ == "__main__":
    unittest.main()
