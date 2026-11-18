"""The lasting log (owner, 11-18): one `cycle` line a cycle with its timings and counts, and a day file under
VR_LOG_DIR that keeps 30 days, stops at its size and never holds a secret setting."""

import io
import re
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from collector import cycle, logfile
from collector.cycle import run_cycle
from collector.store import MemoryStore
from test_cycle import at, recorded

FIELDS = ("start took read link distros sheets summaries board new summaries_asked summaries_kept_back summaries_failed "
          "summaries_batched sheets_asked sheets_kept_back sheets_failed summaries_deadline titles_kept_back distros_asked "
          "distros_kept_back refused refused_hosts skipped fixes_lines fixes_flagged fixes_carried result").split()


def fields(text):
    head, *pairs = text.split(" ")
    return head, dict(pair.split("=", 1) for pair in pairs)


class CycleLineTest(unittest.TestCase):
    def run_one(self, http_get, store=None):
        lines, t = [], [0.0]

        def clock():  # every reading moves the clock on by 2 s
            t[0] += 2
            return t[0]
        with mock.patch.object(cycle, "emit", lines.append), redirect_stderr(io.StringIO()):
            try:
                run_cycle(store or MemoryStore(), http_get, at("2026-11-07T13:30:00"), "test-box", clock=clock)
            except RuntimeError:
                pass
        [line] = lines
        return line

    def test_a_cycle_writes_one_line_of_stable_fields_with_refusals_and_skipped_sources(self):
        get = recorded()

        def refusing(url, headers=None):
            if url.startswith("https://www.cisa.gov/"):  # KEV refuses: the source is skipped, the cycle goes on
                raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)
            return get(url, headers)
        head, got = fields(self.run_one(refusing))
        self.assertEqual(head, "cycle")
        self.assertEqual(list(got), FIELDS)
        self.assertEqual(got["start"], "2026-11-07T13:30:00Z")
        self.assertTrue(all(re.fullmatch(r"\d+", got[k]) for k in ("took", "read", "link", "board")), got)
        # No Claude client: the sheets and Summaries are off, as is the Distribution table by default.
        self.assertEqual((got["distros"], got["sheets"], got["summaries"]), ("off", "off", "off"))
        self.assertEqual((got["refused"], got["refused_hosts"], got["skipped"]), ("1", "www.cisa.gov", "kev"))
        self.assertEqual(int(got["new"]), 2)  # the delta log fixture's two records
        self.assertEqual((got["fixes_lines"], got["fixes_flagged"], got["fixes_carried"], got["result"]), ("0", "0", "0", "ok"))

    def test_a_failed_cycle_still_writes_its_line_with_the_stage_it_failed_in(self):
        class Failing(MemoryStore):
            def write(self, name, doc):
                if name.startswith("board/"):
                    raise RuntimeError("bucket gone")
                super().write(name, doc)
        head, got = fields(self.run_one(recorded(), Failing()))
        self.assertEqual(got["result"], "failed:board:RuntimeError")
        self.assertEqual(got["board"], "-")  # never finished


class DayFileTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.out, self.err = io.StringIO(), io.StringIO()
        streams = mock.patch.multiple(sys, stdout=self.out, stderr=self.err)
        streams.start()
        self.addCleanup(streams.stop)
        self.now = datetime(2026, 11, 18, 6, 40, tzinfo=timezone.utc)

    def start(self, **settings):
        file = logfile.start({"VR_LOG_DIR": str(self.dir)} | settings, clock=lambda: self.now)
        self.addCleanup(file.close)
        return file

    def day(self):
        return (self.dir / "collector-2026-11-18.log").read_text(encoding="utf-8")

    def test_printed_lines_reach_the_container_output_and_the_day_file_without_secrets(self):
        hook = "https://discord.com/api/webhooks/123/abcDEF-secret"
        self.start(VR_DISCORD_WEBHOOK=hook, ANTHROPIC_API_KEY="sk-ant-0123456789")
        print("cycle start=2026-11-18T06:40:00Z took=5")
        print(f"post to {hook} failed with key sk-ant-0123456789", file=sys.stderr)
        sys.stdout.write("half a ")
        sys.stdout.write("line\n")
        self.assertIn("cycle start=", self.out.getvalue())  # docker compose logs: as before
        self.assertEqual(self.day().splitlines(), [
            "2026-11-18T06:40:00Z cycle start=2026-11-18T06:40:00Z took=5",
            "2026-11-18T06:40:00Z post to … failed with key …",
            "2026-11-18T06:40:00Z half a line"])

    def test_files_past_thirty_days_are_deleted_and_nothing_else(self):
        old = self.dir / f"collector-{(self.now - timedelta(days=31)):%Y-%m-%d}.log"
        kept = self.dir / f"collector-{(self.now - timedelta(days=29)):%Y-%m-%d}.log"
        other = self.dir / "notes.txt"
        for path in (old, kept, other):
            path.write_text("x")
        self.start()
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()),
                         sorted([kept.name, other.name, "collector-2026-11-18.log"]))

    def test_a_full_day_file_takes_one_last_line_and_then_nothing(self):
        with mock.patch.object(logfile, "DAY_BYTES", 120):
            self.start()
            for n in range(5):
                print(f"line {n} " + "x" * 30)
        lines = self.day().splitlines()
        self.assertIn("this day's file is full", lines[-1])
        self.assertLess(len(lines), 5)

    def test_no_folder_set_writes_no_file(self):
        self.assertIsNone(logfile.start({}))
        self.assertIs(sys.stdout, self.out)


if __name__ == "__main__":
    unittest.main()
