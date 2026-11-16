"""Owner, 11-16: a failed collector cycle posts one Discord line (collector/alert.py, run by compose.yaml's loop)."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from collector import __main__ as cli, alert, discord

T0 = datetime(2026, 11, 16, 1, 0, tzinfo=timezone.utc)
HOOK = "https://discord.com/api/webhooks/123/secret-token"


class CycleAlertTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / alert.STATE_FILE
        self.posts = []

    def tearDown(self):
        self.dir.cleanup()

    def end(self, code, minutes=0, notify=None):
        with contextlib.redirect_stderr(io.StringIO()):
            return alert.cycle_end(self.path, code, notify or self.posts.append, T0 + timedelta(minutes=minutes))

    def test_the_first_failed_cycle_posts_at_once_the_next_ones_within_the_hour_do_not(self):
        self.assertEqual(self.end(1), "Patch Ticker 수집기: 수집 주기 실패 · 종료 코드 1 · 2026-11-16 10:00 KST")
        for m in (10, 20, 50):
            self.assertEqual(self.end(1, m), "")
        self.assertEqual(len(self.posts), 1)

    def test_after_an_hour_of_failures_one_line_says_how_many(self):
        for m in range(0, 70, 10):
            self.end(1, m)
        self.assertEqual(self.posts[1:], ["Patch Ticker 수집기: 수집 주기 7회 연속 실패 · 2026-11-16 10:00 KST부터 · 마지막: 종료 코드 1"])

    def test_a_success_after_failures_posts_one_recovered_line_and_a_success_after_a_success_posts_nothing(self):
        self.end(1)
        self.end(124, 10)
        self.assertEqual(self.end(0, 20), "Patch Ticker 수집기: 수집 주기 복구 · 2회 연속 실패 뒤 성공 · 2026-11-16 10:20 KST")
        self.assertEqual(self.end(0, 30), "")
        self.assertTrue(self.end(1, 40).startswith("Patch Ticker 수집기: 수집 주기 실패 · "))  # a new run of failures
        self.assertEqual(len(self.posts), 3)

    def test_a_post_that_fails_or_times_out_changes_nothing_about_the_cycle(self):
        def timed_out(url, payload):
            raise TimeoutError("timed out")
        notify = discord.make_notifier(HOOK, timed_out)
        self.assertTrue(self.end(1, notify=notify))  # the line was due; Discord did not take it
        self.assertEqual(json.loads(self.path.read_text())["failed"], 1)

        def broken(line):
            raise RuntimeError("bug in the alert")
        self.end(1, 70, notify=broken)
        self.assertEqual(json.loads(self.path.read_text())["failed"], 2)
        # The loop's step itself never fails, whatever happens inside it.
        with mock.patch.object(cli.alert, "cycle_end", side_effect=RuntimeError("bug")), contextlib.redirect_stderr(io.StringIO()):
            self.assertIsNone(cli.cycle_end_main("1", "/nonexistent/.env"))

    def test_a_timed_out_cycle_is_reported_though_no_python_code_of_the_cycle_ran_its_handler(self):
        self.assertIn(f"제한 시간 {alert.TIMEOUT_S}초 초과", self.end(alert.TIMED_OUT))
        compose = (Path(__file__).parent.parent / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn(f"timeout -k 60 {alert.TIMEOUT_S} python -m collector; c=$$?", compose)
        self.assertIn("python -m collector --cycle-end $$c", compose)

    def test_an_uncaught_exception_still_ends_the_cycle_and_its_first_line_is_posted(self):
        error = OSError("https://bucket.r2.example/months/2026-11.json?X-Amz-Signature=abc: 503\nsecond line")
        with mock.patch.dict(os.environ, {"VR_BACKUP_DB": str(Path(self.dir.name) / "store.sqlite")}), \
                mock.patch.object(cli, "cycle_main", side_effect=error), mock.patch.object(cli.sys, "argv", ["collector"]):
            with self.assertRaises(OSError):
                cli.main()
        self.assertEqual(self.end(1), "Patch Ticker 수집기: 수집 주기 실패 · "
                                      "`OSError: https://bucket.r2.example/months/2026-11.json 503` · 2026-11-16 10:00 KST")
        self.assertNotIn("error", json.loads(self.path.read_text()))  # used once

    def test_the_line_carries_no_query_string_and_is_cut_to_length(self):
        with mock.patch.dict(os.environ, {"VR_R2_SECRET_ACCESS_KEY": "s3cr3t-value-123"}):
            line = alert.clean("KeyError: s3cr3t-value-123 at https://x.example/a?token=t0k3n#frag and " + "x" * 400)
        self.assertNotIn("s3cr3t", line)
        self.assertNotIn("t0k3n", line)
        self.assertTrue(line.startswith("KeyError: … at https://x.example/a and "))
        self.assertEqual(len(line), alert.REASON_CHARS)

    def test_no_webhook_means_nothing_is_counted_or_posted(self):
        self.assertEqual(alert.cycle_end(self.path, 1, None, T0), "")
        self.assertFalse(self.path.exists())

    def test_the_hand_test_posts_one_marked_line_and_leaves_the_count(self):
        self.end(1)
        sent = []
        env = {"VR_DISCORD_WEBHOOK": HOOK, "VR_BACKUP_DB": str(Path(self.dir.name) / "store.sqlite")}
        with mock.patch.dict(os.environ, env), mock.patch.object(cli, "make_http_post", lambda agent: lambda url, p: sent.append(p)), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.alert_test_main("/nonexistent/.env"), 0)
        self.assertEqual([p["content"] for p in sent], [alert.TEST_LINE])
        self.assertEqual(json.loads(self.path.read_text())["failed"], 1)
