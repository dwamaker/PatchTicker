"""User, 2026-11-09: below 위험 (CVSS < 7.0), Haiku writes only the row's titles in the cycle that sees the Incident,
several Incidents in one request; the full Summaries wait and go out together in one Message Batch once enough have
gathered (BATCH_MIN) or the oldest has waited BATCH_WAIT_HOURS."""

import contextlib
import io
import unittest
from datetime import datetime

from collector import summaries
from collector.cycle import route_summaries
from test_summaries import FakeClaude, cut

NOW = datetime(2026, 11, 9, 12, 0)
STAMP = "2026-11-09T12:00:00Z"


def row(cve, cvss=5.3, first_seen="2026-11-09T11:30:00Z", text=None):
    return {"id": cve, "cves": [cve], "cvss": cvss, "first_seen": first_seen, "published": first_seen,
            "mentions": [{"kind": "cve_record", "url": f"https://www.cve.org/CVERecord?id={cve}"}],
            "brief": {"text": text or f"Widget 2.1 lets a remote attacker read files ({cve}).", "lead": ""}}


def titles(*ids):
    return {"items": [{"id": i, "ko_title": "위젯 파일 읽기 취약점", "en_title": "Widget file read flaw",
                       "ko_easy_title": "위젯 파일 엿보기 위험", "en_easy_title": "Widget files exposed"} for i in ids]}


class QuickTitleTest(unittest.TestCase):
    def setUp(self):
        self.saved = (summaries.QUICK_TITLES, summaries.BATCH_MIN, summaries.BATCH_WAIT_HOURS)
        summaries.QUICK_TITLES, summaries.BATCH_MIN, summaries.BATCH_WAIT_HOURS = True, 100, 3

    def tearDown(self):
        summaries.QUICK_TITLES, summaries.BATCH_MIN, summaries.BATCH_WAIT_HOURS = self.saved

    def route(self, incidents, claude, batches=None):
        route_summaries(incidents, batches if batches is not None else [], claude, lambda *a, **k: b"", NOW, STAMP, set(), False)

    def test_rows_below_the_risk_level_get_titles_in_one_request_and_their_summaries_wait(self):
        incidents = [row("CVE-2026-1"), row("CVE-2026-2")]
        claude = FakeClaude(titles("CVE-2026-1", "CVE-2026-2"))
        self.route(incidents, claude)
        self.assertEqual(len(claude.sent), 1)  # one request for both
        self.assertEqual(incidents[1]["quick_title"]["ko"], {"title": "위젯 파일 읽기 취약점", "easy_title": "위젯 파일 엿보기 위험"})
        self.assertEqual(claude.batches, [])  # two waiting, the newest minutes old: not yet
        self.route(incidents, claude)  # the next cycle asks for nothing again
        self.assertEqual(len(claude.sent), 1)

    def test_the_waiting_summaries_go_out_together_once_the_oldest_has_waited_three_hours(self):
        incidents = [row("CVE-2026-1", first_seen="2026-11-09T08:30:00Z"), row("CVE-2026-2")]
        for i in incidents:
            i["quick_title"] = {"ko": {}, "en": {}}
        claude = FakeClaude()
        self.route(incidents, claude)
        self.assertEqual(len(claude.batches), 1)
        self.assertEqual(len(claude.batches[0]["requests"]), 2)

    def test_a_title_with_a_number_or_a_cve_id_not_in_its_own_input_is_dropped(self):
        incidents = [row("CVE-2026-1"), row("CVE-2026-2")]
        bad = titles("CVE-2026-1", "CVE-2026-2")
        bad["items"][0]["en_title"] = "Widget 9.9 file read flaw"
        bad["items"][1]["ko_title"] = "CVE-2026-1002 위젯 파일 읽기"  # real IDs have 4+ digits
        self.route(incidents, FakeClaude(bad))
        self.assertNotIn("quick_title", incidents[0])
        self.assertNotIn("quick_title", incidents[1])

    def test_a_risky_row_is_asked_for_its_whole_summary_at_once_before_any_titles(self):
        incidents = [row("CVE-2026-9", cvss=8.1)]
        claude = FakeClaude({"not": "checked here"}, titles("CVE-2026-9"))  # the reply fails, so titles follow
        self.route(incidents, claude)
        self.assertNotIn("Titles for", claude.user_text(0))

    # Owner, 2026-11-09: once a cycle has run, no row on the board shows only its English Brief unless the API failed.
    def test_a_row_waiting_in_a_running_batch_without_titles_gets_them(self):
        incidents = [row("CVE-2026-1")]
        claude = FakeClaude(titles("CVE-2026-1"))
        claude.batches.append({"id": "msgbatch_old", "requests": [], "results": None})  # still running
        pending = {"id": "msgbatch_old", "requests": {"r0": {"incident": "CVE-2026-1", "input": "x", "basis": {}}}}
        self.route(incidents, claude, [pending])
        self.assertEqual(len(claude.sent), 1)
        self.assertIn("quick_title", incidents[0])
        self.assertEqual(len(claude.batches), 1)  # not sent again in a new batch

    def test_a_risky_row_whose_summary_fails_gets_titles_first_in_the_same_cycle(self):
        incidents = [row("CVE-2026-1"), row("CVE-2026-9", cvss=8.1)]
        claude = FakeClaude("not json", titles("CVE-2026-1", "CVE-2026-9"))
        self.route(incidents, claude)
        self.assertEqual(incidents[1]["summary_error"]["tries"], 1)
        self.assertIn("quick_title", incidents[1])
        self.assertIn("quick_title", incidents[0])
        asked = claude.user_text(1)
        self.assertLess(asked.index("CVE-2026-9"), asked.index("CVE-2026-1"))  # the failed candidate leads

    def test_a_risky_row_out_of_summary_tries_still_gets_titles(self):
        incidents = [row("CVE-2026-9", cvss=8.1) | {"summary_error": {"tries": 3, "reason": "x", "final": True, "with_reason": True}}]
        claude = FakeClaude(titles("CVE-2026-9"))
        self.route(incidents, claude)
        self.assertEqual(len(claude.sent), 1)
        self.assertIn("quick_title", incidents[0])

    def test_a_row_the_reply_left_out_is_asked_for_again_next_cycle(self):
        incidents = [row("CVE-2026-1"), row("CVE-2026-2")]
        claude = FakeClaude(titles("CVE-2026-1"), titles("CVE-2026-2"))
        self.route(incidents, claude)
        self.assertNotIn("quick_title", incidents[1])
        self.route(incidents, claude)
        self.assertEqual(len(claude.sent), 2)
        self.assertNotIn("CVE-2026-1", claude.user_text(1))  # titled rows are not asked again
        self.assertIn("quick_title", incidents[1])

    # 11-10: a whole cycle's titles were lost without a trace. Dropped titles say how many and why, on one line.
    def test_dropped_titles_are_logged_with_how_many_and_why(self):
        incidents = [row("CVE-2026-1"), row("CVE-2026-2"), row("CVE-2026-3")]
        bad = titles("CVE-2026-1", "CVE-2026-2", "CVE-2026-3")
        bad["items"][0]["en_title"] = "Widget 9.9 file read flaw"
        bad["items"][1]["ko_title"] = ""
        log = io.StringIO()
        with contextlib.redirect_stderr(log):
            summaries.title_now(incidents, FakeClaude(bad), STAMP)
        self.assertIn("quick_title", incidents[2])
        self.assertEqual(log.getvalue().count("\n"), 1)
        self.assertIn("summaries: titles: dropped 2 of 3", log.getvalue())
        self.assertIn("CVE-2026-1: numbers not in its line", log.getvalue())
        self.assertIn("CVE-2026-2: malformed", log.getvalue())

    def test_a_digit_its_line_spells_as_a_word_is_kept(self):
        # 11-11: the same allowance as the Summary's check (CVE-2026-58805, "zero arbitrary secure memory").
        incidents = [row("CVE-2026-1", text="Widget has a possible way to zero arbitrary secure memory.")]
        good = titles("CVE-2026-1")
        good["items"][0] |= {"ko_title": "위젯 메모리를 0으로 덮어쓰는 결함", "en_title": "Widget can set secure memory to 0"}
        summaries.title_now(incidents, FakeClaude(good), STAMP)
        self.assertEqual(incidents[0]["quick_title"]["en"]["title"], "Widget can set secure memory to 0")

    def test_an_unreadable_titles_reply_is_logged(self):
        log = io.StringIO()
        with contextlib.redirect_stderr(log):
            summaries.title_now([row("CVE-2026-1"), row("CVE-2026-2")], FakeClaude("not json"), STAMP)
        self.assertIn("summaries: titles reply unreadable, dropped 2 of 2", log.getvalue())

    # 2026-11-11, 01:40 KST: two requests of 20 long lines were both cut at max_tokens (thinking counts toward it) and 40
    # rows kept their English source text; the same rows five at a time all came back.
    def test_a_reply_cut_at_max_tokens_is_asked_again_in_halves(self):
        incidents = [row(f"CVE-2026-{n}") for n in range(1, 5)]
        claude = FakeClaude(cut('{"items": [{"id": "CVE-2026-1", "ko_title": "위젯'), titles("CVE-2026-1", "CVE-2026-2"),
                            titles("CVE-2026-3", "CVE-2026-4"))
        log = io.StringIO()
        with contextlib.redirect_stderr(log):
            summaries.title_now(incidents, claude, STAMP)
        self.assertEqual(len(claude.sent), 3)
        self.assertTrue(all("quick_title" in i for i in incidents))
        self.assertEqual(log.getvalue(), "")

    def test_a_reply_for_one_incident_still_cut_is_dropped_and_logged_once(self):
        claude = FakeClaude(cut('{"items": ['))
        log = io.StringIO()
        with contextlib.redirect_stderr(log):
            summaries.title_now([row("CVE-2026-1")], claude, STAMP)
        self.assertEqual(len(claude.sent), 1)
        self.assertEqual(log.getvalue().count("\n"), 1)
        self.assertIn("summaries: titles reply unreadable, dropped 1 of 1 (stop_reason max_tokens)", log.getvalue())

    def test_a_malformed_reply_not_cut_is_not_asked_again(self):
        claude = FakeClaude("not json", titles("CVE-2026-1"))
        with contextlib.redirect_stderr(io.StringIO()):
            summaries.title_now([row("CVE-2026-1"), row("CVE-2026-2")], claude, STAMP)
        self.assertEqual(len(claude.sent), 1)

    def test_titles_the_reply_left_out_are_counted(self):
        log = io.StringIO()
        with contextlib.redirect_stderr(log):
            summaries.title_now([row("CVE-2026-1"), row("CVE-2026-2")], FakeClaude(titles("CVE-2026-1")), STAMP)
        self.assertIn("summaries: titles: dropped 1 of 2: CVE-2026-2: left out", log.getvalue())

    def test_nothing_is_logged_when_every_title_is_kept(self):
        log = io.StringIO()
        with contextlib.redirect_stderr(log):
            summaries.title_now([row("CVE-2026-1")], FakeClaude(titles("CVE-2026-1")), STAMP)
        self.assertEqual(log.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
