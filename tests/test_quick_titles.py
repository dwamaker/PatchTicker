"""User, 2026-11-09: below 위험 (CVSS < 7.0), Haiku writes only the row's titles in the cycle that sees the Incident,
several Incidents in one request; the full Summaries wait and go out together in one Message Batch once enough have
gathered (BATCH_MIN) or the oldest has waited BATCH_WAIT_HOURS."""

import unittest
from datetime import datetime

from collector import summaries
from collector.cycle import route_summaries
from test_summaries import FakeClaude

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

    def test_a_risky_row_is_summarized_whole_at_once_and_gets_no_title_request(self):
        incidents = [row("CVE-2026-9", cvss=8.1)]
        claude = FakeClaude({"not": "checked here"})
        self.route(incidents, claude)
        self.assertEqual(len(claude.sent), 1)
        self.assertNotIn("Titles for", claude.user_text())


if __name__ == "__main__":
    unittest.main()
