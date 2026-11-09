"""The RSS feeds' document (ticket incident-pages/01): the newest 50 search-worthy Incidents, newest first."""

import unittest

from test_cycle import at, incident, recorded

from collector.cycle import FEED_SIZE, run_cycle
from collector.store import MemoryStore

SUMMARY = {"incident": True, "ko": {"title": "제목"}, "en": {"title": "Title"}}


def row(n, cvss, published, **extra):
    return incident(f"CVE-2026-{n}", f"Brief {n}", "2026-11-09T00:00:00Z", published) | {"cvss": cvss, "summary": SUMMARY} | extra


class FeedDocumentTest(unittest.TestCase):
    def run_with(self, rows):
        store = MemoryStore()
        store.write("index.json", {"months": ["2026-11"]})
        store.write("months/2026-11.json", {"month": "2026-11", "incidents": rows})
        run_cycle(store, recorded(None), at("2026-11-09T12:00:00"), "test-box")
        return store

    def test_lists_only_search_worthy_incidents_newest_first(self):
        store = self.run_with([
            row(1, 7.5, "2026-11-08T00:00:00Z"),
            row(2, 9.8, "2026-11-09T00:00:00Z"),
            row(3, 5.0, "2026-11-09T01:00:00Z"),  # 참고 with a CVE: not search-worthy
            row(4, 5.0, "2026-11-07T00:00:00Z", kev=True),  # exploited
            {**row(5, 9.9, "2026-11-09T02:00:00Z"), "summary": None},  # no Summary yet
        ])
        ids = [i["id"] for i in store.read("board/feed.json")["incidents"]]
        self.assertEqual(ids, ["CVE-2026-2", "CVE-2026-1", "CVE-2026-4"])
        self.assertNotIn("urls", store.read("board/feed.json")["incidents"][0])  # the page's slim copy, not the store's

    def test_keeps_the_newest_fifty(self):
        rows = [row(n, 8.0, f"2026-11-0{1 + n // 20}T{n % 20:02d}:00:00Z") for n in range(60)]
        feed = self.run_with(rows).read("board/feed.json")["incidents"]
        self.assertEqual(len(feed), FEED_SIZE)
        self.assertEqual(feed[0]["id"], "CVE-2026-59")
