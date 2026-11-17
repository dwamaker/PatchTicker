"""The RSS feeds' document (ticket incident-pages/01): the newest 50 search-worthy Incidents, newest first."""

import unittest

from test_cycle import at, incident, recorded

from collector.cycle import FEED_SIZE, run_cycle
from collector.incidents import page_slug
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

    def test_keeps_the_newest_feed_size(self):
        rows = [row(n, 8.0, f"2026-11-0{1 + n // 24}T{n % 24:02d}:00:00Z") for n in range(FEED_SIZE + 10)]
        feed = self.run_with(rows).read("board/feed.json")["incidents"]
        self.assertEqual(len(feed), FEED_SIZE)
        self.assertEqual(feed[0]["id"], f"CVE-2026-{FEED_SIZE + 9}")


class FeedSizeTest(unittest.TestCase):
    def test_the_feed_holds_more_than_a_day_for_a_reader_that_looks_once_a_day(self):
        # owner, 11-17: 50 Incidents were 14 hours; 200 were about three and a half days on 11-17
        self.assertEqual(FEED_SIZE, 200)


class AllFeedDocumentTest(unittest.TestCase):
    """Owner, 11-17: a second feed carries the whole Board, notice level included, as light items (board/feed-all.json,
    edge/feed.mjs allFeedResponse): the check documents' entry for each Incident plus its row tags in both languages."""

    def test_holds_the_newest_board_incidents_of_every_level_light(self):
        from test_pages import WatchedStore, cycle
        story = incident("https://news.ycombinator.com/item?id=9", "HN story", "2026-11-09T00:00:00Z", "2026-11-09T05:00:00Z") | {
            "cves": [], "summary": {"incident": False}}  # not an Incident: off the Board
        store = cycle(WatchedStore(), [
            row(1, 7.5, "2026-11-08T00:00:00Z", summary=SUMMARY | {"products": ["OpenSSH"], "platforms": ["Linux"]}),
            row(3, 5.0, "2026-11-09T01:00:00Z"),  # notice: not in /feed.xml, here
            {**row(5, 9.9, "2026-11-09T02:00:00Z"), "summary": None},  # no Summary yet: its Brief and its Board row
            story,
        ])
        doc = store.read("board/feed-all.json")
        self.assertEqual([e["id"] for e in doc["incidents"]], ["CVE-2026-5", "CVE-2026-3", "CVE-2026-1"])
        fresh = doc["incidents"][0]
        self.assertEqual((fresh["title_en"], fresh["url"], fresh["level"]), ("Brief 5", "https://patchticker.com/#i=CVE-2026-5", "highest"))
        self.assertNotIn("detail", fresh)
        self.assertEqual(doc["incidents"][2]["tags"], {"ko": ["Linux", "OpenSSH"], "en": ["Linux", "OpenSSH"]})
        self.assertEqual(doc["incidents"][2]["detail"], f"https://data.patchticker.com/pages/{page_slug('CVE-2026-1')}.json")
        cycle(store)
        self.assertNotIn("board/feed-all.json", store.writes)  # unchanged: not written again

    def test_keeps_the_newest_feed_all_size(self):
        from collector.cycle import FEED_ALL_SIZE
        rows = [row(n, 5.0, f"2026-11-0{1 + n // 100}T{n % 24:02d}:{n % 60:02d}:00Z") for n in range(FEED_ALL_SIZE + 5)]
        feed = FeedDocumentTest.run_with(self, rows).read("board/feed-all.json")["incidents"]
        self.assertEqual(len(feed), FEED_ALL_SIZE)
