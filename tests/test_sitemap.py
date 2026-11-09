"""The Incident sitemap's document (ticket incident-pages/05): every search-worthy page of the last 90 days."""

import unittest

from test_cycle import incident
from test_pages import SUMMARY, WatchedStore, cycle, row


class SitemapDocumentTest(unittest.TestCase):
    def test_lists_every_search_worthy_page_of_the_last_90_days_with_first_seen_and_last_change(self):
        story = incident("https://news.ycombinator.com/item?id=77", "A story", "2026-11-09T03:00:00Z") | {"cves": [], "summary": SUMMARY}
        store = cycle(WatchedStore(), [
            row(1, cvss=9.8),
            row(2),  # 참고 with a CVE: a page for sharing, not for search
            row(3, cvss=9.8, summary=None),  # no Summary yet: no page
            row(4, cvss=9.8, first_seen="2026-08-10T00:00:00Z"),  # first seen 91 days ago: expired
            row(5, kev=True, first_seen="2026-08-12T00:00:00Z"),  # exploited
            story,  # without a CVE
        ])
        self.assertEqual(store.read("sitemap.json"), {"pages": {
            "CVE-2026-1001": {"first_seen": "2026-11-09T00:00:00Z", "changed": "2026-11-09T12:00:00Z"},
            "CVE-2026-1005": {"first_seen": "2026-08-12T00:00:00Z", "changed": "2026-11-09T12:00:00Z"},
            "hn-77": {"first_seen": "2026-11-09T03:00:00Z", "changed": "2026-11-09T12:00:00Z"},
        }})

    def test_the_last_change_is_the_pages_and_the_document_is_rewritten_only_when_it_changed(self):
        store = cycle(WatchedStore(), [row(1, cvss=9.8), row(2)])
        cycle(store, now="2026-11-09T12:10:00")
        self.assertNotIn("sitemap.json", store.writes)
        months = store.read("months/2026-11.json")
        months["incidents"][1]["cvss"] = 7.5  # an NVD score makes it 위험: now search-worthy
        store.write("months/2026-11.json", months)
        cycle(store, now="2026-11-09T12:20:00")
        self.assertEqual(store.read("sitemap.json")["pages"], {
            "CVE-2026-1001": {"first_seen": "2026-11-09T00:00:00Z", "changed": "2026-11-09T12:00:00Z"},
            "CVE-2026-1002": {"first_seen": "2026-11-09T00:00:00Z", "changed": "2026-11-09T12:20:00Z"},
        })


if __name__ == "__main__":
    unittest.main()
