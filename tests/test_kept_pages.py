"""P4 (owner 11-28, Gemini review): a page the sitemaps listed lives PAGE_KEEP_DAYS, frozen after PAGE_DAYS. The
collector keeps, per calendar month of first sight, the pages it listed (sitemaps/<YYYY-MM>.json): the monthly sitemaps
and the page function's "kept" check read it, and the CVE map keeps the kept pages' other CVEs."""

import unittest

from test_pages import WatchedStore, cycle, row
from test_sitemap import OPENSSH

from collector.cycle import cve_map_docs, write_sitemap_months
from collector.store import MemoryStore
from test_cycle import at

NOW = "2026-11-09T12:00:00"


def month(store, name="2026-08"):
    return store.read(f"sitemaps/{name}.json")


class SitemapMonthsTest(unittest.TestCase):
    def test_a_cycle_writes_the_listed_pages_by_month_with_their_other_cves(self):
        store = cycle(WatchedStore(), [row(1, cvss=9.8, products=OPENSSH, cves=["CVE-2026-1001", "CVE-2026-2500"]),
                                       row(5, kev=True, first_seen="2026-08-12T00:00:00Z"),
                                       row(6, cvss=9.8)])  # search-worthy, not listed: in no month
        self.assertEqual(sorted(month(store, "2026-11")), ["CVE-2026-1001"])
        self.assertEqual(month(store, "2026-11")["CVE-2026-1001"]["cves"], ["CVE-2026-2500"])
        self.assertEqual(sorted(month(store)), ["CVE-2026-1005"])
        self.assertEqual(sorted(store.read("sitemaps/index.json")), ["2026-08", "2026-11"])

    def test_an_entry_past_90_days_stays_as_it_was_and_a_month_past_365_days_goes(self):
        store = MemoryStore()
        listed = [row(5, kev=True, first_seen="2026-08-12T00:00:00Z"), row(6, kev=True, first_seen="2026-08-20T00:00:00Z")]
        pages = {"CVE-2026-1005": {"changed": "2026-08-12T00:10:00Z"}, "CVE-2026-1006": {"changed": "2026-08-20T00:10:00Z"}}
        write_sitemap_months(store, listed, pages, at("2026-11-01T00:00:00"))
        first = month(store)
        # the store forgot row 5 (past 90 days); row 6 is no longer listed: row 5 stays, row 6 goes
        write_sitemap_months(store, [], {}, at("2026-11-12T00:00:00"))
        self.assertEqual(month(store), {"CVE-2026-1005": first["CVE-2026-1005"]})
        kept = write_sitemap_months(store, [], {}, at("2027-03-01T00:00:00"))  # frozen: read back, not rewritten
        self.assertEqual(write_sitemap_months(store, [], {}, at("2027-08-15T00:00:00")), {"2026-08": {}})  # past 365: out of the CVE map, the month not yet gone
        self.assertEqual(kept, {"2026-08": {"CVE-2026-1005": first["CVE-2026-1005"]}})
        write_sitemap_months(store, [], {}, at("2027-09-01T00:00:00"))  # past 365 days
        self.assertIsNone(month(store))
        self.assertEqual(store.read("sitemaps/index.json"), {})

    def test_out_of_budget_a_month_keeps_its_old_document_and_hash(self):
        store = MemoryStore()
        listed = [row(5, kev=True, first_seen="2026-11-02T00:00:00Z")]
        write_sitemap_months(store, listed, {"CVE-2026-1005": {"changed": "x"}}, at(NOW))
        old, index = month(store, "2026-11"), store.read("sitemaps/index.json")
        write_sitemap_months(store, listed, {"CVE-2026-1005": {"changed": "y"}}, at(NOW), more=lambda: False)
        self.assertEqual((month(store, "2026-11"), store.read("sitemaps/index.json")), (old, index))


class KeptCveMapTest(unittest.TestCase):
    def test_a_kept_pages_other_cves_still_redirect_and_a_live_incident_wins(self):
        archive = {"2026-08": {"CVE-2026-1005": {"first_seen": "2026-08-12T00:00:00Z", "cves": ["CVE-2026-3001", "CVE-2026-1001"]}}}
        live = row(1, cvss=9.8, cves=["CVE-2026-1001", "CVE-2026-3002"])
        docs = cve_map_docs([live], {"CVE-2026-1001": {}}, archive)
        self.assertEqual(docs["cve_map/2026/3.json"], {"CVE-2026-3001": "CVE-2026-1005", "CVE-2026-3002": "CVE-2026-1001"})
        self.assertEqual(docs["cve_map/2026/1.json"], {"CVE-2026-1001": "CVE-2026-1005"})  # the live Incident's own page: no entry from it


if __name__ == "__main__":
    unittest.main()
