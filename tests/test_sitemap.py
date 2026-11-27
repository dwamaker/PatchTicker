"""The Incident sitemap's document (ticket incident-pages/05): the search-worthy pages of the last 90 days that are
worth a listing (owner, 11-27: a well-known Product, attacked, a story without a CVE, or three sites besides the record)."""

import unittest

from test_cycle import incident
from test_pages import SUMMARY, WatchedStore, cycle, row

from collector.checks import PRODUCT_PAGE_MIN, check_slug
from collector.incidents import sitemap_worthy

OPENSSH = [{"id": "openbsd:openssh", "name": "OpenSSH"}]  # on collector/well_known.json


def told_by(n, sites):
    """row n with one write-up on each of `sites` besides its CVE record."""
    plain = row(n, cvss=9.8)
    return plain | {"mentions": plain["mentions"] + [{"kind": "writeup", "url": f"https://{s}/post/{n}"} for s in sites]}


class SitemapDocumentTest(unittest.TestCase):
    def test_lists_the_pages_worth_a_listing_of_the_last_90_days_with_first_seen_and_last_change(self):
        story = incident("https://news.ycombinator.com/item?id=77", "A story", "2026-11-09T03:00:00Z") | {"cves": [], "summary": SUMMARY}
        store = cycle(WatchedStore(), [
            row(1, cvss=9.8, products=OPENSSH),  # a well-known Product
            row(2),  # 참고 with a CVE: a page for sharing, not for search
            row(3, cvss=9.8, summary=None),  # no Summary yet: no page
            row(4, cvss=9.8, first_seen="2026-08-10T00:00:00Z"),  # first seen 91 days ago: expired
            row(5, kev=True, first_seen="2026-08-12T00:00:00Z"),  # exploited
            story,  # without a CVE
            row(6, cvss=9.8),  # search-worthy, but a Product on no list with its CVE record alone: not listed
            told_by(7, ["a.example", "www.b.example", "c.example"]),  # three sites besides the record
            told_by(8, ["a.example", "www.a.example", "b.example"]),  # two sites: www. is the same site
        ])
        self.assertEqual(store.read("sitemap.json"), {"pages": {
            "CVE-2026-1001": {"first_seen": "2026-11-09T00:00:00Z", "changed": "2026-11-09T12:00:00Z"},
            "CVE-2026-1005": {"first_seen": "2026-08-12T00:00:00Z", "changed": "2026-11-09T12:00:00Z"},
            "hn-77": {"first_seen": "2026-11-09T03:00:00Z", "changed": "2026-11-09T12:00:00Z"},
            "CVE-2026-1007": {"first_seen": "2026-11-09T00:00:00Z", "changed": "2026-11-09T12:00:00Z"},
        }, "products": []})

    def test_a_page_left_off_the_list_is_still_search_worthy(self):
        from collector.incidents import search_worthy
        plain = row(6, cvss=9.8)
        self.assertTrue(search_worthy(plain))
        self.assertFalse(sitemap_worthy(plain))
        self.assertFalse(sitemap_worthy(row(2, products=OPENSSH)))  # 참고 with a CVE: never search-worthy, so never listed
        self.assertTrue(sitemap_worthy(row(5, kev=True)))

    def test_lists_the_product_pages_with_enough_incidents_to_be_worth_a_search(self):
        # owner, 11-17: a page per product (/p/<slug>, edge/product.mjs); one with fewer than PRODUCT_PAGE_MIN Incidents
        # in 90 days is thin: noindex there and left out here
        widget = [{"id": "acme:widget", "name": "Widget"}]
        store = cycle(WatchedStore(), [row(n, cvss=7.5, products=widget) for n in range(1, 1 + PRODUCT_PAGE_MIN)]
                      + [row(9, products=[{"id": "acme:gadget", "name": "Gadget"}])])
        self.assertEqual(store.read("sitemap.json")["products"], [check_slug("acme:widget")])

    def test_the_last_change_is_the_pages_and_the_document_is_rewritten_only_when_it_changed(self):
        store = cycle(WatchedStore(), [row(1, cvss=9.8, products=OPENSSH), row(2, products=OPENSSH)])
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
