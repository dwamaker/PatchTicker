"""The list pages' documents (edge/lists.mjs, owner 11-27): a document per day of the Incident pages the sitemaps list,
and an index of the days and the product pages, so a crawler that reads the home page reaches every listed page."""

import unittest

from test_pages import WatchedStore, cycle, row
from test_sitemap import OPENSSH

from collector.checks import PRODUCT_PAGE_MIN, check_slug
from collector.cycle import write_lists
from collector.incidents import page_slug
from collector.store import MemoryStore


def listed_ids(store):
    index = store.read("lists/index.json")
    return {e["id"] for day in index["days"] for e in store.read(f"lists/d/{day}.json")["incidents"]}


class ListDocumentsTest(unittest.TestCase):
    def test_the_days_hold_exactly_the_pages_the_sitemap_lists_by_the_date_first_seen_in_korea(self):
        store = cycle(WatchedStore(), [
            row(1, cvss=9.8, products=OPENSSH),
            row(2, cvss=9.8, products=OPENSSH, first_seen="2026-11-08T14:59:00Z"),  # 23:59 KST: the 8th
            row(6, cvss=9.8, products=OPENSSH, first_seen="2026-11-08T15:00:00Z"),  # 00:00 KST on the 9th
            row(3, kev=True, first_seen="2026-11-08T01:00:00Z"),
            row(4, cvss=9.8),  # search-worthy but not in the sitemap: in no list either
            row(5, products=OPENSSH),  # 참고 with a CVE: no
        ])
        sitemap = store.read("sitemap.json")
        self.assertEqual({page_slug(i) for i in listed_ids(store)}, set(sitemap["pages"]))
        index = store.read("lists/index.json")
        self.assertEqual(index["days"], {"2026-11-09": 2, "2026-11-08": 2})
        self.assertEqual(list(index["days"]), ["2026-11-09", "2026-11-08"])  # newest first
        day = store.read("lists/d/2026-11-08.json")
        self.assertEqual(day["day"], "2026-11-08")
        self.assertEqual([e["id"] for e in day["incidents"]], ["CVE-2026-1002", "CVE-2026-1003"])  # newest first
        entry = day["incidents"][0]
        self.assertEqual(entry["url"], "https://patchticker.com/i/CVE-2026-1002")
        self.assertEqual((entry["title_ko"], entry["title_en"]), ("제목", "Title"))
        self.assertNotIn("detail", entry)

    def test_the_index_names_each_product_page_of_the_sitemap_with_its_name_and_count_by_name(self):
        widget = [{"id": "acme:widget", "name": "widget"}]
        alpha = [{"id": "acme:alpha", "name": "Alpha"}]
        store = cycle(WatchedStore(), [row(n, cvss=7.5, products=widget) for n in range(1, 1 + PRODUCT_PAGE_MIN)]
                      + [row(n, cvss=7.5, products=alpha) for n in range(10, 11 + PRODUCT_PAGE_MIN)]
                      + [row(9, products=[{"id": "acme:gadget", "name": "Gadget"}])])  # one Incident: no page in the sitemap
        products = store.read("lists/index.json")["products"]
        self.assertEqual(products, [{"slug": check_slug("acme:alpha"), "name": "Alpha", "count": PRODUCT_PAGE_MIN + 1},
                                    {"slug": check_slug("acme:widget"), "name": "widget", "count": PRODUCT_PAGE_MIN}])
        self.assertEqual({p["slug"] for p in products}, set(store.read("sitemap.json")["products"]))

    def test_a_day_is_rewritten_only_when_it_changed(self):
        rows = [row(1, cvss=9.8, products=OPENSSH), row(2, cvss=9.8, products=OPENSSH, first_seen="2026-11-08T00:00:00Z")]
        store = cycle(WatchedStore(), rows)
        cycle(store, now="2026-11-09T12:10:00")
        self.assertEqual([n for n in store.writes if n.startswith("lists/") or n == "list_hashes.json"], [])
        renamed = rows[0] | {"summary": {"incident": True, "ko": {"title": "새 제목"}, "en": {"title": "New title"}}}
        cycle(store, [renamed, rows[1]], now="2026-11-09T12:20:00")
        self.assertEqual([n for n in store.writes if n.startswith("lists/d/")], ["lists/d/2026-11-09.json"])
        self.assertEqual(store.read("lists/d/2026-11-09.json")["incidents"][0]["title_ko"], "새 제목")

    def test_a_day_past_the_90_days_leaves_the_index_and_loses_its_document(self):
        store = cycle(WatchedStore(), [row(1, cvss=9.8, products=OPENSSH), row(5, kev=True, first_seen="2026-08-12T00:00:00Z")])
        self.assertIn("2026-08-12", store.read("lists/index.json")["days"])
        cycle(store, now="2026-11-11T12:00:00")  # the 12th of August is 91 days back
        self.assertEqual(list(store.read("lists/index.json")["days"]), ["2026-11-09"])
        self.assertIsNone(store.read("lists/d/2026-08-12.json"))
        self.assertEqual(list(store.read("list_hashes.json")), ["2026-11-09"])

    def test_out_of_budget_a_new_day_waits_and_the_index_does_not_name_it(self):
        store = MemoryStore()
        write_lists(store, [row(1, cvss=9.8, products=OPENSSH)], {}, more=lambda: False)
        self.assertIsNone(store.read("lists/d/2026-11-09.json"))
        self.assertEqual(store.read("lists/index.json"), {"days": {}, "products": []})
        write_lists(store, [row(1, cvss=9.8, products=OPENSSH)], {})
        self.assertEqual(store.read("lists/index.json")["days"], {"2026-11-09": 1})


if __name__ == "__main__":
    unittest.main()
