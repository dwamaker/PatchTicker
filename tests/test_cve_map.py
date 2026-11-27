"""A CVE inside another Incident (Gemini review, 11-28, P5): /i/<CVE> answered 404, so a person or an agent that builds
the address from a CVE ID met a dead end. The cycle writes small documents that map such a CVE to its Incident's page,
for edge/page.mjs to answer 301."""

import unittest

from test_pages import WatchedStore, cycle, row

from collector.cycle import cve_map_docs, write_cve_map
from collector.incidents import page_slug


class CveMapTest(unittest.TestCase):
    def test_every_cve_of_a_grouped_incident_with_a_page_maps_to_that_page(self):
        group = row(1, cvss=9.8, cves=["CVE-2026-1001", "CVE-2026-2500", "CVE-2025-123456"])
        alone = row(2, cvss=9.8)  # its only CVE is its own page: nothing to map
        story = row(3, cvss=9.8) | {"id": "https://news.ycombinator.com/item?id=5", "cves": ["CVE-2026-1999"]}
        no_page = row(4, cvss=9.8, cves=["CVE-2026-1004", "CVE-2026-7777"])
        pages = {page_slug(i["id"]): {} for i in (group, alone, story)}
        self.assertEqual(cve_map_docs([group, alone, story, no_page], pages), {
            "cve_map/2025/123.json": {"CVE-2025-123456": "CVE-2026-1001"},
            "cve_map/2026/1.json": {"CVE-2026-1999": "hn-5"},
            "cve_map/2026/2.json": {"CVE-2026-2500": "CVE-2026-1001"},
        })

    def test_a_shard_is_written_when_it_changed_and_deleted_when_no_longer_made(self):
        store = WatchedStore()
        docs = {"cve_map/2026/2.json": {"CVE-2026-2500": "CVE-2026-1001"}, "cve_map/2026/3.json": {"CVE-2026-3000": "hn-5"}}
        write_cve_map(store, docs)
        self.assertEqual(store.read("cve_map/2026/3.json"), {"CVE-2026-3000": "hn-5"})
        store.writes = []
        write_cve_map(store, docs)
        self.assertEqual(store.writes, [])  # nothing changed: nothing written
        write_cve_map(store, {"cve_map/2026/2.json": {"CVE-2026-2500": "CVE-2026-1001", "CVE-2026-2501": "CVE-2026-1001"}})
        self.assertIsNone(store.read("cve_map/2026/3.json"))
        self.assertEqual(sorted(store.read("cve_map_hashes.json")), ["cve_map/2026/2.json"])

    def test_a_shard_left_unwritten_keeps_its_old_document_and_hash(self):
        store = WatchedStore()
        write_cve_map(store, {"cve_map/2026/2.json": {"CVE-2026-2500": "CVE-2026-1001"}})
        old = store.read("cve_map_hashes.json")
        write_cve_map(store, {"cve_map/2026/2.json": {"CVE-2026-2500": "hn-5"}}, more=lambda: False)
        self.assertEqual(store.read("cve_map/2026/2.json"), {"CVE-2026-2500": "CVE-2026-1001"})
        self.assertEqual(store.read("cve_map_hashes.json"), old)

    def test_a_cycle_writes_the_map_of_its_pages(self):
        store = cycle(WatchedStore(), [row(1, cvss=9.8, cves=["CVE-2026-1001", "CVE-2026-2500"])])
        self.assertEqual(store.read("cve_map/2026/2.json"), {"CVE-2026-2500": "CVE-2026-1001"})


if __name__ == "__main__":
    unittest.main()
