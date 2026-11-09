"""Incident page documents (ticket incident-pages/02): one per slug, written by the cycle only when it changed."""

import json
import unittest
from pathlib import Path

from test_cycle import at, incident, recorded

from collector.cycle import run_cycle
from collector.incidents import page_slug
from collector.store import MemoryStore

SUMMARY = {"incident": True, "ko": {"title": "제목"}, "en": {"title": "Title"}}
NOW = "2026-11-09T12:00:00"


def row(n, first_seen="2026-11-09T00:00:00Z", **extra):
    return incident(f"CVE-2026-{1000 + n}", f"Brief {n}", first_seen) | {"cvss": 5.0, "summary": SUMMARY} | extra


class WatchedStore(MemoryStore):
    """A memory store that remembers which documents a cycle read and wrote."""

    def __init__(self):
        super().__init__()
        self.reads, self.writes = [], []

    def read(self, name):
        self.reads.append(name)
        return super().read(name)

    def write(self, name, doc):
        self.writes.append(name)
        super().write(name, doc)


def cycle(store, rows=None, now=NOW):
    if rows is not None:
        store.write("index.json", {"months": ["2026-11", "2026-08"]})
        store.write("months/2026-11.json", {"month": "2026-11", "incidents": [r for r in rows if r["first_seen"] >= "2026-11"]})
        store.write("months/2026-08.json", {"month": "2026-08", "incidents": [r for r in rows if r["first_seen"] < "2026-11"]})
    store.reads, store.writes = [], []
    run_cycle(store, recorded(None), at(now), "test-box")
    return store


class PageDocumentTest(unittest.TestCase):
    def test_every_summarized_incident_of_the_last_90_days_has_a_page_document(self):
        story = incident("https://news.ycombinator.com/item?id=77", "A story", "2026-11-09T00:00:00Z") | {"cves": [], "summary": SUMMARY}
        store = cycle(WatchedStore(), [
            row(1),
            row(2, summary=None),  # no Summary yet: no page
            row(3, first_seen="2026-08-10T00:00:00Z"),  # first seen 91 days ago: expired
            row(4, first_seen="2026-08-12T00:00:00Z"),
            story,
        ])
        names = [n for n in store.names() if n.startswith("pages/")]
        self.assertEqual(names, ["pages/CVE-2026-1001.json", "pages/CVE-2026-1004.json", "pages/hn-77.json"])
        page = store.read("pages/CVE-2026-1001.json")
        self.assertEqual((page["id"], page["summary"], page["cvss"]), ("CVE-2026-1001", SUMMARY, 5.0))
        self.assertNotIn("urls", page)  # the page-facing fields, as the Board file carries them

    def test_rewrites_a_page_only_when_it_changed_without_reading_pages(self):
        store = cycle(WatchedStore(), [row(1), row(2)])
        self.assertIn("pages/CVE-2026-1001.json", store.writes)
        cycle(store)
        self.assertEqual([n for n in store.writes if n.startswith("pages/")], [])
        months = store.read("months/2026-11.json")
        months["incidents"][1]["cvss"] = 9.8  # an NVD score arrives
        store.write("months/2026-11.json", months)
        cycle(store)
        self.assertEqual([n for n in store.writes if n.startswith("pages/")], ["pages/CVE-2026-1002.json"])
        self.assertEqual([n for n in store.reads if n.startswith("pages/")], [])  # one index per cycle, not a read per page
        self.assertEqual(store.read("pages/CVE-2026-1002.json")["cvss"], 9.8)


def release(store, *rows):
    """Put the rows in one vendor release (same fix key), so the next cycle's release grouping merges them."""
    months = store.read("months/2026-11.json")
    for r in months["incidents"]:
        if r["id"] in rows:
            r["fix_keys"] = ["acme:widget@2.0"]
    store.write("months/2026-11.json", months)


class MovedPageTest(unittest.TestCase):
    """Ticket incident-pages/04: an absorbed Incident's page moves to the survivor's."""

    def test_a_merge_leaves_a_moved_document_in_place_of_the_absorbed_page(self):
        survivor, absorbed = row(1, first_seen="2026-11-09T01:00:00Z"), row(2, first_seen="2026-11-09T02:00:00Z")
        survivor["cves"].append("CVE-2026-1011")  # a release group needs three CVEs
        store = cycle(WatchedStore(), [survivor, absorbed])
        self.assertIn("summary", store.read("pages/CVE-2026-1002.json"))  # its own page, before the merge
        release(store, "CVE-2026-1001", "CVE-2026-1002")
        cycle(store, now="2026-11-09T13:00:00")
        self.assertEqual(store.read("pages/CVE-2026-1002.json"),
                         {"id": "CVE-2026-1002", "moved_to": "CVE-2026-1001", "moved": "2026-11-09T13:00:00Z"})
        self.assertEqual(store.read("months/2026-11.json")["incidents"][0]["absorbed"], ["CVE-2026-1002"])
        cycle(store, now="2026-11-09T14:00:00")
        self.assertNotIn("pages/CVE-2026-1002.json", store.writes)  # written once, when it moved

    def test_a_chain_of_merges_ends_at_the_last_survivor(self):
        c, b, a = (row(n, first_seen=f"2026-11-09T0{n}:00:00Z") for n in (1, 2, 3))
        b["cves"].append("CVE-2026-1012")
        store = cycle(WatchedStore(), [c, b, a])
        release(store, "CVE-2026-1002", "CVE-2026-1003")  # A into B
        cycle(store, now="2026-11-09T13:00:00")
        self.assertEqual(store.read("pages/CVE-2026-1003.json")["moved_to"], "CVE-2026-1002")
        release(store, "CVE-2026-1001")  # B (with A in it) into C
        cycle(store, now="2026-11-09T14:00:00")
        self.assertEqual(store.read("pages/CVE-2026-1002.json")["moved_to"], "CVE-2026-1001")
        self.assertEqual(store.read("pages/CVE-2026-1003.json"),
                         {"id": "CVE-2026-1003", "moved_to": "CVE-2026-1001", "moved": "2026-11-09T13:00:00Z"})  # moved since


SLUGS = json.loads((Path(__file__).parent / "fixtures" / "board" / "slug-case.json").read_text(encoding="utf-8"))


class SlugTest(unittest.TestCase):
    """The same cases are checked against slug() in tests/page.test.mjs."""

    def test_page_slug_matches_the_function(self):
        for case in SLUGS["cases"]:
            with self.subTest(case["id"]):
                self.assertEqual(page_slug(case["id"]), case["slug"])


if __name__ == "__main__":
    unittest.main()
