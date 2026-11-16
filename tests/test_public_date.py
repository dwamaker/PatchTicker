"""M4 and M1 of the review work list (owner, 11-15): the Public date beside the Published time, and the link to the
product's other Incidents of the last 30 days under the Mitigation. The collector counts each Product's Incidents into one
document, board/others.json (owner, 11-16: a count inside each Incident's document would rewrite thousands of pages); the
site takes the Incident itself out."""

import json
import unittest

from test_cycle import FIXTURES
from test_pages import WatchedStore, cycle, row

from collector import cvelist
from collector.incidents import absorb, board_view, link, product_counts

ZDI = json.loads((FIXTURES / "cvelist" / "CVE-2026-118631.json").read_bytes())  # datePublic 11-06, published 11-12


def record(cve, public):
    """The ZDI record under another id, with its datePublic replaced (None: removed)."""
    r = json.loads(json.dumps(ZDI))
    r["cveMetadata"]["cveId"] = cve
    r["containers"]["cna"].pop("datePublic")
    return r | {"containers": {"cna": r["containers"]["cna"] | ({"datePublic": public} if public is not None else {})}}


class PublicDateTest(unittest.TestCase):
    def test_the_zdi_record_gives_its_public_day(self):
        group = cvelist.mention_group(ZDI)
        self.assertEqual(group["public_dates"], {"CVE-2026-118631": "2026-11-06"})
        self.assertEqual(group["published"], "2026-11-12T02:52:04Z")

    def test_a_record_without_or_with_an_unreadable_date_public_gives_none(self):
        for public in (None, "", "soon", 20261106):
            self.assertNotIn("public_dates", cvelist.mention_group(record("CVE-2026-1", public)), public)

    def test_a_new_incident_shows_the_day_when_it_differs_from_the_published_day(self):
        incidents = []
        link(incidents, cvelist.mention_group(ZDI), "2026-11-12T03:00:00Z")
        self.assertEqual(incidents[0]["public_dates"], {"CVE-2026-118631": "2026-11-06"})
        self.assertEqual(board_view(incidents[0])["public_date"], "2026-11-06")

    def test_the_same_day_as_the_published_time_shows_nothing(self):
        incidents = []
        link(incidents, cvelist.mention_group(record("CVE-2026-1", "2026-11-12T00:00:00Z")), "2026-11-12T03:00:00Z")
        self.assertNotIn("public_date", board_view(incidents[0]))

    def test_with_no_published_time_the_day_is_compared_with_first_seen(self):
        incident = {"id": "A", "cves": ["A"], "first_seen": "2026-11-12T03:00:00Z", "public_dates": {"A": "2026-11-06"},
                    "mentions": [], "brief": {"text": "x", "lead": ""}}
        self.assertEqual(board_view(incident)["public_date"], "2026-11-06")

    def test_a_group_shows_its_lead_cves_day_and_none_when_the_lead_has_none(self):
        group = {"id": "A", "cves": ["A", "B"], "first_seen": "2026-11-12T03:00:00Z", "published": "2026-11-12T02:00:00Z",
                 "cvss": 9.8, "cve_scores": {"A": {"cvss": 5.0, "vector": ""}, "B": {"cvss": 9.8, "vector": ""}},
                 "public_dates": {"A": "2026-11-01", "B": "2026-11-05"}, "mentions": [], "brief": {"text": "x", "lead": ""}}
        self.assertEqual(board_view(group)["public_date"], "2026-11-05")  # B leads by score
        group["public_dates"].pop("B")
        self.assertNotIn("public_date", board_view(group))

    def test_a_merge_keeps_the_earliest_day_and_only_for_cves_the_target_holds(self):
        incidents = []
        link(incidents, cvelist.mention_group(record("CVE-2026-1", "2026-11-08")), "2026-11-12T03:00:00Z")
        target = incidents[0]
        absorb(target, {"cves": ["CVE-2026-1"], "mentions": [], "urls": [], "brief": {"text": "", "lead": ""},
                        "public_dates": {"CVE-2026-1": "2026-11-09", "CVE-2026-9": "2026-11-01"}})
        self.assertEqual(target["public_dates"], {"CVE-2026-1": "2026-11-08"})
        absorb(target, {"cves": [], "mentions": [], "urls": [], "brief": {"text": "", "lead": ""},
                        "public_dates": {"CVE-2026-1": "2026-11-02"}})
        self.assertEqual(target["public_dates"], {"CVE-2026-1": "2026-11-02"})

    def test_the_merge_says_whether_it_changed_anything_so_a_second_backfill_applies_nothing(self):
        from collector.incidents import merge_public_dates
        incident = {"cves": ["A", "B"]}
        self.assertFalse(merge_public_dates(incident, {"C": "2026-11-01"}))
        self.assertNotIn("public_dates", incident)  # nothing held: no empty map either
        self.assertTrue(merge_public_dates(incident, {"A": "2026-11-05", "C": "2026-11-01"}))
        self.assertFalse(merge_public_dates(incident, {"A": "2026-11-05"}))
        self.assertFalse(merge_public_dates(incident, {"A": "2026-11-07"}))
        self.assertEqual(incident["public_dates"], {"A": "2026-11-05"})


def product(pid, name):
    return {"products": [{"id": pid, "name": name}]}


class ProductCountsTest(unittest.TestCase):
    SINCE = "2026-10-10T12:00:00Z"

    def test_each_product_counts_its_board_incidents_published_in_the_window_two_or_more_only(self):
        rows = [row(1, published="2026-11-09T00:00:00Z") | product("acme:widget", "Widget"),
                row(2, published="2026-11-01T00:00:00Z") | product("acme:widget", "Widget"),
                row(3, published="2026-10-11T00:00:00Z") | {"products": [{"id": "acme:widget", "name": "Widget"},
                                                                         {"id": "acme:gadget", "name": "Gadget"}]},
                row(4, published="2026-10-01T00:00:00Z") | product("acme:widget", "Widget"),  # before the window
                row(5, published="2026-11-02T00:00:00Z") | product("acme:gadget", "Gadget"),
                row(6, published="2026-11-02T00:00:00Z") | product("acme:lone", "Lone")]  # one alone: left out
        self.assertEqual(product_counts(rows, self.SINCE), {"acme:gadget": 2, "acme:widget": 3})

    def test_operating_systems_and_incidents_off_the_board_are_not_counted(self):
        on_linux = [row(n, published="2026-11-09T00:00:00Z", summary={"incident": True, "platforms": ["Linux"]}) for n in (1, 2)]
        story = {"id": "https://news.ycombinator.com/item?id=7", "cves": [], "first_seen": "2026-11-09T00:00:00Z",
                 "summary": {"incident": False}, "mentions": [], "brief": {"text": "x", "lead": ""}} | product("acme:widget", "Widget")
        one = row(3, published="2026-11-09T00:00:00Z") | product("acme:widget", "Widget")
        self.assertEqual(product_counts([*on_linux, story, one], self.SINCE), {})

    def test_the_cycle_writes_one_counts_document_and_no_count_in_any_incident_document(self):
        store = cycle(WatchedStore(), [row(n, first_seen="2026-11-09T00:00:00Z") | product("acme:widget", "Widget") for n in (1, 2)])
        self.assertEqual(store.read("board/others.json"), {"since": "2026-10-10T12:00:00Z", "counts": {"acme:widget": 2}})
        docs = [store.read("pages/CVE-2026-1001.json"), *store.read("board/recent.json")["incidents"],
                *store.read("board/rows.json")["incidents"], *store.read("board/2026-11.json")["incidents"]]
        self.assertTrue(docs)
        for doc in docs:
            self.assertFalse({"product_others", "counts"} & doc.keys(), doc["id"])


if __name__ == "__main__":
    unittest.main()
