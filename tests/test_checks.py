"""GET /api/check's documents (owner, 11-11: an agent asks "does anything touch what I run?"): check/index.json maps the
names a Product is asked by to its check/p/<slug>.json, written by the cycle only when it changed."""

import json
import unittest
from pathlib import Path

from test_pages import SUMMARY, WatchedStore, cycle, row

from collector.checks import check_docs, check_slug
from collector.incidents import product_key

KEY_CASE = json.loads((Path(__file__).parent / "fixtures" / "board" / "product-key-case.json").read_text(encoding="utf-8"))
SINCE = "2026-08-11T00:00:00Z"


def held(id, first_seen="2026-11-09T00:00:00Z", **extra):
    return {"id": id, "cves": [id] if id.startswith("CVE-") else [], "first_seen": first_seen,
            "mentions": [], "brief": {"text": f"Brief of {id}"}} | extra


class ProductKeyTest(unittest.TestCase):
    def test_the_collector_normalizes_names_as_the_page_does(self):
        for c in KEY_CASE["cases"]:
            self.assertEqual(product_key(c["name"]), c["key"], c["name"])


class CheckIndexTest(unittest.TestCase):
    def test_a_product_is_found_by_its_names_its_id_tail_without_its_vendor_and_by_its_well_known_aliases(self):
        _, index = check_docs([
            held("CVE-2026-1", products=[{"id": "synology:diskstation_manager", "name": "Synology DiskStation Manager"}]),
            held("CVE-2026-2", products=[{"id": "microsoft:windows_11_24h2", "name": "Windows 11 24H2"}]),
            held("CVE-2026-3", summary={"products": ["Microsoft Paint"], "ko": {"names": ["Windows 그림판"]}}),
        ], SINCE)
        dsm, windows, paint = (check_slug(i) for i in ("synology:diskstation_manager", "microsoft:windows_11_24h2", "name:paint"))
        self.assertEqual(index["synology diskstation manager"], [dsm])  # its shown name
        self.assertEqual(index["diskstation manager"], [dsm])  # the id's tail, and the name without its vendor
        self.assertEqual(index["windows 11 24h2"], [windows])
        self.assertEqual(index["windows"], [windows])  # its well-known label ...
        self.assertEqual(index["windows 10"], [windows])  # ... and an alias of it
        self.assertEqual(index["paint"], [paint])  # "Microsoft" is a known vendor: product_key drops it
        self.assertEqual(index["windows 그림판"], [paint])  # the Korean name
        self.assertEqual(list(index), sorted(index))

    def test_operating_system_tags_are_not_products_here(self):
        docs, index = check_docs([held("CVE-2026-1", summary={"products": ["OpenSSH"], "platforms": ["Linux"]})], SINCE)
        self.assertEqual([d["id"] for d in docs.values()], ["name:openssh"])
        self.assertNotIn("linux", index)

    def test_a_slug_is_safe_in_a_key_and_a_path_whatever_the_id(self):
        for pid in ("openbsd:openssh", "name:windows 그림판", "evil/../vendor:x?y#z"):
            self.assertRegex(check_slug(pid), r"^[0-9a-f]{16}$")


class CheckDocumentTest(unittest.TestCase):
    def test_a_product_document_lists_its_board_incidents_newest_first_with_what_an_agent_needs(self):
        ssh = [{"id": "openbsd:openssh", "name": "OpenSSH"}]
        summary = {"incident": True, "fixed": "9.9p2", "exploited": True, "exploited_source": "https://example.test/attacks",
                   "ko": {"title": "OpenSSH 인증 우회"}, "en": {"title": "OpenSSH auth bypass"}}
        cves = [f"CVE-2026-100{n}" for n in range(6)]
        docs, _ = check_docs([
            held("CVE-2026-1000", published="2026-11-08T00:00:00Z", cvss=9.8, products=ssh, summary=summary, cves=cves),
            held("CVE-2026-2000", published="2026-11-09T00:00:00Z", cvss=5.0, products=ssh,
                 quick_title={"ko": {"title": "빠른 제목"}, "en": {"title": "Quick title"}}),
            held("CVE-2026-3000", first_seen="2026-08-01T00:00:00Z", products=ssh),  # past 90 days
            held("https://news.ycombinator.com/item?id=9", products=ssh, summary={"incident": False}),  # not on the Board
        ], SINCE)
        doc = docs[check_slug("openbsd:openssh")]
        self.assertEqual((doc["product"], doc["id"]), ("OpenSSH", "openbsd:openssh"))
        self.assertEqual(doc["incidents"], [
            {"id": "CVE-2026-2000", "url": "https://patchticker.com/#i=CVE-2026-2000", "first_seen": "2026-11-09T00:00:00Z",
             "published": "2026-11-09T00:00:00Z", "level": "notice", "exploited": False, "cvss": 5.0, "cve_count": 1,
             "cves": ["CVE-2026-2000"], "fixed": "", "title_en": "Quick title", "title_ko": "빠른 제목"},
            {"id": "CVE-2026-1000", "url": "https://patchticker.com/i/CVE-2026-1000", "first_seen": "2026-11-09T00:00:00Z",
             "published": "2026-11-08T00:00:00Z", "level": "highest", "exploited": True, "cvss": 9.8, "cve_count": 6,
             "cves": cves[:5], "fixed": "9.9p2", "title_en": "OpenSSH auth bypass", "title_ko": "OpenSSH 인증 우회"},
        ])

    def test_no_summary_and_no_quick_title_titles_it_by_its_brief(self):
        docs, _ = check_docs([held("CVE-2026-1", products=[{"id": "a:b", "name": "B"}])], SINCE)
        entry = docs[check_slug("a:b")]["incidents"][0]
        self.assertEqual((entry["title_en"], entry["title_ko"], entry["cvss"]), ("Brief of CVE-2026-1", "Brief of CVE-2026-1", None))


def with_product(n, pid, **extra):
    return row(n, products=[{"id": pid, "name": pid.split(":")[1]}], **extra)


class CheckCycleTest(unittest.TestCase):
    def test_the_cycle_writes_the_index_and_rewrites_only_changed_documents(self):
        store = cycle(WatchedStore(), [with_product(1, "acme:widget"), with_product(2, "acme:gadget")])
        widget, gadget = (f"check/p/{check_slug(p)}.json" for p in ("acme:widget", "acme:gadget"))
        self.assertIn(widget, store.writes)
        self.assertEqual(store.read("check/index.json")["widget"], [check_slug("acme:widget")])
        self.assertEqual(set(store.read("check_hashes.json")), {check_slug("acme:widget"), check_slug("acme:gadget")})
        cycle(store)
        self.assertEqual([n for n in store.writes if n.startswith(("check/", "check_"))], [])  # nothing changed, nothing written
        self.assertEqual([n for n in store.reads if n.startswith("check/p/")], [])  # one hash file, not a read per product
        months = store.read("months/2026-11.json")
        months["incidents"][1]["cvss"] = 9.8
        store.write("months/2026-11.json", months)
        cycle(store)
        self.assertEqual([n for n in store.writes if n.startswith(("check/", "check_"))], [gadget, "check_hashes.json"])
        self.assertEqual(store.read(gadget)["incidents"][0]["level"], "highest")

    def test_a_product_with_no_incident_left_loses_its_document_and_its_names(self):
        store = cycle(WatchedStore(), [with_product(1, "acme:widget"), with_product(2, "acme:gadget", first_seen="2026-08-12T00:00:00Z")])
        gadget = f"check/p/{check_slug('acme:gadget')}.json"
        self.assertIsNotNone(store.read(gadget))
        cycle(store, now="2026-11-11T12:00:00")  # the gadget's only Incident is now past 90 days
        self.assertIsNone(store.read(gadget))
        self.assertNotIn("gadget", store.read("check/index.json"))
        self.assertEqual(list(store.read("check_hashes.json")), [check_slug("acme:widget")])


if __name__ == "__main__":
    unittest.main()
