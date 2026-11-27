"""One Product, one id (owner, 11-27: "뼈대 잡혔으니 추천안대로 진행해"): two spellings of one record Product, the CNA's and
NVD's vendor for one product, and a Summary's name for a record Product were two pages, two Board picks, split counts."""

import unittest

from test_checks import SINCE, held

from collector.checks import check_docs, check_slug, product_pages
from collector.incidents import CO_LISTED_MAX, named, product_aliases, products_of


def rec(pid, name):
    return {"id": pid, "name": name}


class ProductAliasesTest(unittest.TestCase):
    def test_spellings_of_one_id_are_one_product(self):
        aliases = product_aliases([
            held("CVE-2026-1", products=[rec("redhat:exploit_intelligence", "Exploit Intelligence")]),
            held("CVE-2026-2", products=[rec("red_hat:exploit_intelligence", "Exploit Intelligence")]),
            held("CVE-2026-3", products=[rec("amd:amd_ryzen™_embedded_5000_series__processors", "AMD Ryzen™ Embedded 5000 Series  Processors")]),
            held("CVE-2026-4", products=[rec("amd:amd_ryzen™_embedded_5000_series_processors", "AMD Ryzen™ Embedded 5000 Series Processors")]),
        ])
        # Both Red Hat spellings are web/vendors.json keys: the first in order is kept; the doubled space is not.
        self.assertEqual(aliases, {"redhat:exploit_intelligence": "red_hat:exploit_intelligence",
                                   "amd:amd_ryzen™_embedded_5000_series__processors": "amd:amd_ryzen™_embedded_5000_series_processors"})

    def test_signs_that_name_another_product_keep_it_apart(self):
        self.assertEqual(product_aliases([
            held("CVE-2026-1", products=[rec("mongodb:c#_driver", "MongoDB C# Driver")]),
            held("CVE-2026-2", products=[rec("mongodb:c_driver", "MongoDB C Driver")]),
            held("CVE-2026-3", products=[rec("x:c++_lib", "C++ lib")]),
            held("CVE-2026-4", products=[rec("x:c_lib", "C lib")]),
        ]), {})

    def test_one_product_under_two_vendors_is_one_when_one_record_lists_both(self):
        aliases = product_aliases([
            held("CVE-2026-1", products=[rec("aio-libs:aiohttp", "aiohttp"), rec("aiohttp:aiohttp", "Aiohttp")]),
            held("CVE-2026-2", products=[rec("aiohttp:aiohttp", "Aiohttp")]),
            # The same name under two vendors, never together: two products.
            held("CVE-2026-3", products=[rec("automattic:mongoose", "mongoose")]),
            held("CVE-2026-4", products=[rec("cesanta:mongoose", "Cesanta Mongoose")]),
        ])
        self.assertEqual(aliases, {"aiohttp:aiohttp": "aio-libs:aiohttp"})

    def test_a_record_of_many_products_joins_no_vendors(self):
        many = [rec(f"v{n}:lib{n}", f"Lib {n}") for n in range(CO_LISTED_MAX - 1)]
        self.assertEqual(product_aliases([held("CVE-2026-1", products=many + [rec("google:brotli", "Brotli"), rec("andybalholm:brotli", "brotli")])]), {})
        self.assertEqual(product_aliases([held("CVE-2026-1", products=many[:-1] + [rec("google:brotli", "Brotli"), rec("andybalholm:brotli", "brotli")])]),
                         {"andybalholm:brotli": "google:brotli"})  # google is a web/vendors.json vendor

    def test_a_joined_ids_machine_name_does_not_become_the_name(self):
        # NVD's "Ws Ftp Server" (progress:ws_ftp_server) beside the CNA's "WS_FTP Server", which the Summary wrote.
        both = [rec("progress:ws_ftp_server", "Ws Ftp Server"), rec("progress_software:ws_ftp_server", "WS_FTP Server")]
        shown = named([held("CVE-2026-1", products=both, summary={"products": ["WS_FTP Server"]}),
                       held("CVE-2026-2", products=both[:1]), held("CVE-2026-3", products=both[:1])])
        self.assertEqual({(p["id"], p["name"]) for i in shown for p in products_of(i, "en")}, {("progress:ws_ftp_server", "WS_FTP Server")})

    def test_the_kept_id_does_not_depend_on_counts(self):
        a = [held(f"CVE-2026-{n}", products=[rec("open-emr:openemr", "OpenEMR")]) for n in range(5)]
        b = [held("CVE-2026-9", products=[rec("openemr:openemr", "OpenEMR")])]
        self.assertEqual(product_aliases(a + b), product_aliases(b + a))
        self.assertEqual(product_aliases(a + b), {"openemr:openemr": "open-emr:openemr"})

    def test_the_views_show_one_id_and_one_name_where_the_summary_wrote_the_other_spelling(self):
        shown = named([
            held("CVE-2026-1", products=[rec("x:pardus_boot_repair", "Pardus Boot Repair")], summary={"products": ["Pardus Boot Repair"]}),
            held("CVE-2026-2", products=[rec("x:pardus-boot-repair", "pardus-boot-repair")], summary={"products": ["pardus-boot-repair"]}),
            held("CVE-2026-3", products=[rec("x:pardus-boot-repair", "pardus-boot-repair")], summary={"products": ["pardus-boot-repair"]}),
            held("CVE-2026-4", products=[rec("x:pardus_boot_repair", "Pardus Boot Repair"), rec("x:pardus-boot-repair", "pardus-boot-repair")]),
        ])
        for incident in shown:
            self.assertEqual([p["id"] for p in products_of(incident, "en")], ["x:pardus-boot-repair"], incident["id"])
        # One name everywhere (which one is chosen_names' rule).
        self.assertEqual(len({products_of(i, "en")[0]["name"] for i in shown}), 1)


class ProductPageIdsTest(unittest.TestCase):
    def test_a_summary_name_another_record_lists_is_that_products_page(self):
        docs, index = check_docs([
            held("CVE-2026-1", products=[rec("google:chrome", "Chrome")], summary={"products": ["Google Chrome"]}),
            held("CVE-2026-2", summary={"products": ["Google Chrome"]}),
            # Both in one Incident: one entry.
            held("CVE-2026-3", products=[rec("google:chrome", "Chrome")], summary={"products": ["Google Chrome", "Chrome"]}),
            # A name two record Products share stays its own.
            held("CVE-2026-4", products=[rec("a:connect", "Connect")]),
            held("CVE-2026-5", products=[rec("b:connect", "Connect")]),
            held("CVE-2026-6", summary={"products": ["Connect"]}),
        ], SINCE)
        chrome = docs[check_slug("google:chrome")]
        self.assertEqual([e["id"] for e in chrome["incidents"]], ["CVE-2026-3", "CVE-2026-2", "CVE-2026-1"])
        self.assertEqual(docs[check_slug("name:chrome")], {"moved": check_slug("google:chrome")})
        self.assertEqual(index["chrome"], [check_slug("google:chrome")])
        self.assertIn(check_slug("name:connect"), index["connect"])
        self.assertNotIn("moved", docs[check_slug("name:connect")])

    def test_an_old_id_gets_a_redirect_and_no_sitemap_entry(self):
        incidents = [held(f"CVE-2026-{n}", cvss=7.5, products=[rec("red_hat:quay" if n % 2 else "redhat:quay", "Quay")]) for n in range(1, 5)]
        aliases = product_aliases(incidents)
        docs, _ = check_docs(named(incidents), SINCE, aliases)
        kept, old = check_slug("red_hat:quay"), check_slug("redhat:quay")
        self.assertEqual(len(docs[kept]["incidents"]), 4)
        self.assertEqual(docs[old], {"moved": kept})
        self.assertEqual(product_pages(docs), [kept])


class SameListTest(unittest.TestCase):
    @staticmethod
    def docs(*products):
        incidents = [held(f"CVE-2026-{n}", cvss=7.5, products=[rec(pid, name) for pid, name in products]) for n in range(1, 4)]
        return check_docs(incidents, SINCE)[0]

    def test_pages_with_the_very_same_incidents_offer_one_and_name_it_canonical(self):
        docs = self.docs(("gl-inet:gl-a1300", "GL.iNet GL-A1300"), ("gl-inet:gl-e750", "GL.iNet GL-E750"),
                         ("gl-inet:gl-ar300m16", "GL.iNet GL-AR300M16"))
        kept = check_slug("gl-inet:gl-e750")  # the shortest name
        self.assertEqual(product_pages(docs), [kept])
        self.assertEqual({d["id"]: d.get("canonical") for d in docs.values()},
                         {"gl-inet:gl-e750": None, "gl-inet:gl-a1300": kept, "gl-inet:gl-ar300m16": kept})

    def test_a_well_known_product_alone_under_its_label_keeps_its_page(self):
        docs = self.docs(("apple:macos", "macOS"), ("apple:iphone_os", "iOS"), ("apple:ipados", "iPadOS"), ("apple:tvos", "tvOS"))
        # iOS and iPadOS share the iOS label: one page for both; macOS stands alone; tvOS has no label.
        self.assertEqual(sorted(docs[s]["id"] for s in product_pages(docs)), ["apple:iphone_os", "apple:macos"])
        self.assertEqual(docs[check_slug("apple:ipados")]["canonical"], check_slug("apple:iphone_os"))
        self.assertEqual(docs[check_slug("apple:tvos")]["canonical"], check_slug("apple:iphone_os"))

    def test_different_lists_are_left_alone(self):
        incidents = [held(f"CVE-2026-{n}", cvss=7.5, products=[rec("a:x", "X")] + ([rec("a:y", "Y")] if n < 4 else [])) for n in range(1, 5)]
        docs, _ = check_docs(incidents, SINCE)
        self.assertEqual(len(product_pages(docs)), 2)
        self.assertFalse(any("canonical" in d for d in docs.values()))


class QuietPageTest(unittest.TestCase):
    def test_a_product_page_of_only_note_incidents_is_not_offered(self):
        quiet = [held(f"CVE-2026-{n}", products=[rec("a:quiet", "Quiet")], cvss=5.0) for n in range(1, 4)]
        loud = [held(f"CVE-2026-{n}", products=[rec("a:loud", "Loud")], cvss=5.0 if n < 3 else 7.5) for n in range(4, 7)]
        docs, _ = check_docs(quiet + loud, SINCE)
        self.assertEqual([docs[s]["id"] for s in product_pages(docs)], ["a:loud"])
        # A 참고 story without a CVE has its own page: a list holding one stays.
        story = [held(f"https://example.com/{n}", products=[rec("a:story", "Story")], cvss=5.0) for n in range(1, 3)]
        story += [held("https://news.ycombinator.com/item?id=1", products=[rec("a:story", "Story")], summary={"products": ["Story"]},
                       mentions=[{"kind": "discussion", "url": "https://news.ycombinator.com/item?id=1", "title": "Story"}])]
        docs, _ = check_docs(story, SINCE)
        self.assertTrue(any("/i/" in e["url"] for e in docs[check_slug("a:story")]["incidents"]))
        self.assertEqual([docs[s]["id"] for s in product_pages(docs)], ["a:story"])


if __name__ == "__main__":
    unittest.main()
