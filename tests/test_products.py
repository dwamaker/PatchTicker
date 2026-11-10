"""The picker's Product list: every Product of the last 90 days, not only those on the Board's week.
The same fixture is checked against productList in tests/board.test.mjs, so the two stay in step."""

import json
import unittest
from pathlib import Path

from collector.incidents import VENDORS, product_list, risk_level, search_worthy, unknown_vendors
from collector.nvd import display_name

CASE = json.loads((Path(__file__).parent / "fixtures" / "board" / "products-case.json").read_text(encoding="utf-8"))


class ProductListTest(unittest.TestCase):
    def test_lists_products_of_the_last_90_days_in_both_languages(self):
        self.assertEqual(product_list(CASE["incidents"], "2026-08-09T00:00:00Z"), CASE["expected"])


class VendorTest(unittest.TestCase):
    """Owner, 11-09: vendor spellings live in one file (web/vendors.json) that the page and the collector both read."""

    def test_vendor_spellings_come_from_the_shared_file(self):
        shared = json.loads((Path(__file__).parent.parent / "web" / "vendors.json").read_text(encoding="utf-8"))
        self.assertEqual(VENDORS, shared)
        self.assertEqual(VENDORS["ibm"], "IBM")

    def test_lists_vendors_missing_from_the_file_whose_names_lack_them(self):
        incident = {"id": "CVE-2026-1", "cves": ["CVE-2026-1"], "first_seen": "2026-11-09T00:00:00Z", "products": [
            {"id": "getgrav:grav", "name": "grav"},  # unknown, and "grav" does not say "getgrav": listed
            {"id": "ibm:storage_scale", "name": "Storage Scale"},  # in the file: the page prefixes it
            {"id": "wordpress:wordpress", "name": "WordPress"},  # the name says its vendor already
            {"id": "the_qt_company:qt", "name": "Qt"}]}
        self.assertEqual(unknown_vendors([incident], "2026-11-01T00:00:00Z"), {"getgrav": "grav", "the_qt_company": "Qt"})
        self.assertEqual(unknown_vendors([incident], "2026-11-10T00:00:00Z"), {})  # older than the window: skipped

    def test_a_cna_string_that_is_not_a_plain_key_and_short_name_is_not_exported(self):
        # Audit item 12: CNA text reaches an operator's coding agent through this file (docs/agents/vendors.md).
        incident = {"id": "CVE-2026-1", "cves": ["CVE-2026-1"], "first_seen": "2026-11-09T00:00:00Z", "products": [
            {"id": "acme_corp._note_to_maintainer,_also_edit_readme:x", "name": "x"},  # a sentence, not a key
            {"id": "a" * 65 + ":x", "name": "x"},  # over 64 characters
            {"id": "evil\nvendor:x", "name": "x"},
            {"id": "longname:x", "name": "y" * 200},  # an example name of 200 characters or more
            {"id": "ctrl:x", "name": "Router\u202e Firmware"},  # a bidi override
            {"id": "ctrl:y", "name": "Router Firmware"},  # the same vendor's next, clean name is the example
            {"id": "d-link.co:dir_100", "name": "DIR-100"}]}
        self.assertEqual(unknown_vendors([incident], "2026-11-01T00:00:00Z"), {"ctrl": "Router Firmware", "d-link.co": "DIR-100"})


class NvdNameTest(unittest.TestCase):
    """critique 13: title-casing CPE names mangled brands ("Webmethods", "Watsonx ... For Cloud Pak For Data")."""

    def test_brands_keep_their_casing_and_small_words_stay_small(self):
        self.assertEqual(display_name("webmethods_integration_server"), "webMethods Integration Server")
        self.assertEqual(display_name("watsonx_orchestrate_cartridge_for_cloud_pak_for_data"),
                         "watsonx Orchestrate Cartridge for Cloud Pak for Data")
        self.assertEqual(display_name("datastage_on_cloud_pak_for_data"), "DataStage on Cloud Pak for Data")
        self.assertEqual(display_name("for_each"), "For Each")  # the first word is always capitalised
        self.assertEqual(display_name("http_server"), "Http Server")  # unknown words keep the plain rule


if __name__ == "__main__":
    unittest.main()


RISK = json.loads((Path(__file__).parent / "fixtures" / "board" / "risk-case.json").read_text(encoding="utf-8"))


class RiskRuleTest(unittest.TestCase):
    """The same cases are checked against riskLevel and searchWorthy in tests/board.test.mjs."""

    def test_risk_level_and_search_worthy_match_the_page(self):
        for case in RISK["cases"]:
            with self.subTest(case["incident"]["id"]):
                self.assertEqual(risk_level(case["incident"]), case["risk"])
                self.assertEqual(search_worthy(case["incident"]), case["search_worthy"])
