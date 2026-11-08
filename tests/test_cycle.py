"""Seam 1: one collection cycle, replayed against recorded source responses."""

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from collector import nvd
from collector.cycle import run_cycle
from collector.cvelist import DELTA_LOG_URL
from collector.store import MemoryStore

FIXTURES = Path(__file__).parent / "fixtures"
NVD_FIXTURES = FIXTURES / "nvd"
# Mention sources by URL prefix: (fixture folder, answer when the test gives no fixture).
MENTION_SOURCES = {
    "https://hn.algolia.com/": ("hn", b'{"hits": [], "nbPages": 0}'),
    "https://seclists.org/": ("oss-security", b"<rss><channel></channel></rss>"),
    "https://api.github.com/": ("github", b'{"items": []}'),
    "https://www.cisa.gov/": ("kev", b'{"vulnerabilities": []}'),
    "https://rss.beehiiv.com/": ("curators", b"<rss><channel></channel></rss>"),
}

KEYCLOAK_TEXT = (
    "A flaw was found in the Keycloak server's client management component. When a client is "
    "created or imported with authorization services enabled, the system fails to properly clear "
    "an internal session attribute used during the setup process. This allows an authenticated "
    "attacker with client management permissions to bypass security controls and upload a "
    "malicious JavaScript policy, which is then executed on the server when an authorization "
    "request is made. Successful exploitation could allow the attacker to run arbitrary code on "
    "the server, potentially compromising the entire system."
)
WPTRAVELLY_TEXT = (
    "Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File "
    "Inclusion') vulnerability in Magepeople inc. WpTravelly tour-booking-manager allows PHP Local "
    "File Inclusion.This issue affects WpTravelly: from n/a through 2.3.8."
)


def recorded(delta_log="deltaLog.json", nvd_pages=("empty.json",), nvd_range=None, hn=None, oss=None, github=None,
             kev=None, curators=None, web=None, hn_buzz=None):
    """An http_get that answers from fixtures and fails on anything not recorded.

    NVD pages are trimmed real responses, keyed by the startIndex they answer.
    delta_log=None serves an empty delta log; a Mention source given no fixture answers empty.
    web maps a Mention's URL to its page in fixtures/pages/ (what a Summary reads).
    hn_buzz answers the HN points refresh (the search with a points filter); without it, no hits.
    """
    pages = {json.loads((NVD_FIXTURES / p).read_bytes())["startIndex"]: p for p in nvd_pages}
    names = {"hn": hn, "oss-security": oss, "github": github, "kev": kev, "curators": curators}

    def get(url, headers=None):
        if url in (web or {}):
            return (FIXTURES / "pages" / web[url]).read_bytes()
        if url.startswith("https://hn.algolia.com/") and "points" in parse_qs(urlsplit(url).query).get("numericFilters", [""])[0]:
            return (FIXTURES / "hn" / hn_buzz).read_bytes() if hn_buzz else b'{"hits": [], "nbPages": 0}'
        if url.startswith(nvd.API_URL):
            query = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
            if nvd_range:
                assert (query["lastModStartDate"], query["lastModEndDate"]) == nvd_range, query
            return (NVD_FIXTURES / pages[int(query["startIndex"])]).read_bytes()
        if url == DELTA_LOG_URL:
            return (FIXTURES / "cvelist" / delta_log).read_bytes() if delta_log else b"[]"
        for prefix, (folder, empty) in MENTION_SOURCES.items():
            if url.startswith(prefix):
                return (FIXTURES / folder / names[folder]).read_bytes() if names[folder] else empty
        return (FIXTURES / "cvelist" / url.rsplit("/", 1)[-1]).read_bytes()

    return get


def at(text):
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc)


def incident(cve, text, first_seen, published=None):
    url = f"https://www.cve.org/CVERecord?id={cve}"
    return {
        "id": cve,
        "cves": [cve],
        "first_seen": first_seen,
        **({"published": published} if published else {}),
        "mentions": [{"kind": "cve_record", "url": url}],
        "urls": [f"cve.org/CVERecord?id={cve}"],
        "brief": {"text": text, "lead": url},
    }


class CycleTest(unittest.TestCase):
    def make_store(self):
        return MemoryStore()

    def setUp(self):
        self.store = self.make_store()
        # Pretend an earlier cycle already read the delta log up to 12:00.
        self.store.write("checkpoints.json", {"cvelist": "2026-11-07T12:00:00.000Z"})

    def test_cycle_writes_new_cves_into_monthly_file(self):
        run_cycle(self.store, recorded(), at("2026-11-07T13:30:00"), "test-box")

        month = self.store.read("months/2026-11.json")
        self.assertCountEqual(
            month["incidents"],
            [
                # published: each record's datePublished, not the cycle time
                incident("CVE-2026-120984", KEYCLOAK_TEXT, "2026-11-07T13:30:00Z", "2026-11-07T13:22:00Z"),
                incident("CVE-2026-120839", WPTRAVELLY_TEXT, "2026-11-07T13:30:00Z", "2026-11-07T12:43:21Z"),
            ],
        )
        self.assertEqual(self.store.read("index.json"), {"months": ["2026-11"]})

    def test_the_page_gets_slim_board_files_for_the_last_week_and_each_month(self):
        self.store.write("months/2026-10.json", {"month": "2026-10", "incidents": [
            incident("CVE-2026-1", "old", "2026-10-20T00:00:00Z") | {"cites": {"cves": [], "urls": ["x.org"]}}]})
        self.store.write("index.json", {"months": ["2026-10"]})
        run_cycle(self.store, recorded(), at("2026-11-07T13:30:00"), "test-box")

        recent = self.store.read("board/recent.json")
        self.assertEqual(recent["since"], "2026-10-31T13:30:00Z")
        self.assertCountEqual([i["id"] for i in recent["incidents"]], ["CVE-2026-120984", "CVE-2026-120839"])
        self.assertNotIn("urls", recent["incidents"][0])  # linking keys stay in the collector's files
        # A month the page has no file for yet is written too, without its citations.
        self.assertEqual([i["id"] for i in self.store.read("board/2026-10.json")["incidents"]], ["CVE-2026-1"])
        self.assertNotIn("urls", self.store.read("board/2026-10.json")["incidents"][0])
        # The picker's Product list covers 90 days, so it is written every cycle beside recent.json.
        self.assertIn("products", self.store.read("board/products.json"))

    def test_status_file_holds_last_update_and_collector(self):
        run_cycle(self.store, recorded(), at("2026-11-07T13:30:00"), "test-box")

        self.assertEqual(
            self.store.read("status.json"),
            {"updated": "2026-11-07T13:30:00Z", "collector": "test-box"},
        )

    def test_second_cycle_with_nothing_new_changes_nothing(self):
        run_cycle(self.store, recorded(), at("2026-11-07T13:30:00"), "test-box")
        month, index = self.store.read("months/2026-11.json"), self.store.read("index.json")

        run_cycle(self.store, recorded(), at("2026-11-07T13:45:00"), "test-box")

        self.assertEqual(self.store.read("months/2026-11.json"), month)
        self.assertEqual(self.store.read("index.json"), index)

    def test_new_month_gets_its_own_file_and_a_seen_again_cve_no_second_incident(self):
        run_cycle(self.store, recorded("deltaLog-early.json"), at("2026-11-30T23:50:00"), "test-box")
        run_cycle(self.store, recorded("deltaLog.json"), at("2026-12-01T00:05:00"), "test-box")

        self.assertEqual(
            self.store.read("months/2026-11.json")["incidents"],
            [incident("CVE-2026-120839", WPTRAVELLY_TEXT, "2026-11-30T23:50:00Z", "2026-11-07T12:43:21Z")],
        )
        self.assertEqual(
            self.store.read("months/2026-12.json")["incidents"],
            [incident("CVE-2026-120984", KEYCLOAK_TEXT, "2026-12-01T00:05:00Z", "2026-11-07T13:22:00Z")],
        )
        self.assertEqual(self.store.read("index.json"), {"months": ["2026-11", "2026-12"]})

    def test_first_cycle_without_checkpoint_takes_only_the_newest_delta(self):
        store = self.make_store()
        run_cycle(store, recorded("deltaLog-early.json"), at("2026-11-07T13:00:00"), "test-box")

        # The newest entry of deltaLog-early only updates a record, so nothing is new.
        self.assertIsNone(store.read("months/2026-11.json"))
        self.assertEqual(store.read("status.json")["collector"], "test-box")


class NvdEnrichmentTest(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        # An earlier cycle saw these CVEs in cvelistV5 and read NVD up to 13:15.
        self.store.write("checkpoints.json", {"cvelist": "2026-11-07T13:22:16.396Z", "nvd": "2026-11-07T13:15:00.000Z"})
        self.store.write("index.json", {"months": ["2026-11"]})
        self.store.write("months/2026-11.json", {"month": "2026-11", "incidents": [
            incident("CVE-2026-123957", "TOTOLINK CA300-PoE ...", "2026-11-07T09:00:00Z"),
            incident("CVE-2024-6387", "regreSSHion ...", "2026-11-07T09:00:00Z"),
        ]})

    def test_cycle_adds_cvss_and_products_to_matching_incidents(self):
        http_get = recorded(
            nvd_pages=("page-0.json", "page-2.json"),
            nvd_range=("2026-11-07T13:15:00.000Z", "2026-11-07T13:30:00.000Z"),
        )
        run_cycle(self.store, http_get, at("2026-11-07T13:30:00"), "test-box", sleep=lambda s: None)

        incidents = {i["id"]: i for i in self.store.read("months/2026-11.json")["incidents"]}
        # CVE-2026-62032 is in the NVD response but not on the Board, so it is not added.
        self.assertEqual(sorted(incidents), ["CVE-2024-6387", "CVE-2026-123957"])
        self.assertEqual(incidents["CVE-2026-123957"]["cvss"], 9.9)
        self.assertEqual(
            incidents["CVE-2026-123957"]["products"],
            [{"id": "totolink:ca300-poe_firmware", "name": "Ca300-poe Firmware"}],
        )
        self.assertEqual(incidents["CVE-2024-6387"]["cvss"], 8.1)
        # Vulnerable CPEs only: not the SonicWall hardware it runs on, not the unaffected RHEL 7.
        self.assertEqual(
            incidents["CVE-2024-6387"]["products"],
            [
                {"id": "openbsd:openssh", "name": "Openssh"},
                {"id": "redhat:enterprise_linux", "name": "Enterprise Linux"},
                {"id": "sonicwall:sma_6200_firmware", "name": "Sma 6200 Firmware"},
            ],
        )
        self.assertEqual(self.store.read("checkpoints.json")["nvd"], "2026-11-07T13:30:00.000Z")

    def test_nvd_outage_still_publishes_new_cves_and_retries_the_same_range(self):
        cvelist_get = recorded()

        def get(url, headers=None):
            if url.startswith(nvd.API_URL):
                raise OSError("HTTP Error 503: Service Unavailable")
            return cvelist_get(url)

        self.store.write("checkpoints.json", {"cvelist": "2026-11-07T12:00:00.000Z", "nvd": "2026-11-07T13:15:00.000Z"})
        run_cycle(self.store, get, at("2026-11-07T13:30:00"), "test-box", sleep=lambda s: None)

        ids = [i["id"] for i in self.store.read("months/2026-11.json")["incidents"]]
        self.assertIn("CVE-2026-120984", ids)
        self.assertEqual(self.store.read("checkpoints.json")["nvd"], "2026-11-07T13:15:00.000Z")
        self.assertEqual(self.store.read("status.json")["updated"], "2026-11-07T13:30:00Z")

    def busy_nvd(self, pages):
        """A fake clock and an NVD that answers `pages` one-item pages; records when each request came."""
        clock = {"now": 0.0}
        calls = []
        item = json.loads((NVD_FIXTURES / "page-0.json").read_bytes())["vulnerabilities"][0]
        cvelist_get = recorded()

        def get(url, headers=None):
            if not url.startswith(nvd.API_URL):
                return cvelist_get(url)
            calls.append((clock["now"], headers or {}))
            start = int(parse_qs(urlsplit(url).query)["startIndex"][0])
            return json.dumps({"startIndex": start, "totalResults": pages, "vulnerabilities": [item]}).encode()

        def sleep(seconds):
            clock["now"] += seconds

        return get, sleep, calls

    def assert_at_most_per_30s(self, calls, limit):
        times = [t for t, _ in calls]
        busiest = max(sum(1 for u in times if t <= u < t + 30) for t in times)
        self.assertLessEqual(busiest, limit)

    def test_nvd_requests_stay_within_the_keyless_rate_limit(self):
        get, sleep, calls = self.busy_nvd(pages=12)
        run_cycle(self.store, get, at("2026-11-07T13:30:00"), "test-box", sleep=sleep)

        self.assertEqual(len(calls), 12)
        self.assert_at_most_per_30s(calls, 5)
        self.assertTrue(all("apiKey" not in h for _, h in calls))

    def test_nvd_requests_with_a_key_send_it_and_stay_within_its_rate_limit(self):
        get, sleep, calls = self.busy_nvd(pages=120)
        run_cycle(self.store, get, at("2026-11-07T13:30:00"), "test-box", sleep=sleep, nvd_api_key="k-123")

        self.assertEqual(len(calls), 120)
        self.assert_at_most_per_30s(calls, 50)
        self.assertTrue(all(h.get("apiKey") == "k-123" for _, h in calls))


if __name__ == "__main__":
    unittest.main()
