"""Seam 1: one collection cycle, replayed against recorded source responses."""

import io
import json
import unittest
import urllib.error
from contextlib import redirect_stderr
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from collector import cvelist, cycle, github, hn, kev, nvd
from collector.cycle import run_cycle
from collector.cvelist import DELTA_LOG_URL
from collector.store import MemoryStore

# The older seam tests predate quick titles and gathered batches (2026-11-09): every waiting Summary goes out at once.
from collector import summaries as _summaries  # noqa: E402
_summaries.QUICK_TITLES, _summaries.BATCH_MIN = False, 1

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
             kev=None, curators=None, web=None, hn_buzz=None, unpublished=()):
    """An http_get that answers from fixtures and fails on anything not recorded.

    NVD pages are trimmed real responses, keyed by the startIndex they answer.
    delta_log=None serves an empty delta log; a Mention source given no fixture answers empty.
    web maps a Mention's URL to its page in fixtures/pages/ (what a Summary reads).
    hn_buzz answers the HN points refresh (the search with a points filter); without it, no hits.
    unpublished: CVE IDs whose record is not out yet, so its raw path answers 404 (FileNotFoundError here).
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
        name = url.rsplit("/", 1)[-1]
        if name.removesuffix(".json") in unpublished:
            raise FileNotFoundError(url)
        return (FIXTURES / "cvelist" / name).read_bytes()

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
        # The page opens on this file alone: a failed status.json fetch drew an error Board for Googlebot (11-10).
        self.assertEqual(recent["status"], self.store.read("status.json"))
        self.assertCountEqual([i["id"] for i in recent["incidents"]], ["CVE-2026-120984", "CVE-2026-120839"])
        self.assertNotIn("urls", recent["incidents"][0])  # linking keys stay in the collector's files
        # A month the page has no file for yet is written too, without its citations.
        self.assertEqual([i["id"] for i in self.store.read("board/2026-10.json")["incidents"]], ["CVE-2026-1"])
        self.assertNotIn("urls", self.store.read("board/2026-10.json")["incidents"][0])
        # The picker's Product list covers 90 days, so it is written every cycle beside recent.json.
        self.assertIn("products", self.store.read("board/products.json"))

    def test_the_board_draws_first_from_row_views_with_the_newest_and_the_highlights_whole(self):
        # Owner, 11-10: board/recent.json is 9 MB of details; rows.json holds the same week light, except the rows most
        # likely opened first. One newest here (100 live), so the older plain row is a row view.
        self.store.write("months/2026-11.json", {"month": "2026-11", "incidents": [
            incident("CVE-2026-2", "critical", "2026-11-06T00:00:00Z", "2026-11-05T00:00:00Z") | {"cvss": 9.8}]})
        self.store.write("index.json", {"months": ["2026-11"]})
        with patch.object(cycle, "WHOLE_NEWEST", 1):
            run_cycle(self.store, recorded(), at("2026-11-07T13:30:00"), "test-box")

        recent, rows = self.store.read("board/recent.json"), self.store.read("board/rows.json")
        self.assertEqual((rows["since"], rows["status"]), (recent["since"], recent["status"]))
        self.assertEqual([i["id"] for i in rows["incidents"]], [i["id"] for i in recent["incidents"]])
        by_id = {i["id"]: i for i in rows["incidents"]}
        full = {i["id"]: i for i in recent["incidents"]}
        self.assertEqual(by_id["CVE-2026-120984"], full["CVE-2026-120984"])  # the newest
        self.assertEqual(by_id["CVE-2026-2"], full["CVE-2026-2"])  # a Highlight
        row = by_id["CVE-2026-120839"]
        self.assertTrue(row["rows"])
        self.assertIs(row["wp_plugin"], False)
        self.assertEqual(row["mentions"], [{"kind": "cve_record"}])
        self.assertEqual(row["brief"], {"text": WPTRAVELLY_TEXT})  # no Summary or quick title: the row's own title
        self.assertNotIn("cve_texts", row)

    def test_among_equal_highlight_scores_the_newer_stays_whole(self):
        # Owner, 11-10: the newer first among equal scores, as filterBoard picks them.
        older, newer = (incident(cve, "x", seen, seen) | {"cvss": 9.8}  # not exploited: every exploited one stays whole
                        for cve, seen in (("CVE-2026-7001", "2026-11-05T00:00:00Z"), ("CVE-2026-7002", "2026-11-06T00:00:00Z")))
        self.store.write("months/2026-11.json", {"month": "2026-11", "incidents": [older, newer]})
        self.store.write("index.json", {"months": ["2026-11"]})
        with patch.object(cycle, "WHOLE_NEWEST", 0), patch.object(cycle, "HIGHLIGHTS", 1):
            run_cycle(self.store, recorded(), at("2026-11-07T13:30:00"), "test-box")

        by_id = {i["id"]: i for i in self.store.read("board/rows.json")["incidents"]}
        self.assertNotIn("rows", by_id["CVE-2026-7002"])
        self.assertTrue(by_id["CVE-2026-7001"]["rows"])

    def test_every_exploited_highlight_of_the_week_stays_whole(self):
        # Owner, 11-10: the week had eleven exploited Incidents and the eleventh was cut off at ten.
        exploited = [incident(f"CVE-2026-71{n:02d}", "x", f"2026-11-0{1 + n // 2}T{n:02d}:00:00Z") | {"kev": True}
                     for n in range(11)]
        critical = incident("CVE-2026-7200", "x", "2026-11-06T12:00:00Z") | {"cvss": 9.8}
        self.store.write("months/2026-11.json", {"month": "2026-11", "incidents": [*exploited, critical]})
        self.store.write("index.json", {"months": ["2026-11"]})
        with patch.object(cycle, "WHOLE_NEWEST", 0):
            run_cycle(self.store, recorded(), at("2026-11-07T13:30:00"), "test-box")

        by_id = {i["id"]: i for i in self.store.read("board/rows.json")["incidents"]}
        for i in exploited:
            self.assertNotIn("rows", by_id[i["id"]], i["id"])
        self.assertTrue(by_id["CVE-2026-7200"]["rows"])  # the twelfth candidate, not exploited

    def test_a_well_known_highlight_stays_whole_over_better_scored_rows(self):
        # Owner, 11-11: a CVSS 9.6 Zoom Workplace flaw with one Mention ranked 265th of the week.
        zoom = incident("CVE-2026-7300", "x", "2026-11-06T00:00:00Z") | {
            "cvss": 9.6, "products": [{"id": "zoom_communications:zoom_workplace", "name": "Zoom Workplace"}]}
        busy = [incident(f"CVE-2026-74{n:02d}", "x", f"2026-11-06T{n:02d}:00:00Z") | {
            "cvss": 9.8, "mentions": [{"kind": "advisory", "url": f"https://a/{n}/{k}"} for k in range(10)]} for n in range(10)]
        self.store.write("months/2026-11.json", {"month": "2026-11", "incidents": [zoom, *busy]})
        self.store.write("index.json", {"months": ["2026-11"]})
        with patch.object(cycle, "WHOLE_NEWEST", 0):
            run_cycle(self.store, recorded(), at("2026-11-07T13:30:00"), "test-box")

        by_id = {i["id"]: i for i in self.store.read("board/rows.json")["incidents"]}
        self.assertEqual(by_id["CVE-2026-7300"]["known"], "Zoom")
        self.assertNotIn("rows", by_id["CVE-2026-7300"])
        self.assertTrue(by_id["CVE-2026-7400"]["rows"])  # the oldest of ten better-scored rows: the eleventh

    def test_the_highlights_match_the_page_on_the_shared_case(self):
        # tests/board.test.mjs checks filterBoard on the same case.
        case = json.loads((Path(__file__).parent / "fixtures" / "board" / "highlights-case.json").read_text(encoding="utf-8"))
        since = "2026-11-04T00:00:00Z"  # seven days before case["now"]
        self.assertEqual([i["id"] for i in cycle.highlights(case["incidents"], since)], case["expected"])
        plain = [{k: v for k, v in i.items() if k != "known"} for i in case["incidents"]]
        self.assertEqual([i["id"] for i in cycle.highlights(plain, since)], case["expected_without_known"])
        self.assertEqual([i["id"] for i in cycle.highlights(case["capped"]["incidents"], since)], case["capped"]["expected"])

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

    def test_a_long_gap_is_read_oldest_first_a_bounded_number_of_records_a_cycle(self):
        # 11-09: a 7-day backfill (about 3,760 new CVEs) in one cycle would run for hours with every 위험+ row
        # summarized at once; whole delta entries are read oldest first until the limit, and the checkpoint stops there.
        get = recorded()
        first, checkpoint = cvelist.fetch("2026-11-07T12:00:00.000Z", get, limit=1)
        self.assertEqual([r["cveMetadata"]["cveId"] for r in first], ["CVE-2026-120839"])
        self.assertEqual(checkpoint, "2026-11-07T12:47:54.668Z")
        rest, checkpoint = cvelist.fetch(checkpoint, get, limit=1)
        self.assertCountEqual([r["cveMetadata"]["cveId"] for r in rest], ["CVE-2026-120984", "CVE-2026-120839"])
        self.assertEqual(checkpoint, "2026-11-07T13:22:16.396Z")  # caught up: the newest entry

    def test_a_cve_cited_before_its_record_was_read_gets_the_record(self):
        # oss-security named the CVE first and the record came out before this store's first delta (11-09: nine Apache
        # Airflow rows with no Product, so no vendor fold). The cycle reads the record itself.
        cve = "CVE-2026-123158"
        self.store.write("months/2026-11.json", {"month": "2026-11", "incidents": [{
            "id": cve, "cves": [cve], "first_seen": "2026-11-07T10:00:00Z",
            "mentions": [{"kind": "discussion", "url": "https://seclists.org/oss-sec/2026/q4/1"}],
            "urls": ["seclists.org/oss-sec/2026/q4/1"], "brief": {"text": "sshd on musl", "lead": "https://seclists.org/oss-sec/2026/q4/1"}}]})
        self.store.write("index.json", {"months": ["2026-11"]})
        run_cycle(self.store, recorded(delta_log=None), at("2026-11-07T13:30:00"), "test-box")

        row = next(i for i in self.store.read("months/2026-11.json")["incidents"] if i["id"] == cve)
        self.assertIn({"kind": "cve_record", "url": f"https://www.cve.org/CVERecord?id={cve}"}, row["mentions"])
        self.assertEqual([p["id"] for p in row["products"]], ["openbsd:openssh"])

    def test_a_cited_cve_with_no_record_yet_is_skipped_quietly(self):
        self.store.write("months/2026-11.json", {"month": "2026-11", "incidents": [{
            "id": "CVE-2026-999999", "cves": ["CVE-2026-999999"], "first_seen": "2026-11-07T10:00:00Z",
            "mentions": [{"kind": "discussion", "url": "https://seclists.org/oss-sec/2026/q4/2"}],
            "urls": ["seclists.org/oss-sec/2026/q4/2"], "brief": {"text": "reserved", "lead": "https://seclists.org/oss-sec/2026/q4/2"}}]})
        self.store.write("index.json", {"months": ["2026-11"]})
        run_cycle(self.store, recorded(delta_log=None), at("2026-11-07T13:30:00"), "test-box")  # the fixture 404s: no error

        row = self.store.read("months/2026-11.json")["incidents"][0]
        self.assertNotIn("products", row)

    def test_first_cycle_without_checkpoint_takes_only_the_newest_delta(self):
        store = self.make_store()
        run_cycle(store, recorded("deltaLog-early.json"), at("2026-11-07T13:00:00"), "test-box")

        # The newest entry of deltaLog-early only updates a record, so nothing is new.
        self.assertIsNone(store.read("months/2026-11.json"))
        self.assertEqual(store.read("status.json")["collector"], "test-box")

    def hold(self, *rows):
        """The store as earlier cycles left it: rows in their month files (and the page's), the months indexed."""
        months = sorted({r["first_seen"][:7] for r in rows})
        for m in months:
            self.store.write(f"months/{m}.json", {"month": m, "incidents": [r for r in rows if r["first_seen"][:7] == m]})
            self.store.write(f"board/{m}.json", {"month": m, "incidents": []})
        self.store.write("index.json", {"months": months})

    def test_an_incident_is_kept_90_days_from_first_seen_and_its_month_rewritten_for_that_alone(self):
        # Owner, 11-10: 90 days, really. Nothing else touches 2026-08 this cycle; ageing alone rewrites it.
        self.hold(incident("CVE-2026-1", "91 days", "2026-08-08T13:30:00Z"),
                  incident("CVE-2026-2", "exactly 90 days", "2026-08-09T13:30:00Z"),
                  incident("CVE-2026-3", "89 days", "2026-08-10T13:30:00Z"))
        run_cycle(self.store, recorded(delta_log=None), at("2026-11-07T13:30:00"), "test-box")

        self.assertEqual([i["id"] for i in self.store.read("months/2026-08.json")["incidents"]], ["CVE-2026-2", "CVE-2026-3"])
        self.assertEqual([i["id"] for i in self.store.read("board/2026-08.json")["incidents"]], ["CVE-2026-2", "CVE-2026-3"])
        self.assertEqual(self.store.read("index.json"), {"months": ["2026-08"]})

    def test_a_month_left_with_no_incident_is_deleted_and_leaves_the_index(self):
        self.hold(incident("CVE-2026-1", "old", "2026-07-30T00:00:00Z"), incident("CVE-2026-2", "kept", "2026-10-20T00:00:00Z"))
        run_cycle(self.store, recorded(), at("2026-11-07T13:30:00"), "test-box")

        self.assertEqual(self.store.read("index.json"), {"months": ["2026-10", "2026-11"]})
        self.assertFalse([n for n in self.store.names() if "2026-07" in n])
        self.assertEqual([i["id"] for i in self.store.read("months/2026-10.json")["incidents"]], ["CVE-2026-2"])

    def test_a_cycle_that_would_prune_more_than_half_of_its_incidents_prunes_none(self):
        # Deletion cannot be undone: a clock months ahead, or bad first_seen data, must not empty the store.
        self.hold(incident("CVE-2026-1", "old", "2026-07-30T00:00:00Z"), incident("CVE-2026-2", "old", "2026-07-31T00:00:00Z"),
                  incident("CVE-2026-3", "kept", "2026-10-20T00:00:00Z"))
        with redirect_stderr(io.StringIO()) as err:
            run_cycle(self.store, recorded(delta_log=None), at("2026-11-07T13:30:00"), "test-box")

        self.assertEqual(len(self.store.read("months/2026-07.json")["incidents"]), 2)
        self.assertEqual(self.store.read("index.json"), {"months": ["2026-07", "2026-10"]})
        self.assertEqual([line for line in err.getvalue().splitlines() if line.startswith("retention:")],
                         ["retention: 2 of 3 Incidents are past 90 days; pruned none (wrong clock or bad data?)"])


def unavailable(url):
    raise urllib.error.HTTPError(url, 503, "Service Unavailable", {}, None)


def rate_limited(url):
    raise urllib.error.HTTPError(url, 403, "rate limit exceeded", {}, None)


def is_hn_points(url):
    return url.startswith(hn.SEARCH_URL) and "points" in parse_qs(urlsplit(url).query).get("numericFilters", [""])[0]


class OutageTest(unittest.TestCase):
    """One source's network or format error skips that source for the cycle, never the cycle (2026-11-11: a
    rate-limited GitHub search, no token: 10 a minute, ended a whole cycle on the live box)."""

    def rows(self):
        return [incident("CVE-2026-123158", "SSHole ...", "2026-11-07T09:00:00Z")]

    def setUp(self):
        self.store = MemoryStore()
        self.store.write("index.json", {"months": ["2026-11"]})
        self.store.write("months/2026-11.json", {"month": "2026-11", "incidents": self.rows()})
        self.store.write("checkpoints.json", {"cvelist": "2026-11-07T12:00:00.000Z"})

    def held(self, cve):
        return next(i for i in self.store.read("months/2026-11.json")["incidents"] if cve in i["cves"])

    def answering(self, matches, answer, **fixtures):
        """recorded(**fixtures), but a URL that matches calls answer(url)."""
        rest = recorded(**fixtures)

        def get(url, headers=None):
            return answer(url) if matches(url) else rest(url)

        return get

    def cycle(self, http_get, source, when="2026-11-07T13:30:00"):
        """Run one cycle; return its stderr lines about `source`."""
        with redirect_stderr(io.StringIO()) as err:
            run_cycle(self.store, http_get, at(when), "test-box", sleep=lambda s: None)
        return [line for line in err.getvalue().splitlines() if line.startswith(f"{source}:")]

    def assert_skipped(self, http_get, source, when="2026-11-07T13:30:00"):
        lines = self.cycle(http_get, source, when)

        self.assertEqual(len(lines), 1, lines)
        self.assertTrue(lines[0].startswith(f"{source}: skipped this cycle:"), lines[0])
        self.assertEqual(self.store.read("status.json")["updated"], at(when).strftime("%Y-%m-%dT%H:%M:%SZ"))
        # The cycle's cvelist record still became an Incident.
        self.assertIn("CVE-2026-120984", [i["id"] for i in self.store.read("months/2026-11.json")["incidents"]])

    def assert_checkpoint_kept(self, http_get, source):
        for before in ({"cvelist": "2026-11-07T12:00:00.000Z"},
                       {"cvelist": "2026-11-07T12:00:00.000Z", source: self.earlier_checkpoint}):
            with self.subTest(before=before):
                self.setUp()
                self.store.write("checkpoints.json", before)
                self.assert_skipped(http_get, source)
                # Left as it was (absent stays absent), so the next cycle asks the same range.
                self.assertEqual(self.store.read("checkpoints.json").get(source, "absent"), before.get(source, "absent"))


class GithubOutageTest(OutageTest):
    earlier_checkpoint = "2026-11-04T00:00:00Z"

    def search(self, answer):
        return self.answering(lambda url: url.startswith(github.SEARCH_URL), answer)

    def test_a_rate_limited_search_skips_github_and_the_cycle_goes_on(self):
        self.assert_checkpoint_kept(self.search(rate_limited), "github")

    def test_a_search_answer_without_items_is_skipped_the_same_way(self):
        self.assert_checkpoint_kept(self.search(lambda url: b'{"message": "API rate limit exceeded"}'), "github")

    def test_the_next_cycle_takes_the_repos_and_moves_the_checkpoint(self):
        self.cycle(self.search(rate_limited), "github")
        self.assertEqual(self.cycle(recorded(github="sshole.json"), "github", "2026-11-07T14:00:00"), [])

        self.assertIn("https://github.com/gabrielunknown/CVE-2026-123158_SSHole",
                      [m["url"] for m in self.held("CVE-2026-123158")["mentions"] if m["kind"] == "repo"])
        self.assertEqual(self.store.read("checkpoints.json")["github"], "2026-11-05T22:51:12Z")


class HnOutageTest(OutageTest):
    earlier_checkpoint = 1793800000

    def rows(self):
        # A recent Incident with an HN story, so the cycle reads its points again.
        story = incident("CVE-2026-123158", "SSHole ...", "2026-11-07T09:00:00Z")
        story["mentions"].append({"kind": "discussion", "url": hn.ITEM_URL + "50399569", "title": "SSHole", "points": 12})
        return [story]

    def stories(self, answer, **fixtures):
        return self.answering(lambda url: url.startswith(hn.SEARCH_URL) and not is_hn_points(url), answer, **fixtures)

    def test_a_failed_story_search_skips_hn_and_keeps_its_checkpoint(self):
        self.assert_checkpoint_kept(self.stories(unavailable), "hn")

    def test_the_next_cycle_takes_the_stories_and_moves_the_checkpoint(self):
        self.cycle(self.stories(unavailable), "hn")
        self.assertEqual(self.cycle(recorded(hn="sshole.json"), "hn", "2026-11-07T14:00:00"), [])

        urls = [m["url"] for i in self.store.read("months/2026-11.json")["incidents"] for m in i["mentions"]]
        self.assertIn(hn.ITEM_URL + "50378228", urls)
        self.assertEqual(self.store.read("checkpoints.json")["hn"], 1793881300)

    def test_a_failed_points_refresh_skips_it_and_keeps_the_points(self):
        self.assert_skipped(self.answering(is_hn_points, unavailable), "hn points")

        [story] = [m for m in self.held("CVE-2026-123158")["mentions"] if m["kind"] == "discussion"]
        self.assertEqual(story["points"], 12)


class KevOutageTest(OutageTest):
    def rows(self):
        # Flagged by an earlier cycle; CVE-2026-19868 is listed in kev.json but not flagged yet.
        return [{**incident("CVE-2026-123158", "SSHole ...", "2026-11-07T09:00:00Z"), "kev": True, "kev_date": "2026-11-01"},
                incident("CVE-2026-19868", "SonicWall SonicOS SSLVPN ...", "2026-11-07T09:00:00Z")]

    def test_a_failed_catalog_skips_kev_and_keeps_every_flag(self):
        self.assert_skipped(self.answering(lambda url: url.startswith(kev.FEED_URL), unavailable), "kev")

        self.assertEqual((self.held("CVE-2026-123158")["kev"], self.held("CVE-2026-123158")["kev_date"]), (True, "2026-11-01"))
        self.assertNotIn("kev", self.held("CVE-2026-19868"))

    def test_the_next_cycle_flags_a_newly_listed_cve(self):
        self.cycle(self.answering(lambda url: url.startswith(kev.FEED_URL), unavailable), "kev")
        self.assertEqual(self.cycle(recorded(kev="kev.json"), "kev", "2026-11-07T14:00:00"), [])

        self.assertEqual((self.held("CVE-2026-19868")["kev"], self.held("CVE-2026-19868")["kev_date"]), (True, "2026-11-06"))
        self.assertIs(self.held("CVE-2026-123158")["kev"], True)


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
                {"id": "openbsd:openssh", "name": "OpenSSH"},  # a known brand keeps its casing (critique 13)
                {"id": "redhat:enterprise_linux", "name": "Enterprise Linux"},
                {"id": "sonicwall:sma_6200_firmware", "name": "Sma 6200 Firmware"},
            ],
        )
        self.assertEqual(self.store.read("checkpoints.json")["nvd"], "2026-11-07T13:30:00.000Z")
        # Vendors not in web/vendors.json whose Product names lack them, with an example, for a person or agent to add.
        self.assertEqual(self.store.read("unknown_vendors.json"), {"openbsd": "OpenSSH", "totolink": "Ca300-poe Firmware"})

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
