"""Seam 1: Mention sources and Incident linking, replayed against recorded responses.

hn/sshole.json, github/sshole.json and oss-security/oss-sec.rss are real responses, trimmed.
The sshole CVE record, its delta log, the Axis2 records and the two-CVE advisory are hand-built
in the real shapes (the non-security HN story in hn/sshole.json is hand-built too).
"""

import json
import unittest

from collector.cycle import run_cycle
from collector.store import MemoryStore
from test_cycle import FIXTURES, at, recorded

HN_STORY = "https://news.ycombinator.com/item?id=50378228"
RELEASE_NOTE = "https://www.openssh.com/txt/release-10.6p2"


class SsholeReplayTest(unittest.TestCase):
    """The HN story, sshhole.com, the oz9un/sshole repo and CVE-2026-123158, in their real order."""

    def setUp(self):
        self.store = MemoryStore()
        self.store.write("checkpoints.json", {"cvelist": "2026-11-05T12:00:00.000Z"})

    def incidents(self):
        return self.store.read("months/2026-11.json")["incidents"]

    def test_hn_story_alone_is_an_unassigned_incident_on_the_board(self):
        run_cycle(self.store, recorded(None, hn="sshole.json"), at("2026-11-05T12:30:00"), "test-box")

        # The non-security story in the same response is not an Incident.
        self.assertEqual(
            self.incidents(),
            [{
                "id": HN_STORY,
                "cves": [],
                "first_seen": "2026-11-05T12:30:00Z",
                "published": "2026-11-05T12:19:02Z",  # the HN post time, before the cycle saw it
                "mentions": [
                    {"kind": "discussion", "url": HN_STORY, "title": "sshole", "points": 2935},
                    {"kind": "writeup", "url": "https://sshhole.com"},
                ],
                "urls": ["news.ycombinator.com/item?id=50378228", "sshhole.com"],
                "brief": {"text": "sshole", "lead": "https://sshhole.com"},
            }],
        )

    def test_cve_merges_into_the_unassigned_incident_and_release_note_becomes_lead(self):
        run_cycle(self.store, recorded(None, hn="sshole.json"), at("2026-11-05T12:30:00"), "test-box")
        run_cycle(self.store, recorded("deltaLog-sshole.json"), at("2026-11-05T16:00:00"), "test-box")

        [incident] = self.incidents()
        self.assertEqual(incident["id"], HN_STORY)  # same row as before the CVE
        self.assertEqual(incident["first_seen"], "2026-11-05T12:30:00Z")
        self.assertEqual(incident["cves"], ["CVE-2026-123158"])
        self.assertEqual(
            incident["mentions"],
            [
                {"kind": "discussion", "url": HN_STORY, "title": "sshole", "points": 2935},
                {"kind": "writeup", "url": "https://sshhole.com"},
                {"kind": "cve_record", "url": "https://www.cve.org/CVERecord?id=CVE-2026-123158"},
                {"kind": "advisory", "url": RELEASE_NOTE},
            ],
        )
        self.assertEqual(incident["brief"]["lead"], RELEASE_NOTE)
        self.assertTrue(incident["brief"]["text"].startswith("sshd in OpenSSH before 10.6p2"))

    def test_repos_join_by_homepage_and_by_cve_and_the_replay_ends_as_one_incident(self):
        run_cycle(self.store, recorded(None, hn="sshole.json"), at("2026-11-05T12:30:00"), "test-box")
        run_cycle(self.store, recorded("deltaLog-sshole.json"), at("2026-11-05T16:00:00"), "test-box")
        run_cycle(self.store, recorded(None, github="sshole.json"), at("2026-11-05T23:00:00"), "test-box")

        [incident] = self.incidents()
        self.assertEqual(incident["cves"], ["CVE-2026-123158"])
        self.assertEqual(
            incident["mentions"][4:],
            [
                {"kind": "repo", "url": "https://github.com/oz9un/sshole", "title": "oz9un/sshole"},
                {
                    "kind": "repo",
                    "url": "https://github.com/gabrielunknown/CVE-2026-123158_SSHole",
                    "title": "gabrielunknown/CVE-2026-123158_SSHole",
                },
            ],
        )  # leonjza/sshhole-lab cites neither a CVE nor a known URL, so it is not listed
        self.assertEqual(incident["brief"]["lead"], RELEASE_NOTE)
        # The Board test (seam 2) reads this same row to check that sshole becomes a Highlight.
        self.assertEqual(incident, json.loads((FIXTURES / "board" / "sshole.json").read_bytes()))


class PublishedTest(unittest.TestCase):
    def test_published_is_the_earliest_post_and_a_late_joiner_does_not_move_it(self):
        from collector.incidents import link
        incidents = []
        story = {"mentions": [{"kind": "discussion", "url": "https://news.ycombinator.com/item?id=1"}], "cves": ["CVE-2026-1"],
                 "urls": [], "text": "story", "published": "2026-11-05T12:00:00Z"}
        record = {"mentions": [{"kind": "cve_record", "url": "https://www.cve.org/CVERecord?id=CVE-2026-1"}], "cves": ["CVE-2026-1"],
                  "urls": [], "text": "record", "published": "2026-11-05T15:00:00Z"}
        old_repo = {"mentions": [{"kind": "repo", "url": "https://github.com/a/b"}], "cves": ["CVE-2026-1"],
                    "urls": [], "text": "repo", "join_only": True, "published": "2019-01-01T00:00:00Z"}
        link(incidents, record, "2026-11-05T16:00:00Z")
        link(incidents, story, "2026-11-05T16:15:00Z")
        link(incidents, old_repo, "2026-11-05T16:30:00Z")
        [incident] = incidents
        self.assertEqual((incident["first_seen"], incident["published"]), ("2026-11-05T16:00:00Z", "2026-11-05T12:00:00Z"))

    def test_a_source_without_a_time_leaves_the_publish_time_unknown(self):
        # The cycle's own time is not when the news broke; the page says "처음 확인" instead.
        from collector.incidents import link
        incidents = []
        post = {"mentions": [{"kind": "discussion", "url": "https://example.org/post"}], "cves": ["CVE-2026-2"], "urls": [], "text": "post"}
        link(incidents, post, "2026-11-05T16:00:00Z")
        self.assertNotIn("published", incidents[0])
        # A later source with a time after the cycle first saw it does not become the publish time either.
        later = {"mentions": [{"kind": "cve_record", "url": "https://www.cve.org/CVERecord?id=CVE-2026-2"}], "cves": ["CVE-2026-2"],
                 "urls": [], "text": "record", "published": "2026-11-05T18:00:00Z"}
        link(incidents, later, "2026-11-05T18:15:00Z")
        self.assertNotIn("published", incidents[0])
        earlier = dict(later, mentions=[{"kind": "advisory", "url": "https://example.org/advisory"}], published="2026-11-04T09:00:00Z")
        link(incidents, earlier, "2026-11-05T18:30:00Z")
        self.assertEqual(incidents[0]["published"], "2026-11-04T09:00:00Z")

    def test_nvd_publish_date_fills_or_moves_back_the_publish_time(self):
        from collector.incidents import enrich
        unknown = {"first_seen": "2026-11-08T03:38:07Z"}
        enrich(unknown, {"cvss": None, "products": [], "published": "2026-10-13T18:59:53.123"})
        self.assertEqual(unknown["published"], "2026-10-13T18:59:53Z")
        known = {"first_seen": "2026-11-08T03:38:07Z", "published": "2026-11-07T12:00:00Z"}
        enrich(known, {"cvss": None, "products": [], "published": "2026-11-07T15:00:00.000"})
        self.assertEqual(known["published"], "2026-11-07T12:00:00Z")

    def test_a_malformed_url_in_a_page_does_not_stop_the_cycle(self):
        # 11-09 live run: a write-up page held "http://[...", urlsplit raised "Invalid IPv6 URL" and the whole cycle died.
        from collector.incidents import page_keys, url_key
        self.assertEqual(url_key("http://[broken/path"), "http://[broken/path")
        self.assertIn("example.net/a", page_keys("see http://[broken and https://example.net/a", "https://example.org/w")["urls"])

    def test_a_malformed_reference_url_is_neither_a_repo_nor_hn_and_is_not_fetched(self):
        import urllib.error
        from collector.hn import is_repo
        from collector.net import make_http_get
        from collector.summaries import is_hn
        self.assertFalse(is_repo("http://[broken"))
        self.assertFalse(is_hn("http://[broken"))
        with self.assertRaises(urllib.error.URLError):
            make_http_get("test")("http://[broken")

    def test_an_rss_time_in_another_zone_is_turned_into_utc(self):
        import xml.etree.ElementTree as ET
        from collector import rss
        item = ET.fromstring("<item><pubDate>Fri, 06 Nov 2026 13:14:32 -0500</pubDate></item>")
        self.assertEqual(rss.posted(item), "2026-11-06T18:14:32Z")

    def test_a_source_time_reads_as_utc_and_a_bad_one_is_none(self):
        from collector.incidents import to_stamp
        self.assertEqual(to_stamp("2026-11-07T12:43:21.399Z"), "2026-11-07T12:43:21Z")
        self.assertEqual(to_stamp("2026-11-07T21:43:21+09:00"), "2026-11-07T12:43:21Z")
        self.assertEqual(to_stamp("2026-11-07T12:43:21"), "2026-11-07T12:43:21Z")
        self.assertIsNone(to_stamp(None))
        self.assertIsNone(to_stamp("soon"))


class StoryPageTest(unittest.TestCase):
    """A CVE-less story joins the one Incident its linked page cites (the sunshowers.io post on sshole, 11-08)."""

    def setUp(self):
        from collector.incidents import link
        self.link, self.incidents = link, []
        for cve, writeup in (("CVE-2026-123158", "https://sshhole.com"), ("CVE-2026-9999", "https://other.example/post")):
            self.link(self.incidents, {"mentions": [{"kind": "cve_record", "url": f"https://www.cve.org/CVERecord?id={cve}"},
                                                    {"kind": "writeup", "url": writeup}],
                                       "cves": [cve], "urls": [], "text": cve}, "2026-11-05T16:00:00Z")

    def story(self, page):
        from collector.incidents import page_keys
        url = "https://sunshowers.io/posts/sshole/"
        return {"mentions": [{"kind": "discussion", "url": "https://news.ycombinator.com/item?id=50399400"},
                             {"kind": "writeup", "url": url}],
                "cves": [], "urls": [], "text": "*sshole, or when are we going to get rid of C?", "join_only": False,
                "page": page_keys(page, url)}

    def rejoin(self):
        from collector.incidents import rejoin
        return rejoin(self.incidents, "2026-11-01T00:00:00Z")

    def test_a_page_linking_one_incidents_write_up_joins_it(self):
        page = '<a href="https://sunshowers.io/">home</a> <a href="https://sshhole.com/">yet</a>'
        self.link(self.incidents, self.story(page), "2026-11-08T03:00:00Z")
        self.assertEqual(self.incidents[2]["cites"]["urls"], ["sshhole.com"])  # its own site is navigation
        self.assertEqual(self.rejoin(), {"2026-11"})
        self.assertEqual(len(self.incidents), 2)
        self.assertIn("https://sunshowers.io/posts/sshole/", [m["url"] for m in self.incidents[0]["mentions"]])
        self.assertNotIn("cites", self.incidents[0])

    def test_a_story_that_came_first_joins_when_its_incident_arrives(self):
        early = []
        self.link(early, self.story('<a href="https://sshhole.com/">yet</a>'), "2026-11-05T12:00:00Z")
        self.incidents = early + self.incidents
        self.rejoin()
        self.assertEqual([i["id"] for i in self.incidents], ["CVE-2026-123158", "CVE-2026-9999"])

    def test_a_page_citing_two_incidents_or_none_stands_alone(self):
        self.link(self.incidents, self.story("CVE-2026-123158 and CVE-2026-9999"), "2026-11-08T03:00:00Z")
        self.assertEqual(self.rejoin(), set())
        self.assertEqual(len(self.incidents), 3)

    def test_citations_are_dropped_after_a_week(self):
        from collector.incidents import rejoin
        self.link(self.incidents, self.story("CVE-2026-123158 and CVE-2026-9999"), "2026-11-08T03:00:00Z")
        rejoin(self.incidents, "2026-11-09T00:00:00Z")
        self.assertNotIn("cites", self.incidents[2])

    def test_tagged_references_in_cna_and_adp_become_mentions(self):
        from collector import cvelist
        record = {"cveMetadata": {"cveId": "CVE-2026-123158", "datePublished": "2026-11-05T15:46:00Z"},
                  "containers": {"cna": {"references": [{"url": "https://www.openssh.org/releasenotes.html#10.6p2"},
                                                        {"url": "https://example.org/a", "tags": ["vendor-advisory"]}]},
                                 "adp": [{"references": [{"url": "https://sshhole.com", "tags": ["exploit"]},
                                                         {"url": "https://github.com/x/poc", "tags": ["exploit"]}]}]}}
        group = cvelist.mention_group(record)
        self.assertEqual([(m["kind"], m["url"]) for m in group["mentions"][1:]],
                         [("advisory", "https://example.org/a"), ("writeup", "https://sshhole.com"), ("repo", "https://github.com/x/poc")])
        self.assertIn("https://www.openssh.org/releasenotes.html#10.6p2", group["urls"])  # untagged: a key only

    def test_a_page_an_hn_story_linked_first_becomes_the_advisory_once_the_cve_record_tags_it(self):
        # SonicWall's PSIRT page came in as an HN story's link (a write-up), then the CVE record tagged it vendor-advisory.
        from collector.incidents import absorb
        psirt = "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0014"
        target = {"cves": [], "first_seen": "2026-11-07T00:00:00Z", "brief": {"text": "", "lead": psirt}, "urls": [],
                  "mentions": [{"kind": "discussion", "url": HN_STORY}, {"kind": "writeup", "url": psirt}]}
        record = {"cves": ["CVE-2026-19868"], "brief": {"text": "x", "lead": ""}, "urls": [],
                  "mentions": [{"kind": "cve_record", "url": "https://www.cve.org/CVERecord?id=CVE-2026-19868"},
                               {"kind": "advisory", "url": psirt}]}
        absorb(target, record)
        self.assertEqual([m["kind"] for m in target["mentions"]], ["discussion", "advisory", "cve_record"])
        self.assertEqual(target["brief"]["lead"], psirt)

    def test_the_records_own_cvss_is_used_cna_first_then_adp_and_v3_before_v4(self):
        from collector.cvelist import record_cvss
        self.assertEqual(record_cvss([{"metrics": [{"cvssV3_1": {"baseScore": 8.1}}]}, {}]), 8.1)  # sshole's CNA score
        self.assertEqual(record_cvss([{}, {"metrics": [{"cvssV3_1": {"baseScore": 7.5}}]}]), 7.5)  # CISA ADP only
        self.assertEqual(record_cvss([{"metrics": [{"cvssV4_0": {"baseScore": 9.3}}, {"cvssV3_1": {"baseScore": 8.8}}]}]), 8.8)
        self.assertIsNone(record_cvss([{"metrics": [{"other": {"content": {}}}]}]))

    def test_an_updated_record_is_read_only_for_a_cve_on_the_board(self):
        from collector import cvelist
        log = [{"fetchTime": "2026-11-08T04:00:00Z", "new": [], "updated": [
            {"cveId": "CVE-2026-123158", "githubLink": "https://raw.example/CVE-2026-123158.json"},
            {"cveId": "CVE-2019-1", "githubLink": "https://raw.example/CVE-2019-1.json"}]}]
        asked = []

        def get(url):
            asked.append(url)
            if url == cvelist.DELTA_LOG_URL:
                return json.dumps(log).encode()
            return (FIXTURES / "cvelist" / "CVE-2026-123158.json").read_bytes()

        records, _ = cvelist.fetch("2026-11-08T03:00:00Z", get, {"CVE-2026-123158"})
        self.assertEqual(asked[1:], ["https://raw.example/CVE-2026-123158.json"])
        self.assertEqual([r["cveMetadata"]["cveId"] for r in records], ["CVE-2026-123158"])


class LinkingTest(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.store.write("checkpoints.json", {"cvelist": "2026-11-06T09:00:00.000Z"})

    def incidents(self):
        return self.store.read("months/2026-11.json")["incidents"]

    def test_two_cves_named_in_one_advisory_are_one_row_and_stay_one(self):
        run_cycle(self.store, recorded("deltaLog-axis2.json"), at("2026-11-06T09:15:00"), "test-box")
        self.assertEqual([i["cves"] for i in self.incidents()], [["CVE-2026-123770"], ["CVE-2026-123766"]])

        run_cycle(self.store, recorded(None, oss="axis2-two-cves.rss"), at("2026-11-06T10:00:00"), "test-box")
        run_cycle(self.store, recorded(None, oss="axis2-two-cves.rss"), at("2026-11-06T10:15:00"), "test-box")

        [incident] = self.incidents()
        self.assertEqual(incident["cves"], ["CVE-2026-123770", "CVE-2026-123766"])
        self.assertEqual(
            [m["kind"] for m in incident["mentions"]], ["cve_record", "cve_record", "discussion"]
        )

    def test_merged_rows_keep_the_highest_cvss_and_all_products(self):
        run_cycle(self.store, recorded("deltaLog-axis2.json"), at("2026-11-06T09:15:00"), "test-box")
        month = self.store.read("months/2026-11.json")
        month["incidents"][0] |= {"cvss": 5.3, "products": [{"id": "apache:axis2", "name": "Axis2"}]}
        month["incidents"][1] |= {"cvss": 6.1, "products": [{"id": "apache:axis2_openapi", "name": "Axis2 Openapi"}]}
        self.store.write("months/2026-11.json", month)

        run_cycle(self.store, recorded(None, oss="axis2-two-cves.rss"), at("2026-11-06T10:00:00"), "test-box")

        [incident] = self.incidents()
        self.assertEqual(incident["cvss"], 6.1)
        self.assertEqual([p["id"] for p in incident["products"]], ["apache:axis2", "apache:axis2_openapi"])

    def test_an_hn_story_or_news_headline_naming_two_cves_does_not_merge_their_rows(self):
        # Audit item 6: anyone can submit an HN story whose URL names many CVEs; only a CVE record or an oss-security
        # advisory ties existing rows together (the Axis2 test above).
        from collector.incidents import link
        record = lambda cve: {"mentions": [{"kind": "cve_record", "url": f"https://www.cve.org/CVERecord?id={cve}"}],
                              "cves": [cve], "urls": [], "text": cve}
        story = {"mentions": [{"kind": "discussion", "url": "https://news.ycombinator.com/item?id=1", "title": "test"},
                              {"kind": "writeup", "url": "https://example.test/CVE-2026-0001/CVE-2026-0002"}],
                 "cves": ["CVE-2026-0001", "CVE-2026-0002"], "urls": [], "text": "test", "join_only": False}
        news = {"mentions": [{"kind": "writeup", "url": "https://www.bleepingcomputer.com/news/security/x/"}],
                "cves": ["CVE-2026-0002", "CVE-2026-0001"], "urls": [], "text": "x", "join_only": False}
        incidents = []
        link(incidents, record("CVE-2026-0001"), "2026-10-05T00:00:00Z")
        link(incidents, record("CVE-2026-0002"), "2026-11-05T00:00:00Z")
        link(incidents, story, "2026-11-06T00:00:00Z")
        link(incidents, news, "2026-11-06T00:15:00Z")
        self.assertEqual([i["cves"] for i in incidents], [["CVE-2026-0001"], ["CVE-2026-0002"]])
        self.assertNotIn("absorbed", incidents[0])
        self.assertIn("https://news.ycombinator.com/item?id=1", [m["url"] for m in incidents[0]["mentions"]])  # joins the earliest
        # A later record of the second CVE still finds only its own row.
        link(incidents, record("CVE-2026-0002"), "2026-11-06T00:30:00Z")
        self.assertEqual([i["cves"] for i in incidents], [["CVE-2026-0001"], ["CVE-2026-0002"]])

    def test_an_hn_story_naming_one_cve_still_merges_the_unassigned_row_into_it(self):
        # ADR 0001: an Unassigned incident is merged when its CVE lands, here through a story naming the CVE.
        from collector.incidents import link
        story = lambda n, cves: {"mentions": [{"kind": "discussion", "url": f"https://news.ycombinator.com/item?id={n}", "title": "t"},
                                              {"kind": "writeup", "url": "https://sshole.example/"}],
                                 "cves": cves, "urls": [], "text": "t", "join_only": False}
        record = {"mentions": [{"kind": "cve_record", "url": "https://www.cve.org/CVERecord?id=CVE-2026-123158"},
                               {"kind": "advisory", "url": "https://vendor.example/adv"}],
                  "cves": ["CVE-2026-123158"], "urls": [], "text": "rec"}
        incidents = []
        link(incidents, story(1, []), "2026-11-05T00:00:00Z")
        link(incidents, record, "2026-11-05T06:00:00Z")
        link(incidents, story(2, ["CVE-2026-123158"]), "2026-11-05T08:00:00Z")
        self.assertEqual([(i["id"], i["cves"]) for i in incidents],
                         [("https://news.ycombinator.com/item?id=1", ["CVE-2026-123158"])])

    def test_an_hn_story_naming_several_cves_attaches_none_that_its_row_lacks(self):
        # Audit item 6: else the named CVE's record joins that row, lends it its CVSS, and group_releases folds its
        # release's rows into it.
        from collector.incidents import group_releases, link
        record = lambda cve, fix_keys=(), cvss=None: {
            "mentions": [{"kind": "cve_record", "url": f"https://www.cve.org/CVERecord?id={cve}"}], "cves": [cve],
            "urls": [], "text": cve, "published": "2026-11-05T02:00:00Z",
            **({"fix_keys": list(fix_keys)} if fix_keys else {}), **({"cvss": cvss} if cvss else {})}
        story = lambda *cves: {"mentions": [{"kind": "discussion", "url": "https://news.ycombinator.com/item?id=9", "title": "t"},
                                            {"kind": "writeup", "url": "https://example.test/" + "/".join(cves)}],
                               "cves": list(cves), "urls": [], "text": "t", "join_only": False}
        incidents = []
        link(incidents, record("CVE-2026-1000", cvss=3.1), "2026-11-05T00:00:00Z")
        link(incidents, story("CVE-2026-1000", "CVE-2026-9999", "CVE-2026-2003"), "2026-11-05T01:00:00Z")
        self.assertEqual(incidents[0]["cves"], ["CVE-2026-1000"])
        link(incidents, record("CVE-2026-9999", cvss=10.0), "2026-11-05T02:00:00Z")
        for cve in ("CVE-2026-2001", "CVE-2026-2002", "CVE-2026-2003"):
            link(incidents, record(cve, ["acme:router<2.0"]), "2026-11-05T03:00:00Z")
        group_releases(incidents)
        self.assertEqual([(i["cves"], i.get("cvss")) for i in incidents],
                         [(["CVE-2026-1000"], 3.1), (["CVE-2026-9999"], 10.0),
                          (["CVE-2026-2001", "CVE-2026-2002", "CVE-2026-2003"], None)])

    def test_oss_security_posts_start_incidents_and_unmatched_replies_do_not(self):
        run_cycle(self.store, recorded(None, oss="oss-sec.rss"), at("2026-11-07T06:00:00"), "test-box")

        self.assertEqual(
            [(i["cves"], i["brief"]["text"], i["brief"]["lead"]) for i in self.incidents()],
            [
                (
                    ["CVE-2026-118196"],
                    "CVE-2026-118196: Apache Allura: OAuth1 rebinding",
                    "https://seclists.org/oss-sec/2026/q4/565",
                ),
                (
                    [],
                    "InfiniteWP Client: the NOSSL signing key has 31 bits of secret — recovered live in 291.9 seconds",
                    "https://seclists.org/oss-sec/2026/q4/563",
                ),
            ],
        )
        month = self.store.read("months/2026-11.json")
        run_cycle(self.store, recorded(None, oss="oss-sec.rss"), at("2026-11-07T06:15:00"), "test-box")
        self.assertEqual(self.store.read("months/2026-11.json"), month)


class SourceLimitTest(unittest.TestCase):
    """Each adapter stays inside its source's documented limit, even when the source has more."""

    def run_against(self, prefix, page, **cycle_args):
        clock, calls = [0.0], []
        others = recorded(None)

        def get(url, headers=None):
            if not url.startswith(prefix):
                return others(url, headers)
            calls.append((clock[0], headers))
            return page

        def sleep(seconds):
            clock[0] += seconds

        run_cycle(MemoryStore(), get, at("2026-11-07T12:00:00"), "test-box", sleep=sleep, **cycle_args)
        return calls

    def test_github_search_stays_under_30_per_minute_with_the_token(self):
        repo = {"full_name": "a/b", "html_url": "https://github.com/a/b", "created_at": "2026-11-07T11:00:00Z"}
        full_page = json.dumps({"items": [repo] * 100}).encode()

        calls = self.run_against("https://api.github.com/", full_page, github_token="test-token")

        times = [t for t, _ in calls]
        self.assertGreater(len(times), 1)
        for i, t in enumerate(times):
            self.assertLessEqual(sum(1 for u in times[i:] if u < t + 60), 30)
        self.assertGreaterEqual(min(b - a for a, b in zip(times, times[1:])), 60 / 30)
        self.assertTrue(all(h["Authorization"] == "Bearer test-token" for _, h in calls))

    def test_github_search_without_a_token_stays_under_10_per_minute(self):
        repo = {"full_name": "a/b", "html_url": "https://github.com/a/b", "created_at": "2026-11-07T11:00:00Z"}
        calls = self.run_against("https://api.github.com/", json.dumps({"items": [repo] * 100}).encode())

        times = [t for t, _ in calls]
        self.assertGreaterEqual(min(b - a for a, b in zip(times, times[1:])), 60 / 10)
        self.assertTrue(all("Authorization" not in h for _, h in calls))

    def test_hn_reads_at_most_ten_pages_a_cycle(self):
        # 10 requests per 15-minute cycle is 40/h, far under Algolia's 10,000/h per IP.
        calls = self.run_against("https://hn.algolia.com/", b'{"hits": [], "nbPages": 500}')

        self.assertEqual(len(calls), 10)


if __name__ == "__main__":
    unittest.main()


class ReleaseGroupTest(unittest.TestCase):
    """User, 11-09: more than two CVEs for the same product, fixed in the same version and published within 48 hours,
    are one Incident (OpenEMR 8.3.0 fixed a dozen at once and filled the Board)."""

    def record(self, product="openemr", less_than="8.3.0"):
        return {"containers": {"cna": {"affected": [{"vendor": "openemr", "product": product, "versions": [
            {"version": "0", "status": "affected", "lessThan": less_than}, {"version": less_than, "status": "unaffected"}]}]}}}

    def row(self, cve, published, key="openemr:openemr<8.3.0", cvss=7.1):
        return {"id": cve, "cves": [cve], "first_seen": "2026-11-08T22:30:00Z", "published": published, "cvss": cvss,
                "fix_keys": [key], "mentions": [{"kind": "cve_record", "url": f"https://www.cve.org/CVERecord?id={cve}"}],
                "urls": [], "brief": {"text": f"{cve} text", "lead": ""}}

    def test_the_fix_key_is_the_product_and_the_first_unaffected_version(self):
        from collector.cvelist import record_fix_keys
        self.assertEqual(record_fix_keys(self.record()), ["openemr:openemr<8.3.0"])
        self.assertEqual(record_fix_keys({"containers": {"cna": {"affected": [{"vendor": "a", "product": "b", "versions": [{"version": "1.0", "status": "affected"}]}]}}}), ["a:b<=1.0"])  # no range: the listed version

    def test_a_record_listing_each_affected_version_keys_on_the_last_one(self):
        # 11-09: VulDB records list 1.23.0 ... 1.23.49 one by one, with no lessThan, so FlowCI's three CVEs never grouped.
        from collector.cvelist import record_fix_keys
        listed = {"containers": {"cna": {"affected": [{"vendor": "FlowCI", "product": "flow-core-x", "versions":
                  [{"version": f"1.23.{n}", "status": "affected"} for n in (0, 2, 10, 9)]}]}}}
        self.assertEqual(record_fix_keys(listed), ["flowci:flow-core-x<=1.23.10"])
        ranged = {"containers": {"cna": {"affected": [{"vendor": "wpvibes", "product": "anywhere_elementor", "versions":
                  [{"version": "0", "lessThanOrEqual": "1.2.11", "status": "affected"}]}]}}}
        self.assertEqual(record_fix_keys(ranged), ["wpvibes:anywhere_elementor<=1.2.11"])

    def test_two_stay_apart_and_a_third_joins_them_into_one_incident(self):
        from collector.incidents import group_releases
        incidents = [self.row("CVE-2026-1", "2026-11-08T22:15:00Z"), self.row("CVE-2026-2", "2026-11-08T22:16:00Z")]
        self.assertEqual(group_releases(incidents), set())
        self.assertEqual(len(incidents), 2)
        incidents.append(self.row("CVE-2026-3", "2026-11-09T10:00:00Z", cvss=8.8))
        incidents.append(self.row("CVE-2026-4", "2026-11-08T22:17:00Z", key="openemr:openemr<8.4.0"))  # another fix version
        incidents.append(self.row("CVE-2026-5", "2026-11-11T09:00:00Z"))  # past 48 hours
        self.assertEqual(group_releases(incidents), {"2026-11"})
        group = incidents[0]
        self.assertEqual(group["cves"], ["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"])
        self.assertEqual(group["cvss"], 8.8)
        self.assertEqual(group["cve_texts"], {f"CVE-2026-{n}": f"CVE-2026-{n} text" for n in (1, 2, 3)})
        self.assertEqual([i["id"] for i in incidents], ["CVE-2026-1", "CVE-2026-4", "CVE-2026-5"])

    def test_each_cve_keeps_its_own_advisory_and_write_up_links_in_the_group(self):
        from collector.incidents import group_releases
        incidents = []
        for n in (1, 2, 3):
            row = self.row(f"CVE-2026-{n}", f"2026-11-08T22:1{n}:00Z")
            row["mentions"] += [{"kind": "advisory", "url": f"https://github.com/o/r/security/advisories/GHSA-{n}"},
                                {"kind": "writeup", "url": f"https://vulncheck.com/a/{n}"}]
            incidents.append(row)
        group_releases(incidents)
        self.assertEqual(incidents[0]["cve_links"]["CVE-2026-2"],
                         [{"kind": "advisory", "url": "https://github.com/o/r/security/advisories/GHSA-2"},
                          {"kind": "writeup", "url": "https://vulncheck.com/a/2"}])
        self.assertEqual(sorted(incidents[0]["cve_links"]), ["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"])

    def test_a_later_cve_of_the_same_release_joins_the_group(self):
        from collector.incidents import group_releases
        incidents = [self.row(f"CVE-2026-{n}", f"2026-11-08T22:1{n}:00Z") for n in (1, 2, 3)]
        group_releases(incidents)
        incidents.append(self.row("CVE-2026-6", "2026-11-09T20:00:00Z"))
        group_releases(incidents)
        self.assertEqual(len(incidents), 1)
        self.assertIn("CVE-2026-6", incidents[0]["cve_texts"])

