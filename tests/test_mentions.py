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
        from collector.summary_input import is_hn
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

    def story(self, page, url="https://sunshowers.io/posts/sshole/", item=50399400):
        from collector.incidents import page_keys
        return {"mentions": [{"kind": "discussion", "url": f"https://news.ycombinator.com/item?id={item}"},
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

    def test_a_page_linking_a_page_another_incident_also_links_stands_alone(self):
        self.link(self.incidents, {"mentions": [{"kind": "cve_record", "url": "https://www.cve.org/CVERecord?id=CVE-2026-8888"}],
                                   "cves": ["CVE-2026-8888"], "urls": ["https://other.example/post"], "text": "x"}, "2026-11-06T00:00:00Z")
        self.link(self.incidents, self.story('<a href="https://other.example/post">post</a>'), "2026-11-08T03:00:00Z")
        self.assertEqual(self.rejoin(), set())
        self.assertEqual(len(self.incidents), 4)

    def test_a_page_linking_a_vendors_list_of_advisories_stands_alone_and_one_notice_still_joins(self):
        for cve, url in (("CVE-2026-8888", "https://www.asus.com/security-advisory"),
                         ("CVE-2026-7777", "https://www.asus.com/content/asus-security-advisory-2026-11/")):
            self.link(self.incidents, {"mentions": [{"kind": "cve_record", "url": f"https://www.cve.org/CVERecord?id={cve}"},
                                                    {"kind": "advisory", "url": url}], "cves": [cve], "urls": [], "text": cve},
                      "2026-11-06T00:00:00Z")
        self.link(self.incidents, self.story('<a href="https://www.asus.com/security-advisory">list</a>'), "2026-11-08T03:00:00Z")
        self.assertEqual(self.rejoin(), set())
        self.link(self.incidents, self.story('<a href="https://www.asus.com/content/asus-security-advisory-2026-11/">one</a>',
                                             "https://blog.example/asus", 50399401), "2026-11-08T03:00:00Z")
        self.rejoin()
        self.assertIn("https://blog.example/asus", [m["url"] for m in self.incidents[3]["mentions"]])
        self.assertEqual(len(self.incidents), 5)

    def test_a_page_naming_one_incidents_cve_next_to_another_incidents_list_page_stands_alone(self):
        self.link(self.incidents, {"mentions": [{"kind": "cve_record", "url": "https://www.cve.org/CVERecord?id=CVE-2026-8888"},
                                                {"kind": "advisory", "url": "https://www.asus.com/security-advisory"}],
                                   "cves": ["CVE-2026-8888"], "urls": [], "text": "x"}, "2026-11-06T00:00:00Z")
        self.link(self.incidents, self.story('CVE-2026-9999 <a href="https://www.asus.com/security-advisory">list</a>'),
                  "2026-11-08T03:00:00Z")
        self.assertEqual(self.rejoin(), set())
        self.assertEqual(len(self.incidents), 4)

    def test_a_page_naming_a_cve_only_in_its_related_posts_cards_stands_alone(self):
        apache = {"mentions": [{"kind": "cve_record", "url": "https://www.cve.org/CVERecord?id=CVE-2026-119618"}],
                  "cves": ["CVE-2026-119618"], "urls": [], "text": "x"}
        self.link(self.incidents, apache, "2026-11-06T00:00:00Z")
        url = "https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories"
        page = (FIXTURES / "pages" / "aikido-wfx-loot.html").read_text(encoding="utf-8")  # HN 50462319, folded into Brotli on 11-12
        self.link(self.incidents, self.story(page, url, 50462319), "2026-11-12T03:00:00Z")
        self.assertEqual(self.incidents[3]["cites"]["cves"], [])
        self.assertEqual(self.rejoin(), set())

    def test_a_cve_in_the_text_in_a_link_elsewhere_or_as_a_links_whole_text_is_cited_not_one_only_a_sibling_page_names(self):
        from collector.incidents import page_keys
        page = ('<p>A flaw, CVE-2026-1001, and <a href="https://nvd.nist.gov/vuln/detail/cve-2026-1002">its NVD entry</a>.</p>'
                '<a href="/security/CVE-2026-1003">CVE-2026-1003</a>'
                '<div class="card"><h2>CVE-2026-1004 explained</h2><a href="/blog/cve-2026-1004-explained"></a></div>'
                '<ul class="sidebar"><li><a href="/notices/USN-2">USN-2: CVE-2026-1005 in the login</a></li></ul>')
        self.assertCountEqual(page_keys(page, "https://ubuntu.com/security/notices/USN-1")["cves"],
                              ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"])
        own = '<p>We analysed CVE-2026-1006.</p><a href="/blog/cve-2026-1006-rce/?share=x">share</a>'  # a page links itself
        self.assertEqual(page_keys(own, "https://blog.example.org/blog/cve-2026-1006-rce/")["cves"], ["CVE-2026-1006"])

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

    def record_mentions(self, cve):
        from collector import cvelist
        record = json.loads((FIXTURES / "cvelist" / f"{cve}.json").read_bytes())
        return [(m["kind"], m["url"]) for m in cvelist.mention_group(record)["mentions"][1:]]

    def test_an_untagged_link_on_the_vendors_own_site_is_an_advisory_when_the_vendor_wrote_the_record(self):
        self.assertEqual(self.record_mentions("CVE-2026-13672"),  # Synology tags nothing
                         [("advisory", "https://www.synology.com/en-global/security/advisory/Synology_SA_26_18")])

    def test_zdis_research_advisory_tag_makes_a_writeup(self):
        self.assertEqual(self.record_mentions("CVE-2026-118631"), [("writeup", "https://www.zerodayinitiative.com/advisories/ZDI-26-890/")])

    def test_githubs_confirm_tag_makes_an_advisory_and_its_commit_and_release_stay_keys(self):
        self.assertEqual(self.record_mentions("CVE-2026-67540"),  # CISA's ADP tags the same page exploit: still one advisory
                         [("advisory", "https://github.com/heymrun/heym/security/advisories/GHSA-5748-x76g-v68m")])

    def test_a_coordinators_record_takes_the_vendors_site_as_advisory_and_its_own_as_a_writeup(self):
        # JPCERT/CC for Six Apart: movabletype.org is the product's site, not the vendor's name, so it stays a key.
        self.assertEqual(self.record_mentions("CVE-2026-117687"),
                         [("advisory", "https://www.sixapart.jp/movabletype/news/2026/11/11-1100.html"),
                          ("writeup", "https://jvn.jp/en/jp/JVN11786640/")])

    def test_a_bug_tracker_entry_on_the_vendors_own_site_is_a_writeup(self):
        # Eclipse's GitLab work item: outsiders write there. The GHSA on github.com is not Eclipse's site: a key only.
        self.assertEqual(self.record_mentions("CVE-2026-114408"), [("writeup", "https://gitlab.eclipse.org/security/cve-assignment/-/work_items/482")])

    def test_tracker_and_code_review_pages_are_writeups_and_an_encoded_space_is_no_id(self):
        from collector import cvelist
        def kinds(cna, vendor, *refs):
            record = {"cveMetadata": {"cveId": "CVE-2026-1", "assignerShortName": cna},
                      "containers": {"cna": {"affected": [{"vendor": vendor, "product": "X"}], "references": list(refs)}}}
            return [(m["kind"], m["url"]) for m in cvelist.mention_group(record)["mentions"][1:]]
        # Firefox's memory-safety records (CVE-2024-9401) and Wikimedia's (CVE-2025-23072) link these untagged.
        for url in ("https://bugzilla.mozilla.org/buglist.cgi?bug_id=1872744%2C1897792", "https://phabricator.wikimedia.org/T378885",
                    "https://gerrit.wikimedia.org/r/q/Ic9547e80a8296d707ad8a157eb8ba7aa26fb08dc"):
            self.assertEqual(kinds("mozilla" if "mozilla" in url else "wikimedia-foundation",
                                   "Mozilla" if "mozilla" in url else "Wikimedia Foundation", {"url": url}), [("writeup", url)])
        esa = "https://discuss.elastic.co/t/kibana-security-update-esa-2026-203/391357"  # a Discourse topic shows anyone's replies
        self.assertEqual(kinds("elastic", "Elastic", {"url": esa}), [("writeup", esa)])
        bug = "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-10160"  # tagged CONFIRM in a MITRE-format record
        self.assertEqual(kinds("redhat", "Red Hat", {"url": bug, "tags": ["x_refsource_CONFIRM"]}), [("writeup", bug)])
        self.assertEqual(kinds("redhat", "Red Hat", {"url": bug, "tags": ["vendor-advisory"]}), [("advisory", bug)])
        self.assertEqual(kinds("arm", "Arm Ltd", {"url": "https://developer.arm.com/Arm%20Security%20Center/Mali"}), [])  # CVE-2024-4610

    def test_a_reference_whose_tags_are_null_still_gives_its_record_a_mention_group(self):
        from collector import cvelist
        record = {"cveMetadata": {"cveId": "CVE-2026-1", "assignerShortName": "synology"},
                  "containers": {"cna": {"affected": [{"vendor": "Synology", "product": "DSM"}],
                                         "references": [{"url": "https://www.synology.com/security/advisory/Synology_SA_26_18", "tags": None}]},
                                 "adp": [{"references": [{"url": "https://example.org/poc/1", "tags": None}]}]}}
        groups = cvelist.mention_groups([record])
        self.assertEqual([(m["kind"], m["url"]) for m in groups[0]["mentions"]],
                         [("cve_record", "https://www.cve.org/CVERecord?id=CVE-2026-1"),
                          ("advisory", "https://www.synology.com/security/advisory/Synology_SA_26_18")])

    def test_a_vendor_list_page_with_no_id_in_its_address_is_not_promoted(self):
        self.assertEqual(self.record_mentions("CVE-2026-112116"), [])  # ASUS: www.asus.com/security-advisory

    def test_a_vendor_link_the_cna_tagged_otherwise_is_not_promoted(self):
        # OpenSSL tags its commitdiff links "patch": they stay keys; the tagged advisory is the only one.
        self.assertEqual(self.record_mentions("CVE-2023-0286"), [("advisory", "https://www.openssl.org/news/secadv/20230207.txt")])

    def test_a_cna_filing_for_another_vendor_gives_its_links_no_advisory(self):
        self.assertEqual(self.record_mentions("CVE-2026-105606"), [])  # the Joomla CNA for joomlaboat.com's extension

    def test_the_vendor_and_its_site_match_in_whole_words_only(self):
        from collector import cvelist
        def advisories(assigner, vendor, url):
            record = {"cveMetadata": {"cveId": "CVE-2026-1", "assignerShortName": assigner},
                      "containers": {"cna": {"affected": [{"vendor": vendor, "product": "X"}], "references": [{"url": url}]}}}
            return [m["url"] for m in cvelist.mention_group(record)["mentions"] if m["kind"] == "advisory"]
        self.assertEqual(advisories("hp", "HP Inc.", "https://support.hp.com/a1"), ["https://support.hp.com/a1"])
        self.assertEqual(advisories("hp", "HP Inc.", "https://www.php.net/a1"), [])
        self.assertEqual(advisories("redhat", "Red Hat", "https://access.redhat.com/a1"), ["https://access.redhat.com/a1"])
        self.assertEqual(advisories("acme", "Acme Corp", "https://acme.co.jp/a1"), ["https://acme.co.jp/a1"])
        self.assertEqual(advisories("acme", "Acme Corp", "https://acme.evil.example/a1"), [])
        self.assertEqual(advisories("joomla", "Joomla Bamboo", "https://joomla.org/a1"), [])  # a CNA name inside the vendor's is not the vendor
        self.assertEqual(advisories("vuldb", "Acme", "https://acme.com/a1"), [])  # a third-party CNA
        self.assertEqual(advisories("sonicwall", "SonicWall", "https://sonic-wall.com/a1"), [])  # a look-alike site

    def test_a_cna_paired_with_the_vendor_name_it_files_under_counts_as_that_vendor_on_its_own_site_only(self):
        # Owner, 11-15: HPE writes "Hewlett Packard Enterprise (HPE)", Intel "n/a"; neither is its CNA name in whole words.
        from collector import cvelist
        def advisories(assigner, vendor, url):
            record = {"cveMetadata": {"cveId": "CVE-2026-1", "assignerShortName": assigner},
                      "containers": {"cna": {"affected": [{"vendor": vendor, "product": "X"}], "references": [{"url": url}]}}}
            return [m["url"] for m in cvelist.mention_group(record)["mentions"] if m["kind"] == "advisory"]
        hpe = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw05172en_us"
        self.assertEqual(advisories("hpe", "Hewlett Packard Enterprise (HPE)", hpe), [hpe])
        intel = "https://intel.com/content/www/us/en/security-center/advisory/intel-sa-01440.html"
        self.assertEqual(advisories("intel", "n/a", intel), [intel])
        self.assertEqual(advisories("hpe", "Aruba Networks", hpe), [])  # a vendor name not in its pair
        self.assertEqual(advisories("hpe", "Hewlett Packard Enterprise", hpe), [])  # matched exactly, as the records write it
        self.assertEqual(advisories("hpe", "Hewlett Packard Enterprise (HPE)", "https://example.com/advisory/1"), [])  # not its site
        self.assertEqual(advisories("acme", "n/a", "https://acme.com/a1"), [])  # "n/a" counts only for the CNAs paired with it

    def test_a_vendor_advisory_tag_outranks_a_confirm_tag_and_a_known_tag_elsewhere_outranks_the_vendors_site(self):
        from collector import cvelist
        # Log4j's record (CVE-2021-45046) lists SonicWall's note as CONFIRM before Cisco's vendor-advisory.
        record = {"cveMetadata": {"cveId": "CVE-2026-1", "assignerShortName": "eclipse"},
                  "containers": {"cna": {"affected": [{"vendor": "Eclipse Foundation", "product": "X"}],
                                         "references": [{"url": "https://psirt.sonicwall.com/a", "tags": ["x_refsource_CONFIRM"]},
                                                        {"url": "https://tools.cisco.com/a", "tags": ["vendor-advisory"]},
                                                        {"url": "https://gitlab.eclipse.org/report/1"}]},
                                 "adp": [{"references": [{"url": "https://gitlab.eclipse.org/report/1", "tags": ["exploit"]}]}]}}
        self.assertEqual([(m["kind"], m["url"]) for m in cvelist.mention_group(record)["mentions"][1:]],
                         [("advisory", "https://tools.cisco.com/a"), ("advisory", "https://psirt.sonicwall.com/a"),
                          ("writeup", "https://gitlab.eclipse.org/report/1")])

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

    def test_a_range_written_into_the_version_string_keys_on_the_bound_it_states(self):
        # 11-15: GitHub's records write "< 1.4.5" as the version; the key was "bacnet-stack:bacnet-stack<=< 1.6.0".
        from collector.cvelist import record_fix_keys
        record = lambda cve: json.loads((FIXTURES / "cvelist" / f"{cve}.json").read_bytes())
        self.assertEqual(record_fix_keys(record("CVE-2026-67540")), ["heymrun:heym<0.0.70"])
        self.assertEqual(record_fix_keys(record("CVE-2026-52786")),
                         ["bacnet-stack:bacnet-stack<1.4.5", "bacnet-stack:bacnet-stack<1.5.1", "bacnet-stack:bacnet-stack<1.6.0"])
        for version, key in ((">= 8.0.0, < 8.10.2", "a:b<8.10.2"), ("before version v5.4.2.1", "a:b<5.4.2.1"),
                             ("All driver versions prior to 615.71.09", "a:b<615.71.09"), ("<= 7.0.0", "a:b<=7.0.0"),
                             (">= 0.11.0, <= 0.16.0", "a:b<=0.16.0"), ("= 1.27.0", "a:b<=1.27.0"),
                             ("25.05.0 through 25.05.8", "a:b<=25.05.8"), ("11.13.1 and earlier", "a:b<=11.13.1"),
                             (">= 6.7.0", "a:b<=>= 6.7.0"), ("Versions prior to latest one", "a:b<=Versions prior to latest one")):
            listed = {"containers": {"cna": {"affected": [{"vendor": "a", "product": "b", "versions": [{"version": version, "status": "affected"}]}]}}}
            self.assertEqual(record_fix_keys(listed), [key], version)

    def test_a_fixed_version_below_bacnets_stated_bound_is_rejected_and_the_fix_itself_passes(self):
        # 11-15: a re-summary of CVE-2026-52786 said "update to 1.4.4"; the record says 1.4.5, 1.5.1 and 1.6.0 fix it.
        from collector import cvelist, summaries
        group = cvelist.mention_group(json.loads((FIXTURES / "cvelist" / "CVE-2026-52786.json").read_bytes()))
        incident = {"fix_keys": group["fix_keys"]}
        self.assertIn("1.4.4 is below 1.4.5", summaries.fixed_conflict(incident, {"fixed": "1.4.4"}))
        for fixed in ("1.4.5", "1.5.1", "1.6.0"):
            self.assertEqual(summaries.fixed_conflict(incident, {"fixed": fixed}), "", fixed)

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

