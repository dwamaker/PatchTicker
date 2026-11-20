"""Vendor advisory feeds (owner, 2026-11-19): Synology-SA-26:21 (DSM, CVSS 9.8) had no CVE record when Synology posted
it, so the Board missed it. The fixtures are the real Synology and Drupal core feeds of 2026-11-19, trimmed."""

import io
import json
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from test_cycle import at, incident, recorded
from test_summaries import board

from collector import cvelist, vendors
from collector.cycle import run_cycle
from collector.incidents import link, on_board
from collector.store import MemoryStore

FIXTURES = Path(__file__).parent / "fixtures"
SYNOLOGY, DRUPAL = vendors.FEEDS
FEEDS = {SYNOLOGY: (FIXTURES / "vendors" / "synology.rss").read_bytes(),
         DRUPAL: (FIXTURES / "vendors" / "drupal.rss").read_bytes()}
STAMP = "2026-11-19T12:00:00Z"
SA = "https://www.synology.com/en-global/support/security/Synology_SA_26_{}"  # the feed's guid and link
ADVISORY = "https://www.synology.com/en-global/security/advisory/Synology_SA_26_{}"  # what CVE records cite


# The advisory pages vendors.read_severity reads, trimmed to the lines that matter (the real pages of 2026-11-20 say
# "Severity Critical" and "Security risk: Critical 18 ∕ 25"). Any other page reads as an empty one.
PAGES = {ADVISORY.format(21): b"<html><body><main><h1>Synology-SA-26:21 DSM, BeeStation OS</h1><h3>Severity</h3>"
                              b"<p>Critical</p><h3>Status</h3><p>Resolved</p></main></body></html>",
         "https://www.drupal.org/sa-core-2026-017": "<html><body><main><h1>Drupal core - Critical - Remote code execution"
                                                    " - SA-CORE-2026-017</h1><p>Security risk: Critical 18 ∕ 25"
                                                    " AC:Complex/A:None</p></main></body></html>".encode()}


def get(url, headers=None):
    return FEEDS.get(url) or PAGES.get(url, b"<html></html>")


def all_ids():
    _, checkpoints = vendors.fetch(None, get, vendors.FEEDS, STAMP)
    return checkpoints


def unseen(*keys):
    """Checkpoints with every fixture item seen except these guids."""
    return {feed: [k for k in ids if k not in keys] for feed, ids in all_ids().items()}


def fetched(*keys):
    groups, _ = vendors.fetch(unseen(*keys), get, vendors.FEEDS, STAMP)
    return {g["mentions"][0]["url"]: g for g in groups}


class VendorFeedTest(unittest.TestCase):
    def test_an_own_advisory_is_an_advisory_group_at_the_link_cve_records_cite(self):
        group = fetched(SA.format(21))[ADVISORY.format(21)]
        self.assertEqual(group, {
            "mentions": [{"kind": "advisory", "url": ADVISORY.format(21), "title": "Synology-SA-26:21 DSM, BeeStation OS",
                          "severity": "critical"}],
            "cves": ["CVE-2026-120382"], "urls": [], "text": "Synology-SA-26:21 DSM, BeeStation OS", "join_only": False,
            "published": "2026-11-19T07:47:20Z"})

    def test_drupal_cves_come_from_the_html_description(self):
        group = fetched("3636972 at https://www.drupal.org")["https://www.drupal.org/sa-core-2026-017"]
        self.assertEqual((group["cves"], group["join_only"], group["mentions"][0]["kind"]), (["CVE-2026-132165"], False, "advisory"))
        self.assertEqual(group["published"], "2026-11-18T17:43:11Z")

    def test_the_severity_word_comes_from_the_advisory_page_never_the_feed_title(self):
        # Owner, 11-20: read once when the item is new, so a no-CVSS Critical row is an instant Summary candidate.
        self.assertEqual(fetched("3636972 at https://www.drupal.org")["https://www.drupal.org/sa-core-2026-017"]["mentions"][0]["severity"],
                         "critical")
        pages = []
        quiet = lambda url, headers=None: pages.append(url) or FEEDS.get(url) or b"<html><body><p>Fixed.</p></body></html>"
        groups, _ = vendors.fetch(unseen("3636972 at https://www.drupal.org", SA.format(16)), quiet, vendors.FEEDS, STAMP)
        self.assertEqual([g["mentions"][0].get("severity") for g in groups], [None, None])  # "Drupal core - Critical - ..."
        # A post on another project's flaw (SA-26:16, join only) is never fetched; the own advisory's page once.
        self.assertEqual([u for u in pages if u not in FEEDS], ["https://www.drupal.org/sa-core-2026-017"])

    def test_the_first_read_lets_the_last_days_through_and_records_the_rest(self):
        # owner, 11-19: SA-26:21 (posted that day, no CVE record yet) must reach the Board when the feed is first read
        groups, checkpoints = vendors.fetch({}, get, vendors.FEEDS, STAMP)
        self.assertEqual([(g["mentions"][0]["url"], g["join_only"]) for g in groups], [
            (ADVISORY.format(21), False), (ADVISORY.format(20), True),
            ("https://www.drupal.org/sa-core-2026-018", False), ("https://www.drupal.org/sa-core-2026-017", False)])
        self.assertTrue(all(g["published"] >= "2026-11-16T12:00:00Z" for g in groups))
        self.assertEqual(len(checkpoints[SYNOLOGY]), 5)
        self.assertEqual(checkpoints[DRUPAL], ["3623427 at https://www.drupal.org", "3637891 at https://www.drupal.org",
                                               "3636972 at https://www.drupal.org"])  # the old one first, then as read
        self.assertEqual(vendors.fetch(checkpoints, get, vendors.FEEDS, STAMP), ([], checkpoints))

    def test_a_first_read_long_after_the_last_post_starts_nothing(self):
        groups, checkpoints = vendors.fetch({}, get, vendors.FEEDS, "2026-12-01T00:00:00Z")
        self.assertEqual(groups, [])
        self.assertEqual((len(checkpoints[SYNOLOGY]), len(checkpoints[DRUPAL])), (5, 3))

    def test_only_unseen_items_are_built_and_then_recorded(self):
        before = unseen(SA.format(21))
        groups, after = vendors.fetch(before, get, vendors.FEEDS, STAMP)
        self.assertEqual([g["mentions"][0]["url"] for g in groups], [ADVISORY.format(21)])
        self.assertEqual(after[SYNOLOGY], before[SYNOLOGY] + [SA.format(21)])
        self.assertEqual(after[DRUPAL], before[DRUPAL])

    def test_other_projects_flaws_only_join_as_discussion(self):
        groups = fetched(SA.format(16), SA.format(17), SA.format(20), "3623427 at https://www.drupal.org")
        sshole = groups[ADVISORY.format(16)]  # "None of Synology's products are affected by CVE-2026-123158."
        self.assertEqual((sshole["join_only"], sshole["mentions"][0]["kind"], sshole["cves"]), (True, "discussion", ["CVE-2026-123158"]))
        self.assertTrue(groups[ADVISORY.format(17)]["join_only"])  # Plex Media Server (Plex2Shell), no CVE ID
        self.assertTrue(groups[ADVISORY.format(20)]["join_only"])  # NGINX2Root
        self.assertNotIn("https://www.drupal.org/sa-core-2026-013", groups)  # Third-party libraries, but September: too old

    def test_a_cve_less_own_advisory_may_start(self):
        group = fetched(SA.format(18))[ADVISORY.format(18)]
        self.assertEqual((group["cves"], group["join_only"]), ([], False))

    def test_an_item_older_than_max_age_starts_nothing_but_is_recorded(self):
        old = "3623427 at https://www.drupal.org"  # SA-CORE-2026-013, 2026-09-16
        groups, after = vendors.fetch(unseen(old), get, vendors.FEEDS, STAMP)
        self.assertEqual(groups, [])
        self.assertIn(old, after[DRUPAL])
        third_party = vendors.mention_group(next(i for i in vendors.ET.fromstring(FEEDS[DRUPAL]).iter("item")
                                                 if "2026-013" in i.findtext("title")), vendors.FEEDS[DRUPAL])
        self.assertTrue(third_party["join_only"])

    def test_a_dead_or_empty_feed_keeps_its_checkpoint(self):
        def dead(url, headers=None):
            raise OSError("down")
        empty = lambda url, headers=None: b"<rss><channel></channel></rss>"
        for answer in (dead, empty):
            with self.subTest(answer), redirect_stderr(io.StringIO()):
                self.assertEqual(vendors.fetch({SYNOLOGY: ["x"]}, answer, vendors.FEEDS, STAMP), ([], {SYNOLOGY: ["x"]}))
                self.assertEqual(vendors.fetch({}, answer, vendors.FEEDS, STAMP), ([], {}))  # no first read recorded

    def test_a_bad_item_is_skipped_and_read_again_next_cycle(self):
        feed = (b"<rss><channel><item><title>Drupal core - Critical - X - SA-CORE-2026-099</title><guid>9</guid>"
                b"<link>https://www.drupal.org/sa-core-2026-099</link><pubDate>not a date</pubDate></item></channel></rss>")
        with redirect_stderr(io.StringIO()):
            groups, after = vendors.fetch({DRUPAL: []}, lambda url, headers=None: feed, {DRUPAL: vendors.FEEDS[DRUPAL]}, STAMP)
        self.assertEqual((groups, after), ([], {DRUPAL: []}))


class VendorLinkTest(unittest.TestCase):
    """Through incidents.link, as the cycle does."""

    def test_a_cve_less_advisory_starts_an_incident_on_the_board_and_the_cve_record_joins_it_later(self):
        incidents = []
        link(incidents, fetched(SA.format(18))[ADVISORY.format(18)], STAMP)
        self.assertEqual([i["id"] for i in incidents], [ADVISORY.format(18)])
        self.assertTrue(on_board(incidents[0]))
        record = json.loads((FIXTURES / "cvelist" / "CVE-2026-13672.json").read_bytes())  # cites SA_26_18
        for group in cvelist.mention_groups([record]):
            link(incidents, group, "2026-11-20T00:00:00Z")
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["cves"], ["CVE-2026-13672"])
        self.assertEqual(incidents[0]["brief"]["lead"], ADVISORY.format(18))

    def test_a_cve_less_advisory_joins_the_incident_whose_record_cites_it(self):
        incidents = []
        record = json.loads((FIXTURES / "cvelist" / "CVE-2026-13672.json").read_bytes())
        for group in cvelist.mention_groups([record]):
            link(incidents, group, STAMP)
        before = [m["url"] for m in incidents[0]["mentions"]]
        link(incidents, fetched(SA.format(18))[ADVISORY.format(18)], STAMP)
        self.assertEqual(len(incidents), 1)
        self.assertEqual([m["url"] for m in incidents[0]["mentions"]], before)  # the same page, not a second Mention

    def test_the_severity_word_survives_joining_the_page_a_record_cited_first(self):
        incidents = [incident("CVE-2026-120382", "DSM ...", "2026-11-19T10:00:00Z", published="2026-11-19T10:00:00Z")]
        incidents[0]["mentions"].append({"kind": "writeup", "url": ADVISORY.format(21)})
        link(incidents, fetched(SA.format(21))[ADVISORY.format(21)], STAMP)
        self.assertEqual([m.get("severity") for m in incidents[0]["mentions"] if m["url"] == ADVISORY.format(21)], ["critical"])

    def test_an_advisory_with_a_cve_joins_that_incident_and_leads_it(self):
        incidents = [incident("CVE-2026-120382", "DSM ...", "2026-11-19T10:00:00Z", published="2026-11-19T10:00:00Z")]
        link(incidents, fetched(SA.format(21))[ADVISORY.format(21)], STAMP)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["brief"]["lead"], ADVISORY.format(21))
        self.assertEqual(incidents[0]["published"], "2026-11-19T07:47:20Z")  # Synology posted first

    def test_not_affected_joins_the_flaws_incident_as_discussion_and_never_starts_one(self):
        group = fetched(SA.format(16))[ADVISORY.format(16)]
        incidents = []
        link(incidents, group, STAMP)
        self.assertEqual(incidents, [])
        sshole = incident("CVE-2026-123158", "OpenSSH sshd ...", "2026-11-06T00:46:00Z")
        incidents = [sshole]
        link(incidents, group, STAMP)
        self.assertIn({"kind": "discussion", "url": ADVISORY.format(16), "title": "Synology-SA-26:16 OpenSSH (sshole)"},
                      sshole["mentions"])
        self.assertEqual(sshole["brief"]["lead"], "https://www.cve.org/CVERecord?id=CVE-2026-123158")

    def test_the_cycle_puts_new_vendor_advisories_on_the_board_with_or_without_a_cve(self):
        store = MemoryStore()
        store.write("checkpoints.json", {"vendors": unseen(SA.format(21), SA.format(18))})
        answer = recorded(None, unpublished=("CVE-2026-120382",))
        run_cycle(store, lambda url, headers=None: FEEDS[url] if url in FEEDS else answer(url, headers),
                  at("2026-11-19T12:00:00"), "test-box", vendor_feeds=vendors.FEEDS)
        rows = board(store)
        self.assertEqual(sorted(rows), ["CVE-2026-120382", ADVISORY.format(18)])
        self.assertEqual(rows["CVE-2026-120382"]["brief"]["lead"], ADVISORY.format(21))
        self.assertTrue(on_board(rows[ADVISORY.format(18)]))
        self.assertTrue({SA.format(21), SA.format(18)} <= set(store.read("checkpoints.json")["vendors"][SYNOLOGY]))

    def test_synology_own_products_start_and_packaged_projects_only_join(self):
        own = vendors.FEEDS[SYNOLOGY]["own"]
        for title in ("Synology-SA-26:21 DSM, BeeStation OS", "Synology-SA-25:07 SMB Service", "Synology-SA-24:25 Surveillance Station",
                      "Synology-SA-24:11 Synology Active Backup for Business Agent", "Synology-SA-23:01 MailPlus Server", "Synology-SA-20:01 VS960HD"):
            self.assertTrue(own.search(title), title)
        for title in ("Synology-SA-26:17 Plex Media Server (Plex2Shell)", "Synology-SA-26:20 NGINX2Root", "Synology-SA-22:20 Samba",
                      "Synology-SA-24:12 GitLab", "Synology-SA-26:09 Linux Kernel (Dirty Frag)", "Synology-SA-21:10 Apache HTTP Server"):
            self.assertFalse(own.search(title), title)


if __name__ == "__main__":
    unittest.main()
