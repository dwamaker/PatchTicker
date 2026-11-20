"""The six vendor feeds added on 2026-11-20 (Fortinet, Palo Alto Networks, Grafana, SonicWall, Sophos, Chrome stable).
The fixtures are the real feeds fetched at 09:31 UTC that day, trimmed to a few items; the advisory pages below are the
real pages of that day cut to the lines that matter."""

import copy
import io
import unittest
from contextlib import redirect_stderr
from unittest import mock
from pathlib import Path

from test_cycle import incident

from collector import vendors
from collector.incidents import group_releases, link, url_key

FIXTURES = Path(__file__).parent / "fixtures" / "vendors"
FORTINET, PALO_ALTO, GRAFANA, SONICWALL, SOPHOS, CHROME = list(vendors.FEEDS)[2:]
FEEDS = {FORTINET: "fortinet.rss", PALO_ALTO: "paloalto.rss", GRAFANA: "grafana.rss", SONICWALL: "sonicwall.json",
         SOPHOS: "sophos.rss", CHROME: "chrome.atom"}
FEEDS = {url: (FIXTURES / name).read_bytes() for url, name in FEEDS.items()}
SIX = {feed: vendors.FEEDS[feed] for feed in FEEDS}
CSAF = "https://filestore.fortinet.com/fortiguard/psirt/csaf_unauthenticated-adjacent-command-execution-via-ha_fg-ir-26-273.json"
STAMP = "2026-11-20T09:00:00Z"  # the hour's first mark: the hourly feeds are read
FG = "https://fortiguard.fortinet.com/psirt/FG-IR-26-{}"
POST_158 = "https://chromereleases.googleblog.com/2026/11/stable-channel-update-for-desktop_01699533288.html"
POST_157 = "https://chromereleases.googleblog.com/2026/11/stable-channel-update-for-desktop_01744469280.html"
PAGES = {
    CSAF: (FIXTURES / "fortinet-csaf-fg-ir-26-273.json").read_bytes(),
    # Fortinet's page: "Severity Critical" under its label; Palo Alto's: "Severity 6.6 · MEDIUM", then "Severity: MEDIUM".
    FG.format(273): b"<html><body><main><h1>Unauthenticated adjacent command execution via HA</h1><p>Updated Date Nov 16,"
                    b" 2026</p><p>Severity</p><p>Critical</p><p>CVSSv3 Score 9.0</p></main></body></html>",
    "https://security.paloaltonetworks.com/CVE-2026-0331": "<html><body><main><h1>CVE-2026-0331 PAN-OS: Sensitive "
        "Information Disclosure Vulnerability</h1><p>Urgency MODERATE</p><p>Severity 6.6 · MEDIUM</p><p>Published"
        " 2026-11-11</p><p>Updated 2026-11-11</p><p>Severity: MEDIUM, Suggested Urgency: MODERATE</p></main></body></html>".encode(),
    # CVE-2026-0250's page: a May advisory revised on Nov 10, which the feed dates Nov 10.
    "https://security.paloaltonetworks.com/CVE-2026-0250": "<html><body><main><h1>CVE-2026-0250 GlobalProtect App: Buffer "
        "Overflow Vulnerability during connection to Portal or Gateway</h1><p>Severity 5.9 · MEDIUM</p><p>Published"
        " 2026-05-13</p><p>Updated 2026-11-10</p><p>Timeline</p><p>2026-11-10 Updated</p><p>2026-05-13 Initial Publication"
        "</p></main></body></html>".encode(),
}


def get(url, headers=None):
    return FEEDS.get(url) or PAGES.get(url, b"<html></html>")


def unseen(*keys):
    """Checkpoints with every fixture item seen except these ids."""
    ids = {f: [e["id"] for e in vendors.FEEDS[f].get("read", vendors.rss_entries)(body)] for f, body in FEEDS.items()}
    return {f: [k for k in found if k not in keys] for f, found in ids.items()}


def fetched(*keys, answer=get, stamp=STAMP):
    with redirect_stderr(io.StringIO()):
        groups, _ = vendors.fetch(unseen(*keys), answer, SIX, stamp)
    return {g["mentions"][0]["url"]: g for g in groups}


class SixFeedsTest(unittest.TestCase):
    def test_fortinet_own_advisory_gets_its_cve_from_the_csaf_file_and_its_first_seen_time(self):
        group = fetched(FG.format(273))[FG.format(273)]  # the feed's /psirt/cvrf/ link, as CVE records cite it
        self.assertEqual(group, {
            "mentions": [{"kind": "advisory", "url": FG.format(273), "title": "Unauthenticated adjacent command execution via HA",
                          "severity": "critical"}],
            "cves": ["CVE-2026-126259"], "urls": [], "text": "Unauthenticated adjacent command execution via HA",
            "join_only": False, "published": STAMP})  # not "Tue, 10 Nov 2026 00:00:00 -0800": the feed gives only a day

    def test_fortinet_restating_another_projects_flaw_only_joins_and_fetches_nothing(self):
        pages = []
        answer = lambda url, headers=None: pages.append(url) or get(url)
        group = fetched(FG.format(278), answer=answer)[FG.format(278)]
        self.assertEqual((group["join_only"], group["mentions"][0]["kind"], group["cves"]), (True, "discussion", ["CVE-2026-114938"]))
        self.assertEqual([u for u in pages if u not in FEEDS], [])

    def test_fortinet_without_its_csaf_file_starts_keyed_by_its_link(self):
        dead = lambda url, headers=None: (_ for _ in ()).throw(OSError("down")) if url == CSAF else get(url)
        group = fetched(FG.format(273), answer=dead)[FG.format(273)]
        self.assertEqual((group["cves"], group["join_only"]), ([], False))

    def test_palo_alto_iso_dates_and_own_products(self):
        groups = fetched(*[f"https://security.paloaltonetworks.com/{k}" for k in ("CVE-2026-114938", "CVE-2026-0331", "PAN-SA-2026-0014")])
        own = groups["https://security.paloaltonetworks.com/CVE-2026-0331"]
        self.assertEqual((own["join_only"], own["cves"], own["published"]), (False, ["CVE-2026-0331"], "2026-11-11T17:00:00Z"))
        self.assertEqual(own["mentions"][0]["severity"], "medium")  # from its page
        self.assertTrue(groups["https://security.paloaltonetworks.com/CVE-2026-114938"]["join_only"])  # Portfolio Status: Java
        self.assertTrue(groups["https://security.paloaltonetworks.com/PAN-SA-2026-0014"]["join_only"])  # Chromium update

    def test_palo_alto_an_old_advisory_revised_back_into_the_feed_only_joins(self):
        # 11-20: the feed dates CVE-2026-0250 Nov 10; its page says "Published 2026-05-13 Updated 2026-11-10".
        groups = fetched("https://security.paloaltonetworks.com/CVE-2026-0250", "https://security.paloaltonetworks.com/CVE-2026-0331")
        revised = groups["https://security.paloaltonetworks.com/CVE-2026-0250"]
        self.assertEqual((revised["join_only"], revised["mentions"][0]["kind"]), (True, "advisory"))
        rows = []
        link(rows, revised, STAMP)
        self.assertEqual(rows, [])  # starts nothing; with its May row kept, it would join and lead it
        rows = [incident("CVE-2026-0250", "A buffer overflow ...", "2026-05-13T20:00:00Z")]
        link(rows, revised, STAMP)
        self.assertEqual(rows[0]["brief"]["lead"], "https://security.paloaltonetworks.com/CVE-2026-0250")
        self.assertFalse(groups["https://security.paloaltonetworks.com/CVE-2026-0331"]["join_only"])  # a new PAN-OS one starts

    def test_per_item_reads_use_the_short_get_and_a_timeout_costs_only_the_severity(self):
        plain, short = [], []

        def answer(url, headers=None):
            plain.append(url)
            return get(url)

        def timeout(url, headers=None):
            short.append(url)
            raise OSError("no full answer within 15 s")

        answer.short = timeout
        groups = fetched(FG.format(273), "https://security.paloaltonetworks.com/CVE-2026-0331", answer=answer)
        self.assertEqual(sorted(short), sorted([CSAF, FG.format(273), "https://security.paloaltonetworks.com/CVE-2026-0331"]))
        self.assertTrue(set(plain) <= set(FEEDS))
        self.assertEqual([(g["join_only"], g["mentions"][0].get("severity")) for g in groups.values()], [(False, None), (False, None)])

    def test_a_patch_day_is_read_a_few_advisories_per_cycle_and_none_is_lost(self):
        pages = []
        answer = lambda url, headers=None: pages.append(url) or get(url)
        checkpoints = unseen(FG.format(278), FG.format(188), FG.format(273), FG.format(268))
        read = []
        with mock.patch.object(vendors, "MAX_READS", 1), redirect_stderr(io.StringIO()):
            for _ in range(3):
                groups, checkpoints = vendors.fetch(checkpoints, answer, {FORTINET: SIX[FORTINET]}, STAMP)
                read.append(sorted(g["mentions"][0]["url"] for g in groups))
        # Join-only posts need no request and all go at once; each own advisory costs its CSAF file and its page.
        self.assertEqual(read, [[FG.format(188), FG.format(273), FG.format(278)], [FG.format(268)], []])
        self.assertEqual(len([u for u in pages if u not in FEEDS]), 4)
        self.assertEqual(set(checkpoints[FORTINET]), {e["id"] for e in vendors.rss_entries(FEEDS[FORTINET])})

    def test_a_title_or_feed_severity_word_never_counts(self):
        # Palo Alto's "(Severity: MEDIUM)" and Grafana's advisory:severity "Medium" are in the feed; the pages say nothing.
        quiet = lambda url, headers=None: FEEDS.get(url, b"<html><body><p>Fixed.</p></body></html>")
        groups = fetched("https://security.paloaltonetworks.com/CVE-2026-0331",
                         "https://grafana.com/security/security-advisories/cve-2026-110337/", answer=quiet)
        self.assertEqual([g["mentions"][0].get("severity") for g in groups.values()], [None, None])

    def test_grafana_cve_comes_from_its_link_and_a_day_only_date_is_first_seen(self):
        url = "https://grafana.com/security/security-advisories/cve-2026-110337/"
        group = fetched(url)[url]
        self.assertEqual((group["cves"], group["join_only"], group["published"]), (["CVE-2026-110337"], False, STAMP))

    def test_sonicwall_json_at_the_page_records_cite(self):
        groups = fetched("SNWLID-2026-0019", "SNWLID-2026-0021", "SNWLID-2024-0016", "SNWLID-2024-0010",
                         stamp=STAMP)  # the last two are 2024: older than MAX_AGE_DAYS, so recorded but not built
        gms = groups["https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0019"]
        self.assertEqual((gms["join_only"], gms["cves"], gms["published"]),
                         (False, ["CVE-2026-109593", "CVE-2026-109594"], "2026-11-03T08:16:31Z"))
        self.assertTrue(groups["https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0021"]["join_only"])  # Informational
        self.assertEqual(len(groups), 2)

    def test_sonicwall_not_applicable_and_third_party_titles_only_join(self):
        rules = vendors.FEEDS[SONICWALL]
        entries = {e["id"]: e for e in vendors.sonicwall_entries(FEEDS[SONICWALL])}
        for key in ("SNWLID-2026-0021", "SNWLID-2024-0016", "SNWLID-2024-0010"):  # Informational, CUPS (null cvss), regreSSHion
            self.assertTrue(vendors.mention_group(entries[key], rules, STAMP)["join_only"], key)
        self.assertFalse(vendors.mention_group(entries["SNWLID-2026-0014"], rules, STAMP)["join_only"])

    def test_sophos_first_published_time_comes_from_the_description(self):
        groups = fetched("sophos-sa-20261028-utm-rce", "sophos-sa-20261118-java4shell")
        utm = groups["https://www.sophos.com/en-us/security-advisories/sophos-sa-20261028-utm-rce"]
        self.assertEqual((utm["join_only"], utm["cves"], utm["published"]), (False, ["CVE-2026-118633"], "2026-10-28T17:00:00Z"))
        java = groups["https://www.sophos.com/en-us/security-advisories/sophos-sa-20261118-java4shell"]
        self.assertEqual((java["join_only"], java["published"]), (True, "2026-11-18T09:40:00Z"))  # pubDate says Nov 19

    def test_chrome_stable_posts_carry_no_cve(self):
        groups = fetched(*[e["id"] for e in vendors.atom_entries(FEEDS[CHROME])])
        self.assertEqual(sorted(groups), [POST_158, POST_157])
        self.assertEqual([(g["cves"], g["join_only"]) for g in groups.values()], [([], False), ([], False)])
        self.assertEqual(groups[POST_158]["published"], "2026-11-17T19:12:07Z")
        self.assertIn("CVE-2026-121101", FEEDS[CHROME].decode())  # the 158 post names a 157 CVE

    def test_the_first_read_lets_the_last_days_through(self):
        with redirect_stderr(io.StringIO()):
            groups, checkpoints = vendors.fetch({}, get, SIX, STAMP)
        self.assertEqual([(g["mentions"][0]["url"], g["join_only"]) for g in groups], [
            (FG.format(278), True),
            ("https://security.paloaltonetworks.com/CVE-2026-114938", True),
            ("https://grafana.com/security/security-advisories/cve-2026-110337/", False),
            ("https://www.sophos.com/en-us/security-advisories/sophos-sa-20261118-java4shell", True),
            (POST_158, False)])
        self.assertEqual(checkpoints[FORTINET][-1], FG.format(278))  # after the three of Nov 10 and Nov 2, the last read
        self.assertEqual(checkpoints[CHROME], [e["id"] for e in vendors.atom_entries(FEEDS[CHROME])][::-1])  # Nov 11, then Nov 17
        with redirect_stderr(io.StringIO()):
            self.assertEqual(vendors.fetch(checkpoints, get, SIX, STAMP), ([], checkpoints))

    def test_the_large_feeds_are_read_only_on_the_hours_first_mark(self):
        asked = []
        answer = lambda url, headers=None: asked.append(url) or get(url)
        with redirect_stderr(io.StringIO()):
            _, checkpoints = vendors.fetch({}, answer, SIX, "2026-11-20T09:10:00Z")
        self.assertNotIn(SONICWALL, asked)
        self.assertNotIn(CHROME, asked)
        self.assertNotIn(SONICWALL, checkpoints)
        self.assertIn(FORTINET, asked)

    def test_a_feed_that_is_not_its_format_keeps_its_checkpoint(self):
        for feed in (SONICWALL, CHROME):
            for body in (b"<html></html>", b"{\"detail\": \"x\"}", b"not json"):
                with self.subTest(feed=feed, body=body), redirect_stderr(io.StringIO()):
                    self.assertEqual(vendors.fetch({feed: ["x"]}, lambda url, headers=None: body, {feed: vendors.FEEDS[feed]}, STAMP),
                                     ([], {feed: ["x"]}))


class ChromeLinkTest(unittest.TestCase):
    """A stable post joins its release's Incident by its link, never by the CVEs it lists (a roll-up repeats old ones)."""

    def post(self, url):
        return fetched(*[e["id"] for e in vendors.atom_entries(FEEDS[CHROME])])[url]

    def release(self, cve, first_seen, *posts):
        row = incident(cve, "Use after free in ...", first_seen, published=first_seen)
        row["urls"] += [url_key(p) for p in posts]
        return row

    def test_a_post_after_its_records_joins_and_leads(self):
        rows = [self.release("CVE-2026-130910", "2026-11-17T20:50:01Z", POST_158)]
        link(rows, self.post(POST_158), "2026-11-17T21:00:00Z")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["brief"]["lead"], POST_158)
        self.assertEqual(rows[0]["published"], "2026-11-17T19:12:07Z")

    def test_a_roll_up_never_touches_the_older_release(self):
        old = self.release("CVE-2026-121101", "2026-11-03T22:00:00Z")  # the 157 release's row holds the CVE the 158 post repeats
        rows = [old]
        before = copy.deepcopy(old)
        link(rows, self.post(POST_158), "2026-11-17T20:00:00Z")
        self.assertEqual(rows[0], before)
        self.assertEqual([r["id"] for r in rows], ["CVE-2026-121101", POST_158])

    def test_a_post_before_its_records_starts_the_row_they_then_join(self):
        rows = []
        link(rows, self.post(POST_158), "2026-11-17T19:20:00Z")
        for n, cve in enumerate(("CVE-2026-130910", "CVE-2026-130963", "CVE-2026-131031")):
            url = f"https://www.cve.org/CVERecord?id={cve}"
            link(rows, {"mentions": [{"kind": "cve_record", "url": url}], "cves": [cve], "urls": [POST_158],
                        "text": "Use after free in ...", "join_only": False, "published": f"2026-11-17T20:3{n}:00Z",
                        "fix_keys": ["google:chrome<158.0.8127.36"]}, "2026-11-17T20:50:00Z")
        group_releases(rows)
        self.assertEqual([r["id"] for r in rows], [POST_158])
        self.assertEqual(sorted(rows[0]["cves"]), ["CVE-2026-130910", "CVE-2026-130963", "CVE-2026-131031"])
        self.assertEqual(rows[0]["brief"]["lead"], POST_158)


if __name__ == "__main__":
    unittest.main()
