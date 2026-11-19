"""Owner, 11-19: an official advisory's own severity word (summary_input.advisory_severity), read by code from the
Summary's input. The page texts are cut from the real pages of 11-19 as page_text() gave them."""

import json
import unittest

from collector import summaries, summary_input
from test_summaries import SSHOLE_SUMMARY, FakeClaude

GHSA = "https://github.com/ruby/ruby/security/advisories/GHSA-34m4-m9fh-gqp5"
SYNOLOGY = "https://www.synology.com/en-global/security/advisory/Synology_SA_26_21"
DRUPAL = "https://www.drupal.org/sa-core-2026-017"
WRITEUP = "https://blog.example.com/ruby2shell"

GHSA_TEXT = ("Heap buffer overflow in case conversion of strings · Advisory · ruby/ruby · GitHub Heap buffer overflow in case "
             "conversion of strings Critical mame published GHSA-34m4-m9fh-gqp5 Nov 19, 2026 Package ruby Affected versions "
             "<= 3.3.13 Patched versions 3.3.14 3.4.13 4.0.10 Description Summary Ruby has a one-byte heap-based buffer "
             "overflow in the case conversion of strings. Severity Critical CVE ID No known CVE Weaknesses CWE-193")
SYNOLOGY_TEXT = ("Last Updated: 2026-11-19 15:50:54 UTC+8 Severity Critical Status Ongoing Abstract Synology has released a "
                 "security update. Affected Products Product Severity Fixed Release Availability APM 2.0 Not affected N/A "
                 "DSM 7.4 Critical Upgrade to 7.4.1-90080-2 or above")
DRUPAL_TEXT = ("Drupal core - Critical - Remote code execution - SA-CORE-2026-017 Project: Drupal core Date: 2026-November-18 "
               "Security risk: Critical 18 ∕ 25 AC:Complex/A:None/CI:All/II:All/E:Proof/TD:Uncommon Vulnerability: Remote code execution")


def input_text(mentions, pages):
    """A Summary input as summary_input() lays it out: the Mentions list, then each page's text block."""
    head = ["Incident: no CVE yet", "CVSS: not rated yet", "Description: x", "Mentions:",
            *(f"- {kind} {url}" for kind, url in mentions)]
    return "\n".join(head + [line for url, text in pages for line in (f"Text of {url}:", text)])


class AdvisorySeverityTest(unittest.TestCase):

    def test_the_three_real_advisories_state_critical_under_their_label(self):
        for url, text in ((GHSA, GHSA_TEXT), (SYNOLOGY, SYNOLOGY_TEXT), (DRUPAL, DRUPAL_TEXT)):
            with self.subTest(url):
                found = summary_input.advisory_severity(input_text([("advisory", url)], [(url, text)]))
                self.assertEqual(found, {"severity": "critical", "severity_source": url})

    def test_a_write_up_news_page_or_title_never_gives_one(self):
        # The same words on a write-up's page, and a Drupal-like title in the Mentions list, count for nothing.
        text = input_text([("writeup", WRITEUP), ("discussion", "https://news.ycombinator.com/item?id=1")],
                          [(WRITEUP, "Severity: Critical. Security risk: Critical")])
        self.assertEqual(summary_input.advisory_severity(text + "\n- advisory https://x (Drupal core - Critical - RCE)"), {})

    def test_only_the_word_after_the_label_counts(self):
        def word(text):
            return summary_input.advisory_severity(input_text([("advisory", DRUPAL)], [(DRUPAL, text)])).get("severity")
        self.assertIsNone(word("Drupal core - Critical - Remote code execution. A critical component is affected."))
        self.assertEqual(word("Security risk: Moderately critical 12 ∕ 25"), "medium")  # not "critical"
        self.assertEqual(word("Security risk: Highly critical 20 ∕ 25"), "critical")
        self.assertEqual(word("Max Severity: Important"), "high")
        self.assertEqual(word("Severity Moderate"), "medium")  # GitHub's word for medium

    def test_the_first_advisory_that_states_one_is_the_source(self):
        text = input_text([("advisory", DRUPAL), ("advisory", SYNOLOGY)], [(DRUPAL, "no word here"), (SYNOLOGY, SYNOLOGY_TEXT)])
        self.assertEqual(summary_input.advisory_severity(text)["severity_source"], SYNOLOGY)

    def test_parse_stores_it_with_the_summary(self):
        reply = SSHOLE_SUMMARY | {"lead": GHSA}
        text = input_text([("advisory", GHSA)], [(GHSA, GHSA_TEXT + " " + json.dumps(SSHOLE_SUMMARY, ensure_ascii=False))])
        summary = summaries.parse(FakeClaude.message(reply), text, [GHSA])
        self.assertEqual((summary["severity"], summary["severity_source"]), ("critical", GHSA))
        plain = input_text([("writeup", GHSA)], [(GHSA, GHSA_TEXT + " " + json.dumps(SSHOLE_SUMMARY, ensure_ascii=False))])
        self.assertNotIn("severity", summaries.parse(FakeClaude.message(reply), plain, [GHSA]))

    def test_a_re_summary_whose_advisory_page_did_not_load_keeps_the_stored_word(self):
        def resummarize(mentions, text):
            incident = {"id": SYNOLOGY, "cves": [], "brief": {"text": "x"}, "mentions": mentions,
                        "summary": SSHOLE_SUMMARY | {"severity": "critical", "severity_source": SYNOLOGY}}
            reply = SSHOLE_SUMMARY | {"lead": WRITEUP}
            body = json.dumps(SSHOLE_SUMMARY, ensure_ascii=False)
            summaries.save_reply(incident, FakeClaude.message(reply), input_text([(m["kind"], m["url"]) for m in mentions], text(body)),
                                 summaries.basis(incident), "2026-11-19T12:00:00Z")
            return incident["summary"].get("severity")
        both = [{"kind": "advisory", "url": SYNOLOGY}, {"kind": "writeup", "url": WRITEUP}]
        self.assertEqual(resummarize(both, lambda body: [(WRITEUP, body)]), "critical")  # the advisory failed to load: kept
        self.assertEqual(resummarize(both, lambda body: [(WRITEUP, body), (SYNOLOGY, "Severity Low")]), "low")  # read again: new word
        self.assertIsNone(resummarize(both[1:], lambda body: [(WRITEUP, body)]))  # no longer an advisory Mention: gone


if __name__ == "__main__":
    unittest.main()
