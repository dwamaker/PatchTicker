"""Three owner decisions of 11-16 on top of the Summary audit: a version may stand in the Easy action, fixed_conflict
compares a fix only within its own release line, and stray_script reads the request's input too."""

import json
import unittest

from collector import summaries, summary_input
from test_summaries import SSHOLE_SUMMARY, FakeClaude

TEXT = f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n" + json.dumps(SSHOLE_SUMMARY, ensure_ascii=False)


def with_fields(lang, **fields):
    return SSHOLE_SUMMARY | {lang: SSHOLE_SUMMARY[lang] | fields}


class EasyActionVersionTest(unittest.TestCase):
    """Owner: "버전 허용". The Easy action may name the fixed version, never a new one, in both languages."""

    def test_the_prompt_allows_the_fixed_version_and_no_other(self):
        self.assertNotIn("a version range or a product version", summaries.INSTRUCTIONS)
        self.assertIn("ash_ai를 1.5.1 이상으로 업데이트하세요.", summaries.INSTRUCTIONS)

    def test_the_fixed_version_passes_even_when_the_mitigation_does_not_repeat_it(self):
        reply = SSHOLE_SUMMARY | {
            "ko": SSHOLE_SUMMARY["ko"] | {"mitigation": "OpenSSH를 업데이트하세요.", "easy_action": "OpenSSH를 10.6p2 이상으로 업데이트하세요."},
            "en": SSHOLE_SUMMARY["en"] | {"easy_action": "Update OpenSSH to 10.6p2 or later."}}
        self.assertEqual(summaries.easy_action_mismatch(reply), [])

    def test_a_version_no_field_names_is_sent_back(self):
        reply = SSHOLE_SUMMARY | {"en": SSHOLE_SUMMARY["en"] | {"easy_action": "Update OpenSSH to 10.7p1."},
                                  "ko": SSHOLE_SUMMARY["ko"] | {"easy_action": "OpenSSH를 10.7p1로 업데이트하세요."}}
        self.assertEqual(summaries.easy_action_mismatch(reply), ["ko", "en"])

    def test_a_version_in_one_languages_easy_action_only_is_sent_back(self):
        reply = with_fields("ko", easy_action="OpenSSH를 10.6p2 이상으로 업데이트하세요.")  # en: no version
        self.assertEqual(summaries.easy_action_mismatch(reply), ["ko"])


class FixedLineTest(unittest.TestCase):
    """fixed_conflict compares a fix with the bound of its own release line only (the audit's first open point)."""

    def conflict(self, fixed, keys, fixes=()):
        return summaries.fixed_conflict({"fix_keys": keys}, {"fixed": fixed, "fixes": list(fixes)})

    def test_a_backport_on_an_older_line_passes(self):
        self.assertEqual(self.conflict("2.2.35", ["apache:http_server<2.4.62"]), "")
        self.assertEqual(self.conflict("2.4.62", ["apache:http_server<2.4.62"],
                                       [{"for": "Apache HTTP Server 2.2", "version": "2.2.35", "devices": []}]), "")

    def test_a_version_below_the_bound_of_its_own_line_is_still_rejected(self):
        self.assertIn("2.4.60 is below 2.4.62", self.conflict("2.4.60", ["apache:http_server<2.4.62"]))
        self.assertIn("2.2.30 is below 2.2.35", self.conflict("2.2.30", ["apache:http_server<2.4.62, 2.2.35"]))

    def test_a_distributions_build_key_still_bounds_nothing(self):
        self.assertEqual(self.conflict("1.21.1", ["red_hat:enterprise_linux:krb5<0:1.21.1-10.el9_9.2"]), "")


class StrayInputTest(unittest.TestCase):
    """stray_script counts the request's input as the Incident's own text."""

    def test_a_name_only_a_fetched_page_writes_passes_with_the_input(self):
        incident = {"brief": {"text": "A flaw in the app."}, "mentions": []}
        summary = {"ko": {"title": "豆瓣电影 앱 결함"}}
        self.assertTrue(summaries.stray_script(incident, summary))
        self.assertEqual(summaries.stray_script(incident, summary, "Text of a page: 豆瓣电影 is a movie app"), "")

    def test_a_summary_stored_with_such_a_name_is_not_made_again(self):
        incident = {"id": "x", "cves": ["CVE-2026-1"], "brief": {"text": "A flaw."},
                    "mentions": [{"kind": "writeup", "url": SSHOLE_SUMMARY["lead"]}]}
        reply = with_fields("ko", title=SSHOLE_SUMMARY["ko"]["title"] + " 豆瓣电影")
        summaries.save_reply(incident, FakeClaude.message(reply), TEXT + "\n豆瓣电影", summaries.basis(incident), "2026-11-08T12:00:00Z")
        self.assertIn("豆瓣电影", incident["summary"]["ko"]["title"])
        self.assertEqual(summaries.stray_script(incident, incident["summary"]), "")
        self.assertFalse(summaries.needs_summary(incident))


if __name__ == "__main__":
    unittest.main()
