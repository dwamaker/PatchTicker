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


class NoFixReleaseTest(unittest.TestCase):
    """Owner, 11-16 evening: a group with no fixed version still wrote "the same release also fixes other flaws"
    (CVE-2026-121685 and about 20 more of the 453 re-written Summaries)."""
    NO_FIX = {"ko": "수정 버전은 아직 없습니다. 관리 화면을 인터넷에 열어 두지 마세요.", "en": "There is no fix yet. Keep the admin page off the internet."}

    def group(self, ko_summary, en_summary, mitigation=None, fixed=""):
        mitigation = mitigation or self.NO_FIX
        return SSHOLE_SUMMARY | {"fixed": fixed, "fixes": [],
                                 "ko": SSHOLE_SUMMARY["ko"] | {"summary": ko_summary, "mitigation": mitigation["ko"]},
                                 "en": SSHOLE_SUMMARY["en"] | {"summary": en_summary, "mitigation": mitigation["en"]}}

    def test_the_prompt_says_what_to_write_when_nothing_is_fixed(self):
        bullet = next(l for l in summaries.GROUP_INSTRUCTIONS.splitlines() if "its second sentence says, by kind" in l)
        self.assertIn("never that a release or an update fixes them", bullet)

    def test_a_release_that_fixes_the_others_without_a_fix_is_sent_back(self):
        for ko, en in (("인증 없이 로그인할 수 있습니다. 같은 릴리스는 서비스 거부 결함도 고칩니다.", "Anyone can log in."),
                       ("인증 없이 로그인할 수 있습니다. 같은 업데이트가 정보 노출 결함도 수정합니다.", "Anyone can log in."),
                       ("인증 없이 로그인할 수 있습니다.", "Anyone can log in. The same release also fixes a denial of service flaw."),
                       ("인증 없이 로그인할 수 있습니다.", "Anyone can log in. The same update fixes two other flaws too.")):
            with self.subTest(ko + en):
                self.assertEqual(summaries.release_without_fix(self.group(ko, en)), summaries.NO_FIX_RELEASE)
        no_source = {"ko": "수정 버전을 밝힌 출처가 아직 없습니다.", "en": "No source names a fixed version yet."}
        reply = self.group("같은 릴리스는 다른 결함도 고칩니다.", "Anyone can log in.", no_source)
        self.assertEqual(summaries.release_without_fix(reply), summaries.NO_FIX_RELEASE)

    def test_other_flaws_by_kind_or_a_real_update_pass(self):
        # The group also holds other flaws, said without a release: what the rule asks for.
        self.assertEqual(summaries.release_without_fix(self.group("로그인할 수 있습니다. 서비스 거부 결함도 함께 보고되었습니다.",
                                                                  "Anyone can log in. Denial of service flaws are reported too.")), "")
        # Android's monthly update: fixed empty by rule, yet the update exists and the mitigation says to install it, even
        # beside "no source names a fixed version" (CVE-2026-0053's stored mitigation, word for word), and the others that
        # point at an update that is out (Intel, IBM, ASUS, a dated security update, a named build).
        for en in ("Install the Android security update. No source names a fixed version yet.",
                   "No source names a fixed version yet. Intel says updates are out; check the advisory and update VTune Profiler.",
                   "Apply the Fix Central patch from the IBM security bulletin. No source names a fixed version number.",
                   "No source names a fixed version yet. Check your router's series and apply the firmware update in the ASUS advisory.",
                   "Check that the device has a security update from September 2026 or later. No source names a fixed version yet.",
                   "No source names a fixed version yet. As Intel recommends, update Slim Bootloader to the build with hash 9e77d9ab.",
                   "Update the Matchpoint app to the latest available version. No source names a fixed version number."):
            with self.subTest(en):
                update = {"ko": "보안 업데이트를 설치하세요.", "en": en}
                self.assertEqual(summaries.release_without_fix(self.group("같은 업데이트가 다른 결함도 고칩니다.",
                                                                          "The same update also fixes other flaws.", update)), "")
        # Not an update that is out: checking for a version newer than a bound.
        bound = {"ko": "수정 버전을 밝힌 출처가 아직 없습니다. 2.3.1보다 새 버전인지 확인하세요.",
                 "en": "No source names a fixed version yet. Check that you run a version newer than 2.3.1."}
        self.assertEqual(summaries.release_without_fix(self.group("같은 릴리스는 다른 결함도 고칩니다.", "Anyone can log in.", bound)),
                         summaries.NO_FIX_RELEASE)
        # A fixed version named: the sentence is true.
        self.assertEqual(summaries.release_without_fix(self.group("같은 릴리스는 다른 결함도 고칩니다.",
                                                                  "The same release also fixes other flaws.", fixed="10.6p2")), "")

    def test_only_a_group_is_checked(self):
        reply = self.group("같은 릴리스는 다른 결함도 고칩니다.", "The same release also fixes other flaws.")
        incident = {"id": "x", "mentions": [{"kind": "writeup", "url": SSHOLE_SUMMARY["lead"]}]}
        group_text = "Incident: CVE-2026-0001, CVE-2026-0002\nLead CVE: CVE-2026-0001\n" + TEXT
        summaries.save_reply(incident, FakeClaude.message(reply), group_text, {"cves": [], "kev": False, "advisories": [], "n": 0},
                             "2026-11-08T12:00:00Z")
        self.assertIn(summaries.NO_FIX_RELEASE, incident["summary_error"]["reason"])
        self.assertIn("never that a release or an update fixes them", summaries.retry(incident, group_text)["note"])
        one = {"id": "y", "mentions": [{"kind": "writeup", "url": SSHOLE_SUMMARY["lead"]}]}
        summaries.save_reply(one, FakeClaude.message(reply), TEXT, {"cves": [], "kev": False, "advisories": [], "n": 0},
                             "2026-11-08T12:00:00Z")
        self.assertNotIn(summaries.NO_FIX_RELEASE, (one.get("summary_error") or {}).get("reason", ""))


if __name__ == "__main__":
    unittest.main()
