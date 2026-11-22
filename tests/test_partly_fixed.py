"""A partly fixed Incident (11-22, GL.iNet, HN 50587789): the KVM fix is out (1.10.2 beta, 1.8.6 beta), the routers'
is not (stable firmware scheduled for 11-22). Every gate read "is there a fix" as one yes or no, so no Easy action
passed: "install now" read as an update beside "no fix", "wait for the rest" as a wait beside a fixed version."""

import unittest

from collector import review, summaries
from test_summaries import SSHOLE_SUMMARY

KO_MITIGATION = ("KVM은 1.10.2 베타 또는 1.8.6 베타 펌웨어를 바로 설치하세요. 라우터용 수정 버전은 아직 확인되지 않았습니다. "
                 "그때까지 라우터의 원격 관리 기능을 꺼 두세요.")
EN_MITIGATION = ("Install the KVM beta firmware 1.10.2 or 1.8.6 now. No router fix is confirmed yet. "
                 "Until then, turn off remote management on the routers.")


def glinet(ko_action="사용 중인 기기의 보안 펌웨어를 바로 설치하세요.", en_action="Install your device's security firmware now.",
           ko_mitigation=KO_MITIGATION, en_mitigation=EN_MITIGATION, fixed="1.10.2", fixes=None):
    fixes = [{"for": "GL.iNet Comet KVM", "version": "1.10.2", "devices": []},
             {"for": "GL.iNet KVM", "version": "1.8.6", "devices": []}] if fixes is None else fixes
    return SSHOLE_SUMMARY | {
        "fixed": fixed, "fixes": fixes, "products": ["GL.iNet KVM", "GL.iNet routers"],
        "ko": SSHOLE_SUMMARY["ko"] | {"mitigation": ko_mitigation, "easy_action": ko_action},
        "en": SSHOLE_SUMMARY["en"] | {"mitigation": en_mitigation, "easy_action": en_action}}


class PartlyFixedActionTest(unittest.TestCase):
    def test_the_owners_first_draft_passes(self):
        self.assertEqual(summaries.easy_action_mismatch(glinet()), [])

    def test_install_here_and_update_the_rest_when_out_passes(self):
        for ko, en in (("고친 버전이 나온 제품은 바로 업데이트하고, 나머지는 나오는 대로 업데이트하세요.",
                        "Update now where a fix is out, and the rest as soon as theirs is."),
                       ("KVM은 바로 업데이트하고, 라우터는 업데이트가 나오면 바로 설치하세요.",
                        "Update the KVM now, and the router once the fix is out.")):
            self.assertEqual(summaries.easy_action_mismatch(glinet(ko, en)), [], en)

    def test_the_last_try_that_blanked_english_only_now_passes_in_both(self):
        # 11-22: "No router fix is confirmed yet" was no "no fix" to the code, so the English wait was blanked.
        reply = glinet("라우터는 업데이트가 나오면 바로 설치하세요.", "Update the routers once the fix is out.")
        self.assertEqual(summaries.easy_action_mismatch(reply), [])

    def test_a_named_fixed_version_may_be_updated_to(self):
        reply = glinet("KVM을 1.10.2로 업데이트하세요.", "Update the KVM to 1.10.2.")
        self.assertEqual(summaries.easy_action_mismatch(reply), [])

    def test_an_action_naming_the_line_with_no_fix_passes(self):
        # 19 stored rows (CVE-2026-99733 and kin) were refused when the line ("7.2") read as a version beside "no fix".
        reply = SSHOLE_SUMMARY | {"fixed": "7.3.5", "fixes": [],
                                  "ko": SSHOLE_SUMMARY["ko"] | {"mitigation": "7.3 계열은 7.3.5 이상으로 업데이트하세요. 7.2 계열의 수정 버전은 확인되지 않았습니다.",
                                                                "easy_action": "7.3 계열은 7.3.5 이상으로 업데이트하고, 7.2 계열은 7.3 계열로 옮기세요."},
                                  "en": SSHOLE_SUMMARY["en"] | {"mitigation": "Update the 7.3 line to 7.3.5 or later. A fixed version for the 7.2 line is not confirmed.",
                                                                "easy_action": "Update the 7.3 line to 7.3.5 or later, and move 7.2 systems to the 7.3 line."}}
        self.assertEqual(summaries.easy_action_mismatch(reply), [])

    def test_a_version_nothing_names_as_fixed_is_still_caught(self):
        reply = glinet("라우터를 4.8.1로 업데이트하세요.", "Update the router to 4.8.1.")
        self.assertEqual(summaries.easy_action_mismatch(reply), ["ko", "en"])

    def test_the_prompts_own_examples_pass(self):
        ko = "고친 버전이 나온 제품은 바로 업데이트하고, 나머지는 나오는 대로 업데이트하세요."
        en = "Update now where a fix is out, and the rest as soon as theirs is."
        self.assertIn(f'("{ko}", "{en}")', summaries.INSTRUCTIONS)
        ko_m, en_m = "라우터용 수정 펌웨어는 아직 나오지 않았습니다.", "The routers' fixed firmware is not out yet."
        self.assertIn(f'("{ko_m}", "{en_m}")', summaries.INSTRUCTIONS)
        reply = glinet(ko, en, "KVM은 1.10.2 베타 펌웨어를 설치하세요. " + ko_m, "Install the KVM beta firmware 1.10.2. " + en_m)
        self.assertEqual(summaries.easy_action_mismatch(reply), [])

    def test_the_review_is_told_the_split_agrees(self):
        self.assertIn("A partly fixed entry is none of these", review.INSTRUCTIONS)
        self.assertIn('"update now" when mitigation says the fix is not out yet', review.INSTRUCTIONS)


class NearbyCasesTest(unittest.TestCase):
    """Nothing else loosens: a fully fixed or a not-at-all fixed Summary is checked as before."""

    def test_fully_fixed_wait_is_still_caught(self):
        for lang, mitigation, action in (
                ("ko", "7.3.2로 업데이트하세요. 수정 버전은 제조사가 확인했습니다.", "새 버전이 나오면 바로 업데이트하세요."),
                ("en", "Update to 7.3.2. The fix is confirmed by the vendor.", "Update as soon as the new version is out.")):
            reply = SSHOLE_SUMMARY | {"fixed": "7.3.2", lang: SSHOLE_SUMMARY[lang] | {"mitigation": mitigation, "easy_action": action}}
            self.assertEqual(summaries.easy_action_mismatch(reply), [lang], action)

    def test_no_fix_at_all_update_to_a_bound_is_still_caught(self):
        for lang, mitigation, action in (
                ("ko", "수정 버전은 아직 없습니다. 7.3.3-7015보다 새 버전인지 확인하세요.", "7.3.3으로 업데이트하세요."),
                ("en", "There is no fix yet. Check that you run a version newer than 7.3.3-7015.", "Update to 7.3.3.")):
            reply = SSHOLE_SUMMARY | {"fixed": "", "fixes": [], lang: SSHOLE_SUMMARY[lang] | {"mitigation": mitigation, "easy_action": action}}
            self.assertEqual(summaries.easy_action_mismatch(reply), [lang], action)

    def test_no_fix_at_all_update_now_is_still_caught(self):
        reply = glinet("지금 바로 업데이트하세요.", "Update now.", "수정 버전은 아직 없습니다. 원격 관리를 끄세요.",
                       "There is no fix yet. Turn off remote management.", fixed="", fixes=[])
        self.assertEqual(summaries.easy_action_mismatch(reply), ["ko", "en"])


class NoFixWordsTest(unittest.TestCase):
    def test_an_unconfirmed_fix_reads_as_none_in_both_languages(self):
        for text in ("No router fix is confirmed yet.", "A fixed version for the 7.2 line is not confirmed.",
                     "No fixed version for 7.2 has been confirmed.", "라우터용 수정 버전은 아직 확인되지 않았습니다.",
                     "7.2 계열의 수정 버전은 확인되지 않았습니다.", "라우터용 펌웨어는 아직 확인되지 않았습니다.",
                     "The 7.0 line has no confirmed fixed version.", "7.0 계열은 수정 버전이 확인되지 않았으니 옮기세요.",
                     "A fixed version for the 6.19 and 7.4 lines is not confirmed."):
            self.assertTrue(summaries.NO_FIX_RE.search(text), text)

    def test_other_unconfirmed_things_are_not_a_missing_fix(self):
        for text in ("No attacks are confirmed yet.", "공격은 아직 확인되지 않았습니다.",
                     "Update to the fixed version 1.2. No attacks are confirmed yet.",
                     "수정 버전 1.2로 업데이트하세요. 공격은 확인되지 않았습니다.", "The fix in 7.3.2 is confirmed by the vendor.",
                     "패치는 나왔지만 공격은 확인되지 않았습니다.", "No workaround exists, but the fix is confirmed in 1.2.",
                     "The fix is out and exploitation is not confirmed."):
            self.assertFalse(summaries.NO_FIX_RE.search(text), text)

    def test_a_fix_still_to_come_reads_as_not_out_in_both_languages(self):
        for text in ("Install the stable firmware scheduled for November 22.", "The routers' fixed firmware is not out yet.",
                     "11월 22일 출시 예정인 정식 펌웨어를 설치하세요.", "라우터용 수정 펌웨어는 아직 나오지 않았습니다.",
                     "The router firmware will be released on November 22.", "The router fix is due on November 22.",
                     "라우터용 펌웨어는 11월 22일 출시될 예정입니다.", "라우터용 펌웨어는 11월 22일 나올 예정입니다."):
            self.assertTrue(summaries.NOT_OUT_RE.search(text), text)

    def test_a_scheduled_task_is_no_release(self):
        self.assertFalse(summaries.NOT_OUT_RE.search("Until then, disable the scheduled task and update to 1.2."))


if __name__ == "__main__":
    unittest.main()
