"""Owner, 2026-11-10: CVE-2026-106007 (FraudLabs Pro SMS Verification) was given up after three tries with "Korean and
English numbers differ: ['3']": the Korean Summary wrote "제3자에게" (to third parties), the English one "third parties".
A digit that is part of a fixed Korean word is not a number; the check stays exact otherwise."""

import unittest

from collector import numbers, summaries
from test_batch_summaries import plain
from test_command_provenance import POSTER, checked, incident
from test_cve_lines import MANY, MAX, line, lines_row, saved

SPAM = "Widget lets attackers send SMS messages, spamming arbitrary third parties."


def spam_reply(ko, en):
    reply = plain("Widget")
    return reply | {"ko": reply["ko"] | {"summary": ko}, "en": reply["en"] | {"summary": en}}


class KoreanDigitWordTest(unittest.TestCase):
    def test_a_digit_inside_a_fixed_korean_word_is_not_a_number(self):
        self.assertEqual(numbers.ko_numbers("제3자에게 스팸을 보낼 수 있습니다. 제3자가 받습니다."), set())
        self.assertEqual(numbers.ko_numbers("3자리 코드"), {"3"})
        self.assertEqual(numbers.ko_numbers("제30자리"), {"30"})
        self.assertEqual(numbers.numbers("제3자"), {"3"})  # English text and numbers() itself are untouched
        # 11-19: MFA in Korean (CVE-2026-16021, Mattermost: refused three times for '2').
        self.assertEqual(numbers.ko_numbers("2단계 인증을 쓰지 않은 사용자, 2단계 로그인 강제, 2차 인증"), set())
        self.assertEqual(numbers.ko_numbers("2단계인증, 2차인증, 2FA 강제"), set())
        self.assertEqual(numbers.ko_numbers("2단계로 나눠 공격합니다"), {"2"})

    def test_a_version_before_man_meaning_only_stays_the_version(self):
        # 11-16: Zephyr's "4.3.2만" ("only 4.3.2") was read as 4. and 3.2만 = "4.32000" and the Summary rejected.
        self.assertEqual(numbers.ko_numbers("GOEP 빌드는 4.3.2만 고칩니다."), {"4.3.2"})
        self.assertEqual(numbers.ko_numbers("4.3.2 만"), {"4.3.2"})
        self.assertEqual(numbers.ko_numbers("회원 580만 명, 1.5만 건"), {"5800000", "15000"})  # amounts stay amounts
        self.assertEqual(numbers.numbers("version 2.1.5 million"), {"2.1.5"})

    def test_third_parties_pass_the_summary_check(self):
        item = incident([{"kind": "writeup", "url": POSTER}])
        reply = spam_reply("Widget로 제3자에게 스팸 문자를 보낼 수 있습니다.", "Widget can spam arbitrary third parties.")
        for page in (SPAM, "Version 3: " + SPAM):  # with no 3 in the input, and with one (the Korean/English comparison)
            with self.subTest(page):
                self.assertIn("제3자", checked(item, {POSTER: page}, reply)["ko"]["summary"])

    def test_a_real_mismatch_still_fails(self):
        item = incident([{"kind": "writeup", "url": POSTER}])
        reply = spam_reply("파일 3개가 열립니다.", "Four files open.")
        with self.assertRaisesRegex(summaries.Rejected, r"Korean and English numbers differ: \['3'\]"):
            checked(item, {POSTER: "3 files, four files."}, reply)

    def test_a_korean_title_line_with_the_word_is_kept(self):
        item = incident([{"kind": "writeup", "url": POSTER, "title": "Spamming third parties"}])
        reply = plain("Widget") | {"titles_ko": [{"url": POSTER, "title": "제3자 스팸"}]}
        self.assertEqual(checked(item, {POSTER: SPAM}, reply)["titles_ko"], [{"url": POSTER, "title": "제3자 스팸"}])

    def test_a_per_cve_line_with_the_word_is_kept(self):
        cves, log = saved(lines_row(SPAM), line(MANY[MAX], "제3자에게 스팸을 보냅니다.", "Spams arbitrary third parties."))
        self.assertEqual(cves, [MANY[MAX]])
        self.assertNotIn("dropped", log)

    def test_two_factor_in_english_is_not_a_number(self):
        # 11-20: CVE-2026-133611 (vulnerability-lookup) was given up on '2': Korean "2단계 인증", English "2FA".
        for text in ("2FA", "2fa", "two-factor", "2-factor authentication", "2-Step verification", "Disables 2FA."):
            with self.subTest(text):
                self.assertEqual(numbers.en_numbers(text), set())
        self.assertEqual(numbers.en_numbers("2 users"), {"2"})
        self.assertEqual(numbers.en_numbers("version 2 drops 2FA"), {"2"})
        self.assertEqual(numbers.en_numbers("toggle_2fa"), {"2"})  # not a whole word
        self.assertEqual(numbers.numbers("2FA"), {"2"})  # numbers() itself is untouched

    def test_two_factor_passes_the_summary_check(self):
        item = incident([{"kind": "writeup", "url": POSTER}])
        page = "An unauthenticated GET to /user/toggle_2fa disables 2FA for any user."
        reply = spam_reply("인증 없는 GET 요청으로 2단계 인증을 끌 수 있습니다.", "An unauthenticated GET disables 2FA.")
        self.assertIn("2단계 인증", checked(item, {POSTER: page}, reply)["ko"]["summary"])
        reply = spam_reply("사용자 2명의 인증을 끌 수 있습니다.", "Disables authentication for users.")
        with self.assertRaisesRegex(summaries.Rejected, r"Korean and English numbers differ: \['2'\]"):
            checked(item, {POSTER: page}, reply)

    def test_a_per_cve_line_with_two_factor_is_kept(self):
        page = "An unauthenticated GET to /user/toggle_2fa disables 2FA."
        cves, log = saved(lines_row(page), line(MANY[MAX], "2단계 인증을 끌 수 있습니다.", "Disables 2FA."))
        self.assertEqual(cves, [MANY[MAX]])
        self.assertNotIn("dropped", log)

    def test_a_cve_id_before_man_only_is_not_an_amount(self):
        # 11-16, Rails CVE-2026-126067: "CVE-2026-126067만" (만: "only") was read as 1260670000, not in the input.
        self.assertEqual(numbers.ko_numbers("CVE-2026-126067만 해당합니다"), {"2026", "126067"})
        self.assertEqual(numbers.ko_numbers("cve-2026-126067만"), {"2026", "126067"})
        self.assertEqual(numbers.ko_numbers("580만 명, 2만 건"), {"5800000", "20000"})


if __name__ == "__main__":
    unittest.main()
