"""Owner, 2026-11-10: CVE-2026-106007 (FraudLabs Pro SMS Verification) was given up after three tries with "Korean and
English numbers differ: ['3']": the Korean Summary wrote "제3자에게" (to third parties), the English one "third parties".
A digit that is part of a fixed Korean word is not a number; the check stays exact otherwise."""

import unittest

from collector import summaries
from test_batch_summaries import plain
from test_command_provenance import POSTER, checked, incident
from test_cve_lines import MANY, MAX, line, lines_row, saved

SPAM = "Widget lets attackers send SMS messages, spamming arbitrary third parties."


def spam_reply(ko, en):
    reply = plain("Widget")
    return reply | {"ko": reply["ko"] | {"summary": ko}, "en": reply["en"] | {"summary": en}}


class KoreanDigitWordTest(unittest.TestCase):
    def test_a_digit_inside_a_fixed_korean_word_is_not_a_number(self):
        self.assertEqual(summaries.ko_numbers("제3자에게 스팸을 보낼 수 있습니다. 제3자가 받습니다."), set())
        self.assertEqual(summaries.ko_numbers("3자리 코드"), {"3"})
        self.assertEqual(summaries.ko_numbers("제30자리"), {"30"})
        self.assertEqual(summaries.numbers("제3자"), {"3"})  # English text and numbers() itself are untouched

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


if __name__ == "__main__":
    unittest.main()
