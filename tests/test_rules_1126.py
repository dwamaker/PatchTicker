"""Four Summaries given up on 11-24 to 11-26 by checks that were wrong about them: a fix written without its trailing
zero, a build of a release, a major named without a line word, and "1:1" for a name spelled "One to one"."""

import unittest

from collector import summaries
from collector.numbers import ko_numbers, number_words, numbers, without_line_names


def conflict(fixed, keys, fixes=()):
    return summaries.fixed_conflict({"fix_keys": keys}, {"fixed": fixed, "fixes": list(fixes)})


class TrailingZeroTest(unittest.TestCase):
    """CVE-2026-122075 (Drupal Scheduler): "fixed version 1.7 is below 1.7.0"."""

    KEYS = ["drupal:scheduler<1.7.0", "drupal:scheduler<2.0.*", "drupal:scheduler<2.1.*", "drupal:scheduler<2.2.3",
            "drupal:scheduler<2.3.1"]

    def test_a_fix_without_its_trailing_zero_is_the_bound_itself(self):
        self.assertEqual(conflict("1.7", self.KEYS), "")
        self.assertEqual(conflict("1.7.0", self.KEYS), "")
        self.assertEqual(conflict("2.4.62.0", ["apache:http_server<2.4.62"]), "")

    def test_a_version_below_the_bound_is_still_rejected(self):
        self.assertIn("2.2.2 is below 2.2.3", conflict("2.2.2", self.KEYS))
        self.assertIn("1.7 is below 1.7.10", conflict("1.7", ["drupal:scheduler<1.7.10"]))  # 1.7 is 1.7.0, below 1.7.10
        self.assertIn("2.4.60 is below 2.4.62", conflict("2.4.60", ["apache:http_server<2.4.62"]))


class BuildOfAReleaseTest(unittest.TestCase):
    """CVE-2026-123926 (VMware Avi): the record bounds 32.1.3-2p1, its text fixes 32.1.1-32.1.2 in 32.1.2-2p3."""

    KEYS = ["vmware:vmware_avi_load_balancer<32.1.3-2p1"]

    def test_a_build_of_an_earlier_release_passes(self):
        fixes = [{"for": "32.1.1 ~ 32.1.2", "version": "32.1.2-2p3", "devices": []},
                 {"for": "32.1.3", "version": "32.1.3-2p1", "devices": []}]
        self.assertEqual(conflict("", self.KEYS, fixes), "")
        self.assertEqual(conflict("32.1.2-2p3", self.KEYS), "")

    def test_the_bare_release_below_the_bound_is_still_rejected(self):
        self.assertIn("32.1.2 is below 32.1.3", conflict("32.1.2", self.KEYS))
        self.assertIn("32.1.2 is below 32.1.3", conflict("32.1.2 or later", self.KEYS))
        self.assertIn("32.1.2 is below 32.1.3", conflict("32.1.2로 업데이트", self.KEYS))

    def test_a_build_below_a_bare_bound_is_still_rejected(self):
        # The records name a plain release, so nothing says the product is fixed by builds.
        self.assertIn("32.1.2 is below 32.1.3", conflict("32.1.2-2p3", ["vmware:vmware_avi_load_balancer<32.1.3"]))
        self.assertIn("10.6 is below 10.6.3", conflict("10.6p2", ["openbsd:openssh<10.6.3"]))


class MajorAfterANameTest(unittest.TestCase):
    """CVE-2026-119443 (Erlang/OTP): the English named "OTP 28" and "OTP 29" with no line word."""

    INPUT = ("This issue affects OTP from OTP 17.0 before OTP 27.3.4.20, OTP 28.5.0.9, and OTP 29.1.3. The allow_entities "
             "option is false by default since OTP 27.")
    FIXED = numbers("27.3.4.20\n28.5.0.9\n29.1.3")

    def unknown(self, text, read=numbers):
        known = numbers(self.INPUT)
        return sorted(read(without_line_names(text, self.FIXED, known)) - known - number_words(self.INPUT))

    def test_a_major_after_the_name_beside_its_own_fix_is_a_line(self):
        for text in ("Update OTP 27 to 27.3.4.20, OTP 28 to 28.5.0.9, and OTP 29 to 29.1.3.",
                     "Update to 27.3.4.20 on OTP 27, 28.5.0.9 on OTP 28, or 29.1.3 on OTP 29.",
                     "Erlang/OTP 28 users need 28.5.0.9; OTP 29 users need 29.1.3."):
            self.assertEqual(self.unknown(text), [], text)
        self.assertEqual(self.unknown("OTP 28은 28.5.0.9, OTP 29는 29.1.3으로 업데이트하세요.", ko_numbers), [])

    def test_a_count_or_a_version_to_install_stays_a_number(self):
        for text, left in (("Fixes 28 flaws in 28.5.0.9.", ["28"]),            # a count, not after a name
                           ("OTP 28 flaws are fixed in 28.5.0.9.", ["28"]),    # a count after a name
                           ("Update to OTP 29.", ["29"]),                      # no fix of its line in the sentence
                           ("OTP 30 to 28.5.0.9.", ["30"])):                   # not a line of the input
            self.assertEqual(self.unknown(text), left, text)
        self.assertEqual(self.unknown("OTP 28건이 28.5.0.9에서 고쳐졌습니다.", ko_numbers), ["28"])
        self.assertEqual(self.unknown("OTP 28로 올리거나 28.5.0.9를 설치하세요.", ko_numbers), ["28"])


class OneToOneTest(unittest.TestCase):
    """CVE-2026-107654 (WPGuppy "One to one user Chat"): the Korean wrote "1:1 채팅"."""

    def test_one_to_one_written_in_digits_has_no_number(self):
        self.assertEqual(ko_numbers("WPGuppy 1:1 채팅 플러그인 SQL 삽입 취약점"), set())
        self.assertEqual(ko_numbers("1대1 채팅 플러그인"), set())

    def test_a_time_a_ratio_or_a_version_keeps_its_digits(self):
        self.assertEqual(ko_numbers("21:15에 1:10 비율로"), {"21", "15", "1", "10"})
        self.assertEqual(ko_numbers("버전 1.1:1 이하"), {"1.1", "1"})
        self.assertEqual(ko_numbers("12단계 인증"), {"12"})

    def test_the_older_words_still_have_none(self):
        self.assertEqual(ko_numbers("제3자에게 2단계 인증과 2FA를"), set())


if __name__ == "__main__":
    unittest.main()
