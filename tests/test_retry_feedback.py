"""Owner, 2026-11-10: 48 Incidents (29 at 위험 or above) were given up after three rejected Summaries, most for shortening
a version the input states in full (Netpbm "10.86.51" written "10.86"). A retry now says why the last reply was
rejected, a reply cut off at the token cap gets more room, and one given up after MAX_TRIES stays given up."""

import copy
import unittest

from test_cycle import at, recorded
from test_summaries import HN_STORY, PAGES, SSHOLE_SUMMARY, FakeClaude, board

from collector import summaries
from collector.cycle import run_cycle
from collector.store import MemoryStore

SHORTENED = copy.deepcopy(SSHOLE_SUMMARY)
SHORTENED["ko"]["summary"] += " 10.86 계열이 해당합니다."
SHORTENED["en"]["summary"] += " The 10.86 line is affected."


class RetryFeedbackTest(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.store.write("checkpoints.json", {"cvelist": "2026-11-07T12:00:00.000Z"})

    def run_at(self, when, claude, **sources):
        sources.setdefault("delta_log", None)
        run_cycle(self.store, recorded(web=PAGES, **sources), at(when), "test-box", claude=claude)

    def set_error(self, error):
        month = self.store.read("months/2026-11.json")
        next(i for i in month["incidents"] if i["id"] == HN_STORY)["summary_error"] = error
        self.store.write("months/2026-11.json", month)

    def test_a_retry_says_why_the_last_reply_was_rejected(self):
        claude = FakeClaude(SHORTENED, SSHOLE_SUMMARY)
        self.run_at("2026-11-07T12:30:00", claude, hn="sshole.json")
        self.assertIn("numbers not in the input: ['10.86']", board(self.store)[HN_STORY]["summary_error"]["reason"])
        self.assertNotIn("rejected", claude.user_text(0))

        self.run_at("2026-11-07T12:45:00", claude)

        self.assertIn("Your previous reply for this Incident was rejected: numbers not in the input: ['10.86']", claude.user_text(1))
        self.assertIn("summary", board(self.store)[HN_STORY])

    def test_a_number_named_in_the_note_is_still_not_allowed(self):
        claude = FakeClaude(SHORTENED, SHORTENED)
        self.run_at("2026-11-07T12:30:00", claude, hn="sshole.json")
        self.run_at("2026-11-07T12:45:00", claude)

        incident = board(self.store)[HN_STORY]
        self.assertNotIn("summary", incident)
        self.assertEqual(incident["summary_error"]["tries"], 2)

    def test_a_reply_cut_off_at_the_token_cap_gets_more_room_next_time(self):
        self.run_at("2026-11-07T12:30:00", None, hn="sshole.json")
        self.set_error({"tries": 1, "reason": "stop_reason max_tokens"})
        claude = FakeClaude(SSHOLE_SUMMARY)

        self.run_at("2026-11-07T12:45:00", claude)

        self.assertEqual(claude.sent[0]["max_tokens"], summaries.MAX_TOKENS_RETRY)
        self.assertGreater(summaries.MAX_TOKENS_RETRY, summaries.MAX_TOKENS)

    def test_a_summary_given_up_over_a_number_is_not_tried_again(self):
        claude = FakeClaude(*[SHORTENED] * (summaries.MAX_TRIES + 1))
        self.run_at("2026-11-07T12:30:00", claude, hn="sshole.json")
        for when in ("2026-11-07T12:45:00", "2026-11-07T13:00:00", "2026-11-07T13:15:00", "2026-11-07T13:30:00"):
            self.run_at(when, claude)

        self.assertEqual(len(claude.sent), summaries.MAX_TRIES)
        error = board(self.store)[HN_STORY]["summary_error"]
        self.assertTrue(error["reason"].startswith("numbers not in the input"))
        self.assertTrue(error["final"])
        # Still listed for a person or an agent to fix by hand, so the owner is told once (owner, 11-10).
        [failure] = self.store.read("summary_failures.json")
        self.assertEqual((failure["id"], failure["tries"], failure["shows"]), (HN_STORY, summaries.MAX_TRIES, "brief"))


class ExactNumbersTest(unittest.TestCase):
    """Owner, 2026-11-10 ("그냥 정확하게 하고 싶은데"): the check stays exact; a retry names the input's own numbers that a
    rejected one stood for. IBM API Connect's "10.0.8.0 through 10.0.8.12" came back as "10.0.8" three times."""
    TEXT = "IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote attacker."

    def note(self, reason):
        return summaries.retry({"summary_error": {"reason": reason}}, self.TEXT)["note"]

    def test_a_shortened_version_is_answered_with_the_input_versions_it_stands_for(self):
        note = self.note("numbers not in the input: ['10.0.8', '12.1']")
        self.assertIn("10.0.8: the input has 10.0.8.0, 10.0.8.12", note)
        self.assertIn("12.1: the input has 12.1.0.0, 12.1.1.2", note)

    def test_a_number_with_no_input_version_behind_it_is_said_to_be_absent(self):
        self.assertIn("9.9: not in the input, leave it out", self.note("numbers not in the input: ['9.9']"))

    def test_other_reasons_keep_the_plain_note(self):
        note = self.note("Korean and English numbers differ: ['2']")
        self.assertNotIn("the input has", note)
        self.assertEqual(summaries.retry({}, self.TEXT), {})

    def test_a_product_name_without_its_vendor_is_not_jargon(self):
        summary = {"products": ["IBM API Connect"], "devices": [], "ko": {"names": [], "easy": "API Connect 관리 화면이 뚫릴 수 있습니다!",
                   "easy_title": "", "easy_action": "", "easy_conditions": []}, "en": {"names": [], "easy": "", "easy_title": "",
                   "easy_action": "", "easy_conditions": []}}
        self.assertEqual(summaries.easy_jargon(summary), [])
        summary["ko"]["easy"] = "API 키가 새어 나갈 수 있습니다!"
        self.assertEqual(summaries.easy_jargon(summary), ["API"])


class MonthNameTest(unittest.TestCase):
    """Owner, 2026-11-10: "October 23" written "10월 23일" was rejected as a number not in the input (NIKKE's gist, three
    times), and "11월 3일" against "November 3" as Korean and English numbers that differ."""

    def test_an_english_month_name_counts_as_its_number(self):
        self.assertLessEqual({"10", "23"}, summaries.numbers("The launcher was tampered with on October 23, 2026."))
        self.assertIn("11", summaries.numbers("Fixed Nov. 3"))
        self.assertIn("9", summaries.numbers("since Sept 27"))
        self.assertIn("5", summaries.numbers("released May 4"))

    def test_a_word_that_only_looks_like_a_month_does_not(self):
        self.assertEqual(summaries.numbers("Attackers may exploit it"), set())
        self.assertEqual(summaries.numbers("a decision in March"), {"3"})  # a full month name needs no day
        self.assertEqual(summaries.numbers("Octoberfest tickets"), set())  # a full name must end the word

    def test_korean_and_english_dates_now_agree(self):
        self.assertEqual(summaries.numbers("2026년 10월 23일부터"), summaries.numbers("from October 23, 2026"))
