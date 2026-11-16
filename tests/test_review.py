"""The review request (owner, 2026-11-16): parsing its reply into findings and turning findings into a retry reason."""

import json
import unittest
from types import SimpleNamespace

from collector import review
from collector.model import MODEL


def lang(summary, lines=()):
    return {"title": "Widget flaw", "summary": summary, "conditions": [], "easy_conditions": [], "mitigation": "Update to 2.1.",
            "easy": "", "easy_title": "", "easy_action": "Update Widget.", "names": ["Widget"], "command_for": "",
            "stopgap_then": "", "cve_lines": [{"cve": c, "text": t} for c, t in lines]}


SUMMARY = {"ko": lang("로그인한   사용자가 파일을 읽을 수 있습니다."),
           "en": lang("Anyone can read files without logging in.",
                      [("CVE-2026-0001", "Runs commands as root."), ("CVE-2026-0002", "Reads files.")]),
           "fixed": "2.1", "fixes": [], "products": ["Widget"], "exploited": False, "stopgap": ""}
INCIDENT = {"id": "CVE-2026-0001", "cves": ["CVE-2026-0001", "CVE-2026-0002"]}


def finding(quote, against="", severity="high", field="summary", lang_="both", problem="Korean says a login is needed."):
    return {"field": field, "lang": lang_, "quote": quote, "against": against, "problem": problem, "severity": severity}


def reply(findings=None, text=None, stop="end_turn"):
    body = text if text is not None else json.dumps({"findings": findings}, ensure_ascii=False)
    return SimpleNamespace(stop_reason=stop, content=[SimpleNamespace(type="text", text=body)])


class FindingsTest(unittest.TestCase):
    def test_a_finding_quoting_the_entry_is_kept(self):
        item = finding("로그인한 사용자가", "Anyone can read files without logging in.")
        self.assertEqual(review.findings_of(reply([item]), SUMMARY), [item])

    def test_whitespace_and_surrounding_quotes_do_not_matter(self):
        item = finding("\"로그인한 사용자가 파일을\"", "“Anyone can read files”")
        self.assertEqual(review.findings_of(reply([item]), SUMMARY), [item])

    def test_a_language_free_value_can_be_the_other_side(self):
        item = finding("Update to 2.1.", "2.1", field="mitigation")
        self.assertEqual(review.findings_of(reply([item]), SUMMARY), [item])
        self.assertEqual(len(review.findings_of(reply([finding("Reads files.", "false")]), SUMMARY)), 1)

    def test_a_made_up_quote_is_dropped_a_paraphrased_against_is_not(self):
        made_up = [finding("관리자만 파일을 읽을 수 있습니다"), finding("로그인한 / Anyone", "")]
        self.assertEqual(review.findings_of(reply(made_up), SUMMARY), [])
        paraphrased = finding("로그인한 사용자가", "en summary: no login needed")
        self.assertEqual(review.findings_of(reply([paraphrased]), SUMMARY), [paraphrased])

    def test_a_bad_severity_or_shape_is_dropped(self):
        self.assertEqual(review.findings_of(reply([finding("Reads files.", severity="medium"), "x", None]), SUMMARY), [])

    def test_an_unreadable_or_cut_off_reply_is_no_finding(self):
        item = finding("로그인한 사용자가")
        self.assertEqual(review.findings_of(reply([item], stop="max_tokens"), SUMMARY), [])
        self.assertEqual(review.findings_of(reply(text="not json"), SUMMARY), [])
        self.assertEqual(review.findings_of(reply(text='{"other": []}'), SUMMARY), [])
        self.assertEqual(review.findings_of(reply(text='{"findings": "none"}'), SUMMARY), [])
        self.assertEqual(review.findings_of(SimpleNamespace(stop_reason="end_turn", content=[]), SUMMARY), [])


class ReasonTest(unittest.TestCase):
    def test_no_high_finding_is_no_reason(self):
        self.assertEqual(review.reason([]), "")
        self.assertEqual(review.reason([finding("Reads files.", severity="low")]), "")

    def test_the_reason_names_field_language_problem_and_both_quotes(self):
        text = review.reason([finding("로그인한 사용자가", "Anyone can read files", problem="Korean says a login is needed.")])
        self.assertEqual(text, 'the review found: summary (both): Korean says a login is needed: "로그인한 사용자가"'
                               ' vs "Anyone can read files"')
        self.assertTrue(text.startswith(review.REASON))

    def test_long_quotes_are_cut_and_only_whole_findings_fit_the_budget(self):
        long = "x" * 200
        text = review.reason([finding(long, long, problem="p" * 300)] * 5 + [finding("Reads files.", severity="low")])
        self.assertLessEqual(len(text), review.MAX_REASON)
        self.assertIn("x" * (review.MAX_QUOTE - 1) + "…\"", text)
        self.assertNotIn("x" * review.MAX_QUOTE, text)
        self.assertIn("p" * (review.MAX_PROBLEM - 1) + "…", text)
        self.assertTrue(text.endswith('"'))  # never a finding cut mid-quote
        self.assertNotIn("Reads files", text)

    def test_one_finding_longer_than_the_budget_is_still_sent(self):
        text = review.reason([finding("Reads files.", field="f" * 500)])
        self.assertEqual(len(text), review.MAX_REASON)

    def test_the_reason_never_holds_the_soft_problem_separator(self):
        # summaries.SEPARATOR ("; ") splits a reason into parts for retry(); a finding's own "; " must not split it.
        self.assertNotIn("; ", review.reason([finding("Reads files.", problem="One says this; the other says that.")]))


class ParamsTest(unittest.TestCase):
    def test_one_request_carries_the_entry_and_the_small_schema(self):
        asked = review.params(SUMMARY, INCIDENT, ttl="1h")
        self.assertEqual(asked["model"], MODEL)
        self.assertEqual(asked["output_config"]["format"]["schema"], review.SCHEMA)
        self.assertEqual(asked["system"][0]["cache_control"], {"type": "ephemeral", "ttl": "1h"})
        content = asked["messages"][0]["content"]
        for text in ("CVE-2026-0001, CVE-2026-0002", '"fixed": "2.1"', "로그인한", "without logging in", "Runs commands as root."):
            self.assertIn(text, content)
        self.assertNotIn('"names"', content)
        self.assertNotIn("cache_control", json.dumps(review.params(SUMMARY, INCIDENT)["messages"]))
        self.assertNotIn("ttl", review.params(SUMMARY, INCIDENT)["system"][0]["cache_control"])


if __name__ == "__main__":
    unittest.main()
