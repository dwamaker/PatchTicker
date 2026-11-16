"""The review hooked into every Summary (owner, 11-16 "모든 요약에 검토 추가"): collector/review.py's request after a
Summary passes the rule checks, on the instant path and as a second batch round. No network: FakeClaude answers."""

import contextlib
import io
import json
import unittest
from types import SimpleNamespace

import anthropic

from collector import review, summaries, summary_input
from test_summaries import SSHOLE_SUMMARY, FakeClaude

TEXT = f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n" + json.dumps(SSHOLE_SUMMARY, ensure_ascii=False)
BASIS = {"cves": [], "kev": False, "advisories": [], "n": 0}
STAMP = "2026-11-08T12:00:00Z"
FINDING = {"findings": [{"field": "summary", "lang": "both", "quote": SSHOLE_SUMMARY["en"]["summary"][:40],
                         "against": "", "problem": "The summary says one thing, the mitigation another.", "severity": "high"}]}
CLEAN = {"findings": []}


def incident(tries=0, **more):
    i = {"id": "CVE-2026-1", "cves": ["CVE-2026-1"], "mentions": [{"kind": "writeup", "url": SSHOLE_SUMMARY["lead"]}]} | more
    if tries:
        i["summary_error"] = {"tries": tries, "reason": "earlier"}
    return i


def quiet(fn, *args, **kwargs):
    log = io.StringIO()
    with contextlib.redirect_stderr(log):
        fn(*args, **kwargs)
    return log.getvalue()


class InstantReviewTest(unittest.TestCase):
    """The instant path: one review call inside save_reply, after the rule checks."""

    def save(self, claude, item, reply=SSHOLE_SUMMARY):
        return quiet(summaries.save_reply, item, FakeClaude.message(reply), TEXT, BASIS, STAMP, review_with=claude)

    def test_a_finding_costs_one_retry_and_carries_the_note(self):
        claude, item = FakeClaude(FINDING), incident()
        self.save(claude, item)
        self.assertNotIn("summary", item)
        self.assertTrue(item["summary_error"]["reason"].startswith(review.REASON))
        self.assertEqual(item["summary_error"]["tries"], 1)
        self.assertIn("draft", item["summary_error"])  # the reply is kept for a hard failure on the last try
        self.assertIn(review.RETRY_SENTENCE, summaries.retry(item, TEXT)["note"])
        self.assertEqual(claude.sent[0]["output_config"]["format"]["schema"], review.SCHEMA)

    def test_a_clean_review_stores_the_summary(self):
        claude, item = FakeClaude(CLEAN), incident()
        self.save(claude, item)
        self.assertEqual(item["summary"]["en"]["title"], SSHOLE_SUMMARY["en"]["title"])
        self.assertNotIn("summary_error", item)

    def test_the_last_try_is_stored_unreviewed(self):
        claude, item = FakeClaude(), incident(tries=summaries.MAX_TRIES - 1)
        self.save(claude, item)
        self.assertIn("summary", item)
        self.assertEqual(claude.sent, [])  # no review asked: a finding could change nothing

    def test_a_rule_problem_costs_the_retry_without_a_review(self):
        claude, item = FakeClaude(), incident()
        self.save(claude, item, SSHOLE_SUMMARY | {"ko": SSHOLE_SUMMARY["ko"] | {"easy": "SQL 서버가 뚫립니다!"}})
        self.assertIn("jargon", item["summary_error"]["reason"])
        self.assertEqual(claude.sent, [])

    def test_a_review_call_that_fails_stores_the_summary_and_says_so(self):
        claude, item = FakeClaude(), incident()
        claude.error = anthropic.APIConnectionError(request=SimpleNamespace(method="POST", url="x"))
        log = self.save(claude, item)
        self.assertIn("summary", item)
        self.assertIn("unreviewed", log)

    def test_the_switch_off_sends_no_review(self):
        claude, item = FakeClaude(), incident()
        quiet(summaries.save_reply, item, FakeClaude.message(SSHOLE_SUMMARY), TEXT, BASIS, STAMP)  # review_with=None
        self.assertIn("summary", item)
        self.assertEqual(claude.sent, [])

    def test_an_entry_too_large_is_reviewed_without_its_lines_or_not_at_all(self):
        lines = [{"cve": f"CVE-2026-{n}", "text": "x" * 200} for n in range(1000, 1400)]
        big = {lang: SSHOLE_SUMMARY[lang] | {"cve_lines": lines} for lang in ("ko", "en")}
        asked = summaries.review_params(SSHOLE_SUMMARY | big, incident())
        self.assertNotIn("CVE-2026-1001", asked["messages"][0]["content"])
        huge = {lang: SSHOLE_SUMMARY[lang] | {"conditions": ["y" * 200] * 400} for lang in ("ko", "en")}
        self.assertIsNone(summaries.review_params(SSHOLE_SUMMARY | huge, incident()))
        claude, item = FakeClaude(), incident()
        log = quiet(summaries.save_reply, item, FakeClaude.message(SSHOLE_SUMMARY | huge), TEXT, BASIS, STAMP, review_with=claude)
        self.assertIn("summary", item)
        self.assertEqual(claude.sent, [])
        self.assertIn("too large", log)


class BatchReviewTest(unittest.TestCase):
    """The batch path: a Summary batch's reply waits for a second round (review requests), then is stored or retried."""

    def summary_batch(self, claude, item, answer):
        sent = claude.messages.batches.create(requests=[{"custom_id": "r0", "params": {}}])
        claude.batch(sent.id)["results"] = [SimpleNamespace(custom_id="r0", result=SimpleNamespace(
            type="succeeded", message=FakeClaude.message(answer)))]
        pending = {"id": sent.id, "requests": {"r0": {"incident": item["id"], "input": TEXT, "basis": BASIS}}}
        quiet(summaries.collect_batch, pending, [item], claude, STAMP, review=True)

    def end_review(self, claude, pending, result):
        claude.batch(pending["id"])["results"] = [SimpleNamespace(custom_id=cid, result=result) for cid in pending["requests"]]

    def test_a_summary_waits_for_its_review_and_is_asked_once(self):
        claude, item = FakeClaude(), incident()
        self.summary_batch(claude, item, SSHOLE_SUMMARY)
        self.assertNotIn("summary", item)  # not shown before its review
        self.assertIn("review_pending", item)
        first = summaries.submit_reviews([item], [], claude)
        self.assertEqual([r["incident"] for r in first["requests"].values()], [item["id"]])
        self.assertTrue(all(r.get("review") for r in first["requests"].values()))
        self.assertIsNone(summaries.submit_reviews([item], [first], claude))  # never asked twice

    def test_a_finding_from_the_review_round_costs_a_retry(self):
        claude, item = FakeClaude(), incident()
        self.summary_batch(claude, item, SSHOLE_SUMMARY)
        pending = summaries.submit_reviews([item], [], claude)
        self.end_review(claude, pending, SimpleNamespace(type="succeeded", message=FakeClaude.message(FINDING)))
        quiet(summaries.collect_batch, pending, [item], claude, STAMP, review=True)
        self.assertNotIn("summary", item)
        self.assertTrue(item["summary_error"]["reason"].startswith(review.REASON))
        self.assertNotIn("review_pending", item)

    def test_a_clean_review_round_stores_the_summary(self):
        claude, item = FakeClaude(), incident()
        self.summary_batch(claude, item, SSHOLE_SUMMARY)
        pending = summaries.submit_reviews([item], [], claude)
        self.end_review(claude, pending, SimpleNamespace(type="succeeded", message=FakeClaude.message(CLEAN)))
        quiet(summaries.collect_batch, pending, [item], claude, STAMP, review=True)
        self.assertEqual(item["summary"]["en"]["title"], SSHOLE_SUMMARY["en"]["title"])
        self.assertNotIn("review_pending", item)

    def test_a_review_round_that_fails_stores_the_summary(self):
        for kind in ("errored", "expired"):
            with self.subTest(kind):
                claude, item = FakeClaude(), incident()
                self.summary_batch(claude, item, SSHOLE_SUMMARY)
                pending = summaries.submit_reviews([item], [], claude)
                failure = SimpleNamespace(type=kind, error=SimpleNamespace(type="error", error=SimpleNamespace(type="api_error")))
                self.end_review(claude, pending, failure)
                log = quiet(summaries.collect_batch, pending, [item], claude, STAMP, review=True)
                self.assertEqual(item["summary"]["en"]["title"], SSHOLE_SUMMARY["en"]["title"])
                self.assertIn("unreviewed", log)

    def test_the_last_try_from_a_batch_is_stored_unreviewed(self):
        claude, item = FakeClaude(), incident(tries=summaries.MAX_TRIES - 1)
        self.summary_batch(claude, item, SSHOLE_SUMMARY)
        self.assertIn("summary", item)
        self.assertNotIn("review_pending", item)

    def test_switched_off_the_batch_reply_is_stored_at_once_and_a_waiting_one_is_released(self):
        claude, item = FakeClaude(), incident()
        sent = claude.messages.batches.create(requests=[{"custom_id": "r0", "params": {}}])
        claude.batch(sent.id)["results"] = [SimpleNamespace(custom_id="r0", result=SimpleNamespace(
            type="succeeded", message=FakeClaude.message(SSHOLE_SUMMARY)))]
        quiet(summaries.collect_batch, {"id": sent.id, "requests": {"r0": {"incident": item["id"], "input": TEXT, "basis": BASIS}}},
              [item], claude, STAMP)  # review off
        self.assertIn("summary", item)
        waiting = incident()
        self.summary_batch(claude, waiting, SSHOLE_SUMMARY)
        log = quiet(summaries.release_reviews, [waiting], [])
        self.assertIn("summary", waiting)
        self.assertIn("unreviewed", log)


class RouteTest(unittest.TestCase):
    """cycle.route_summaries: a Summary waiting for its review is not asked again, its review goes out the same cycle,
    and with the switch off it is stored at once."""

    def waiting(self):
        summary = json.loads(json.dumps(SSHOLE_SUMMARY)) | {"same_as": ""}  # as parse() leaves it
        draft = {"summary": summary, "seen": BASIS, "stamp": STAMP, "listed": [], "due": True, "words": []}
        return incident(first_seen=STAMP, brief={"text": "A flaw.", "lead": ""}, quick_title={"ko": "t", "en": "t"},
                        review_pending=draft)

    def route(self, item, batches, review_on, claude=None):
        from datetime import datetime, timezone
        from collector.cycle import route_summaries
        claude, changed = claude or FakeClaude(), set()
        log = quiet(route_summaries, [item], batches, claude, None, datetime(2026, 11, 8, 12, tzinfo=timezone.utc), STAMP,
                    changed, probe=False, review=review_on)
        return claude, changed, log

    def test_the_review_goes_out_and_the_summary_is_not_asked_again(self):
        item, batches = self.waiting(), []
        claude, _, _ = self.route(item, batches, True)
        self.assertEqual(len(batches), 1)
        self.assertTrue(all(r.get("review") for r in batches[0]["requests"].values()))
        self.assertEqual(claude.sent, [])  # no instant Summary, no title
        self.route(item, batches, True, claude)
        self.assertEqual(len(batches), 1)  # in a pending batch: not asked twice

    def test_switched_off_a_waiting_summary_is_stored(self):
        item = self.waiting()
        _, changed, log = self.route(item, [], False)
        self.assertIn("summary", item)
        self.assertEqual(changed, {"2026-11"})
        self.assertIn("switched off", log)


class ReasonPlumbingTest(unittest.TestCase):
    def test_the_failure_list_cuts_the_reviews_quotes(self):
        from collector.incidents import REVIEW_REASON, plain_reason
        self.assertEqual(REVIEW_REASON, review.REASON)
        self.assertEqual(plain_reason(f"{review.REASON}: summary (en): wrong: \"abc\""), review.REASON)
        self.assertEqual(plain_reason(f"jargon in the Easy view: ['SQL']; {review.REASON}: summary (en): x"), "jargon in the Easy view")


if __name__ == "__main__":
    unittest.main()
