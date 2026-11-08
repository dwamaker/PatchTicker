"""Seam 1: batch Summaries for ordinary Incidents, re-summaries and the budget stop, with a fake Claude client."""

import unittest

import anthropic
import httpx2  # the anthropic SDK's HTTP library, only to build its error objects

from collector.cycle import run_cycle
from collector.store import MemoryStore
from test_cycle import at, recorded
from test_summaries import HN_STORY, PAGES, SSHOLE_SUMMARY, FakeClaude, board

KEYCLOAK, WPTRAVELLY = "CVE-2026-120984", "CVE-2026-120839"


def plain(name):
    """A Summary reply with no numbers in it, so it passes the code check for any input."""
    fields = {"title": f"{name} flaw", "summary": f"A flaw in {name}.", "conditions": [],
              "mitigation": "", "easy": f"Someone could misuse {name}.", "easy_title": f"{name} risk found", "names": [name]}
    return {"ko": fields | {"title": f"{name} 취약점", "summary": f"{name}의 취약점입니다."}, "en": fields,
            "products": [name], "lead": "", "fixed": "", "command": "", "stopgap": "", "devices": [], "incident": True, "platforms": []}


class BatchSummaryTest(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.store.write("checkpoints.json", {"cvelist": "2026-11-07T12:00:00.000Z"})

    def run_at(self, when, claude, **sources):
        sources.setdefault("delta_log", None)
        run_cycle(self.store, recorded(web=PAGES, **sources), at(when), "test-box", claude=claude)

    def test_an_ordinary_incident_has_a_brief_until_a_later_cycle_collects_its_batch_summary(self):
        claude = FakeClaude()
        self.run_at("2026-11-07T12:30:00", claude, delta_log="deltaLog.json")

        self.assertNotIn("summary", board(self.store)[KEYCLOAK])
        self.assertEqual(len(claude.batches), 1)
        self.assertEqual(sorted(t.split("\n")[0] for t in claude.batch_inputs()),
                         [f"Incident: {WPTRAVELLY}", f"Incident: {KEYCLOAK}"])

        self.run_at("2026-11-07T12:45:00", claude)  # still in progress
        self.assertNotIn("summary", board(self.store)[KEYCLOAK])
        self.assertEqual(len(claude.batches), 1)  # pending Incidents are not sent again

        claude.end_batch({KEYCLOAK: plain("Keycloak"), WPTRAVELLY: plain("WpTravelly")})
        self.run_at("2026-11-07T13:00:00", claude)

        incidents = board(self.store)
        self.assertEqual(incidents[KEYCLOAK]["summary"], plain("Keycloak") | {"at": "2026-11-07T13:00:00Z"})
        self.assertEqual(incidents[WPTRAVELLY]["summary"]["en"]["title"], "WpTravelly flaw")
        self.assertEqual(claude.sent, [])  # nothing went through the instant path

    def test_expired_and_errored_requests_leave_briefs_and_go_into_a_later_batch(self):
        for failure in ("expired", "errored"):
            with self.subTest(failure):
                self.setUp()
                claude = FakeClaude()
                self.run_at("2026-11-07T12:30:00", claude, delta_log="deltaLog.json")
                claude.end_batch({KEYCLOAK: plain("Keycloak"), WPTRAVELLY: failure})

                self.run_at("2026-11-07T12:45:00", claude)

                incidents = board(self.store)
                self.assertIn("summary", incidents[KEYCLOAK])
                self.assertNotIn("summary", incidents[WPTRAVELLY])
                self.assertEqual(len(claude.batches), 2)
                self.assertEqual([t.split("\n")[0] for t in claude.batch_inputs()], [f"Incident: {WPTRAVELLY}"])

                claude.end_batch({WPTRAVELLY: plain("WpTravelly")})
                self.run_at("2026-11-07T13:00:00", claude)
                self.assertEqual(board(self.store)[WPTRAVELLY]["summary"]["at"], "2026-11-07T13:00:00Z")

    def test_a_rejected_batch_reply_counts_a_try_like_the_instant_path(self):
        claude = FakeClaude()
        self.run_at("2026-11-07T12:30:00", claude, delta_log="deltaLog.json")
        made_up = plain("Keycloak") | {"fixed": "99.1"}
        claude.end_batch({KEYCLOAK: made_up, WPTRAVELLY: plain("WpTravelly")})

        self.run_at("2026-11-07T12:45:00", claude)

        incident = board(self.store)[KEYCLOAK]
        self.assertNotIn("summary", incident)
        self.assertEqual(incident["summary_error"]["tries"], 1)

    def test_batch_requests_are_the_summary_request_with_a_one_hour_cache(self):
        claude = FakeClaude()
        self.run_at("2026-11-07T12:30:00", claude, delta_log="deltaLog.json")

        params = claude.batches[0]["requests"][0]["params"]
        self.assertEqual(params["model"], "claude-haiku-5-5")
        self.assertEqual(params["output_config"]["format"]["type"], "json_schema")
        [instructions] = params["system"]
        self.assertEqual(instructions["cache_control"], {"type": "ephemeral", "ttl": "1h"})


def api_error(status, kind, message):
    response = httpx2.Response(status, request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages/batches"))
    return anthropic.APIStatusError(message, response=response, body={"type": "error", "error": {"type": kind, "message": message}})


CREDIT_EXHAUSTED = api_error(402, "billing_error", "Your credit balance is too low to access the Anthropic API.")
SPEND_LIMIT = api_error(400, "invalid_request_error", "You have reached your specified workspace API usage limits.")


class BudgetStopTest(unittest.TestCase):
    run_at = BatchSummaryTest.run_at
    setUp = BatchSummaryTest.setUp

    def test_a_credit_or_spend_limit_error_pauses_summaries_and_briefs_keep_flowing(self):
        for error in (CREDIT_EXHAUSTED, SPEND_LIMIT):
            with self.subTest(error.message):
                self.setUp()
                claude = FakeClaude(SSHOLE_SUMMARY)
                claude.error = error
                self.run_at("2026-11-07T12:30:00", claude, delta_log="deltaLog.json", hn="sshole.json")

                incidents = board(self.store)
                self.assertEqual(sorted(incidents), [WPTRAVELLY, KEYCLOAK, HN_STORY])
                self.assertFalse(any("summary" in i for i in incidents.values()))
                self.assertEqual(self.store.read("status.json")["summaries"], "paused")

                # The next cycle asks again: once with one batch request, then as usual.
                claude.error = None
                self.run_at("2026-11-07T12:45:00", claude)
                self.assertNotIn("summaries", self.store.read("status.json"))
                self.assertIn("summary", board(self.store)[HN_STORY])
                self.assertEqual(len(claude.batches[0]["requests"]), 1)
                self.run_at("2026-11-07T13:00:00", claude)
                self.assertEqual(len(claude.batches[1]["requests"]), 1)  # the other one

    def test_another_api_error_stops_summaries_for_the_cycle_without_pausing(self):
        claude = FakeClaude()
        claude.error = api_error(529, "overloaded_error", "Overloaded")
        self.run_at("2026-11-07T12:30:00", claude, delta_log="deltaLog.json")

        self.assertIn(KEYCLOAK, board(self.store))
        self.assertNotIn("summaries", self.store.read("status.json"))


SSHOLE = "CVE-2026-123158"


class ReSummaryTest(unittest.TestCase):
    run_at = BatchSummaryTest.run_at

    def setUp(self):
        self.store = MemoryStore()
        self.store.write("checkpoints.json", {"cvelist": "2026-11-05T12:00:00.000Z"})

    def test_a_new_cve_and_a_kev_listing_each_bring_a_new_summary_and_three_is_the_limit(self):
        claude = FakeClaude(SSHOLE_SUMMARY, SSHOLE_SUMMARY, SSHOLE_SUMMARY)
        self.run_at("2026-11-05T12:30:00", claude, hn="sshole.json")  # an Unassigned incident: Summary 1
        self.run_at("2026-11-05T16:00:00", claude, delta_log="deltaLog-sshole.json")  # its CVE attaches: 2
        self.assertEqual(len(claude.sent), 2)
        self.assertEqual(board(self.store)[HN_STORY]["summary"]["at"], "2026-11-05T16:00:00Z")

        self.run_at("2026-11-05T16:15:00", claude)  # nothing new: no request
        self.assertEqual(len(claude.sent), 2)

        self.run_at("2026-11-06T10:00:00", claude, kev="kev-sshole.json")  # listed in KEV: 3
        self.assertEqual(len(claude.sent), 3)
        self.assertEqual(board(self.store)[HN_STORY]["summary"]["at"], "2026-11-06T10:00:00Z")

        self.run_at("2026-11-06T11:00:00", claude, oss="sshole-cves.rss")  # another CVE, but three is enough
        self.assertEqual(board(self.store)[HN_STORY]["cves"], [SSHOLE, "CVE-2026-123999"])
        self.assertEqual(len(claude.sent), 3)
        self.assertEqual(claude.batches, [])

    def test_a_new_kev_listing_is_summarized_at_once_however_old_the_incident(self):
        for summarized_before in (False, True):
            with self.subTest(summarized_before=summarized_before):
                self.setUp()
                claude = FakeClaude(SSHOLE_SUMMARY, SSHOLE_SUMMARY)
                self.run_at("2026-11-05T12:30:00", None, hn="sshole.json")  # no API key: Briefs only
                self.run_at("2026-11-05T16:00:00", claude if summarized_before else None, delta_log="deltaLog-sshole.json")
                sent = len(claude.sent)

                # Listed in KEV six weeks later: past both the seven-day and the 30-day windows.
                self.run_at("2026-12-17T10:00:00", claude, kev="kev-sshole.json")

                self.assertEqual(len(claude.sent), sent + 1)
                self.assertEqual(claude.batches, [])
                self.assertEqual(board(self.store)[HN_STORY]["summary"]["at"], "2026-12-17T10:00:00Z")

    def test_a_new_official_advisory_brings_a_new_summary_through_the_batch(self):
        claude = FakeClaude()
        # An oss-security post names the CVEs before the record (with the release note) is published.
        self.run_at("2026-11-05T14:00:00", claude, oss="sshole-cves.rss")
        claude.end_batch({SSHOLE: plain("OpenSSH")})
        self.run_at("2026-11-05T14:15:00", claude)
        self.assertEqual(board(self.store)[SSHOLE]["summary"]["at"], "2026-11-05T14:15:00Z")
        self.run_at("2026-11-05T14:30:00", claude)
        self.assertEqual(len(claude.batches), 1)

        self.run_at("2026-11-05T16:00:00", claude, delta_log="deltaLog-sshole.json")

        self.assertEqual(board(self.store)[SSHOLE]["cves"], [SSHOLE, "CVE-2026-123999"])  # no new CVE
        self.assertEqual(len(claude.batches), 2)
        [sent] = claude.batch_inputs()
        self.assertIn("advisory https://www.openssh.com/txt/release-10.6p2", sent)
        claude.end_batch({SSHOLE: plain("OpenSSH")})
        self.run_at("2026-11-05T16:15:00", claude)
        self.assertEqual(board(self.store)[SSHOLE]["summary"]["at"], "2026-11-05T16:15:00Z")


if __name__ == "__main__":
    unittest.main()
