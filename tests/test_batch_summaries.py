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
    fields = {"title": f"{name} flaw", "summary": f"A flaw in {name}.", "conditions": [], "easy_conditions": [],
              "mitigation": "", "easy": f"Someone could misuse {name}.", "easy_title": f"{name} risk found", "easy_action": f"Update {name}.", "names": [name], "command_for": "", "stopgap_then": "", "cve_lines": []}
    return {"ko": fields | {"title": f"{name} 취약점", "summary": f"{name}의 취약점입니다."}, "en": fields,
            "products": [name], "lead": "", "fixed": "", "command": "", "stopgap": "", "devices": [], "fixes": [], "incident": True, "platforms": [], "stopgap_file": "", "titles_ko": [], "exploited": False,
            "exploited_source": "", "poc_public": False, "library": False, "widely_used": False}


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


class HighRiskWaitsForNoBatchTest(unittest.TestCase):
    """User, 11-09: 위험 (CVSS 7.0+) and up never wait for a Message Batch, even one they were already put in."""

    def stub(self, status):
        from types import SimpleNamespace as NS
        sent = []
        reply = NS(stop_reason="end_turn", content=[NS(type="text", text="not json")], usage=NS(input_tokens=1, output_tokens=1))
        batches = NS(retrieve=lambda _id: NS(processing_status=status),
                     results=lambda _id: [NS(custom_id="r0", result=NS(type="succeeded", message=reply))])
        return NS(messages=NS(batches=batches, create=lambda **kw: sent.append(kw) or reply)), sent

    def incident(self, cvss):
        return {"id": "CVE-2026-7", "cves": ["CVE-2026-7"], "cvss": cvss, "first_seen": "2026-11-09T10:00:00Z",
                "published": "2026-11-09T09:00:00Z", "mentions": [{"kind": "cve_record", "url": "https://www.cve.org/CVERecord?id=CVE-2026-7"}],
                "brief": {"text": "x", "lead": ""}}

    def test_a_high_risk_incident_in_a_running_batch_is_summarized_now(self):
        from datetime import datetime
        from collector.cycle import route_summaries
        claude, sent = self.stub("in_progress")
        pending = {"id": "b1", "requests": {"r0": {"incident": "CVE-2026-7", "input": "x", "basis": {}}}}
        route_summaries([self.incident(7.5)], [pending], claude, lambda *a, **k: b"", datetime(2026, 11, 9, 12), "2026-11-09T12:00:00Z", set(), False)
        self.assertEqual(len(sent), 1)

    def test_a_batch_reply_does_not_overwrite_a_summary_written_from_the_same_sources(self):
        from collector import summaries
        claude, _ = self.stub("ended")
        incident = self.incident(7.5) | {"summary": {"at": "2026-11-09T11:00:00Z"}}
        basis = summaries.basis(incident)
        incident["summary_basis"] = basis | {"n": 1}
        pending = {"id": "b1", "requests": {"r0": {"incident": "CVE-2026-7", "input": "x", "basis": basis}}}
        summaries.collect_batch(pending, [incident], claude, "2026-11-09T12:00:00Z")
        self.assertEqual(incident["summary"], {"at": "2026-11-09T11:00:00Z"})
        self.assertNotIn("summary_error", incident)  # the "not json" reply was never read

    def test_a_batch_reply_is_read_for_a_summary_that_must_be_made_again_from_the_same_sources(self):
        # Critique 14: a Summary saying exploited with no source is redone though its sources did not change.
        from collector import summaries
        claude, _ = self.stub("ended")
        incident = self.incident(5.0) | {"summary": {"exploited": True, "at": "2026-11-09T11:00:00Z"}}
        basis = summaries.basis(incident)
        incident["summary_basis"] = basis | {"n": 1}
        pending = {"id": "b1", "requests": {"r0": {"incident": "CVE-2026-7", "input": "x", "basis": basis}}}
        summaries.collect_batch(pending, [incident], claude, "2026-11-09T12:00:00Z")
        self.assertEqual(incident["summary_error"]["tries"], 1)  # the reply was read (and, being "not json", failed)


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
        self.assertEqual(self.store.read("status.json")["summaries"], "stopped")  # not "paused": the page shows nothing

        # The next cycle asks again in full, not with a one-request probe batch.
        claude.error = None
        self.run_at("2026-11-07T12:45:00", claude)
        self.assertNotIn("summaries", self.store.read("status.json"))
        self.assertEqual(len(claude.batches[0]["requests"]), 2)

    def test_a_request_the_api_always_rejects_counts_a_try_and_the_others_go_on(self):
        # Audit item 10: a too-long prompt for one KEV Incident blocked every lower one and the batch, each cycle.
        from datetime import datetime
        from types import SimpleNamespace as NS
        from collector import summaries
        from collector.cycle import route_summaries

        def incident(cve, **extra):
            return {"id": cve, "cves": [cve], "first_seen": "2026-11-09T10:00:00Z", "published": "2026-11-09T09:00:00Z",
                    "mentions": [], "brief": {"text": cve, "lead": ""}} | extra
        poisoned, other, low = incident("CVE-2026-1", kev=True), incident("CVE-2026-2", cvss=9.0), incident("CVE-2026-3", cvss=5.0)
        batched = []

        def create(**params):
            if "CVE-2026-1" in params["messages"][0]["content"]:
                raise api_error(400, "invalid_request_error", "prompt is too long: 250000 tokens > 200000 maximum")
            return FakeClaude.message(plain("Widget"))
        claude = NS(messages=NS(create=create, batches=NS(create=lambda requests: batched.append(requests) or NS(id="b1"))))
        now = datetime(2026, 11, 9, 12)
        for n in range(1, summaries.MAX_TRIES + 1):
            route_summaries([poisoned, other, low], [], claude, lambda url: b"", now, "2026-11-09T12:00:00Z", set(), probe=True)
            self.assertEqual(poisoned["summary_error"]["tries"], n)
        self.assertTrue(poisoned["summary_error"]["final"])
        self.assertFalse(summaries.needs_summary(poisoned))
        self.assertIn("summary", other)
        self.assertEqual(len(batched), summaries.MAX_TRIES)  # the batch still went out every cycle
        # The account's own limits still stop the cycle (and pause), never cost an Incident a try.
        poisoned.pop("summary_error")
        claude.messages.create = lambda **params: (_ for _ in ()).throw(SPEND_LIMIT)
        with self.assertRaises(anthropic.APIStatusError):
            route_summaries([poisoned], [], claude, lambda url: b"", now, "2026-11-09T12:00:00Z", set(), probe=False)
        self.assertNotIn("summary_error", poisoned)
        # A 400 every request gets (a parameter the API stopped accepting) is the account's, not one Incident's: the
        # cycle stops, as before, and no candidate is given up for it.
        kev = [incident(f"CVE-2026-{n}", kev=True) for n in range(10, 15)]
        claude.messages.create = lambda **params: (_ for _ in ()).throw(
            api_error(400, "invalid_request_error", "output_config.effort: Extra inputs are not permitted"))
        for _ in range(summaries.MAX_TRIES):
            with self.assertRaises(anthropic.APIStatusError):
                route_summaries(kev, [], claude, lambda url: b"", now, "2026-11-09T12:00:00Z", set(), probe=False)
        self.assertEqual([i.get("summary_error") for i in kev], [None] * 5)


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
        early = {"unpublished": (SSHOLE,)}
        self.run_at("2026-11-05T14:00:00", claude, oss="sshole-cves.rss", **early)
        claude.end_batch({SSHOLE: plain("OpenSSH")})
        self.run_at("2026-11-05T14:15:00", claude, **early)
        self.assertEqual(board(self.store)[SSHOLE]["summary"]["at"], "2026-11-05T14:15:00Z")
        self.run_at("2026-11-05T14:30:00", claude, **early)
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


class SummaryCountTest(unittest.TestCase):
    """Critique 14: summary_basis.n reached 16 (SonicWall) and 12 (an HN story) in a day, past MAX_SUMMARIES."""

    stub, incident = HighRiskWaitsForNoBatchTest.stub, HighRiskWaitsForNoBatchTest.incident

    def made(self, n, cves=("CVE-2026-7",)):
        from collector import summaries
        incident = self.incident(5.0) | {"summary": {"at": "2026-11-09T11:00:00Z"}}
        incident["summary_basis"] = summaries.basis(incident | {"cves": list(cves)}) | {"n": n}
        return incident

    def save(self, incident):
        from collector import summaries
        reply = FakeClaude.message(plain("Keycloak"))
        summaries.save_reply(incident, reply, "x", summaries.basis(incident), "2026-11-09T12:00:00Z")

    def test_a_summary_made_again_from_the_same_sources_is_not_counted(self):
        incident = self.made(1)  # a hand re-make after a prompt change, or a reply nothing asked for
        self.save(incident)
        self.assertEqual(incident["summary"]["en"]["title"], "Keycloak flaw")
        self.assertEqual(incident["summary_basis"]["n"], 1)

    def test_the_first_summary_and_each_triggered_one_count(self):
        incident = self.incident(5.0)
        self.save(incident)
        self.assertEqual(incident["summary_basis"]["n"], 1)
        incident = self.made(1, cves=())  # its CVE attached since: a re-summary trigger
        self.save(incident)
        self.assertEqual(incident["summary_basis"]["n"], 2)

    def test_a_batch_reply_for_an_incident_at_the_limit_is_not_read_even_from_other_sources(self):
        from collector import summaries
        claude, _ = self.stub("ended")
        incident = self.made(summaries.MAX_SUMMARIES, cves=())
        pending = {"id": "b1", "requests": {"r0": {"incident": "CVE-2026-7", "input": "x", "basis": {"cves": ["CVE-2026-6"], "kev": False, "advisories": []}}}}
        summaries.collect_batch(pending, [incident], claude, "2026-11-09T12:00:00Z")
        self.assertEqual(incident["summary"], {"at": "2026-11-09T11:00:00Z"})
        self.assertNotIn("summary_error", incident)
        self.assertEqual(incident["summary_basis"]["n"], summaries.MAX_SUMMARIES)
