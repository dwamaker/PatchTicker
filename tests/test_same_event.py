"""Owner, 11-10: a CVE-less Incident's Summary request lists the recent CVE-less Incidents it could be the same event as;
the model names one in same_as, the code decides whether they merge, and every decision lands in merge_log.json."""

import contextlib
import io
import unittest

from collector import summaries
from collector.cycle import run_cycle
from collector.incidents import page_slug, url_key
from collector.store import MemoryStore
from test_batch_summaries import plain
from test_cycle import at, incident, recorded
from test_summaries import FakeClaude, board

PLEX_BC = "https://www.bleepingcomputer.com/news/security/plex2shell-flaw-lets-attackers-take-over-plex-servers/"
PLEX_SW = "https://www.securityweek.com/plex-media-server-flaw-plex2shell/"
NCENTRAL_HN = "https://news.ycombinator.com/item?id=46000001"
NCENTRAL_BC = "https://www.bleepingcomputer.com/news/security/n-able-n-central-flaw/"
STAMP = "2026-11-09T13:30:00Z"


def story(url, first_seen, title=None, products=(), mentions=None, asked=True):
    """A CVE-less news or HN Incident; with a title it already has a Summary naming these products, asked with a
    candidate list unless asked=False (summarized before same_as shipped)."""
    mentions = mentions or [{"kind": "writeup", "url": url}]
    incident = {"id": url, "cves": [], "first_seen": first_seen, "published": first_seen, "mentions": mentions,
                "urls": sorted({url_key(m["url"]) for m in mentions}), "brief": {"text": "A story", "lead": mentions[0]["url"]}}
    if title:
        reply = plain(products[0])
        incident["summary"] = reply | {"en": reply["en"] | {"title": title}, "at": first_seen}
        incident["summary_basis"] = summaries.basis(incident) | {"n": 1}
        if asked:
            incident["same_as_asked"] = True
    return incident


def seed(store, rows):
    store.write("index.json", {"months": ["2026-11"]})
    store.write("months/2026-11.json", {"month": "2026-11", "incidents": rows})


def quiet(fn, *args, **kwargs):
    with contextlib.redirect_stderr(io.StringIO()) as err:
        result = fn(*args, **kwargs)
    return result, err.getvalue()


def no_pages(url, headers=None):
    raise FileNotFoundError(url)


class InstantPathTest(unittest.TestCase):
    """Plex2Shell: BleepingComputer on 11-06, SecurityWeek 68 hours later."""

    def setUp(self):
        self.store = MemoryStore()
        self.old = story(PLEX_BC, "2026-11-06T17:10:00Z", "Plex2Shell lets attackers take over Plex Media Server", ["Plex Media Server"])
        self.new = story(PLEX_SW, "2026-11-09T13:20:00Z")

    def cycle(self, reply, rows=None):
        seed(self.store, rows or [self.old, self.new])
        claude = FakeClaude(reply)
        _, err = quiet(run_cycle, self.store, recorded(None), at(STAMP[:-1]), "test-box", claude=claude)
        return claude, err

    def test_the_request_lists_the_recent_cve_less_incidents_beside_the_input(self):
        claude, _ = self.cycle(plain("Plex Media Server") | {"same_as": ""})
        sent = claude.user_text()
        self.assertIn(f"- {PLEX_BC} | Plex2Shell lets attackers take over Plex Media Server | Plex Media Server", sent)
        self.assertIn("same_as", claude.sent[0]["output_config"]["format"]["schema"]["required"])
        self.assertNotIn(PLEX_BC, sent.split("\n\n")[0])  # beside the input, which the reply is checked against
        self.assertIn("when unsure, answer \"\"", claude.sent[0]["system"][0]["text"])

    def test_an_accepted_same_as_folds_the_later_incident_into_the_earlier_one(self):
        _, err = self.cycle(plain("Plex Media Server") | {"same_as": PLEX_BC})

        incidents = board(self.store)
        self.assertNotIn(PLEX_SW, incidents)
        survivor = incidents[PLEX_BC]
        self.assertEqual({m["url"] for m in survivor["mentions"]}, {PLEX_BC, PLEX_SW})
        self.assertEqual(survivor["absorbed"], [PLEX_SW])
        self.assertNotIn("same_as", survivor)
        self.assertTrue(summaries.needs_summary(survivor))  # its sources changed: a new Summary next cycle
        self.assertEqual(self.store.read("merge_log.json"), [{
            "at": STAMP, "incident": {"id": PLEX_SW, "title": "Plex Media Server flaw"}, "candidates": 1,
            "same_as": {"id": PLEX_BC, "title": "Plex2Shell lets attackers take over Plex Media Server"},
            "accepted": True, "why": "accepted", "into": PLEX_BC}])
        self.assertIn(f"summaries: same_as: merged {PLEX_SW} into {PLEX_BC}", err)

    def test_same_as_empty_with_candidates_merges_nothing_and_is_logged(self):
        self.cycle(plain("Plex Media Server") | {"same_as": ""})

        incidents = board(self.store)
        self.assertEqual(set(incidents), {PLEX_BC, PLEX_SW})
        self.assertEqual(incidents[PLEX_SW]["summary"]["en"]["title"], "Plex Media Server flaw")
        [entry] = self.store.read("merge_log.json")
        self.assertEqual((entry["candidates"], entry["same_as"], entry["accepted"]), (1, "", False))

    def test_an_incident_with_a_cve_gets_no_list_and_no_merge(self):
        self.new["cves"] = ["CVE-2026-55555"]
        self.new["id"] = "CVE-2026-55555"
        claude, _ = self.cycle(plain("Plex Media Server") | {"same_as": PLEX_BC})

        self.assertNotIn(PLEX_BC, claude.user_text())
        incidents = board(self.store)
        self.assertIn("CVE-2026-55555", incidents)
        self.assertIn("summary", incidents["CVE-2026-55555"])
        [entry] = self.store.read("merge_log.json")
        self.assertEqual((entry["candidates"], entry["accepted"], entry["why"]), (0, False, "not listed"))

    def test_the_log_keeps_the_last_300_newest_first(self):
        older = [{"at": "2026-11-08T00:00:00Z", "n": n} for n in range(300)]
        self.store.write("merge_log.json", older)
        self.cycle(plain("Plex Media Server") | {"same_as": ""})

        log = self.store.read("merge_log.json")
        self.assertEqual(len(log), 300)
        self.assertEqual(log[0]["at"], STAMP)
        self.assertEqual(log[1:], older[:299])

    def test_no_candidates_and_no_same_as_write_no_log(self):
        self.old["first_seen"] = self.old["published"] = "2026-11-01T00:00:00Z"  # past the seven days
        claude, _ = self.cycle(plain("Plex Media Server") | {"same_as": ""})
        self.assertNotIn(PLEX_BC, claude.user_text())
        self.assertIsNone(self.store.read("merge_log.json"))


class BatchPathTest(unittest.TestCase):
    """N-able N-central: a Huntress write-up via HN, summarized in a batch, and BleepingComputer's story."""

    def test_a_batch_reply_merges_after_the_cycle_collects_it_and_the_absorbed_page_moves(self):
        store = MemoryStore()
        asker = story(NCENTRAL_HN, "2026-11-09T10:00:00Z", mentions=[
            {"kind": "writeup", "url": "https://www.huntress.com/blog/n-central-exploited"}, {"kind": "discussion", "url": NCENTRAL_HN}])
        asker["quick_title"] = {"ko": {"title": "x"}, "en": {"title": "x"}}  # no titles call in this cycle
        candidate = story(NCENTRAL_BC, "2026-11-09T11:00:00Z", "N-able N-central flaw exploited in attacks", ["N-able N-central"])
        seed(store, [asker, candidate])
        claude = FakeClaude()
        quiet(run_cycle, store, recorded(None), at("2026-11-09T12:00:00"), "test-box", claude=claude)
        [text] = claude.batch_inputs()
        self.assertIn(f"- {NCENTRAL_BC} | N-able N-central flaw exploited in attacks | N-able N-central", text)
        self.assertEqual(store.read("batches.json")[0]["requests"]["r0"]["candidates"], [NCENTRAL_BC])
        self.assertIn(page_slug(NCENTRAL_BC), store.read("page_hashes.json"))

        claude.end_batch({"no CVE yet": plain("N-able N-central") | {"same_as": NCENTRAL_BC}})
        _, err = quiet(run_cycle, store, recorded(None), at("2026-11-09T12:10:00"), "test-box", claude=claude)

        incidents = board(store)
        self.assertEqual(set(incidents), {NCENTRAL_HN})  # the earlier first seen survives
        survivor = incidents[NCENTRAL_HN]
        self.assertEqual(survivor["absorbed"], [NCENTRAL_BC])
        self.assertIn(NCENTRAL_BC, {m["url"] for m in survivor["mentions"]})
        self.assertEqual(survivor["summary"]["en"]["title"], "N-able N-central flaw")
        self.assertEqual(store.read("moves.json")[page_slug(NCENTRAL_BC)]["moved_to_id"], NCENTRAL_HN)
        self.assertTrue(store.read("merge_log.json")[0]["accepted"])
        self.assertIn(f"merged {NCENTRAL_BC} into {NCENTRAL_HN}", err)


class RefusalTest(unittest.TestCase):
    """Each refusal stores the Summary as usual and logs why, through the instant path's functions."""

    def setUp(self):
        self.candidate = story(PLEX_BC, "2026-11-06T17:10:00Z", "Plex2Shell lets attackers take over Plex Media Server", ["Plex Media Server"])
        self.asker = story(PLEX_SW, "2026-11-09T13:20:00Z")
        self.incidents = [self.candidate, self.asker]

    def decide(self, reply, meanwhile=lambda: None):
        listed = summaries.same_as_candidates(self.asker, self.incidents, at(STAMP[:-1]))
        self.assertEqual(listed, [self.candidate])
        quiet(summaries.summarize_now, self.asker, FakeClaude(reply), no_pages, STAMP, listed)
        self.assertIn("summary", self.asker)
        meanwhile()
        (changed, log), _ = quiet(summaries.apply_same_as, self.incidents, STAMP)
        self.assertEqual(self.incidents, [self.candidate, self.asker])  # nothing merged
        self.assertNotIn("same_as", self.asker)
        self.assertFalse(log[0]["accepted"])
        return log[0]

    def test_an_id_that_was_not_listed(self):
        entry = self.decide(plain("Plex Media Server") | {"same_as": "https://example.com/other"})
        self.assertEqual((entry["why"], entry["same_as"]), ("not listed", {"id": "https://example.com/other", "title": ""}))

    def test_a_candidate_that_got_a_cve_meanwhile(self):
        entry = self.decide(plain("Plex Media Server") | {"same_as": PLEX_BC}, lambda: self.candidate["cves"].append("CVE-2026-1"))
        self.assertEqual(entry["why"], "has a CVE now")

    def test_a_candidate_no_longer_on_the_board(self):
        entry = self.decide(plain("Plex Media Server") | {"same_as": PLEX_BC},
                            lambda: self.candidate["summary"].update(incident=False))
        self.assertEqual(entry["why"], "not on the Board")

    def test_a_candidate_gone_meanwhile(self):
        def gone():
            self.incidents.remove(self.candidate)
            self.incidents.append(self.candidate | {"id": "https://example.com/elsewhere"})
        listed = summaries.same_as_candidates(self.asker, self.incidents, at(STAMP[:-1]))
        quiet(summaries.summarize_now, self.asker, FakeClaude(plain("Plex Media Server") | {"same_as": PLEX_BC}), no_pages, STAMP, listed)
        gone()
        (_, log), _ = quiet(summaries.apply_same_as, self.incidents, STAMP)
        self.assertEqual((log[0]["why"], log[0]["accepted"]), ("gone", False))

    def test_no_shared_product(self):
        entry = self.decide(plain("Plex Web App") | {"same_as": PLEX_BC})
        self.assertEqual(entry["why"], "no shared Product")

    def test_a_vendor_or_suffix_spelling_still_counts_as_the_same_product(self):
        self.candidate["summary"]["products"] = ["Plex Media Server plugin"]  # product_key drops the generic suffix
        quiet(summaries.summarize_now, self.asker, FakeClaude(plain("Plex Media Server") | {"same_as": PLEX_BC}), no_pages, STAMP,
              [self.candidate])
        (_, log), _ = quiet(summaries.apply_same_as, self.incidents, STAMP)
        self.assertEqual(log[0]["why"], "accepted")

    def test_a_same_as_that_is_not_text_never_fails_the_summary(self):
        quiet(summaries.summarize_now, self.asker, FakeClaude(plain("Plex Media Server") | {"same_as": 7}), no_pages, STAMP,
              [self.candidate])
        self.assertIn("summary", self.asker)
        self.assertNotIn("same_as", self.asker["summary"])
        (_, log), _ = quiet(summaries.apply_same_as, self.incidents, STAMP)
        self.assertEqual((log[0]["same_as"], log[0]["why"]), ("", "none named"))

    def test_titles_in_the_log_are_short_and_printable(self):
        self.candidate["summary"]["en"]["title"] = "Bad\x1b[31m title"
        quiet(summaries.summarize_now, self.asker, FakeClaude(plain("Plex Media Server") | {"same_as": PLEX_BC}), no_pages, STAMP,
              [self.candidate])
        (_, log), _ = quiet(summaries.apply_same_as, self.incidents, STAMP)
        self.assertEqual(log[0]["same_as"]["title"], "")


CHROME_SW = "https://www.securityweek.com/chrome-xml-zero-day/"
CHROME_BC = "https://www.bleepingcomputer.com/news/security/google-chrome-xml-zero-day/"
NC_BC = "https://www.bleepingcomputer.com/news/security/n-able-n-central-flaw/"
NC_SW = "https://www.securityweek.com/n-able-n-central-flaw/"
NC_TR = "https://therecord.media/n-able-n-central-flaw"
ROUTER = "https://www.securityweek.com/acme-router-flaw/"


class AskedAgainOnceTest(unittest.TestCase):
    """Owner, 11-10 ("갈라진 줄들 합쳐줘"): CVE-less Incidents summarized before same_as shipped are asked once more, with
    the candidate list, so duplicates from before then merge through apply_same_as as usual."""

    def setUp(self):
        self.store = MemoryStore()

    def cycle(self, now, claude, rows=None):
        if rows is not None:
            seed(self.store, rows)
        _, err = quiet(run_cycle, self.store, recorded(None), at(now), "test-box", claude=claude)
        return err

    def test_a_pair_naming_each_other_in_one_cycle_ends_as_one_row(self):
        a = story(CHROME_SW, "2026-11-10T06:20:00Z", "Chrome XML zero-day exploited", ["Google Chrome"], asked=False)
        b = story(CHROME_BC, "2026-11-10T08:55:00Z", "Google Chrome fixes an XML zero-day", ["Google Chrome"], asked=False)
        claude = FakeClaude(plain("Google Chrome") | {"same_as": CHROME_BC}, plain("Google Chrome") | {"same_as": CHROME_SW})
        self.cycle("2026-11-10T09:00:00", claude, [a, b])

        self.assertIn(f"- {CHROME_BC} |", claude.user_text(0))
        self.assertIn(f"- {CHROME_SW} |", claude.user_text(1))
        incidents = board(self.store)
        self.assertEqual(list(incidents), [CHROME_SW])  # the earlier first seen
        self.assertEqual(incidents[CHROME_SW]["absorbed"], [CHROME_BC])
        self.assertTrue(incidents[CHROME_SW]["same_as_asked"])
        self.assertNotIn("same_as_due", incidents[CHROME_SW])
        self.assertEqual([(e["incident"]["id"], e["why"]) for e in self.store.read("merge_log.json")],
                         [(CHROME_BC, "already one"), (CHROME_SW, "accepted")])

    def test_three_rows_of_one_event_end_as_one_row(self):
        rows = [story(url, when, f"N-able N-central flaw {k}", ["N-able N-central"], asked=False)
                for k, (url, when) in enumerate([(NC_BC, "2026-11-09T21:30:00Z"), (NC_SW, "2026-11-10T02:05:00Z"),
                                                 (NC_TR, "2026-11-10T03:00:00Z")])]
        reply = lambda same: plain("N-able N-central") | {"same_as": same}
        self.cycle("2026-11-10T09:00:00", FakeClaude(reply(NC_SW), reply(NC_TR), reply(NC_SW)), rows)

        incidents = board(self.store)
        self.assertEqual(list(incidents), [NC_BC])
        self.assertEqual(incidents[NC_BC]["absorbed"], [NC_SW, NC_TR])
        self.assertEqual([e["why"] for e in self.store.read("merge_log.json")], ["already one", "accepted", "accepted"])

    def test_a_later_batch_result_naming_an_incident_folded_meanwhile_joins_its_survivor(self):
        early = story(PLEX_BC, "2026-11-06T17:10:00Z", "Plex2Shell takes over Plex Media Server", ["Plex Media Server"], asked=False)
        later = story(PLEX_SW, "2026-11-09T13:20:00Z", "Plex Media Server flaw Plex2Shell", ["Plex Media Server"], asked=False)
        hn = story(NCENTRAL_HN, "2026-11-09T12:00:00Z", "Plex Media Server takeover write-up", ["Plex Media Server"], asked=False,
                   mentions=[{"kind": "writeup", "url": "https://example.org/plex-writeup"}, {"kind": "discussion", "url": NCENTRAL_HN}])
        claude = FakeClaude(plain("Plex Media Server") | {"same_as": ""}, plain("Plex Media Server") | {"same_as": PLEX_BC})
        self.cycle("2026-11-09T13:30:00", claude, [early, later, hn])
        self.assertEqual(set(board(self.store)), {PLEX_BC, NCENTRAL_HN})  # later folded into early; hn waits in a batch
        self.assertEqual(self.store.read("batches.json")[0]["requests"]["r0"]["candidates"], [PLEX_SW, PLEX_BC])

        claude.end_batch({"no CVE yet": plain("Plex Media Server") | {"same_as": PLEX_SW}})
        claude.replies.append(plain("Plex Media Server") | {"same_as": ""})  # early's re-summary: it merged
        self.cycle("2026-11-09T13:40:00", claude)

        incidents = board(self.store)
        self.assertEqual(list(incidents), [PLEX_BC])
        self.assertEqual(incidents[PLEX_BC]["absorbed"], [PLEX_SW, NCENTRAL_HN])
        entry = next(e for e in self.store.read("merge_log.json") if e["incident"]["id"] == NCENTRAL_HN)
        self.assertEqual((entry["why"], entry["into"]), ("accepted", PLEX_BC))

    def test_an_unrelated_incident_is_asked_once_even_at_its_summary_limit_and_left_alone(self):
        router = story(ROUTER, "2026-11-09T10:00:00Z", "Acme router flaw", ["Acme Router"], asked=False)
        router["summary_basis"]["n"] = summaries.MAX_SUMMARIES
        cve = incident("CVE-2026-5555", "A flaw", "2026-11-09T09:00:00Z", "2026-11-09T09:00:00Z") | {
            "summary": plain("Other"), "summary_basis": {"cves": ["CVE-2026-5555"], "kev": False, "advisories": [], "n": 1}}
        claude = FakeClaude(plain("Acme Router") | {"same_as": ""})
        self.cycle("2026-11-09T12:00:00", claude, [router, cve])

        self.assertEqual(len(claude.sent), 1)  # the Incident with a CVE is never asked
        self.assertNotIn(summaries.SAME_AS_HEAD, claude.user_text())  # no candidates: still asked once, still marked
        stored = board(self.store)[ROUTER]
        self.assertEqual((stored["summary"]["en"]["title"], stored["summary_basis"]["n"]), ("Acme Router flaw", summaries.MAX_SUMMARIES))
        self.assertTrue(stored["same_as_asked"])
        self.assertNotIn("same_as_asked", board(self.store)["CVE-2026-5555"])

        self.cycle("2026-11-09T12:10:00", claude)
        self.assertEqual(len(claude.sent), 1)

    def test_a_rejected_reply_keeps_the_question_and_the_retry_merges(self):
        early = story(PLEX_BC, "2026-11-06T17:10:00Z", "Plex2Shell takes over Plex Media Server", ["Plex Media Server"])
        later = story(PLEX_SW, "2026-11-09T13:20:00Z", "Able2Shell in Plex Media Server", ["Plex Media Server"], asked=False)
        claude = FakeClaude('{"ko": {"title": "cut', plain("Plex Media Server") | {"same_as": PLEX_BC})
        self.cycle("2026-11-09T13:30:00", claude, [early, later])

        stored = board(self.store)[PLEX_SW]
        self.assertEqual((stored["summary_error"]["tries"], stored["same_as_due"]), (1, True))
        shown = {i["id"]: i for i in self.store.read("board/recent.json")["incidents"]}[PLEX_SW]
        self.assertEqual(shown["summary"]["en"]["title"], "Able2Shell in Plex Media Server")  # the old Summary stays shown
        self.assertNotIn("summary_error", shown)

        self.cycle("2026-11-09T13:40:00", claude)
        self.assertIn("Your previous reply for this Incident was rejected", claude.user_text(1))
        self.assertIn(f"- {PLEX_BC} |", claude.user_text(1))
        self.assertEqual(list(board(self.store)), [PLEX_BC])

    def test_three_rejections_end_the_question_and_keep_the_old_summary(self):
        router = story(ROUTER, "2026-11-09T10:00:00Z", "Acme router flaw", ["Acme Router"], asked=False)
        claude = FakeClaude(*['{"ko": {"title": "cut'] * summaries.MAX_TRIES)
        self.cycle("2026-11-09T12:00:00", claude, [router])
        self.cycle("2026-11-09T12:10:00", claude)
        err = self.cycle("2026-11-09T12:20:00", claude)

        self.assertIn(f"summaries: same_as: {ROUTER} not asked again: its Summary was given up", err)
        stored = board(self.store)[ROUTER]
        self.assertEqual(stored["summary"]["en"]["title"], "Acme router flaw")
        self.assertNotIn("same_as_due", stored)
        self.assertTrue(stored["summary_error"]["final"])
        self.assertEqual([(f["id"], f["shows"]) for f in self.store.read("summary_failures.json")], [(ROUTER, "summary")])

        self.cycle("2026-11-09T12:30:00", claude)
        self.assertEqual(len(claude.sent), summaries.MAX_TRIES)  # no fourth request

    def test_a_given_up_incident_is_not_asked_but_says_so_once(self):
        router = story(ROUTER, "2026-11-09T10:00:00Z", "Acme router flaw", ["Acme Router"], asked=False)
        router["summary_error"] = {"tries": summaries.MAX_TRIES, "final": True, "reason": "x", "with_reason": True,
                                   "hinted": True, "ko_words": True}
        claude = FakeClaude()
        err = self.cycle("2026-11-09T12:00:00", claude, [router])
        self.assertIn(f"summaries: same_as: {ROUTER} not asked again: its Summary was given up", err)
        err = self.cycle("2026-11-09T12:10:00", claude)
        self.assertNotIn("not asked again", err)
        self.assertEqual(claude.sent, [])


if __name__ == "__main__":
    unittest.main()
