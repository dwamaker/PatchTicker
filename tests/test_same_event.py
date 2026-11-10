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
from test_cycle import at, recorded
from test_summaries import FakeClaude, board

PLEX_BC = "https://www.bleepingcomputer.com/news/security/plex2shell-flaw-lets-attackers-take-over-plex-servers/"
PLEX_SW = "https://www.securityweek.com/plex-media-server-flaw-plex2shell/"
NCENTRAL_HN = "https://news.ycombinator.com/item?id=46000001"
NCENTRAL_BC = "https://www.bleepingcomputer.com/news/security/n-able-n-central-flaw/"
STAMP = "2026-11-09T13:30:00Z"


def story(url, first_seen, title=None, products=(), mentions=None):
    """A CVE-less news or HN Incident; with a title it already has a Summary naming these products."""
    mentions = mentions or [{"kind": "writeup", "url": url}]
    incident = {"id": url, "cves": [], "first_seen": first_seen, "published": first_seen, "mentions": mentions,
                "urls": sorted({url_key(m["url"]) for m in mentions}), "brief": {"text": "A story", "lead": mentions[0]["url"]}}
    if title:
        reply = plain(products[0])
        incident["summary"] = reply | {"en": reply["en"] | {"title": title}, "at": first_seen}
        incident["summary_basis"] = summaries.basis(incident) | {"n": 1}
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
            "accepted": True, "why": "accepted"}])
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


if __name__ == "__main__":
    unittest.main()
