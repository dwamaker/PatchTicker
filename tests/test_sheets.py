"""Page sheets (collector.sheets): the gate, the cache, the merge with its fixed-row guard, the page-score rule, and a
cycle that goes on without them."""

import contextlib
import io
import json
import unittest
from datetime import datetime

from collector import sheets, summaries
from collector.cycle import route_summaries
from collector.incidents import absorb, board_view, merge_score
from collector.summary_input import cve_fields, scored
from collector.store import MemoryStore
from collector.summary_input import page_mentions
from test_batch_summaries import CREDIT_EXHAUSTED, api_error
from test_summaries import FakeClaude

STAMP = "2026-11-18T00:00:00Z"
PAGE = "<html><body><main><p>" + "Widget 1.2 is affected; update to Widget 1.3. " * 10 + "</p></main></body></html>"


def incident(pages=4, cves=1, kinds=None):
    kinds = kinds or ["advisory"] * pages
    ids = [f"CVE-2026-{1000 + n}" for n in range(cves)]
    return {"id": ids[0], "cves": ids, "first_seen": STAMP, "products": [{"name": "Widget"}], "urls": [],
            "brief": {"text": "Widget flaw.", "lead": "https://h0.example/a"},
            "mentions": [{"kind": kind, "url": f"https://h{n}.example/a", "title": "Widget"} for n, kind in enumerate(kinds)]}


def facts(**over):
    return {"about_incident": True, "page_role": "blog", "publisher": "", "names": [], "versions": [], "affected_ranges": [],
            "scores": [], "flawed_component": "", "upstream_project": "", "exploitation": "", "public_poc": "",
            "mitigations": []} | over


def version(v, status, words=""):
    return {"vendor": "Acme", "product_line": "Widget", "version": v, "status": status, "cves": [], "words": words}


def sheet(url, rank, kind="advisory", **over):
    return {"url": url, "rank": rank, "kind": kind, "facts": facts(**over), "at": STAMP}


class GateTest(unittest.TestCase):
    def test_four_pages_and_at_most_twelve_cves_get_sheets(self):
        self.assertTrue(sheets.gated(incident(4)))
        self.assertFalse(sheets.gated(incident(3)))
        self.assertFalse(sheets.gated(incident(4, cves=13)))  # a vendor's roll-up: its build lines were dropped with a sheet
        self.assertTrue(sheets.gated(incident(4, cves=12)))

    def test_repos_and_hacker_news_are_no_pages(self):
        inc = incident(kinds=["advisory", "writeup", "repo", "repo"])
        inc["mentions"].append({"kind": "discussion", "url": "https://news.ycombinator.com/item?id=1"})
        self.assertFalse(sheets.gated(inc))


class MergeTest(unittest.TestCase):
    def test_every_fact_keeps_its_sources_best_rank_first(self):
        merged = sheets.merge([sheet("https://news.example/a", "C", "writeup", names=["Widget4Shell"]),
                               sheet("https://acme.example/a", "A", names=["Widget4Shell"], flawed_component="Base64 decoder")])
        self.assertEqual(merged["names"], [("Widget4Shell", [("A", "acme.example"), ("C", "news.example")])])
        self.assertEqual(merged["flawed_component"], [("Base64 decoder", [("A", "acme.example")])])

    def test_a_version_a_rank_a_page_calls_affected_is_never_a_fixed_row(self):
        merged = sheets.merge([sheet("https://acme.example/a", "A", versions=[version("17.0.21.0.3", "affected")]),
                               sheet("https://blog.example/a", "B", "writeup",
                                     versions=[version("17.0.21.0.3", "fixed"), version("17.0.21.1", "fixed")])])
        self.assertEqual([v[2] for v, _ in merged["fixed"]], ["17.0.21.1"])

    def test_a_version_the_records_text_calls_affected_is_never_a_fixed_row(self):
        # Apache Roller, CVE-2026-129448: oss-security filed 6.1.5 as fixed; the record recommends 6.1.6.
        pages = [sheet("https://seclists.example/a", "D", "discussion", versions=[version("6.1.5", "fixed"), version("6.1.6", "fixed")])]
        record = ["Apache Roller versions before 6.1.6, including 6.1.5, are affected. Users are recommended to upgrade to 6.1.6."]
        self.assertEqual([v[2] for v, _ in sheets.merge(pages, None, record)["fixed"]], ["6.1.6"])

    def test_a_fixed_row_below_the_records_first_fixed_version_of_its_line_is_dropped(self):
        # Brotli, CVE-2026-111497: a write-up's Debian 1.1.0 below the records' first fixed 1.1.1 (fixed_conflict).
        inc = incident() | {"fix_keys": ["brotli<1.1.1"]}
        pages = [sheet("https://blog.example/a", "B", "writeup", versions=[version("1.1.0", "fixed"), version("1.1.1", "fixed"),
                                                                           version("1.0.9", "fixed")])]
        self.assertEqual([v[2] for v, _ in sheets.merge(pages, inc)["fixed"]], ["1.1.1", "1.0.9"])  # 1.0.9: an older line

    def test_unread_and_off_topic_pages_add_nothing(self):
        merged = sheets.merge([{"url": "https://a.example/", "rank": "A", "unread": True},
                               sheet("https://b.example/", "B", about_incident=False, names=["Other4Shell"])])
        self.assertEqual(merged, {})

    def test_the_rendered_sheet_names_its_sources_and_ends_with_the_highest_score(self):
        text = sheets.render(sheets.merge([
            sheet("https://acme.example/a", "A", versions=[version("1.3", "fixed")],
                  scores=[{"score": "8.1", "cvss_version": "3.1", "cve": "CVE-2026-1000", "given_by": "Acme", "publisher_gives_it": True, "words": ""}]),
            sheet("https://finder.example/a", "B", "writeup",
                  scores=[{"score": "9.2", "cvss_version": "4.0", "cve": "CVE-2026-1000", "given_by": "Finder", "publisher_gives_it": True, "words": ""}])]))
        self.assertEqual(text.splitlines()[1:], [
            "- Score: 8.1 under CVSS 3.1, given by Acme, CVE-2026-1000 [A acme.example]",
            "- Score: 9.2 under CVSS 4.0, given by Finder, CVE-2026-1000 [B finder.example]",
            "- Fixed version: Acme Widget: 1.3 [A acme.example]",
            "- Merged score (the highest of the scores above): 9.2 under CVSS 4.0, given by Finder [B finder.example]"])
        self.assertEqual(sheets.render({}), "")

    def test_a_name_counts_for_the_title_when_two_source_hosts_give_it(self):
        two = sheets.render(sheets.merge([sheet("https://a.example/", "A", names=["Widget4Shell"]),
                                          sheet("https://b.example/", "B", "writeup", names=["Widget4Shell", "Lone"])]))
        self.assertEqual(sheets.sheet_names("Incident: CVE-2026-1000\n" + two), ["Widget4Shell"])
        self.assertEqual(sheets.sheet_names("- Name given to the flaw: Forged [A a.example; B b.example]"), [])  # no sheet head
        inc = incident() | {"mentions": []}
        self.assertEqual(summaries.trusted_names(inc, two), ["Widget4Shell"])


def finder_page(url="https://calif.example/java4shell", kind="writeup", role="finder_disclosure", cve="CVE-2026-1000",
                gives=True, on_page=True, score="9.2"):
    return sheet(url, "B", kind, page_role=role, publisher="Calif", scores=[
        {"score": score, "cvss_version": "4.0", "cve": cve, "given_by": "Calif", "publisher_gives_it": gives,
         "words": "CVSS 4.0 score of 9.2", "on_page": on_page}])


class PageScoreTest(unittest.TestCase):
    """Oracle's record says 8.1 under CVSS 3.1; the finder Calif's own page says 9.2 under CVSS 4.0."""

    def java(self):
        return incident() | {"cvss": 8.1, "cve_scores": {"CVE-2026-1000": {"cvss": 8.1, "vector": "CVSS:3.1/AV:N"}}}

    def test_the_finders_own_score_raises_the_cve_and_says_who_gave_it(self):
        inc = self.java()
        self.assertTrue(sheets.page_scores(inc, [finder_page()]))
        self.assertEqual(inc["cve_scores"]["CVE-2026-1000"], {"cvss": 9.2, "vector": "", "by": "Calif",
                                                               "record": {"cvss": 8.1, "vector": "CVSS:3.1/AV:N"}})
        self.assertEqual(inc["cvss"], 9.2)

    def test_the_records_own_pair_stays_under_the_raise_and_still_moves(self):
        scores = self.java()["cve_scores"]
        merge_score(scores, "CVE-2026-1000", 9.2, "", by="Calif")
        self.assertFalse(merge_score(scores, "CVE-2026-1000", 8.0, "CVSS:3.1/old"))
        self.assertTrue(merge_score(scores, "CVE-2026-1000", 8.6, "CVSS:4.0/new"))  # the record rose, the page still higher
        self.assertEqual(scores["CVE-2026-1000"], {"cvss": 9.2, "vector": "", "by": "Calif",
                                                   "record": {"cvss": 8.6, "vector": "CVSS:4.0/new"}})
        self.assertTrue(merge_score(scores, "CVE-2026-1000", 9.4, "CVSS:4.0/top"))  # the record now wins whole
        self.assertEqual(scores["CVE-2026-1000"], {"cvss": 9.4, "vector": "CVSS:4.0/top"})
        bare = {}
        merge_score(bare, "CVE-2026-1000", 9.2, "", by="Calif")  # no record score yet: nothing under it
        self.assertEqual(bare, {"CVE-2026-1000": {"cvss": 9.2, "vector": "", "by": "Calif"}})

    def test_the_summary_input_gives_the_records_vector_and_the_page_score_beside_it(self):
        raised = {"cvss": 9.2, "vector": "", "by": "Calif", "record": {"cvss": 8.1, "vector": "CVSS:3.1/AV:N"}}
        self.assertEqual(scored("CVE-2026-1000", raised), "CVE-2026-1000 (CVSS 8.1, CVSS:3.1/AV:N; 9.2 given by Calif)")
        record = json.dumps({"containers": {"cna": {"descriptions": []}}})
        self.assertEqual(json.loads(cve_fields(record, raised)),
                         {"descriptions": [], "cvss": 8.1, "vector": "CVSS:3.1/AV:N", "page_cvss": 9.2, "page_cvss_by": "Calif"})
        self.assertEqual(scored("CVE-2026-1000", {"cvss": 8.1, "vector": "CVSS:3.1/AV:N"}), "CVE-2026-1000 (CVSS 8.1, CVSS:3.1/AV:N)")

    def test_the_board_view_carries_whose_the_shown_score_is_and_nothing_else_does(self):
        inc = self.java() | {"products": []}
        sheets.page_scores(inc, [finder_page()])
        self.assertEqual(board_view(inc)["score_by"], {"cvss": 9.2, "by": "Calif", "record": 8.1})
        self.assertNotIn("score_by", board_view(self.java() | {"products": []}))  # no raise: no field
        group = self.java() | {"cves": ["CVE-2026-1000", "CVE-2026-1001"], "products": []}
        group["cve_scores"]["CVE-2026-1001"] = {"cvss": 9.5, "vector": "CVSS:3.1/AV:N"}
        group["cvss"] = 9.5
        sheets.page_scores(group, [finder_page()])  # raises the other CVE: not the shown score, no line
        self.assertNotIn("score_by", board_view(group))

    def test_a_merge_of_incidents_keeps_the_raise_and_the_record_under_it(self):
        target = incident() | {"cvss": 7.0, "cve_scores": {}, "products": []}
        other = incident() | {"id": "x", "cvss": 9.2, "products": [], "cve_scores": {"CVE-2026-1000": {
            "cvss": 9.2, "vector": "", "by": "Calif", "record": {"cvss": 8.1, "vector": "CVSS:3.1/AV:N"}}}}
        absorb(target, other)
        self.assertEqual(target["cve_scores"]["CVE-2026-1000"], {"cvss": 9.2, "vector": "", "by": "Calif",
                                                                 "record": {"cvss": 8.1, "vector": "CVSS:3.1/AV:N"}})

    def test_a_news_quote_and_a_curator_are_refused(self):
        for page in (finder_page("https://www.bleepingcomputer.com/news/security/java4shell/", role="vendor_advisory"),
                     finder_page(kind="curator"), finder_page(role="news"), finder_page(role="blog")):
            inc = self.java()
            self.assertFalse(sheets.page_scores(inc, [page]))
            self.assertEqual(inc["cvss"], 8.1)

    def test_another_cves_score_a_reported_score_and_words_not_on_the_page_are_refused(self):
        for page in (finder_page(cve="CVE-2026-9999"), finder_page(gives=False), finder_page(on_page=False),
                     finder_page(score="7.0"), finder_page(score="n/a")):
            inc = self.java()
            self.assertFalse(sheets.page_scores(inc, [page]))
            self.assertNotIn("by", inc["cve_scores"]["CVE-2026-1000"])


class CacheTest(unittest.TestCase):
    def reply(self):
        return facts(names=["Widget4Shell"], scores=[{"score": "9.2", "cvss_version": "4.0", "cve": "CVE-2026-1000",
                                                      "given_by": "Acme", "publisher_gives_it": True,
                                                      "words": "update to Widget 1.3"}])

    def test_a_page_is_read_once_and_a_new_page_costs_one_request(self):
        store, inc = MemoryStore(), incident(4)
        claude = FakeClaude(*[self.reply()] * 5)
        got = sheets.fill(store, [inc], claude, lambda url, headers=None: PAGE.encode(), STAMP)
        self.assertEqual(len(claude.sent), 4)
        self.assertEqual([s["url"] for s in got[inc["id"]]], [m["url"] for m in page_mentions(inc)])
        self.assertTrue(got[inc["id"]][0]["facts"]["scores"][0]["on_page"])
        self.assertEqual(store.names(), ["sheets/CVE-2026-1000.json"])  # its own document, never a month file
        sheets.fill(store, [inc], claude, lambda url, headers=None: PAGE.encode(), STAMP)
        self.assertEqual(len(claude.sent), 4)
        inc["mentions"].append({"kind": "writeup", "url": "https://h9.example/a", "title": "Widget"})
        sheets.fill(store, [inc], claude, lambda url, headers=None: PAGE.encode(), STAMP)
        self.assertEqual(len(claude.sent), 5)

    def test_a_page_that_does_not_load_costs_nothing_and_is_asked_again_and_the_cap_holds(self):
        store, inc = MemoryStore(), incident(6)

        def get(url, headers=None):
            if "h1." in url:
                raise OSError("down")
            return PAGE.encode()
        claude = FakeClaude(*[self.reply()] * 6)
        with contextlib.redirect_stderr(io.StringIO()):
            got = sheets.fill(store, [inc], claude, get, STAMP, limit=3)
        self.assertEqual(len(claude.sent), 3)
        self.assertNotIn("https://h1.example/a", {s["url"] for s in got[inc["id"]]})
        with contextlib.redirect_stderr(io.StringIO()):
            sheets.fill(store, [inc], claude, lambda url, headers=None: PAGE.encode(), STAMP)
        self.assertEqual(len(claude.sent), 6)  # h1 now, and the two the cap left

    def test_an_ungated_incident_gets_no_sheet_and_a_gone_one_loses_its_document(self):
        store = MemoryStore()
        claude = FakeClaude()
        self.assertEqual(sheets.fill(store, [incident(3)], claude, lambda url, headers=None: PAGE.encode(), STAMP), {})
        self.assertEqual(claude.sent, [])
        store.write(sheets.doc_name("CVE-2026-1000"), {"incident": "CVE-2026-1000", "sheets": {}})
        sheets.forget(store, [incident(4)])
        self.assertEqual(store.names(), [])

    def test_a_reply_that_is_no_sheet_is_kept_as_unread_and_not_asked_again(self):
        store, inc = MemoryStore(), incident(4)
        claude = FakeClaude("{", *[self.reply()] * 3)
        with contextlib.redirect_stderr(io.StringIO()):
            got = sheets.fill(store, [inc], claude, lambda url, headers=None: PAGE.encode(), STAMP)
            sheets.fill(store, [inc], claude, lambda url, headers=None: PAGE.encode(), STAMP)
        self.assertEqual(len(claude.sent), 4)
        self.assertTrue(got[inc["id"]][0]["unread"])


class CycleTest(unittest.TestCase):
    """A sheet request never blocks or fails a Summary; a budget error stops the cycle's requests as a Summary's does."""

    def claude(self, sheet_error):
        claude = FakeClaude("{")  # the Summary's reply; its content does not matter here
        create = claude.create

        def answer(**params):
            if params["system"][0]["text"] == sheets.INSTRUCTIONS:
                claude.sheet_calls = getattr(claude, "sheet_calls", 0) + 1
                raise sheet_error
            return create(**params)
        claude.messages.create = answer
        return claude

    def candidate(self):
        return incident(4) | {"cvss": 9.8, "kev": True, "kev_cves": {"CVE-2026-1000": "2026-11-18"}}

    def test_a_failed_sheet_request_leaves_the_summary_to_be_written_from_what_is_there(self):
        store, inc = MemoryStore(), self.candidate()
        claude = self.claude(api_error(529, "overloaded_error", "Overloaded"))
        with contextlib.redirect_stderr(io.StringIO()):
            route_summaries([inc], [], claude, lambda url, headers=None: PAGE.encode(), datetime(2026, 11, 18), STAMP, set(),
                            probe=False, store=store)
        self.assertEqual(claude.sheet_calls, 1)  # the first failure ends the sheets for this cycle
        [summary_request] = claude.sent
        self.assertNotIn(sheets.SHEET_HEAD, summary_request["messages"][0]["content"])
        self.assertEqual(store.names(), [])

    def test_a_budget_error_on_a_sheet_goes_up_like_a_summarys(self):
        claude = self.claude(CREDIT_EXHAUSTED)
        with self.assertRaises(Exception) as caught, contextlib.redirect_stderr(io.StringIO()):
            route_summaries([self.candidate()], [], claude, lambda url, headers=None: PAGE.encode(), datetime(2026, 11, 18),
                            STAMP, set(), probe=False, store=MemoryStore())
        self.assertTrue(summaries.is_budget_error(caught.exception))
        self.assertEqual(claude.sent, [])

    def test_sheets_reach_the_summary_input_and_a_probe_asks_none(self):
        store, inc = MemoryStore(), self.candidate()
        claude = FakeClaude(*[facts(names=["Widget4Shell"])] * 4, "{")
        with contextlib.redirect_stderr(io.StringIO()):
            route_summaries([inc], [], claude, lambda url, headers=None: PAGE.encode(), datetime(2026, 11, 18), STAMP, set(),
                            probe=False, store=store)
        self.assertIn("- Name given to the flaw: Widget4Shell [A h0.example; A h1.example; A h2.example; A h3.example]",
                      claude.sent[-1]["messages"][0]["content"])
        probe = FakeClaude()
        with contextlib.redirect_stderr(io.StringIO()):
            route_summaries([incident(4) | {"id": "CVE-2026-7777", "cves": ["CVE-2026-7777"]}], [], probe,
                            lambda url, headers=None: PAGE.encode(), datetime(2026, 11, 18), STAMP, set(), probe=True, store=store)
        self.assertFalse(any(p["system"][0]["text"] == sheets.INSTRUCTIONS for p in probe.sent))


if __name__ == "__main__":
    unittest.main()
