"""Page sheets (collector.sheets): the gate, the cache, the merge with its fixed-row guard, the page-score rule, and a
cycle that goes on without them."""

import contextlib
import copy
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
    return {"id": ids[0], "cves": ids, "first_seen": STAMP, "products": [{"id": "acme:widget", "name": "Widget"}], "urls": [],
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
                gives=True, on_page=True, score="9.2", given_by="Calif"):
    return sheet(url, "B", kind, page_role=role, publisher="Calif", scores=[
        {"score": score, "cvss_version": "4.0", "cve": cve, "given_by": given_by, "publisher_gives_it": gives,
         "words": "CVSS 4.0 score of 9.2", "on_page": on_page}])


class PageScoreTest(unittest.TestCase):
    """Oracle's record says 8.1 under CVSS 3.1; the finder Calif's own page says 9.2 under CVSS 4.0."""

    def java(self):
        return incident() | {"cvss": 8.1, "cve_scores": {"CVE-2026-1000": {"cvss": 8.1, "vector": "CVSS:3.1/AV:N"}}}

    def test_the_finders_own_score_raises_the_cve_and_says_who_gave_it(self):
        inc = self.java()
        self.assertTrue(sheets.page_scores(inc, [finder_page()]))
        self.assertEqual(inc["cve_scores"]["CVE-2026-1000"], {"cvss": 9.2, "vector": "", "by": "Calif", "version": "4.0",
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
        self.assertEqual(board_view(inc)["score_by"], {"cvss": 9.2, "version": "4.0", "record": 8.1, "record_version": "3.1"})
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

    def test_a_row_given_by_the_publisher_by_name_counts_when_the_model_says_otherwise(self):
        # The live sheet of https://calif.io/java4shell/ (11-18): publisher_gives_it came back false.
        live = sheet("https://calif.io/java4shell/", "B", "writeup", page_role="finder_disclosure", publisher="Calif", scores=[
            {"score": "9.2", "cvss_version": "4.0", "cve": "CVE-2026-1000", "given_by": "Calif", "publisher_gives_it": False,
             "words": "Under CVSS 4.0, this vulnerability scores 9.2 out of 10 (CRITICAL).", "on_page": True}])
        inc = self.java()
        self.assertTrue(sheets.page_scores(inc, [live]))
        self.assertEqual((inc["cvss"], inc["cve_scores"]["CVE-2026-1000"]["by"]), (9.2, "Calif"))
        for given_by in ("Calif.io", "Calif Research", "calif"):
            self.assertTrue(sheets.same_party(given_by, "Calif"), given_by)
        for given_by in ("Califa", "Oracle Calif", ""):
            self.assertFalse(sheets.same_party(given_by, "Calif"), given_by)
        self.assertFalse(sheets.same_party("Oracle Cloud Infrastructure", "Oracle"))

    def test_a_score_whose_number_is_not_in_its_words_is_refused(self):
        # elixir-grpc, CVE-2026-123635 (re-summary dry run 11-18): the model worked 8.7 out of the vector; the GitHub page
        # says "High 8.2".
        vector = sheet("https://github.com/elixir-grpc/grpc/security/advisories/GHSA-c2h9-f9cc", "A", page_role="vendor_advisory",
                       publisher="elixir-grpc", scores=[{"score": "8.7", "cvss_version": "4.0", "cve": "CVE-2026-1000",
                                                          "given_by": "elixir-grpc", "publisher_gives_it": True, "on_page": True,
                                                          "words": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"}])
        inc = self.java()
        self.assertFalse(sheets.page_scores(inc, [vector]))
        self.assertEqual(inc["cvss"], 8.1)

    def test_a_version_the_words_do_not_state_is_not_kept(self):
        # SonicWall's advisory writes "CVSS Score: 5.2": the number counts, the claimed 3.1 is not kept.
        page = sheet("https://psirt.example/SNWLID-2026-0014", "A", page_role="vendor_advisory", publisher="SonicWall", scores=[
            {"score": "9.2", "cvss_version": "3.1", "cve": "CVE-2026-1000", "given_by": "SonicWall", "publisher_gives_it": True,
             "words": "CVSS Score: 9.2", "on_page": True}])
        inc = self.java()
        self.assertTrue(sheets.page_scores(inc, [page]))
        self.assertNotIn("version", inc["cve_scores"]["CVE-2026-1000"])
        for words, version in (("Under CVSS 4.0, this vulnerability scores 9.2", "4.0"), ("CVSSv4 base score 9.2", "4.0"),
                               ("CVSS:4.0/AV:N 9.2", "4.0"), ("score 9.2", "")):
            self.assertEqual(sheets.stated_version({"cvss_version": "4.0", "words": words}), version, words)

    def test_a_blog_quoting_another_partys_score_is_refused(self):
        blog = sheet("https://aikido.example/java4shell", "B", "writeup", page_role="blog", publisher="Aikido", scores=[
            {"score": "9.2", "cvss_version": "4.0", "cve": "CVE-2026-1000", "given_by": "Calif", "publisher_gives_it": False,
             "words": "early reports put it at 9.2", "on_page": True}])
        inc = self.java()
        self.assertFalse(sheets.page_scores(inc, [blog]))
        self.assertFalse(sheets.page_scores(inc, [blog | {"facts": blog["facts"] | {"page_role": "finder_disclosure"}}]))
        self.assertEqual(inc["cvss"], 8.1)

    def test_a_news_quote_and_a_curator_are_refused(self):
        for page in (finder_page("https://www.bleepingcomputer.com/news/security/java4shell/", role="vendor_advisory"),
                     finder_page(kind="curator"), finder_page(role="news"), finder_page(role="blog")):
            inc = self.java()
            self.assertFalse(sheets.page_scores(inc, [page]))
            self.assertEqual(inc["cvss"], 8.1)

    def test_another_cves_score_a_reported_score_and_words_not_on_the_page_are_refused(self):
        for page in (finder_page(cve="CVE-2026-9999"), finder_page(gives=False, given_by="Oracle"), finder_page(on_page=False),
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
        counts = {"sheets_asked": 0, "sheets_failed": 0, "sheets_kept_back": 0}
        with contextlib.redirect_stderr(io.StringIO()):
            got = sheets.fill(store, [inc], claude, get, STAMP, limit=3, counts=counts)
        self.assertEqual(len(claude.sent), 3)
        self.assertEqual(counts, {"sheets_asked": 3, "sheets_failed": 0, "sheets_kept_back": 2})  # the cycle's log line
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

    def test_a_page_the_sheets_fetched_is_not_fetched_again_for_the_summary(self):
        store, inc, fetched = MemoryStore(), self.candidate(), []

        def get(url, headers=None):
            fetched.append(url)
            if "h1." in url:
                raise OSError("HTTP Error 403: Forbidden")
            return PAGE.encode()
        claude = FakeClaude(*[facts()] * 3, "{")
        with contextlib.redirect_stderr(io.StringIO()):
            route_summaries([inc], [], claude, get, datetime(2026, 11, 18), STAMP, set(), probe=False, store=store)
        pages = [u for u in fetched if ".example/" in u]
        self.assertEqual(sorted(pages), sorted(m["url"] for m in inc["mentions"]))  # each once, the refused one too
        self.assertIn("Text of https://h0.example/a", claude.sent[-1]["messages"][0]["content"])
        self.assertNotIn("Text of https://h1.example/a", claude.sent[-1]["messages"][0]["content"])


def row(vendor, line, v, status="fixed", words="Fixed in", cves=()):
    return {"vendor": vendor, "product_line": line, "version": v, "status": status, "cves": list(cves), "words": words}


class UnionTest(unittest.TestCase):
    """The union of fixed versions (owner's carry trial, 11-18), on a rewritten Java4Shell: the model kept Oracle's lines
    and dropped Amazon Corretto's, which only a rank-B blog gives."""

    JAVA = {"id": "CVE-2026-114938", "cves": ["CVE-2026-114938"]}

    def pages(self):
        return [sheet("https://oracle.example/cpu", "A", versions=[
                    row("Oracle", "Java SE 17", "17.0.21.0.3", "affected", "Affected versions are"),
                    row("Oracle", "Java SE 17", "17.0.21.1"), row("Oracle", "Java SE 21", "21.0.13.1"),
                    row("Oracle", "Java SE 8", "8u513")]),
                sheet("https://blog.example/java4shell", "B", "writeup", versions=[
                    row("Amazon", "Amazon Corretto 17", "17.0.21.1.2"), row("Amazon", "Corretto 17", "17.0.21.0.3"),
                    row("Acme", "Widget", "f9416bea"),  # a commit
                    row("Acme", "Widget", "13.1.0", words="Fixed versions: <13.1.0"),  # a range bound
                    row("7-Zip", "7-Zip", "26.02", cves=["CVE-2026-14266"]),  # another CVE's fix
                    row("Acme", "Desktop", "4.4.8", words="Users who upgraded to 4.4.8 are not affected"),
                    row("IBM", "cryptography", "48.01", words="OpenSSL included in wheels prior to cryptography 48.01")]),
                sheet("https://news1.example/a", "C", "writeup", versions=[row("Azul", "Zulu 17", "17.0.21.1-zulu"),
                                                                          row("BellSoft", "Liberica 17", "17.0.21.1-lib")]),
                sheet("https://news2.example/a", "C", "writeup", versions=[row("Azul", "Zulu 17", "17.0.21.1-zulu")])]

    def test_only_trusted_rows_pass_the_row_checks(self):
        rows = sheets.fix_rows(self.pages(), self.JAVA, [])
        self.assertEqual(rows, [{"for": "Oracle Java SE 17", "version": "17.0.21.1"}, {"for": "Oracle Java SE 21", "version": "21.0.13.1"},
                                {"for": "Oracle Java SE 8", "version": "8u513"}, {"for": "Amazon Corretto 17", "version": "17.0.21.1.2"},
                                {"for": "Azul Zulu 17", "version": "17.0.21.1-zulu"}])  # Liberica: one rank-C host only

    def test_a_summary_gains_only_what_it_lacks_and_its_own_lines_stay(self):
        model = [{"for": "Oracle Java SE 17", "version": "17.0.21.1"}, {"for": "Oracle Java SE 21", "version": "21.0.13.1 or later"},
                 {"for": "Red Hat Satellite 6.16 for RHEL 9", "version": "0:0.9.3-2.el9sat"}, {"for": "Check Point", "version": "R82.10"}]
        summary = {"fixed": "17.0.21.1", "fixes": copy.deepcopy(model)}
        rows = sheets.fix_rows(self.pages(), self.JAVA, []) + [
            {"for": "Oracle Java SE Embedded 17", "version": "17.0.20.5"},  # older, on a line the model's Oracle 17 fixes
            {"for": "Red Hat Satellite 6.16 for RHEL 9", "version": "6.16.15"},  # the model's own release label
            {"for": "Check Point Multi-Domain Security Management", "version": "R82.10 이상"}]  # shown under another label
        added = sheets.union(summary, rows)
        self.assertEqual([(a["for"], a["version"]) for a in added],
                         [("Oracle Java SE 8", "8u513"), ("Amazon Corretto 17", "17.0.21.1.2"), ("Azul Zulu 17", "17.0.21.1-zulu")])
        self.assertEqual(summary["fixes"], model)  # union() only returns the lines; save_reply appends them

    def test_save_reply_appends_marked_lines_that_pass_the_checks_on_both_paths(self):
        inc = incident(4) | {"fix_keys": ["acme:widget<1.3.2"]}
        pages = [sheet("https://acme.example/a", "A", versions=[version("1.3.2", "fixed"), version("1.3.1", "fixed")])]
        get = lambda url, headers=None: PAGE.encode()  # noqa: E731
        from test_batch_summaries import plain
        with contextlib.redirect_stderr(io.StringIO()):
            summaries.summarize_now(inc, FakeClaude(plain("Widget")), get, STAMP, sheets=pages)
        # 1.3.1 is below the records' first fixed 1.3.2 (fixed_conflict): never added.
        self.assertEqual(inc["summary"]["fixes"], [{"for": "Acme Widget", "version": "1.3.2", "devices": [], "from_sheet": True}])
        claude, batched = FakeClaude(), incident(4) | {"fix_keys": ["acme:widget<1.3.2"]}
        pending = summaries.submit_batch([batched], claude, get, sheets=lambda i: pages)
        self.assertEqual(pending["requests"]["r0"]["fix_rows"], [{"for": "Acme Widget", "version": "1.3.2"}])
        claude.end_batch({batched["id"]: plain("Widget")})
        summaries.collect_batch(pending, [batched], claude, STAMP)
        self.assertEqual(batched["summary"]["fixes"], inc["summary"]["fixes"])
        # A re-summary that leaves out the added line is no lost fix: the union adds it again.
        self.assertEqual(summaries.lost_fix(batched, plain("Widget"), "Fixed version: Acme Widget: 1.3.2"), "")

    def test_the_cycle_line_counts_the_lines_added(self):
        store, inc = MemoryStore(), incident(4) | {"cvss": 9.8, "kev": True, "kev_cves": {"CVE-2026-1000": "2026-11-18"}}
        from test_batch_summaries import plain
        from collector.logfile import CycleLine
        claude = FakeClaude(*[facts(versions=[version("1.3", "fixed")])] * 4, plain("Widget"))
        line = CycleLine(STAMP, lambda: 0)
        with contextlib.redirect_stderr(io.StringIO()):
            route_summaries([inc], [], claude, lambda url, headers=None: PAGE.encode(), datetime(2026, 11, 18), STAMP, set(),
                            probe=False, store=store, line=line)
        self.assertEqual(inc["summary"]["fixes"], [{"for": "Acme Widget", "version": "1.3", "devices": [], "from_sheet": True}])
        self.assertIn(" fixes_lines=1 ", line.text())


class MustCarryTest(unittest.TestCase):
    """The must-carry list (owner's carry trial, part 2), on a rewritten Java4Shell: the finder's JVM flags, OpenJDK and
    its Base64 decoder, which draws kept leaving out."""

    NOTE = ("Carry these from the pages, in the summary or the mitigation, in both languages, in the input's words (each is"
            " in the input; leave one out only if the input contradicts it):\n"
            "- the stopgap -XX:-UseBASE64Intrinsics (calif.example)\n"
            "- the stopgap -XX:UseAVX=2 (calif.example)\n"
            "- the upstream project the flawed code comes from: OpenJDK (calif.example, mikiri.example)\n"
            "- the flawed component: Base64 decoder (calif.example, mikiri.example)")

    def pages(self):
        return [sheet("https://calif.example/java4shell", "B", "writeup", page_role="finder_disclosure", upstream_project="OpenJDK",
                      flawed_component="Base64 decoder",
                      mitigations=["Run Java with -XX:-UseBASE64Intrinsics", "Or start the JVM with -XX:UseAVX=2"]),
                sheet("https://mikiri.example/a", "B", "writeup", upstream_project="OpenJDK",
                      flawed_component="the Base64 decoder of OpenJDK (x86-64)", mitigations=["Set `-XX:UseAVX=0`"]),  # no finder
                sheet("https://oracle.example/cpu", "A", mitigations=["See the suggested fix: `hash_equals()`",  # a developer's fix
                                                                      "Segment it behind a VPN"]),  # prose
                sheet("https://news.example/a", "C", "writeup", upstream_project="OpenJ9")]  # one host

    def test_the_list_and_its_wording(self):
        carry = sheets.must_carry(self.pages())
        self.assertEqual(summaries.carry_note(carry), self.NOTE)
        self.assertEqual(summaries.retry({"id": "x", "cves": ["CVE-2026-1000"]}, "", carry)["note"], self.NOTE)
        said = {"en": {"summary": "OpenJDK's Base64 decoder ...", "mitigation": "Until then use -XX:-UseBASE64Intrinsics or -XX:UseAVX=2."}}
        self.assertEqual(sheets.carry_left(said, carry), [])
        self.assertEqual([c["words"] for c in sheets.carry_left({"en": {"summary": "A Base64 decoder flaw in OpenJDK."}}, carry)],
                         ["-XX:-UseBASE64Intrinsics", "-XX:UseAVX=2"])

    def test_a_first_reply_that_leaves_an_item_out_is_kept_back_once_and_the_list_goes_with_every_try(self):
        from test_batch_summaries import plain
        inc, get = incident(4), lambda url, headers=None: PAGE.encode()
        claude = FakeClaude(plain("Widget"), plain("Widget"))
        with contextlib.redirect_stderr(io.StringIO()):
            summaries.summarize_now(inc, claude, get, STAMP, sheets=self.pages())
            self.assertTrue(inc["summary_error"]["reason"].startswith(summaries.CARRY_LEFT + "stopgap -XX:-UseBASE64Intrinsics, "))
            summaries.summarize_now(inc, claude, get, STAMP, sheets=self.pages())
        self.assertTrue(claude.user_text(0).endswith("\n\n" + self.NOTE))
        second = claude.user_text(1)
        self.assertIn("\n\n" + self.NOTE + "\n\nYour previous reply for this Incident was rejected: " + summaries.CARRY_LEFT, second)
        self.assertIn("Carry every item of the list above", second)
        self.assertIn("summary", inc)  # a later try is never kept back for the list
        self.assertEqual(claude.sent[0]["system"][0]["text"], summaries.INSTRUCTIONS)  # the cached instructions stay as they were
        # The batch path sends and checks the same list.
        batch, batched = FakeClaude(), incident(4)
        pending = summaries.submit_batch([batched], batch, get, sheets=lambda i: self.pages())
        self.assertTrue(batch.batch_inputs()[0].endswith("\n\n" + self.NOTE))
        batch.end_batch({batched["id"]: plain("Widget")})
        summaries.collect_batch(pending, [batched], batch, STAMP)
        self.assertTrue(batched["summary_error"]["reason"].startswith(summaries.CARRY_LEFT))


if __name__ == "__main__":
    unittest.main()
