"""Per-CVE lines for Incidents with many CVEs (owner, 2026-11-10): IBM API Connect (204 CVEs) ran past 16,000 tokens
writing one line per CVE in two languages, and the 114-, 41- and 39-CVE rows failed the Korean/English number check
on those lines. The Summary now writes lines for the first CVE_LINES_MAX CVEs; the rest go out in batches."""

import unittest

from collector import summaries
from test_batch_summaries import plain
from test_command_provenance import checked, incident
from test_cycle import at, recorded
from test_summaries import HN_STORY, PAGES, FakeClaude, board
from collector.cycle import run_cycle
from collector.store import MemoryStore

MAX = summaries.CVE_LINES_MAX
MANY = [f"CVE-2026-{n}" for n in range(10001, 10001 + MAX + 3)]
TEXTS = {c: f"Widget before 2.{k} lets an attacker read files." for k, c in enumerate(MANY)}


def line(cve, ko, en):
    return {"cve": cve, "ko": ko, "en": en}


class SummaryLinesTest(unittest.TestCase):
    def test_a_summary_writes_lines_only_for_the_first_cves(self):
        lines = {lang: [{"cve": MANY[0], "text": "x"}, {"cve": MANY[MAX], "text": "y"}] for lang in ("ko", "en")}
        reply = {lang: plain("Widget")[lang] | {"cve_lines": lines[lang]} for lang in ("ko", "en")}
        text = summaries.summary_input(incident([], cves=MANY), lambda url: b"")
        self.assertIn(f"{summaries.CVE_LINES_ONLY} {', '.join(MANY[:MAX])}\n", text + "\n")

        summary = checked(incident([], cves=MANY), {}, reply)

        self.assertEqual(summary["ko"]["cve_lines"], [{"cve": MANY[0], "text": "x"}])
        few = checked(incident([], cves=MANY[:2]), {}, reply | {
            lang: plain("Widget")[lang] | {"cve_lines": [{"cve": MANY[1], "text": "y"}]} for lang in ("ko", "en")})
        self.assertEqual(few["en"]["cve_lines"], [{"cve": MANY[1], "text": "y"}])
        self.assertNotIn(summaries.CVE_LINES_ONLY, summaries.summary_input(incident([], cves=MANY[:2]), lambda url: b""))


class BatchLinesTest(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.store.write("checkpoints.json", {"cvelist": "2026-11-07T12:00:00.000Z"})
        self.run_at("2026-11-07T12:30:00", None, hn="sshole.json")

    def run_at(self, when, claude, **sources):
        sources.setdefault("delta_log", None)
        run_cycle(self.store, recorded(web=PAGES, **sources), at(when), "test-box", claude=claude)

    def edit(self, **fields):
        month = self.store.read("months/2026-11.json")
        row = next(i for i in month["incidents"] if i["id"] == HN_STORY)
        row.update(fields)
        self.store.write("months/2026-11.json", month)
        return row

    def summarized(self):
        """The sshole row as a 15-CVE release with a Summary whose lines cover the first MAX CVEs."""
        row = self.edit(cves=MANY, cve_texts=TEXTS)
        summary = plain("Widget")
        for lang in ("ko", "en"):
            summary[lang]["cve_lines"] = [{"cve": c, "text": f"{lang} {c}"} for c in MANY[:MAX]]
        self.edit(summary=summary | {"at": "2026-11-07T12:30:00Z"}, summary_basis=summaries.basis(row) | {"n": 1})

    def lines_batches(self, claude):
        return [b for b in claude.batches if summaries.LINES_HEAD in b["requests"][0]["params"]["messages"][0]["content"]]

    def test_the_rest_go_out_in_a_batch_and_join_the_summary_in_cve_order(self):
        self.summarized()
        claude = FakeClaude()
        self.run_at("2026-11-07T12:45:00", claude)

        [batch] = self.lines_batches(claude)
        [request] = batch["requests"]
        text = request["params"]["messages"][0]["content"]
        for cve in MANY[MAX:]:
            self.assertIn(f"{cve}: {TEXTS[cve]}", text)
        self.assertNotIn(f"{MANY[0]}:", text)

        self.run_at("2026-11-07T13:00:00", claude)  # still running: not sent again
        self.assertEqual(len(self.lines_batches(claude)), 1)

        k = MAX + 2  # the last CVE's text says "before 2.14"
        claude.end_batch({HN_STORY: {"lines": [line(MANY[-1], f"2.{k} 이전 버전에서 파일을 읽을 수 있습니다.", f"Files can be read before 2.{k}."),
                                               line(MANY[MAX], "파일을 읽을 수 있습니다.", "Files can be read.")]}},
                         n=claude.batches.index(batch))
        self.run_at("2026-11-07T13:15:00", claude)

        summary = board(self.store)[HN_STORY]["summary"]
        self.assertEqual([l["cve"] for l in summary["ko"]["cve_lines"]], MANY[:MAX] + [MANY[MAX], MANY[-1]])
        self.assertEqual(summary["en"]["cve_lines"][-1], {"cve": MANY[-1], "text": f"Files can be read before 2.{k}."})

    def test_a_bad_line_is_dropped_and_its_cve_asked_once_more_then_never(self):
        self.summarized()
        claude = FakeClaude()
        bad = {"lines": [line(MANY[MAX], "9.9 이전 버전.", "Before 9.9."),  # a number its record lacks
                         line(MANY[MAX + 1], "3개 파일.", "Two files."),  # Korean and English numbers differ
                         line(MANY[0], "x", "x"),  # a CVE the request did not ask for
                         line(MANY[MAX + 2], f"{MANY[1]} 파일.", "Files.")]}  # a CVE ID inside the line
        for when in ("2026-11-07T12:45:00", "2026-11-07T13:00:00", "2026-11-07T13:15:00", "2026-11-07T13:30:00"):
            self.run_at(when, claude)
            for n, b in enumerate(claude.batches):
                if b["results"] is None:
                    claude.end_batch({HN_STORY: bad}, n=n)

        self.assertEqual(len(self.lines_batches(claude)), summaries.LINES_ROUNDS)
        summary = board(self.store)[HN_STORY]["summary"]
        self.assertEqual([l["cve"] for l in summary["ko"]["cve_lines"]], MANY[:MAX])

    def test_lines_go_out_a_few_cves_a_request(self):
        many = [f"CVE-2026-{n}" for n in range(20001, 20001 + MAX + summaries.LINES_PER_REQUEST + 1)]
        row = self.edit(cves=many, cve_texts={c: "Widget lets an attacker read files." for c in many})
        self.edit(summary=plain("Widget") | {"at": "2026-11-07T12:30:00Z"}, summary_basis=summaries.basis(row) | {"n": 1})
        claude = FakeClaude()
        self.run_at("2026-11-07T12:45:00", claude)

        [batch] = self.lines_batches(claude)
        self.assertEqual(len(batch["requests"]), 2)  # LINES_PER_REQUEST, then the one left


class ReviveTest(unittest.TestCase):
    setUp, run_at, edit = BatchLinesTest.setUp, BatchLinesTest.run_at, BatchLinesTest.edit

    def test_a_many_cve_incident_given_up_before_the_cap_gets_one_more_round(self):
        self.edit(cves=MANY, summary_error={"tries": 3, "reason": "stop_reason max_tokens", "with_reason": True, "final": True})
        claude = FakeClaude("not json", "not json", "not json")

        for when in ("2026-11-07T12:45:00", "2026-11-07T13:00:00", "2026-11-07T13:15:00", "2026-11-07T13:30:00"):
            self.run_at(when, claude)

        self.assertEqual(len(claude.sent), 3)  # one more round, then given up for good
        self.assertTrue(board(self.store)[HN_STORY]["summary_error"]["final"])

    def test_a_few_cve_incident_given_up_is_not_revived(self):
        self.edit(summary_error={"tries": 3, "reason": "stop_reason max_tokens", "with_reason": True, "final": True})
        claude = FakeClaude()
        self.run_at("2026-11-07T12:45:00", claude)
        self.assertEqual(claude.sent, [])


if __name__ == "__main__":
    unittest.main()
