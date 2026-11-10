"""Per-CVE lines for Incidents with many CVEs (owner, 2026-11-10): IBM API Connect (204 CVEs) ran past 16,000 tokens
writing one line per CVE in two languages, and the 114-, 41- and 39-CVE rows failed the Korean/English number check
on those lines. The Summary now writes lines for the first CVE_LINES_MAX CVEs; the rest go out in batches."""

import contextlib
import io
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


WORDS = "Division by zero in a zero-width image; an eight-byte header overflows."


def lines_row(text=WORDS):
    summary = plain("Widget")
    for lang in ("ko", "en"):
        summary[lang] = summary[lang] | {"cve_lines": []}  # plain() shares one list between the languages
    return {"id": "row", "cves": MANY, "cve_texts": {c: text for c in MANY}, "summary": summary}


def saved(row, *items, stop_reason="end_turn"):
    """The CVEs with a line after save_lines, and what it logged."""
    reply = FakeClaude.message({"lines": list(items)} if items else "not json")
    reply.stop_reason = stop_reason
    log = io.StringIO()
    with contextlib.redirect_stderr(log):
        summaries.save_lines(row, reply, MANY[MAX:])
    return [l["cve"] for l in row["summary"]["ko"]["cve_lines"]], log.getvalue()


class LineCheckTest(unittest.TestCase):
    """Owner, 2026-11-10: a line may write as a digit a number its CVE's description writes as an English word
    (FFmpeg's "division by zero", FreeRDP's "eight-byte"); the check stays exact otherwise."""

    def test_a_digit_the_description_spells_as_a_word_counts(self):
        row = lines_row()
        cves, log = saved(row, line(MANY[MAX], "0으로 나누기 오류가 납니다.", "Division by zero."),
                          line(MANY[MAX + 1], "8바이트 헤더가 넘칩니다.", "The eight-byte header overflows."),
                          line(MANY[MAX + 2], "너비가 0인 이미지에서 멈춥니다.", "A zero-width image stops it."))
        self.assertEqual(cves, MANY[MAX:])
        self.assertNotIn("dropped", log)

    def test_a_number_neither_written_nor_spelled_is_still_dropped(self):
        cves, log = saved(lines_row(), line(MANY[MAX], "9바이트 헤더가 넘칩니다.", "A nine-byte header overflows."),
                          line(MANY[MAX + 1], "3개 파일.", "Three files."))
        self.assertEqual(cves, [])
        self.assertIn("dropped 2 of 2", log)
        self.assertIn("row", log)

    def test_korean_and_english_numbers_that_differ_are_still_dropped(self):
        row = lines_row(WORDS + " A seven-byte trailer follows; 7 bytes in all.")
        cves, log = saved(row, line(MANY[MAX], "8바이트 헤더가 넘칩니다.", "The seven-byte trailer overflows."),
                          line(MANY[MAX + 1], "8바이트 헤더가 넘칩니다.", "The 7-byte trailer overflows."))
        self.assertEqual(cves, [])
        self.assertIn("differ", log)

    def test_only_a_korean_digit_the_english_line_spells_matches(self):
        text = WORDS + " A seven-byte trailer; length 8."
        cves, log = saved(lines_row(text), line(MANY[MAX], "7바이트 헤더가 넘칩니다.", "An eight-byte header overflows."),
                          line(MANY[MAX + 1], "길이가 0인 이미지에서 멈춥니다.", "Length 8 with a zero-width image stops it."),
                          # a digit only in English stays a difference, though English also spells it
                          line(MANY[MAX + 2], "헤더가 넘칩니다.", "The 8-byte header, eight bytes long, overflows."))
        self.assertEqual(cves, [])
        self.assertIn("dropped 3 of 3", log)
        cves, _ = saved(lines_row(text), line(MANY[MAX], "8바이트 헤더가 넘칩니다.", "An eight-byte header overflows."))
        self.assertEqual(cves, [MANY[MAX]])

    def test_one_is_not_a_number_word(self):
        cves, log = saved(lines_row("Widget lets one of the fields overflow."), line(MANY[MAX], "1개 필드가 넘칩니다.", "One field overflows."))
        self.assertEqual(cves, [])
        self.assertIn("not in its description", log)

    def test_an_incident_left_out_by_the_limit_spends_no_round(self):
        first, second = lines_row(), lines_row() | {"id": "other", "cve_lines_room": True}
        claude = FakeClaude()
        summaries.submit_lines([first, second], claude, limit=1)
        self.assertEqual(first["cve_lines_rounds"], 1)
        self.assertEqual(second.get("cve_lines_rounds"), None)
        self.assertTrue(second["cve_lines_room"])

    def test_an_unparsable_reply_is_logged_and_changes_nothing(self):
        row = lines_row()
        before = repr(row["summary"])
        cves, log = saved(row, stop_reason="max_tokens")
        self.assertEqual(repr(row["summary"]), before)
        self.assertIn("row", log)
        self.assertIn("max_tokens", log)
        self.assertTrue(row["cve_lines_room"])  # the next round gets MAX_TOKENS_RETRY


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

    def test_a_cut_off_lines_reply_is_asked_again_with_more_room(self):
        self.summarized()
        claude = FakeClaude()
        self.run_at("2026-11-07T12:45:00", claude)
        [first] = self.lines_batches(claude)
        claude.end_batch({HN_STORY: "not json"}, n=claude.batches.index(first))
        first["results"][0].result.message.stop_reason = "max_tokens"
        with contextlib.redirect_stderr(io.StringIO()):
            self.run_at("2026-11-07T13:00:00", claude)

        first, second = self.lines_batches(claude)
        self.assertEqual(first["requests"][0]["params"]["max_tokens"], summaries.MAX_TOKENS)
        self.assertEqual(second["requests"][0]["params"]["max_tokens"], summaries.MAX_TOKENS_RETRY)


if __name__ == "__main__":
    unittest.main()
