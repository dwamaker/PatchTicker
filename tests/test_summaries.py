"""Seam 1: instant Summaries for Highlight candidates, with a fake Claude client.

pages/sshhole.com.html and pages/release-10.6p2.txt are the real pages (2026-11-07), trimmed.
"""

import json
import unittest
import urllib.error
from types import SimpleNamespace

from collector.cycle import run_cycle
from collector.store import MemoryStore
from test_cycle import FIXTURES, at, incident, recorded

PAGES = {"https://sshhole.com": "sshhole.com.html", "https://www.openssh.com/txt/release-10.6p2": "release-10.6p2.txt"}

SSHOLE_SUMMARY = {
    "ko": {
        "title": "musl 기반 OpenSSH, 비밀번호 없는 계정에 긴 비밀번호로 로그인 허용",
        "summary": "musl libc로 빌드되고 PAM을 쓰지 않는 OpenSSH sshd에서 비밀번호가 `*`인 계정이 "
                   "257~1024자 비밀번호를 받아들입니다. Alpine, OpenWrt 같은 musl 시스템이 해당합니다.",
        "conditions": ["musl libc", "PAM 미사용", "비밀번호 로그인 켜짐", "비밀번호가 `*`인 계정"],
        "mitigation": "OpenSSH 10.6p2로 업데이트하세요. 당장 못 하면 PasswordAuthentication no로 비밀번호 로그인을 끄세요.",
        "easy": "Alpine이나 OpenWrt 서버에 아무 긴 비밀번호로 남이 로그인할 수 있습니다.",
    },
    "en": {
        "title": "OpenSSH on musl lets password-less accounts in with a long password",
        "summary": "sshd built against musl libc without PAM accepts any password of 257 to 1024 characters "
                   "for accounts whose password is `*`. musl systems such as Alpine and OpenWrt are affected.",
        "conditions": ["musl libc", "PAM not used", "password logins on", "an account whose password is `*`"],
        "mitigation": "Update to OpenSSH 10.6p2. Until then, set PasswordAuthentication no to turn password logins off.",
        "easy": "Anyone can log in to an Alpine or OpenWrt server with any long password.",
    },
    "products": ["OpenSSH"],
    "lead": "https://sshhole.com",
    "fixed": "10.6p2",
    "command": "apk upgrade openssh",
    "stopgap": "PasswordAuthentication no",
    "devices": [],
}


class FakeClaude:
    """Stands in for anthropic.Anthropic: answers messages.create with the given replies in turn
    (a dict is sent as JSON, a string as is) and records what each request sent.

    Message batches stay in progress until the test calls end_batch. Setting `error` makes every
    messages.create and batch submit raise it (a credit-exhausted error, say)."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.sent = []
        self.batches = []  # each {"id", "requests", "results": None while in progress}
        self.error = None
        self.messages = SimpleNamespace(create=self.create, batches=SimpleNamespace(
            create=self.batch_create, retrieve=self.batch_retrieve, results=self.batch_results))

    def create(self, **params):
        if self.error:
            raise self.error
        self.sent.append(params)
        return self.message(self.replies.pop(0))

    @staticmethod
    def message(reply):
        text = reply if isinstance(reply, str) else json.dumps(reply, ensure_ascii=False)
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)], stop_reason="end_turn",
                               usage=SimpleNamespace(input_tokens=0, output_tokens=0))

    def user_text(self, n=0):
        return self.sent[n]["messages"][0]["content"]

    def batch_create(self, requests):
        if self.error:
            raise self.error
        self.batches.append({"id": f"msgbatch_{len(self.batches)}", "requests": list(requests), "results": None})
        return SimpleNamespace(id=self.batches[-1]["id"], processing_status="in_progress")

    def batch(self, batch_id):
        return next(b for b in self.batches if b["id"] == batch_id)

    def batch_retrieve(self, batch_id):
        return SimpleNamespace(id=batch_id, processing_status="in_progress" if self.batch(batch_id)["results"] is None else "ended")

    def batch_results(self, batch_id):
        return iter(self.batch(batch_id)["results"])

    def batch_inputs(self, n=-1):
        return [r["params"]["messages"][0]["content"] for r in self.batches[n]["requests"]]

    def end_batch(self, answers, n=-1):
        """Ends batch n. Each request gets the answer whose key (a CVE ID or URL) its input names:
        a reply, "errored" or "expired"."""
        batch = self.batches[n]
        batch["results"] = []
        for request in batch["requests"]:
            text = request["params"]["messages"][0]["content"]
            [answer] = [a for key, a in answers.items() if f"Incident: {key}" in text]
            if answer == "errored":
                result = SimpleNamespace(type="errored", error=SimpleNamespace(
                    type="error", error=SimpleNamespace(type="api_error", message="Internal server error")))
            elif answer == "expired":
                result = SimpleNamespace(type="expired")
            else:
                result = SimpleNamespace(type="succeeded", message=self.message(answer))
            batch["results"].append(SimpleNamespace(custom_id=request["custom_id"], result=result))


def board(store):
    return {i["id"]: i for i in store.read("months/2026-11.json")["incidents"]}


HN_STORY = "https://news.ycombinator.com/item?id=50378228"


class InstantSummaryTest(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.store.write("checkpoints.json", {"cvelist": "2026-11-07T12:00:00.000Z"})

    def run_at(self, when, claude, **sources):
        sources.setdefault("delta_log", None)
        run_cycle(self.store, recorded(web=PAGES, **sources), at(when), "test-box", claude=claude)

    def test_a_highlight_candidate_is_summarized_in_its_first_cycle_and_others_are_not(self):
        claude = FakeClaude(SSHOLE_SUMMARY)
        # sshole (an Unassigned incident seen on HN) arrives with two ordinary CVEs (no CVSS, no buzz).
        self.run_at("2026-11-07T12:30:00", claude, delta_log="deltaLog.json", hn="sshole.json")

        incidents = board(self.store)
        self.assertEqual(incidents[HN_STORY]["summary"], SSHOLE_SUMMARY | {"at": "2026-11-07T12:30:00Z"})
        self.assertEqual(len(claude.sent), 1)
        self.assertNotIn("summary", incidents["CVE-2026-120984"])
        self.assertNotIn("summary", incidents["CVE-2026-120839"])

    def test_the_sshole_summary_input_carries_the_write_up_text(self):
        claude = FakeClaude(SSHOLE_SUMMARY)
        self.run_at("2026-11-07T12:30:00", claude, hn="sshole.json")

        sent = claude.user_text()
        self.assertIn("between 257 and 1024 characters", sent)
        self.assertIn('echo "PasswordAuthentication no"', sent)
        self.assertIn("apk upgrade openssh", sent)
        self.assertNotIn("<span", sent)  # page text, not markup
        self.assertNotIn("CVE-2099-0001", sent)  # nor its scripts

    def merged_sshole(self, claude):
        """sshole's real order: the HN cycle runs without an API key, the Summary is asked once the CVE
        has merged in."""
        self.store.write("checkpoints.json", {"cvelist": "2026-11-05T12:00:00.000Z"})
        self.run_at("2026-11-05T12:30:00", None, hn="sshole.json")
        self.run_at("2026-11-05T16:00:00", claude, delta_log="deltaLog-sshole.json")

    def test_the_cve_record_and_release_note_join_the_input_once_known(self):
        claude = FakeClaude(SSHOLE_SUMMARY)
        self.merged_sshole(claude)

        sent = claude.user_text()
        self.assertIn('"defaultStatus"', sent)  # the CVE record's affected list, not only its description
        self.assertIn("musl libc and PAM disabled", sent)  # the release note's text
        self.assertIn("between 257 and 1024 characters", sent)  # and still the write-up's
        self.assertEqual(board(self.store)[HN_STORY]["summary"]["at"], "2026-11-05T16:00:00Z")

    def test_the_request_asks_for_a_json_schema_with_cached_instructions(self):
        claude = FakeClaude(SSHOLE_SUMMARY)
        self.run_at("2026-11-07T12:30:00", claude, hn="sshole.json")

        [sent] = claude.sent
        self.assertEqual(sent["model"], "claude-haiku-5-5")
        self.assertEqual(sent["output_config"]["format"]["type"], "json_schema")
        self.assertEqual(sent["output_config"]["format"]["schema"]["required"], ["ko", "en", "products", "lead", "fixed", "command", "stopgap", "devices"])
        [instructions] = sent["system"]
        self.assertEqual(instructions["cache_control"], {"type": "ephemeral"})
        # Haiku 5.5 caches only a prefix of 512 tokens or more; ~4 characters a token in English.
        self.assertGreater(len(instructions["text"]), 4 * 512)
        self.assertIn("follow the official advisory or the discoverer's write-up", instructions["text"])
        self.assertIn("leave it empty", instructions["text"])

    def test_a_malformed_reply_leaves_the_brief_and_a_later_cycle_retries(self):
        claude = FakeClaude('{"ko": {"title": "musl', SSHOLE_SUMMARY)
        self.run_at("2026-11-07T12:30:00", claude, hn="sshole.json")
        self.assertNotIn("summary", board(self.store)[HN_STORY])
        self.assertEqual(board(self.store)[HN_STORY]["brief"]["text"], "sshole")

        self.run_at("2026-11-07T12:45:00", claude)

        incident = board(self.store)[HN_STORY]
        self.assertEqual(incident["summary"]["at"], "2026-11-07T12:45:00Z")
        self.assertNotIn("summary_error", incident)

    def test_the_code_check_rejects_made_up_numbers_foreign_links_and_mismatched_languages(self):
        en, ko = SSHOLE_SUMMARY["en"], SSHOLE_SUMMARY["ko"]
        bad = {
            "a version not in the input": SSHOLE_SUMMARY | {"en": en | {"mitigation": "Update to OpenSSH 10.7p1."},
                                                            "ko": ko | {"mitigation": "OpenSSH 10.7p1로 업데이트하세요."}},
            "a boundary not in the input": SSHOLE_SUMMARY | {"en": en | {"summary": "Passwords over 300 characters work."},
                                                             "ko": ko | {"summary": "300자를 넘는 비밀번호가 통합니다."}},
            "a Lead that is not an input URL": SSHOLE_SUMMARY | {"lead": "https://example.com/sshole"},
            "Korean and English numbers that differ": SSHOLE_SUMMARY | {"ko": ko | {"summary": "256자 이상 비밀번호를 받아들입니다."}},
            "a fixed version not in the input": SSHOLE_SUMMARY | {"fixed": "10.7p1"},
            "Easy text whose numbers differ": SSHOLE_SUMMARY | {"en": en | {"easy": "Any password over 256 characters works."}},
            "a missing field": {k: v for k, v in SSHOLE_SUMMARY.items() if k != "lead"},
            "a missing Easy field": {k: v for k, v in SSHOLE_SUMMARY.items() if k != "command"},
            "a field of the wrong type": SSHOLE_SUMMARY | {"products": "OpenSSH"},
        }
        for case, reply in bad.items():
            with self.subTest(case):
                self.setUp()
                self.run_at("2026-11-07T12:30:00", FakeClaude(reply), hn="sshole.json")
                incident = board(self.store)[HN_STORY]
                self.assertNotIn("summary", incident)
                self.assertEqual(incident["summary_error"]["tries"], 1)

    def test_the_easy_action_is_the_write_ups_own_command_and_stopgap(self):
        self.run_at("2026-11-07T12:30:00", FakeClaude(SSHOLE_SUMMARY), hn="sshole.json")

        summary = board(self.store)[HN_STORY]["summary"]
        self.assertEqual((summary["command"], summary["stopgap"]), ("apk upgrade openssh", "PasswordAuthentication no"))
        self.assertEqual(summary["ko"]["easy"], SSHOLE_SUMMARY["ko"]["easy"])

    def test_a_command_not_in_the_input_is_dropped_and_the_fixed_version_stays(self):
        made_up = SSHOLE_SUMMARY | {"command": "apk add --upgrade openssh-server", "stopgap": "UsePAM yes"}
        self.run_at("2026-11-07T12:30:00", FakeClaude(made_up), hn="sshole.json")

        summary = board(self.store)[HN_STORY]["summary"]
        self.assertEqual((summary["command"], summary["stopgap"], summary["fixed"]), ("", "", "10.6p2"))
        self.assertEqual(summary["en"], SSHOLE_SUMMARY["en"])  # the rest of the Summary is kept

    def test_numbers_written_differently_in_the_source_still_pass(self):
        # "1,024" and "1024" are one number; so are "05" and "5".
        reply = SSHOLE_SUMMARY | {"en": SSHOLE_SUMMARY["en"] | {"summary": "Any password of 257 to 1,024 characters; fixed 2026-11-05."},
                                  "ko": SSHOLE_SUMMARY["ko"] | {"summary": "257~1024자 비밀번호가 통합니다. 2026-11-5 수정."}}
        self.merged_sshole(FakeClaude(reply))
        self.assertIn("summary", board(self.store)[HN_STORY])

    def test_a_version_named_in_one_language_only_passes_but_whole_numbers_must_match(self):
        # Versions must still appear in the input; only whole numbers are compared across languages.
        reply = SSHOLE_SUMMARY | {"ko": SSHOLE_SUMMARY["ko"] | {"mitigation": "최신 OpenSSH로 업데이트하세요."}}
        self.run_at("2026-11-07T12:30:00", FakeClaude(reply), hn="sshole.json")
        self.assertIn("summary", board(self.store)[HN_STORY])

    def test_the_instructions_ask_to_copy_numbers_and_dates_as_the_source_writes_them(self):
        claude = FakeClaude(SSHOLE_SUMMARY)
        self.run_at("2026-11-07T12:30:00", claude, hn="sshole.json")

        text = claude.sent[0]["system"][0]["text"]
        self.assertIn("as the source writes", text)
        self.assertNotIn("YYYY-MM-DD", text)
        self.assertNotIn("with digits", text)

    def test_after_three_failed_replies_the_incident_is_flagged_and_not_asked_again(self):
        claude = FakeClaude("not json", "not json", "not json")
        self.run_at("2026-11-07T12:30:00", claude, hn="sshole.json")
        self.assertNotIn("final", board(self.store)[HN_STORY]["summary_error"])  # the page still says "in preparation"
        for when in ("2026-11-07T12:45:00", "2026-11-07T13:00:00", "2026-11-07T13:15:00"):
            self.run_at(when, claude)

        self.assertEqual(len(claude.sent), 3)
        incident = board(self.store)[HN_STORY]
        self.assertEqual(incident["summary_error"]["tries"], 3)
        self.assertTrue(incident["summary_error"]["final"])  # the page says no Summary is coming
        self.assertEqual(incident["brief"]["text"], "sshole")

    def test_only_the_last_seven_days_are_summarized_at_once(self):
        claude = FakeClaude(SSHOLE_SUMMARY)
        self.run_at("2026-11-05T12:30:00", None, hn="sshole.json")  # no API key: Briefs only

        self.run_at("2026-11-12T12:31:00", claude)

        self.assertEqual(claude.sent, [])
        self.assertNotIn("summary", board(self.store)[HN_STORY])


def hn_story(item, title, points, first_seen):
    """An Incident seen only as an HN story (no CVE, no Product), as the real 2026-11-08 run stored them."""
    url = f"https://news.ycombinator.com/item?id={item}"
    return {"id": url, "cves": [], "first_seen": first_seen,
            "mentions": [{"kind": "discussion", "url": url, "title": title, "points": points}],
            "urls": [f"news.ycombinator.com/item?id={item}"], "brief": {"text": title, "lead": url}}


REAL_RUN = "2026-11-08T03:38:07Z"


class InstantOrderTest(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.store.write("checkpoints.json", {"cvelist": "2026-11-08T03:00:00.000Z"})
        self.store.write("index.json", {"months": ["2026-11"]})

    def test_the_per_cycle_cap_goes_to_kev_then_cvss_then_curator_then_hn(self):
        # The real run: HN stories arrived before the KEV-listed SonicWall CVE and used up the cap of ten.
        stories = [hn_story(50400000 + n, f"Story {n}", 500, REAL_RUN) for n in range(9)]
        curated = incident("CVE-2026-83844", "A curated flaw", REAL_RUN)
        curated["mentions"].append({"kind": "curator", "url": "https://tldrsec.com/p/tldr-sec-351"})
        critical = incident("CVE-2026-123957", "TOTOLINK CA300-PoE ...", REAL_RUN) | {"cvss": 9.9}
        sonicwall = incident("CVE-2026-19868", "SonicOS SSLVPN ...", REAL_RUN) | {"cvss": 7.5, "kev": True}
        self.store.write("months/2026-11.json", {"month": "2026-11", "incidents": stories + [curated, critical, sonicwall]})
        claude = FakeClaude(*["not json"] * 10)

        run_cycle(self.store, recorded(None), at("2026-11-08T03:45:00"), "test-box", claude=claude)

        firsts = [claude.user_text(n).split("\n")[0] for n in range(len(claude.sent))]
        self.assertEqual(len(firsts), 10)
        self.assertEqual(firsts[:4], ["Incident: CVE-2026-19868", "Incident: CVE-2026-123957",
                                      "Incident: CVE-2026-83844", "Incident: no CVE yet"])

    def test_a_story_seen_only_on_hn_is_summarized_at_once_only_with_strong_buzz(self):
        # Real run stories: general security news at 23 and 93 points; sshole was seen at 2910.
        weak = hn_story(50407643, "Hackers pull off $133M French bank heist via service provider", 23, REAL_RUN)
        near = hn_story(50399569, "A story just short of the bar", 93, REAL_RUN)
        sshole = hn_story(50378228, "sshole", 2910, REAL_RUN)
        self.store.write("months/2026-11.json", {"month": "2026-11", "incidents": [weak, near, sshole]})
        claude = FakeClaude("not json")

        run_cycle(self.store, recorded(None), at("2026-11-08T03:45:00"), "test-box", claude=claude)

        self.assertEqual(len(claude.sent), 1)
        self.assertIn(HN_STORY, claude.user_text())
        self.assertEqual(len(claude.batch_inputs()), 2)  # the other two still get a Summary, through the batch

    def test_a_cve_record_not_yet_on_the_raw_path_is_read_from_the_cve_services_api(self):
        # The real run: three fresh records answered 404 on raw.githubusercontent.com.
        sonicwall = incident("CVE-2026-19868", "SonicOS SSLVPN ...", REAL_RUN) | {"cvss": 7.5, "kev": True}
        self.store.write("months/2026-11.json", {"month": "2026-11", "incidents": [sonicwall]})
        answer = recorded(None)

        def get(url, headers=None):
            if url.startswith("https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/"):
                raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
            if url == "https://cveawg.mitre.org/api/cve/CVE-2026-19868":
                return (FIXTURES / "cvelist" / "cveawg-CVE-2026-19868.json").read_bytes()
            return answer(url, headers)

        claude = FakeClaude("not json")
        run_cycle(self.store, get, at("2026-11-08T03:45:00"), "test-box", claude=claude)

        self.assertIn("7.3.3-7015 and older versions", claude.user_text())


NHS = "https://www.theregister.com/security/2026/11/07/nhs-breach-helpline-left-staff-carrying-a-significant-emotional-burden/5308201"
HEIST = "https://www.bleepingcomputer.com/news/security/hackers-pull-off-133-million-french-bank-heist-via-service-provider/"


def news_reply(ko, en):
    """A Summary reply for general news: no product, no fix, only the sentence under test."""
    fields = {"title": "", "summary": "", "conditions": [], "mitigation": "", "easy": ""}
    return {"ko": fields | {"summary": ko}, "en": fields | {"summary": en},
            "products": [], "lead": "", "fixed": "", "command": "", "stopgap": "", "devices": []}


class NumberCheckTest(unittest.TestCase):
    """The two real-run rejections, '715' and '1', with the write-ups they were built from (trimmed)."""

    def summarize(self, item, page_url, page, reply):
        store = MemoryStore()
        store.write("checkpoints.json", {"cvelist": "2026-11-08T03:00:00.000Z"})
        store.write("index.json", {"months": ["2026-11"]})
        story = hn_story(item, "a story", 500, REAL_RUN)
        story["mentions"].append({"kind": "writeup", "url": page_url})
        store.write("months/2026-11.json", {"month": "2026-11", "incidents": [story]})
        run_cycle(store, recorded(None, web={page_url: page}), at("2026-11-08T03:45:00"), "test-box",
                  claude=FakeClaude(reply))
        return board(store)[story["id"]]

    def test_korean_counters_and_number_units_pass_when_the_value_is_the_sources(self):
        cases = {
            "a counter after a thousands comma": (NHS, "nhs-helpline.txt", news_reply(
                "직원 7,715명과 외부 인력 288명의 건강 정보가 노출되었습니다.",
                "Health data of 7,715 staff and 288 non-trust workers was exposed.")),
            "만 and 억 for millions": (HEIST, "bank-heist.txt", news_reply(
                "최대 1억 3,300만 달러(1억 1,800만 유로)가 빠져나갔고, 은행 회원은 580만 명입니다.",
                "Up to $133 million (118 million euros) was taken; the bank has 5.8 million members.")),
        }
        for case, (url, page, reply) in cases.items():
            with self.subTest(case):
                self.assertIn("summary", self.summarize(50410137, url, page, reply))

    def test_a_korean_amount_with_another_value_is_still_rejected(self):
        incident = self.summarize(50407643, HEIST, "bank-heist.txt", news_reply(
            "최대 1억 3,400만 달러가 빠져나갔습니다.", "Up to $133 million was taken."))
        self.assertNotIn("summary", incident)
        self.assertIn("numbers not in the input", incident["summary_error"]["reason"])


if __name__ == "__main__":
    unittest.main()
