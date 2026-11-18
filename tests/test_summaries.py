"""Seam 1: instant Summaries for Highlight candidates, with a fake Claude client.

pages/sshhole.com.html and pages/release-10.6p2.txt are the real pages (2026-11-07), trimmed.
"""

import contextlib
import copy
import io
import json
import re
import unittest
import unittest.mock
import urllib.error
from types import SimpleNamespace

from collector import summaries, summary_input
from collector.model import MAX_TOKENS, MAX_TOKENS_GROUP, MAX_TOKENS_RETRY, REQUEST_TIMEOUT
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
        "easy_conditions": ["Alpine처럼 musl을 쓰는 리눅스", "PAM을 쓰지 않을 때", "비밀번호로 접속을 허용할 때", "비밀번호가 `*`인 계정이 있을 때"],
        "mitigation": "OpenSSH 10.6p2로 업데이트하세요. 당장 못 하면 PasswordAuthentication no로 비밀번호 로그인을 끄세요.",
        "easy": "Alpine이나 OpenWrt 서버에 아무 긴 비밀번호로 남이 로그인할 수 있습니다.",
        "easy_title": "Alpine·OpenWrt SSH 로그인 뚫림 위험 발견",
        "easy_action": "OpenSSH를 새 버전으로 업데이트하고, 그 전에는 비밀번호 로그인을 끄세요.",
        "names": ["OpenSSH"],
        "command_for": "",
        "stopgap_then": "",
        "cve_lines": [],
    },
    "en": {
        "title": "OpenSSH on musl lets password-less accounts in with a long password",
        "summary": "sshd built against musl libc without PAM accepts any password of 257 to 1024 characters "
                   "for accounts whose password is `*`. musl systems such as Alpine and OpenWrt are affected.",
        "conditions": ["musl libc", "PAM not used", "password logins on", "an account whose password is `*`"],
        "easy_conditions": ["Linux built on musl, such as Alpine", "PAM is not used", "password logins are allowed", "an account has `*` as its password"],
        "mitigation": "Update to OpenSSH 10.6p2. Until then, set PasswordAuthentication no to turn password logins off.",
        "easy": "Anyone can log in to an Alpine or OpenWrt server with any long password.",
        "easy_title": "Alpine and OpenWrt SSH logins open to anyone",
        "easy_action": "Update OpenSSH, and turn password logins off until then.",
        "names": ["OpenSSH"],
        "command_for": "",
        "stopgap_then": "",
        "cve_lines": [],
    },
    "products": ["OpenSSH"],
    "lead": "https://sshhole.com",
    "fixed": "10.6p2",
    "command": "apk upgrade openssh",
    "stopgap": "PasswordAuthentication no",
    "devices": [],
    "fixes": [],
    "incident": True,
    "platforms": ["Linux"],
    "stopgap_file": "",
    "titles_ko": [],
    "exploited": False,
    "exploited_source": "",
    "poc_public": False,
    "library": False,
    "widely_used": False,
}


def cut(text):
    """A reply cut off at max_tokens after `text`, for FakeClaude."""
    return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)], stop_reason="max_tokens",
                           usage=SimpleNamespace(input_tokens=0, output_tokens=0))


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
        if isinstance(reply, SimpleNamespace):  # a whole reply, cut() say
            return reply
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
        self.assertEqual(sent["output_config"]["format"]["schema"]["required"], ["ko", "en", "products", "lead", "fixed", "command", "stopgap", "devices", "fixes", "incident", "platforms", "stopgap_file", "titles_ko", "exploited", "exploited_source", "poc_public", "library", "same_as"])
        [instructions] = sent["system"]
        self.assertEqual(instructions["cache_control"], {"type": "ephemeral"})
        # Haiku 5.5 caches only a prefix of 512 tokens or more; ~4 characters a token in English.
        self.assertGreater(len(instructions["text"]), 4 * 512)
        self.assertIn("use the one in the text marked as the Lead", instructions["text"])
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
            "a per-line fix naming a version not in the input": SSHOLE_SUMMARY | {"fixes": [{"for": "OpenSSH", "version": "10.7p1"}]},
            "a per-line fix that is not an object": SSHOLE_SUMMARY | {"fixes": ["10.6p2"]},
            "a per-line fix without a version": SSHOLE_SUMMARY | {"fixes": [{"for": "OpenSSH"}]},
            "a per-line model with a number not in the input": SSHOLE_SUMMARY | {"fixes": [{"for": "OpenSSH", "version": "10.6p2", "devices": ["Router X9000"]}]},
            "a per-line model list that is not a list": SSHOLE_SUMMARY | {"fixes": [{"for": "OpenSSH", "version": "10.6p2", "devices": "all"}]},
            "a stopgap step with a made-up number": SSHOLE_SUMMARY | {"en": SSHOLE_SUMMARY["en"] | {"stopgap_then": "Wait 30 seconds."}},
            "a command context with a made-up number": SSHOLE_SUMMARY | {"en": SSHOLE_SUMMARY["en"] | {"command_for": "On Alpine 3.99"}},
            "an Easy action naming a version not in the input": SSHOLE_SUMMARY | {"en": en | {"easy_action": "Update to 10.7p1."},
                                                                                 "ko": ko | {"easy_action": "10.7p1로 업데이트하세요."}},
            "a missing field": {k: v for k, v in SSHOLE_SUMMARY.items() if k != "lead"},
            "a missing Easy field": {k: v for k, v in SSHOLE_SUMMARY.items() if k != "command"},
            "a field of the wrong type": SSHOLE_SUMMARY | {"products": "OpenSSH"},
            "an exploited flag that is not true or false": SSHOLE_SUMMARY | {"exploited": "yes"},
            "a public-exploit flag that is not true or false": SSHOLE_SUMMARY | {"poc_public": "yes"},
            "a library flag that is not true or false": SSHOLE_SUMMARY | {"library": 1},
            "a widely-used flag that is not true or false": SSHOLE_SUMMARY | {"widely_used": "yes"},
            "an exploited source that is not text": SSHOLE_SUMMARY | {"exploited": True, "exploited_source": ["https://sshhole.com"]},
        }
        for case, reply in bad.items():
            with self.subTest(case):
                self.setUp()
                self.run_at("2026-11-07T12:30:00", FakeClaude(reply), hn="sshole.json")
                incident = board(self.store)[HN_STORY]
                self.assertNotIn("summary", incident)
                self.assertEqual(incident["summary_error"]["tries"], 1)

    def test_a_lead_written_another_way_is_the_input_url_it_stands_for(self):
        # Round 2: the KISA notice "https://www.boho.or.kr/...?…&nttId=…" came back without www. and was refused.
        self.run_at("2026-11-07T12:30:00", FakeClaude(SSHOLE_SUMMARY | {"lead": "http://www.sshhole.com/"}), hn="sshole.json")

        self.assertEqual(board(self.store)[HN_STORY]["summary"]["lead"], "https://sshhole.com")

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

    def test_a_reply_from_before_easy_title_still_passes_with_it_empty(self):
        old = SSHOLE_SUMMARY | {lang: {k: v for k, v in SSHOLE_SUMMARY[lang].items() if k != "easy_title"} for lang in ("ko", "en")}
        self.merged_sshole(FakeClaude(old))
        summary = board(self.store)[HN_STORY]["summary"]
        self.assertEqual((summary["ko"]["easy_title"], summary["ko"]["title"]), ("", SSHOLE_SUMMARY["ko"]["title"]))

    def test_fixed_versions_per_product_line_are_kept_and_old_replies_have_none(self):
        self.merged_sshole(FakeClaude(SSHOLE_SUMMARY | {"fixes": [{"for": "OpenSSH portable", "version": "10.6p2"}]}))
        # A per-line fix from before its models were asked for has none.
        self.assertEqual(board(self.store)[HN_STORY]["summary"]["fixes"], [{"for": "OpenSSH portable", "version": "10.6p2", "devices": []}])
        self.setUp()
        self.merged_sshole(FakeClaude({k: v for k, v in SSHOLE_SUMMARY.items() if k != "fixes"}))  # a reply from before
        self.assertEqual(board(self.store)[HN_STORY]["summary"]["fixes"], [])

    def test_each_per_line_fix_carries_its_own_models(self):
        fixes = [{"for": "OpenSSH portable", "version": "10.6p2", "devices": ["OpenSSH portable on Alpine"]}]
        self.merged_sshole(FakeClaude(SSHOLE_SUMMARY | {"fixes": fixes}))
        self.assertEqual(board(self.store)[HN_STORY]["summary"]["fixes"], fixes)

    def test_the_command_says_which_system_it_is_for_and_the_stopgap_names_its_file(self):
        reply = SSHOLE_SUMMARY | {"ko": SSHOLE_SUMMARY["ko"] | {"command_for": "Alpine 리눅스라면"},
                                  "en": SSHOLE_SUMMARY["en"] | {"command_for": "On Alpine Linux"},
                                  "stopgap_file": "/etc/ssh/sshd_config.d/00-no-passwords.conf"}
        self.merged_sshole(FakeClaude(reply))
        summary = board(self.store)[HN_STORY]["summary"]
        self.assertEqual((summary["ko"]["command_for"], summary["en"]["command_for"]), ("Alpine 리눅스라면", "On Alpine Linux"))
        self.assertEqual(summary["stopgap_file"], "/etc/ssh/sshd_config.d/00-no-passwords.conf")

    # These check the URL and reporter rules; the owner's evidence rule of 11-16 (own source, reported attacks) has its
    # own tests in test_rules_1116_night.py, so it is set aside here.
    @unittest.mock.patch("collector.summaries.attacks_evidenced", lambda summary, kind: True)
    def test_reported_attacks_need_the_input_url_that_reports_them_and_old_replies_say_no(self):
        # Owner, 11-09: Brotli was 악용 발생 from a write-up, an HN post and PoC repos; no source reported attacks.
        advisory = "https://www.openssh.com/txt/release-10.6p2"
        cases = {"an input URL": ({"exploited": True, "exploited_source": advisory}, (True, advisory)),
                 # Audit run-1 item 1: an HN poster's page below the Lead cannot lift the row to its top Risk level.
                 "a write-up below the Lead": ({"exploited": True, "exploited_source": "https://sshhole.com"}, (False, "")),
                 "no source": ({"exploited": True, "exploited_source": ""}, (False, "")),
                 "a URL not in the input": ({"exploited": True, "exploited_source": "https://example.com/attacks"}, (False, "")),
                 "a reply from before": ({k: v for k, v in SSHOLE_SUMMARY.items() if k not in ("exploited", "exploited_source")}, (False, "")),
                 "a source without the flag": ({"exploited_source": "https://sshhole.com"}, (False, ""))}
        for case, (reply, want) in cases.items():
            with self.subTest(case):
                self.setUp()
                base = {} if case == "a reply from before" else SSHOLE_SUMMARY
                self.merged_sshole(FakeClaude(base | reply))
                summary = board(self.store)[HN_STORY]["summary"]
                self.assertEqual((summary["exploited"], summary["exploited_source"]), want)

    def test_public_exploit_code_is_its_own_flag_and_never_makes_an_incident_exploited(self):
        self.merged_sshole(FakeClaude(SSHOLE_SUMMARY | {"poc_public": True}))
        summary = board(self.store)[HN_STORY]["summary"]
        self.assertEqual((summary["poc_public"], summary["exploited"]), (True, False))
        self.setUp()
        self.merged_sshole(FakeClaude({k: v for k, v in SSHOLE_SUMMARY.items() if k not in ("poc_public", "library", "widely_used")}))
        summary = board(self.store)[HN_STORY]["summary"]
        # Replies from before say none of them (widely_used came on 11-11).
        self.assertEqual((summary["poc_public"], summary["library"], summary["widely_used"]), (False, False, False))

    def test_the_schema_does_not_ask_for_widely_used(self):
        # 11-11: adding it made every request fail with 400 "The compiled grammar is too large"; well_known.json does the job.
        self.assertNotIn("widely_used", summaries.SCHEMA["required"])
        self.assertNotIn("widely_used", summaries.SCHEMA["properties"])
        self.assertNotIn("widely_used", summaries.INSTRUCTIONS)

    def test_the_schema_does_not_ask_for_exploited_cves(self):
        # Step 4, 11-16: even optional, it made --smoke fail with 400 "compiled grammar is too large" (widely_used, 11-11).
        self.assertNotIn("exploited_cves", summaries.SCHEMA["required"])
        self.assertNotIn("exploited_cves", summaries.SCHEMA["properties"])
        self.assertNotIn("exploited_cves", summaries.INSTRUCTIONS)
        self.assertIn("Lead CVE", summaries.INSTRUCTIONS)

    def test_the_instructions_ask_for_the_attack_source_and_name_the_product_in_easy_headlines(self):
        self.assertIn("exploited_source", summaries.INSTRUCTIONS)
        self.assertIn("in the wild", summaries.INSTRUCTIONS)
        self.assertIn("poc_public", summaries.INSTRUCTIONS)
        self.assertIn("never makes it exploited", summaries.INSTRUCTIONS)
        # Critique 14: Easy headlines dropped the product ("서버 멈춤 위험").
        for text in (summaries.INSTRUCTIONS, summaries.TITLE_INSTRUCTIONS):
            self.assertIn("must name the product", text)

    def test_the_instructions_never_translate_product_names(self):
        # Critique 14: "IBM SevOne 네트워크 성능 관리" on the Korean page split one Product in two.
        self.assertIn("Never translate a product name", summaries.INSTRUCTIONS)
        self.assertIn("IBM SevOne Network Performance Management", summaries.INSTRUCTIONS)

    def test_an_exploited_summary_without_its_source_is_made_again_within_the_limit(self):
        incident = {"id": "CVE-2026-111497", "cves": ["CVE-2026-111497"], "kev": True, "mentions": [],
                    "summary": {"exploited": True}, "summary_basis": {"cves": ["CVE-2026-111497"], "kev": True, "advisories": [], "n": 1}}
        self.assertTrue(summaries.needs_summary(incident))
        self.assertFalse(summaries.needs_summary(incident | {"summary": {"exploited": True, "exploited_source": "https://x.example/"}}))
        self.assertFalse(summaries.needs_summary(incident | {"summary": {"exploited": False, "exploited_source": ""}}))
        self.assertFalse(summaries.needs_summary(incident | {"summary_basis": incident["summary_basis"] | {"n": summaries.MAX_SUMMARIES}}))

    def test_repos_joined_after_a_no_poc_summary_ask_once_more(self):
        # 11-18: PoC repositories joined Java4Shell after its Summary; poc_public stayed false for hours.
        repo = lambda n: {"kind": "repo", "url": f"https://github.com/someone/CVE-2026-114938-poc{n}"}  # noqa: E731
        incident = {"id": "CVE-2026-114938", "cves": ["CVE-2026-114938"], "mentions": [repo(1)]}
        incident["summary_basis"] = summaries.basis(incident) | {"n": 1}  # as the first Summary stores it
        incident["summary"] = {"poc_public": False}
        self.assertEqual(incident["summary_basis"], {"cves": ["CVE-2026-114938"], "kev": False, "advisories": [], "repos": 1, "n": 1})
        self.assertFalse(summaries.needs_summary(incident))  # the Summary saw this repo
        incident["mentions"].append(repo(2))
        self.assertTrue(summaries.needs_summary(incident))
        self.assertFalse(summaries.needs_summary(incident | {"summary": {"poc_public": True}}))
        self.assertFalse(summaries.needs_summary(incident | {"summary_basis": incident["summary_basis"] | {"n": summaries.MAX_SUMMARIES}}))
        # Once: the next Summary still says no PoC, and a third repo asks nothing.
        incident["summary_basis"] = summaries.basis(incident) | {"n": 2}
        self.assertTrue(incident["summary_basis"]["poc_asked"])
        incident["mentions"].append(repo(3))
        self.assertFalse(summaries.needs_summary(incident))
        self.assertTrue(summaries.basis(incident)["poc_asked"])  # carried into every later basis
        # A basis from before the rule counts no repos; a CVE-less story's repo is its own project.
        old = {"cves": ["CVE-2026-114938"], "kev": False, "advisories": [], "n": 1}
        self.assertTrue(summaries.needs_summary(incident | {"summary_basis": old}))
        self.assertFalse(summaries.needs_summary(incident | {"cves": [], "summary_basis": old | {"cves": []}}))

    def test_the_easy_stopgap_carries_the_step_that_makes_it_work(self):
        reply = SSHOLE_SUMMARY | {"ko": SSHOLE_SUMMARY["ko"] | {"stopgap_then": "바꾼 뒤 sshd를 다시 시작하세요."},
                                  "en": SSHOLE_SUMMARY["en"] | {"stopgap_then": "Then restart sshd."}}
        self.merged_sshole(FakeClaude(reply))
        self.assertEqual(board(self.store)[HN_STORY]["summary"]["en"]["stopgap_then"], "Then restart sshd.")

    def test_the_instructions_keep_the_condition_in_the_easy_headline(self):
        self.assertIn("never widen it to every user of the product", summaries.INSTRUCTIONS)
        # 11-09: the headline said "Alpine" while the sources said musl Linux such as Alpine or OpenWrt.
        self.assertIn("never one example alone", summaries.INSTRUCTIONS)
        self.assertIn("Alpine·OpenWrt SSH", summaries.INSTRUCTIONS)  # the example names every example

    def test_the_instructions_give_web_software_no_platforms(self):
        # Owner, 11-09: a WordPress plugin wore Windows, macOS and Linux badges because its host can be any OS.
        self.assertIn("installed on and runs natively on", summaries.INSTRUCTIONS)
        self.assertIn("CMS plugins (WordPress, Drupal", summaries.INSTRUCTIONS)
        self.assertIn("empty platforms list even if their host can be any OS", summaries.INSTRUCTIONS)
        self.assertNotIn("Java servers such as Apache Axis2", summaries.INSTRUCTIONS)  # a web app: no longer an example

    def test_a_stopgap_file_not_in_the_input_is_dropped_and_old_replies_have_none(self):
        self.merged_sshole(FakeClaude(SSHOLE_SUMMARY | {"stopgap_file": "/etc/ssh/sshd_config"}))  # the page names another file
        summary = board(self.store)[HN_STORY]["summary"]
        self.assertEqual((summary["stopgap_file"], summary["ko"]["command_for"], summary["titles_ko"]), ("", "", []))

    def test_english_mention_titles_get_a_korean_line_for_input_links_only(self):
        reply = SSHOLE_SUMMARY | {"titles_ko": [{"url": HN_STORY, "title": "sshole (OpenSSH 로그인 결함)"},
                                                {"url": "https://example.org/elsewhere", "title": "다른 곳"},
                                                {"url": HN_STORY, "title": "9999개 서버"}]}  # a made-up number: that line only
        self.merged_sshole(FakeClaude(reply))
        self.assertEqual(board(self.store)[HN_STORY]["summary"]["titles_ko"], [{"url": HN_STORY, "title": "sshole (OpenSSH 로그인 결함)"}])

    def test_the_easy_view_gets_its_own_plain_action_sentence(self):
        self.merged_sshole(FakeClaude(SSHOLE_SUMMARY))
        summary = board(self.store)[HN_STORY]["summary"]
        self.assertEqual(summary["ko"]["easy_action"], SSHOLE_SUMMARY["ko"]["easy_action"])

    def test_a_reply_from_before_easy_action_still_passes_with_it_empty(self):
        # Since 11-16 night an empty Easy action beside a fixed version costs a retry (owner); a reply from before the
        # field (no batch of then can still arrive) is kept on the last try, with the Easy action empty as before.
        old = SSHOLE_SUMMARY | {lang: {k: v for k, v in SSHOLE_SUMMARY[lang].items() if k != "easy_action"} for lang in ("ko", "en")}
        incident = {"id": "x", "mentions": [{"kind": "writeup", "url": SSHOLE_SUMMARY["lead"]}],
                    "summary_error": {"tries": summaries.MAX_TRIES - 1, "reason": "earlier"}}
        text = f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n" + json.dumps(SSHOLE_SUMMARY, ensure_ascii=False)
        summaries.save_reply(incident, FakeClaude.message(old), text, {"cves": [], "kev": False, "advisories": [], "n": 0},
                             "2026-11-08T12:00:00Z")
        self.assertEqual(incident["summary"]["en"]["easy_action"], "")

    def test_a_cve_id_the_model_puts_in_a_title_is_taken_out(self):
        reply = SSHOLE_SUMMARY | {"ko": SSHOLE_SUMMARY["ko"] | {"title": SSHOLE_SUMMARY["ko"]["title"] + " (CVE-2026-123158)"},
                                  "en": SSHOLE_SUMMARY["en"] | {"title": "[CVE-2026-123158] " + SSHOLE_SUMMARY["en"]["title"]}}
        self.merged_sshole(FakeClaude(reply))
        summary = board(self.store)[HN_STORY]["summary"]
        self.assertEqual((summary["ko"]["title"], summary["en"]["title"]), (SSHOLE_SUMMARY["ko"]["title"], SSHOLE_SUMMARY["en"]["title"]))

    def test_a_version_named_in_one_language_only_passes_the_number_check_but_costs_a_retry(self):
        # Versions must still appear in the input; only whole numbers are compared across languages. A version in one
        # language only is a soft problem since the second 11-11 review (language_gaps): retried, the last try kept.
        reply = SSHOLE_SUMMARY | {"ko": SSHOLE_SUMMARY["ko"] | {"mitigation": "최신 OpenSSH로 업데이트하세요."}}
        self.run_at("2026-11-07T12:30:00", FakeClaude(reply), hn="sshole.json")
        self.assertEqual(board(self.store)[HN_STORY]["summary_error"]["reason"],
                         "a version stands in one language only: ['10.6p2']")

    def test_the_instructions_ask_to_copy_numbers_and_dates_as_the_source_writes_them(self):
        claude = FakeClaude(SSHOLE_SUMMARY)
        self.run_at("2026-11-07T12:30:00", claude, hn="sshole.json")

        text = claude.sent[0]["system"][0]["text"]
        self.assertIn("as the source writes", text)
        self.assertNotIn("YYYY-MM-DD", text)
        self.assertNotIn("with digits", text)

    def test_the_instructions_cover_a_flaw_already_fixed_by_unnamed_companies(self):
        # The ForgeRock story (samcurry.net/forgerock): two automakers asked not to be named and fixed it within hours.
        claude = FakeClaude(SSHOLE_SUMMARY)
        self.run_at("2026-11-07T12:30:00", claude, hn="sshole.json")

        text = claude.sent[0]["system"][0]["text"]
        self.assertIn("already fixed it on its own servers", text)
        self.assertIn("never guess them from other names on the page", text)

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

    def test_the_seven_days_count_from_the_publish_time_not_the_first_sighting(self):
        from datetime import datetime
        now = datetime(2026, 11, 9, 12, 0)
        old = {"cves": ["CVE-2026-83844"], "cvss": 9.8, "mentions": [{"kind": "cve_record", "url": "https://www.cve.org/"}],
               "first_seen": "2026-11-08T03:38:07Z", "published": "2026-10-13T18:59:53Z"}
        self.assertFalse(summaries.is_candidate(old, now))
        self.assertTrue(summaries.is_candidate({k: v for k, v in old.items() if k != "published"}, now))

    def test_an_incident_at_the_high_risk_level_or_above_is_summarized_at_once_not_in_a_batch(self):
        # User, 11-09: 위험 (CVSS 7.0+) and up never wait for a Message Batch.
        from datetime import datetime
        now = datetime(2026, 11, 9, 12, 0)
        row = lambda cvss: {"cves": ["CVE-2026-9"], "cvss": cvss, "mentions": [{"kind": "cve_record", "url": "https://www.cve.org/"}],
                            "first_seen": "2026-11-09T11:00:00Z", "published": "2026-11-09T10:00:00Z"}
        self.assertTrue(summaries.is_candidate(row(7.0), now))
        self.assertFalse(summaries.is_candidate(row(6.9), now))
        buzz_only = {**row(None), "mentions": [{"kind": "discussion", "url": "https://news.ycombinator.com/item?id=1", "points": 500}]}
        ranked = sorted([buzz_only, row(7.5), row(9.8)], key=summaries.priority)
        self.assertEqual([i["cvss"] for i in ranked], [9.8, 7.5, None])
        # A well-known product (collector/well_known.json) goes before a lesser one of its band.
        chrome = row(9.6) | {"products": [{"id": "google:chrome", "name": "Google Chrome"}]}
        ranked = sorted([row(9.8), chrome], key=summaries.priority)
        self.assertEqual([i["cvss"] for i in ranked], [9.6, 9.8])

    def test_the_instant_path_stops_at_its_budget_and_the_rest_wait_for_the_next_cycle(self):
        # 11-18 06:40 KST: 96 Incidents at once, every candidate asked one after another; the cycle took 25 min 53 s.
        from datetime import datetime
        from collector.cycle import INSTANT_SECONDS, route_summaries
        from collector.logfile import CycleLine
        now, t = datetime(2026, 11, 9, 12, 0), [0]
        row = lambda n, cvss, **more: {"id": f"CVE-2026-{n}", "cves": [f"CVE-2026-{n}"], "cvss": cvss, "mentions": [],  # noqa: E731
                                       "first_seen": "2026-11-09T11:00:00Z", "published": "2026-11-09T10:00:00Z",
                                       "products": [], "brief": {"text": "A flaw.", "lead": ""}, **more}
        rows = [row(1, 7.5), row(2, 9.8), row(3, 7.0, kev=True), row(4, 8.0)]
        claude = FakeClaude(*["{"] * 8)
        create = claude.messages.create

        def slow(**params):  # each Summary takes 70 s of the clock; the titles request none
            t[0] += 70 if "Incident:" in params["messages"][0]["content"] else 0
            return create(**params)
        claude.messages.create = slow
        asked = lambda: [p["messages"][0]["content"].split("\n")[0] for p in claude.sent if "Incident:" in p["messages"][0]["content"]]  # noqa: E731
        line = CycleLine("2026-11-09T12:00:00Z", lambda: t[0])
        with contextlib.redirect_stderr(io.StringIO()):
            route_summaries(rows, [], claude, lambda url, headers=None: b"", now, "2026-11-09T12:00:00Z", set(), probe=False,
                            clock=lambda: t[0], line=line)
        # The cycle's log line counts them: three asked (each reply unreadable, so failed), one kept back.
        self.assertEqual({k: line.counts[k] for k in ("summaries_asked", "summaries_kept_back", "summaries_failed")},
                         {"summaries_asked": 3, "summaries_kept_back": 1, "summaries_failed": 3})
        # KEV, then CVSS 9+, then arrival order inside the 7+ band; started at 0, 70 and 140 s of the 180.
        self.assertEqual(asked(), ["Incident: CVE-2026-3", "Incident: CVE-2026-2", "Incident: CVE-2026-1"])
        self.assertEqual(INSTANT_SECONDS, 180)
        # Kept back, not failed: no try counted, still due, and still an instant candidate for the next cycle.
        self.assertNotIn("summary_error", rows[3])
        self.assertTrue(summaries.needs_summary(rows[3]) and summaries.is_candidate(rows[3], now))

    def test_a_group_summary_gives_each_cve_one_line_and_names_only_cves_from_the_input(self):
        lines = {"ko": [{"cve": "CVE-2026-123158", "text": "긴 비밀번호로 로그인 우회"}], "en": [{"cve": "CVE-2026-123158", "text": "Login bypass with a long password"}]}
        reply = SSHOLE_SUMMARY | {lang: SSHOLE_SUMMARY[lang] | {"cve_lines": lines[lang]} for lang in ("ko", "en")}
        self.merged_sshole(FakeClaude(reply))
        self.assertEqual(board(self.store)[HN_STORY]["summary"]["ko"]["cve_lines"], lines["ko"])
        self.setUp()
        made_up = SSHOLE_SUMMARY | {"en": SSHOLE_SUMMARY["en"] | {"cve_lines": [{"cve": "CVE-2026-999999", "text": "x"}]}}
        self.merged_sshole(FakeClaude(made_up))
        self.assertNotIn("summary", board(self.store)[HN_STORY])
        self.assertIn("cve_lines", summaries.INSTRUCTIONS)

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

    def test_every_candidate_is_summarized_in_the_cycle_that_sees_it_kev_first(self):
        # No per-cycle cap on a breaking-news board (owner, 2026-11-09); the order still leads with KEV, then CVSS.
        stories = [hn_story(50400000 + n, f"Story {n}", 500, REAL_RUN) for n in range(9)]
        curated = incident("CVE-2026-83844", "A curated flaw", REAL_RUN)
        curated["mentions"].append({"kind": "curator", "url": "https://tldrsec.com/p/tldr-sec-351"})
        critical = incident("CVE-2026-123957", "TOTOLINK CA300-PoE ...", REAL_RUN) | {"cvss": 9.9}
        sonicwall = incident("CVE-2026-19868", "SonicOS SSLVPN ...", REAL_RUN) | {"cvss": 7.5, "kev": True}
        self.store.write("months/2026-11.json", {"month": "2026-11", "incidents": stories + [curated, critical, sonicwall]})
        claude = FakeClaude(*["not json"] * 12)

        run_cycle(self.store, recorded(None), at("2026-11-08T03:45:00"), "test-box", claude=claude)

        firsts = [claude.user_text(n).split("\n")[0] for n in range(len(claude.sent))]
        self.assertEqual(len(firsts), 12)
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
    fields = {"title": "", "summary": "", "conditions": [], "easy_conditions": [], "mitigation": "", "easy": "", "easy_title": "", "easy_action": "", "names": []}
    return {"ko": fields | {"summary": ko}, "en": fields | {"summary": en},
            "products": [], "lead": "", "fixed": "", "command": "", "stopgap": "", "devices": [], "fixes": [], "incident": True, "platforms": []}


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


class ExploitedCvesTest(unittest.TestCase):
    """Step 4: a group's Summary names the CVEs its exploited_source reports attacked; only the Incident's own, by exact id."""

    ADVISORY = "https://vendor.example/advisory"
    INPUT = "\n".join(["Incident: CVE-2026-125350, CVE-2026-125345", "Lead CVE: CVE-2026-125350", "CVSS: not rated yet",
                       "Exploited in the wild (CISA KEV): no", "Products: unknown", "Description: Browser flaws.", "Mentions:",
                       f"- advisory {ADVISORY}"])

    def parsed(self, **fields):
        data = news_reply("", "") | {"exploited": True, "exploited_source": self.ADVISORY} | fields
        reply = SimpleNamespace(content=[SimpleNamespace(type="text", text=json.dumps(data))], stop_reason="end_turn",
                                usage=SimpleNamespace(input_tokens=0, output_tokens=0))
        return summaries.parse(reply, self.INPUT, [self.ADVISORY])

    # These check the URL and reporter rules; the owner's evidence rule of 11-16 (own source, reported attacks) has its
    # own tests in test_rules_1116_night.py, so it is set aside here.
    @unittest.mock.patch("collector.summaries.attacks_evidenced", lambda summary, kind: True)
    def test_attacked_cves_outside_the_incident_are_dropped_by_exact_id(self):
        summary = self.parsed(exploited_cves=["CVE-2026-125350", "CVE-2026-12534", "CVE-2026-999999", "cve-2026-125345",
                                              "CVE-2026-125350", 7])
        self.assertEqual(summary.get("exploited_cves", []), ["CVE-2026-125350"])

    def test_the_list_empties_when_exploited_does_not_survive(self):
        summary = self.parsed(exploited_source="https://example.com/attacks", exploited_cves=["CVE-2026-125350"])
        self.assertEqual((summary["exploited"], summary.get("exploited_cves", [])), (False, []))
        self.assertEqual(self.parsed(exploited=False, exploited_cves=["CVE-2026-125350"]).get("exploited_cves", []), [])

    # These check the URL and reporter rules; the owner's evidence rule of 11-16 (own source, reported attacks) has its
    # own tests in test_rules_1116_night.py, so it is set aside here.
    @unittest.mock.patch("collector.summaries.attacks_evidenced", lambda summary, kind: True)
    def test_an_old_reply_without_the_field_parses(self):
        summary = self.parsed()
        self.assertEqual((summary["exploited"], summary.get("exploited_cves", [])), (True, []))
        self.assertEqual(self.parsed(exploited_cves="CVE-2026-125350").get("exploited_cves", []), [])  # not a list: none named


class ConditionsPerCveTest(unittest.TestCase):
    """H4: a group's condition opens with the ids of the CVEs it holds for; one for every CVE has none."""

    A, B, C = "CVE-2026-125350", "CVE-2026-125345", "CVE-2026-12534"
    GROUP = "\n".join([f"Incident: {A}, {B}, {C}", f"Lead CVE: {A}", "CVSS: not rated yet", "Exploited in the wild (CISA KEV): no",
                       "Products: unknown", "Description: Browser flaws, see also CVE-2026-999999.", "Mentions:"])

    def parsed(self, conditions, text=GROUP, easy=None, field="conditions"):
        data = news_reply("", "")
        for lang in ("ko", "en"):
            data[lang] |= {"conditions": conditions, "easy_conditions": conditions if easy is None else easy}
        reply = SimpleNamespace(content=[SimpleNamespace(type="text", text=json.dumps(data))], stop_reason="end_turn",
                                usage=SimpleNamespace(input_tokens=0, output_tokens=0))
        summary = summaries.parse(reply, text, [])
        if easy is None:
            self.assertEqual(summary["ko"]["easy_conditions"], summary["ko"]["conditions"])
        return summary["en"][field]

    def test_an_easy_condition_takes_its_twins_ids_or_is_left_to_the_conditions(self):
        A, B = self.A, self.B
        self.assertEqual(self.parsed([f"{A}: admin page open", "CVE-2026-999999: other", "every user"],
                                     easy=["admin page reachable", "other one", f"{B}: everyone"], field="easy_conditions"),
                         [f"{A}: admin page reachable", "everyone"])
        self.assertEqual(self.parsed([f"{A}: admin page open"], easy=["admin page", "extra"], field="easy_conditions"), [])

    def test_other_prefix_forms_and_ids_inside_the_text(self):
        A, B, C = self.A, self.B, self.C
        self.assertEqual(self.parsed([f"{A} and {C}： iBGP", f"{A}/{B}/{C}: admin page", f"{A} 및 {B}: 로그인",
                                      f"after CVE-2026-999999 is used", f"{A} — no login, as for {B}"]),
                         [f"{A}, {C}: iBGP", "admin page", f"{A}, {B}: 로그인", f"{A} — no login, as for {B}"])

    def test_only_the_incidents_own_ids_stay_in_its_order(self):
        A, B, C = self.A, self.B, self.C
        self.assertEqual(self.parsed([f"{A}: no login", f"{C} ,  {A}:iBGP set", "every user", f"cve-2026-125345: lower case"]),
                         [f"{A}: no login", f"{A}, {C}: iBGP set", "every user", f"{B}: lower case"])

    def test_an_id_outside_the_incident_drops_the_entry_rather_than_widen_it(self):
        # CVE-2026-999999 is in the input (the Description) but not the Incident's; CVE-2026-12534 is a prefix of 125345.
        self.assertEqual(self.parsed(["CVE-2026-999999: other flaw", f"CVE-2026-999999, {self.C}: only C", f"{self.A}:  "]),
                         [f"{self.C}: only C"])

    def test_a_condition_naming_every_cve_loses_its_ids(self):
        self.assertEqual(self.parsed([f"{self.B}, {self.A}, {self.C}: admin page open"]), ["admin page open"])

    def test_a_one_cve_incident_is_parsed_as_before(self):
        one = self.GROUP.replace(f"Incident: {self.A}, {self.B}, {self.C}", f"Incident: {self.A}")
        self.assertEqual(self.parsed([f"{self.A}: no login", "CVE-2026-999999: kept as written"], one),
                         [f"{self.A}: no login", "CVE-2026-999999: kept as written"])

    def test_a_groups_mitigation_covers_the_whole_group_and_is_never_empty(self):
        # Owner, 11-16: Microsoft's 908-CVE update told only Outlook users what to do; a SourceCodester group said nothing.
        self.assertIn("mitigation, fixed and fixes are the whole group's, never only the Lead CVE's product", summaries.INSTRUCTIONS)
        self.assertIn("mitigation says to install that update on every affected product", summaries.INSTRUCTIONS)
        self.assertIn("Never empty when incident is true", summaries.INSTRUCTIONS)
        self.assertNotIn("Empty string when no source says anything a reader can act on", summaries.INSTRUCTIONS)

    def test_the_prompt_asks_for_the_ids_only_in_a_group(self):
        self.assertIn("a condition that holds for every CVE has no ID", summaries.INSTRUCTIONS)
        self.assertIn("keeping the same CVE IDs at the start of the same entries", summaries.INSTRUCTIONS)


class ReplyBudgetTest(unittest.TestCase):
    """11-16: Zephyr's 13-CVE group was given up after two cut-offs and a rejection between them."""

    def incident(self, n):
        cves = [f"CVE-2026-{100 + k}" for k in range(n)]
        return {"id": cves[0], "cves": cves, "first_seen": "2026-11-16T00:00:00Z", "brief": {"text": "Widget flaws.", "lead": ""},
                "mentions": [], "urls": [], "products": []}

    def sent_budget(self, incident):
        def offline(url, headers=None):
            raise OSError("offline")
        claude = FakeClaude(cut("{"))
        with contextlib.redirect_stderr(io.StringIO()):
            summaries.summarize_now(incident, claude, offline, "2026-11-16T00:00:00Z")
        return claude.sent[0]["max_tokens"], claude.sent[0].get("timeout")

    def test_a_groups_request_asks_with_the_larger_budget_from_the_first_try(self):
        self.assertEqual(self.sent_budget(self.incident(4)), (MAX_TOKENS_GROUP, REQUEST_TIMEOUT))
        claude = FakeClaude()
        with contextlib.redirect_stderr(io.StringIO()):
            summaries.submit_batch([self.incident(4)], claude, lambda url, headers=None: b"")
        self.assertEqual(claude.batches[0]["requests"][0]["params"]["max_tokens"], MAX_TOKENS_GROUP)  # no SDK check there

    def test_after_a_cut_off_a_try_that_follows_a_different_failure_still_asks_with_the_larger_budget(self):
        one = self.incident(1)
        self.assertEqual(self.sent_budget(one), (MAX_TOKENS, None))  # one CVE: the request as before
        self.assertEqual(one["summary_error"]["reason"], "stop_reason max_tokens")
        summaries.failed(one, "numbers not in the input: ['4.4']")
        self.assertEqual(summaries.retry(one)["max_tokens"], MAX_TOKENS_RETRY)
        # An error stored before "cut" came still gives the larger budget by its reason.
        self.assertEqual(summaries.retry({"cves": ["CVE-1"], "summary_error": {"tries": 1, "reason": "stop_reason max_tokens"}})["max_tokens"],
                         MAX_TOKENS_RETRY)
        self.assertNotIn("max_tokens", summaries.retry({"cves": ["CVE-1"], "summary_error": {"tries": 1, "reason": "x"}}))

    def test_a_cut_off_counts_as_one_of_the_three_tries(self):
        group = self.incident(13)
        for _ in range(summaries.MAX_TRIES):
            self.sent_budget(group)
        self.assertEqual({k: group["summary_error"][k] for k in ("tries", "cut", "final")}, {"tries": 3, "cut": True, "final": True})


class EasyJargonTest(unittest.TestCase):
    """The Easy view's three fields are checked for the words the prompt bans; a hit costs a retry, never the Summary."""

    def save(self, reply, tries=0):
        incident = {"id": "x", "mentions": [{"kind": "writeup", "url": SSHOLE_SUMMARY["lead"]}]}
        if tries:
            incident["summary_error"] = {"tries": tries, "reason": "earlier"}
        # The Lead's text holds every number, the command and the stopgap the replies use.
        text = f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n" + json.dumps(SSHOLE_SUMMARY, ensure_ascii=False)
        summaries.save_reply(incident, FakeClaude.message(reply), text, {"cves": [], "kev": False, "advisories": [], "n": 0}, "2026-11-08T12:00:00Z")
        return incident

    def test_a_banned_word_in_an_easy_field_is_sent_back_for_another_try(self):
        for lang, field, text in (("ko", "easy_title", "SonicWall VPN 인증 우회 위험"), ("en", "easy", "Attackers can run code via SSRF."),
                                  ("ko", "easy_action", "세션을 끊고 업데이트하세요.")):
            with self.subTest(field):
                incident = self.save(SSHOLE_SUMMARY | {lang: SSHOLE_SUMMARY[lang] | {field: text}})
                self.assertNotIn("summary", incident)
                self.assertIn("jargon in the Easy view", incident["summary_error"]["reason"])
                self.assertNotIn("final", incident["summary_error"])

    def test_a_stopgap_whose_mitigation_says_restart_needs_its_easy_follow_up_step(self):
        restart = SSHOLE_SUMMARY | {"en": SSHOLE_SUMMARY["en"] | {"mitigation": "Update to OpenSSH 10.6p2, or set PasswordAuthentication no and restart sshd."}}
        incident = self.save(restart)
        self.assertNotIn("summary", incident)
        self.assertIn("stopgap step missing", incident["summary_error"]["reason"])
        both = restart | {lang: restart[lang] | {"stopgap_then": then} for lang, then in (("ko", "바꾼 뒤 sshd를 다시 시작하세요."), ("en", "Then restart sshd."))}
        self.assertIn("summary", self.save(both))

    def test_the_last_try_keeps_the_summary_even_with_jargon(self):
        incident = self.save(SSHOLE_SUMMARY | {"ko": SSHOLE_SUMMARY["ko"] | {"easy_title": "인증 우회 위험"}}, tries=2)
        self.assertEqual(incident["summary"]["ko"]["easy_title"], "인증 우회 위험")
        self.assertNotIn("summary_error", incident)

    def test_product_names_and_the_normal_fields_are_not_checked(self):
        reply = SSHOLE_SUMMARY | {"products": ["SQL::Abstract"], "ko": SSHOLE_SUMMARY["ko"] | {
            "easy_title": "SQL::Abstract 데이터 털림 위험", "names": ["SQL::Abstract"], "title": "SQL 주입으로 원격 코드 실행 가능"}}
        self.assertIn("summary", self.save(reply))

    # critique 13: Easy said "1.2.0 이하라면 끄고 기다리세요" while Normal said something else; Easy must not name a version
    # the mitigation does not, nor promise a fix the mitigation says does not exist.
    def test_an_easy_action_with_a_version_the_mitigation_lacks_is_sent_back(self):
        reply = SSHOLE_SUMMARY | {"ko": SSHOLE_SUMMARY["ko"] | {"mitigation": "OpenSSH를 업데이트하세요.", "easy_action": "OpenSSH 10.6p2로 업데이트하세요."}}
        incident = self.save(reply)
        self.assertNotIn("summary", incident)
        self.assertIn("Easy action", incident["summary_error"]["reason"])

    def test_an_easy_action_promising_a_fix_the_mitigation_says_does_not_exist_is_sent_back(self):
        reply = SSHOLE_SUMMARY | {"en": SSHOLE_SUMMARY["en"] | {"mitigation": "No fixed version yet; 10.6p2 is still affected.",
                                                                 "easy_action": "Update OpenSSH to 10.6p2."}}
        incident = self.save(reply)
        self.assertNotIn("summary", incident)
        self.assertIn("Easy action", incident["summary_error"]["reason"])

    def test_on_the_last_try_a_mismatched_easy_action_is_dropped_so_easy_shows_the_mitigation(self):
        reply = SSHOLE_SUMMARY | {"ko": SSHOLE_SUMMARY["ko"] | {"mitigation": "OpenSSH를 업데이트하세요.", "easy_action": "OpenSSH 10.6p2로 업데이트하세요."}}
        incident = self.save(reply, tries=2)
        self.assertEqual(incident["summary"]["ko"]["easy_action"], "")
        self.assertEqual(incident["summary"]["en"]["easy_action"], SSHOLE_SUMMARY["en"]["easy_action"])

    def test_an_easy_action_that_agrees_with_the_mitigation_passes(self):
        # Owner 11-16: a version named in the Easy action stands in both languages.
        reply = SSHOLE_SUMMARY | {"ko": SSHOLE_SUMMARY["ko"] | {"easy_action": "OpenSSH 10.6p2 이상으로 업데이트하세요."},
                                  "en": SSHOLE_SUMMARY["en"] | {"easy_action": "Update OpenSSH to 10.6p2 or later."}}
        self.assertIn("summary", self.save(reply))

    # 11-16 read of group Summaries: eleven Easy actions said to wait for a release the Summary already names.
    def test_an_easy_action_that_waits_for_a_release_the_summary_names_is_sent_back(self):
        for lang, action in (("ko", "새 버전이 나오면 바로 업데이트하세요."), ("ko", "수정 버전이 출시되면 업데이트하세요."),
                             ("en", "Update as soon as a new version is out."), ("en", "Update to the new version when it arrives."),
                             ("en", "Update to the newest version as soon as one is available.")):
            reply = SSHOLE_SUMMARY | {lang: SSHOLE_SUMMARY[lang] | {"easy_action": action}}
            self.assertEqual(summaries.easy_action_mismatch(reply), [lang], action)
            self.assertIn("Easy action", self.save(reply)["summary_error"]["reason"])

    # 11-16 trial: MongoDB's group summary kept "단독 mongod는 해당하지 않습니다" under the prompt's absolute rule.
    def test_a_groups_summary_or_easy_text_saying_who_is_not_affected_is_sent_back(self):
        for lang, field, said in (("ko", "summary", "복제 세트 멤버가 해당하며 단독 mongod는 해당하지 않습니다."),
                                  ("ko", "easy", "일반 설치는 영향을 받지 않습니다!"), ("ko", "easy_title", "PC는 영향이 없음"),
                                  ("en", "summary", "Standalone mongod is not affected."), ("en", "easy", "Home users are safe."),
                                  ("en", "easy_title", "Unaffected desktops")):
            reply = SSHOLE_SUMMARY | {lang: SSHOLE_SUMMARY[lang] | {field: said}}
            self.assertEqual(summaries.group_scope(reply), f"{summaries.GROUP_SCOPE} ({lang} {field})", said)
        for field in ("conditions", "easy_conditions", "mitigation"):
            reply = SSHOLE_SUMMARY | {"en": SSHOLE_SUMMARY["en"] | {field: ["Standalone mongod is not affected."]
                                                                    if "conditions" in field else "Panorama is not affected."}}
            self.assertEqual(summaries.group_scope(reply), "", field)

    def test_only_a_group_is_checked_for_who_is_not_affected(self):
        reply = SSHOLE_SUMMARY | {"en": SSHOLE_SUMMARY["en"] | {"summary": SSHOLE_SUMMARY["en"]["summary"] + " Windows is not affected."}}
        self.assertIn("summary", self.save(reply))  # one CVE: as before
        incident = {"id": "x", "mentions": [{"kind": "writeup", "url": SSHOLE_SUMMARY["lead"]}]}
        text = ("Incident: CVE-2026-0001, CVE-2026-0002\nLead CVE: CVE-2026-0001\n"
                f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n" + json.dumps(SSHOLE_SUMMARY, ensure_ascii=False))
        summaries.save_reply(incident, FakeClaude.message(reply), text, {"cves": [], "kev": False, "advisories": [], "n": 0},
                             "2026-11-08T12:00:00Z")
        self.assertNotIn("summary", incident)
        self.assertTrue(incident["summary_error"]["reason"].startswith(summaries.GROUP_SCOPE))

    def test_waiting_for_a_release_passes_when_no_fixed_version_is_named(self):
        reply = SSHOLE_SUMMARY | {"fixed": "", "fixes": [], "ko": SSHOLE_SUMMARY["ko"] | {"easy_action": "새 버전이 나오면 바로 업데이트하세요."},
                                  "en": SSHOLE_SUMMARY["en"] | {"easy_action": "Update as soon as a new version is out."}}
        self.assertEqual(summaries.easy_action_mismatch(reply), [])
        for action in ("새로 나온 버전으로 바로 업데이트하세요.", "Update to the newest version right away.",
                       "Update as soon as possible."):
            lang = "en" if action.isascii() else "ko"
            reply = SSHOLE_SUMMARY | {lang: SSHOLE_SUMMARY[lang] | {"easy_action": action}}
            self.assertEqual(summaries.easy_action_mismatch(reply), [], action)

    def test_the_banned_words_are_the_ones_the_prompt_names(self):
        for word in summaries.EASY_BANNED:
            self.assertIn(word, summaries.INSTRUCTIONS)


class ScriptPageTest(unittest.TestCase):
    """SonicWall's advisory page draws its text with script; the input reads the JSON the page itself loads."""

    def test_a_sonicwall_advisory_is_read_from_its_api_with_the_fixed_versions(self):
        asked = []
        api = (FIXTURES / "pages" / "sonicwall-SNWLID-2026-0014.json").read_bytes()

        def http_get(url):
            asked.append(url)
            return api

        text = summary_input.page_text(summary_input.fetch_page(http_get, "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0014"))
        self.assertEqual(asked, ["https://psirtapi.global.sonicwall.com/api/v1/vulndetail/?advisory_id=SNWLID-2026-0014"])
        for words in ("7.3.4-7013 and higher", "8.2.3-8015 and higher", "TZ 270", "7.3.3-7015 and older"):
            self.assertIn(words, text)

    def test_the_fixed_versions_come_before_the_long_detail_so_the_page_cut_keeps_them(self):
        data = json.loads((FIXTURES / "pages" / "sonicwall-SNWLID-2026-0014.json").read_text(encoding="utf-8"))
        data["detail"] = "<p>" + "Long technical detail. " * 1000 + "</p>"
        page = summary_input.fetch_page(lambda url: json.dumps(data).encode(), "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0014")
        self.assertIn("7.3.4-7013 and higher", summary_input.page_text(page)[:summary_input.PAGE_CHARS])


class GroupPromptTest(unittest.TestCase):
    """11-16 read of group Summaries: a group's title, summary and scope sentences spoke for one of its flaws."""

    def test_a_group_request_carries_the_group_rule_and_a_one_cve_request_does_not(self):
        single = summaries.params("Incident: CVE-2026-0001\nProducts: Widget")
        group = summaries.params("Incident: CVE-2026-0001, CVE-2026-0002\nLead CVE: CVE-2026-0001\nProducts: Widget")
        self.assertEqual([b["text"] for b in single["system"]], [summaries.INSTRUCTIONS])
        self.assertEqual([b["text"] for b in group["system"]], [summaries.INSTRUCTIONS, summaries.GROUP_INSTRUCTIONS])
        self.assertIn("cache_control", group["system"][0])  # the shared instructions stay cached for both
        # 11-16 trial: "must hold for every CVE, or name the ids" was read as optional (MongoDB kept "standalone mongod is
        # not affected"), so the limits are banned outright and sent to the conditions.
        for words in ("gravest", "first sentence", "second sentence", "NO sentence about who or what is not affected",
                      "only into conditions", "the group's widest", "stopgap", "easy"):
            self.assertIn(words, summaries.GROUP_INSTRUCTIONS)
        self.assertNotIn(summaries.GROUP_INSTRUCTIONS, summaries.INSTRUCTIONS)


if __name__ == "__main__":
    unittest.main()


class EasyConditionsTest(unittest.TestCase):
    """easy_conditions (after critique 12): the conditions in everyday words, checked like the other Easy fields."""

    def test_a_banned_word_in_the_easy_conditions_is_caught(self):
        summary = {"products": [], "devices": [], **{lang: {"names": [], "easy": "", "easy_title": "", "easy_action": "",
                                                              "easy_conditions": []} for lang in ("ko", "en")}}
        summary["ko"]["easy_conditions"] = ["세션 토큰을 쓸 때"]
        self.assertEqual(summaries.easy_jargon(summary), ["세션", "토큰"])


class FixedConflictTest(unittest.TestCase):
    """Owner, 2026-11-10: FreeRDP's advisory has a typo ("Patched versions 3.22.2" for 3.32.2), the model copied it and
    the number check passed, so the page told readers to install a version every CVE record calls affected. A fixed
    version below the CVE records' first fixed version of the same release line (major.minor; owner 11-16, so a backport passes) is a failed try, the last one included."""
    FREERDP = {"fix_keys": ["freerdp:freerdp<3.32.2"]}

    def conflict(self, fixed="", fixes=(), keys=FREERDP["fix_keys"]):
        return summaries.fixed_conflict({"fix_keys": list(keys)}, {"fixed": fixed, "fixes": [{"for": "x", "version": v} for v in fixes]})

    def test_a_fixed_version_below_the_records_first_fixed_version_conflicts(self):
        self.assertEqual(self.conflict("3.32.1"), "fixed version 3.32.1 is below 3.32.2, the first fixed version in the CVE"
                                                  " records; a version below it is still affected")

    def test_a_version_equal_to_a_bound_or_higher_passes(self):
        self.assertEqual(self.conflict("3.32.2"), "")
        self.assertEqual(self.conflict("FreeRDP 3.33.0"), "")
        self.assertEqual(self.conflict("4.0.1"), "")  # no bound shares its major

    def test_a_record_naming_several_versions_in_one_bound_passes_each_of_them(self):
        keys = ["jetbrains:clion<2026.3, \n2026.2.4.1"]
        self.assertEqual(self.conflict("2026.2.4.1", keys=keys), "")
        self.assertEqual(self.conflict("2026.3", keys=keys), "")

    def test_each_per_line_fix_is_checked(self):
        keys = ["sideway:joi<17.13.9", "sideway:joi<18.3.1"]
        self.assertIn("17.13.6", self.conflict(fixes=["17.13.6", "18.2.5"], keys=keys))
        self.assertEqual(self.conflict(fixes=["17.13.9", "18.3.1"], keys=keys), "")
        self.assertEqual(self.conflict(fixes=["unknown"], keys=keys), "")

    def test_no_check_across_products_or_on_listed_versions_or_without_a_version(self):
        self.assertEqual(self.conflict("3.32.1", keys=["freerdp:freerdp<3.32.2", "freerdp:winpr<3.32.2"]), "")
        self.assertEqual(self.conflict("3.32.1", keys=["freerdp:freerdp<=3.32.1"]), "")
        self.assertIn("3.32.1", self.conflict("3.32.1", keys=["freerdp:freerdp<3.32.2", "freerdp:winpr<=3.40"]))
        self.assertEqual(self.conflict("1.2", keys=["acme:widget<1." + "9" * 5000]), "")  # too long to be a version
        self.assertEqual(self.conflict("3.32.1", keys=[]), "")
        for fixed in ("", "latest"):
            self.assertEqual(self.conflict(fixed), "")

    def test_a_distributions_package_under_fixes_passes_but_not_as_the_bare_fixed_version(self):
        # Owner, 2026-11-12: GStreamer's Red Hat backports (CVE-2026-125712) were rejected three times against 1.28.4.
        keys = ["gstreamer:gst-plugins-base<1.16.4"]
        for version in ("1.16.1-8.el8_10", "0:1.16.1-3.el8_10", "1.22.12-10.el9_9.1", "1.22.0-2+deb12u3", "1.24.2-1ubuntu0.2",
                        "1.16.2-7.1.hum1", "10.3_p1-r2", "3.0.15-r0"):  # 11-15: Red Hat Hardened Images, Alpine (review N2)
            with self.subTest(version):
                self.assertEqual(self.conflict(fixes=[version], keys=keys), "")
        self.assertEqual(self.conflict("1.16.1-3.el8_10", keys=keys), "fixed version 1.16.1 is below 1.16.4, the first fixed"
                         " version in the CVE records; a version below it is still affected")
        self.assertIn("1.16.1 is below 1.16.4", self.conflict(fixes=["1.16.1"], keys=keys))
        for plain in ("1.16.1", "3.32.1", "2.0.0-rc1", "KobiPBX-FOP3-SEC-r1", "10.6p2"):  # a build named "-r1" is no package
            self.assertIsNone(summaries.DISTRO_PACKAGE.search(plain))

    def test_the_retry_note_for_a_conflict_asks_only_for_a_version_the_input_writes(self):
        # 11-15: the bound came from the fix keys, not the input; the old note sent the model to it (CVE-2026-125712).
        sentence = "never write the bound yourself"
        note = summaries.retry({"summary_error": {"reason": self.conflict("1.16.1-3.el8_10", keys=["gstreamer:gst-plugins-base<1.16.4"])}})["note"]
        self.assertIn("rejected: fixed version 1.16.1 is below 1.16.4", note)
        self.assertIn(sentence, note)
        self.assertNotIn("write the product's own first fixed version", note)
        self.assertNotIn("never shorten or round", note)
        other = summaries.retry({"summary_error": {"reason": "numbers not in the input: ['9.9']"}})["note"]
        self.assertNotIn(sentence, other)
        self.assertIn("never shorten or round", other)

    def save(self, tries=0):
        # SSHOLE_SUMMARY says 10.6p2; a record bound of 10.7 makes it the FreeRDP shape.
        incident = {"id": "x", "mentions": [{"kind": "writeup", "url": SSHOLE_SUMMARY["lead"]}], "fix_keys": ["openbsd:openssh<10.6.3"]}
        if tries:
            incident["summary_error"] = {"tries": tries, "reason": "earlier"}
        text = f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n" + json.dumps(SSHOLE_SUMMARY, ensure_ascii=False)
        summaries.save_reply(incident, FakeClaude.message(SSHOLE_SUMMARY), text, {"cves": [], "kev": False, "advisories": [], "n": 0}, "2026-11-08T12:00:00Z")
        return incident

    def test_a_distributions_package_as_the_bare_fixed_version_is_emptied_and_the_summary_kept_on_the_first_try(self):
        # 11-15: CVE-2026-125712 was given up after the model wrote Red Hat's "1.16.1-3.el8_10" as `fixed` twice.
        fixes = [{"for": "Red Hat Enterprise Linux 8", "version": "1.16.1-3.el8_10", "devices": []}]
        reply = SSHOLE_SUMMARY | {"fixed": "1.16.1-3.el8_10", "fixes": fixes}
        incident = {"id": "x", "mentions": [{"kind": "writeup", "url": SSHOLE_SUMMARY["lead"]}],
                    "fix_keys": ["gstreamer:gst-plugins-base<1.16.4"]}
        text = f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n" + json.dumps(reply, ensure_ascii=False)
        summaries.save_reply(incident, FakeClaude.message(reply), text, {"cves": [], "kev": False, "advisories": [], "n": 0}, "2026-11-15T12:00:00Z")
        self.assertNotIn("summary_error", incident)
        self.assertEqual(incident["summary"]["fixed"], "")
        self.assertEqual(incident["summary"]["fixes"], fixes)
        self.assertEqual(incident["summary"]["en"]["mitigation"], SSHOLE_SUMMARY["en"]["mitigation"])

    def test_a_conflicting_reply_is_a_failed_try_even_the_last(self):
        for tries in (0, summaries.MAX_TRIES - 1):
            with self.subTest(tries=tries):
                incident = self.save(tries)
                self.assertNotIn("summary", incident)
                self.assertIn("fixed version 10.6 is below 10.6.3", incident["summary_error"]["reason"])
        self.assertTrue(incident["summary_error"]["final"])

    def test_the_retry_note_carries_the_reason_without_the_number_hints(self):
        note = summaries.retry(self.save(), "")["note"]
        self.assertIn("rejected: fixed version 10.6 is below 10.6.3", note)
        self.assertNotIn("For each rejected number", note)

    def test_a_stored_conflicting_summary_is_made_again_within_the_limit(self):
        incident = {"id": "CVE-2026-121386", "cves": ["CVE-2026-121386"], "kev": False, "mentions": [], **self.FREERDP,
                    "summary": {"fixed": "3.32.1", "fixes": []}, "summary_basis": {"cves": ["CVE-2026-121386"], "kev": False, "advisories": [], "n": 1}}
        self.assertTrue(summaries.needs_summary(incident))
        self.assertFalse(summaries.needs_summary(incident | {"summary": {"fixed": "3.32.2", "fixes": []}}))
        self.assertFalse(summaries.needs_summary(incident | {"summary_basis": incident["summary_basis"] | {"n": summaries.MAX_SUMMARIES}}))
        self.assertFalse(summaries.needs_summary(incident | {"summary_error": {"tries": summaries.MAX_TRIES}}))


class StrayScriptTest(unittest.TestCase):
    """11-11: three stored Summaries had Russian words inside Korean sentences ("1.3.3보다 новее인지", CVE-2026-29508).
    Letters outside Korean, ASCII and Latin with diacritics pass only when the Incident's own text writes them."""
    INCIDENT = {"brief": {"text": "A flaw in the mView app."}, "cve_texts": {"CVE-2026-1": "Pubjet | پاب‌جت plugin"},
                "products": [{"id": "x:mview", "name": "mView 豆瓣电影"}], "mentions": [{"kind": "writeup", "url": "u", "title": "Ελληνικά news"}]}

    def stray(self, text, incident=INCIDENT, lang="ko", field="mitigation"):
        return summaries.stray_script(incident, {lang: {field: text}})

    def test_a_russian_word_in_a_korean_sentence_is_rejected_by_its_run(self):
        self.assertEqual(self.stray("실행 중인 버전이 1.3.3보다 новее인지 확인하세요."), "text in another script: новее")

    def test_korean_ascii_and_latin_with_diacritics_pass(self):
        self.assertEqual(self.stray("café의 µTorrent와 İstanbul 서버를 업데이트하세요 (ㅋ)."), "")

    def test_a_name_from_the_incidents_own_text_passes_and_the_same_name_elsewhere_does_not(self):
        for field, text in (("title", "mView 豆瓣电影 앱 결함"), ("names", ["Pubjet | پاب‌جت"]), ("summary", "Ελληνικά news")):
            with self.subTest(field):
                self.assertEqual(self.stray(text, field=field, lang="en"), "")
        bare = {"brief": {"text": "A flaw."}, "mentions": []}
        self.assertEqual(self.stray("mView 豆瓣电影 앱 결함", bare, field="title"), "text in another script: 豆瓣电影")
        self.assertEqual(self.stray(["Pubjet | پاب‌جت"], bare, field="names"), "text in another script: پاب")
        self.assertEqual(summaries.stray_script(bare, {"en": {"cve_lines": [{"cve": "CVE-2026-1", "text": "новая"}]}}),
                         "text in another script: новая")

    def save(self, tries=0):
        incident = {"id": "x", "mentions": [{"kind": "writeup", "url": SSHOLE_SUMMARY["lead"]}]}
        if tries:
            incident["summary_error"] = {"tries": tries, "reason": "earlier"}
        reply = SSHOLE_SUMMARY | {"ko": SSHOLE_SUMMARY["ko"] | {"mitigation": SSHOLE_SUMMARY["ko"]["mitigation"] + " 버전이 новее인지 확인하세요."}}
        text = f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n" + json.dumps(SSHOLE_SUMMARY, ensure_ascii=False)
        summaries.save_reply(incident, FakeClaude.message(reply), text, {"cves": [], "kev": False, "advisories": [], "n": 0}, "2026-11-08T12:00:00Z")
        return incident

    def test_a_reply_with_a_word_in_another_script_is_a_failed_try_even_the_last(self):
        for tries in (0, summaries.MAX_TRIES - 1):
            with self.subTest(tries=tries):
                incident = self.save(tries)
                self.assertNotIn("summary", incident)
                self.assertEqual(incident["summary_error"]["reason"], "text in another script: новее")
        self.assertTrue(incident["summary_error"]["final"])

    def test_the_retry_note_asks_for_korean_and_english_only(self):
        note = summaries.retry(self.save(), "")["note"]
        self.assertIn("rejected: text in another script: новее", note)
        self.assertIn("Write Korean in Korean and English in English", note)
        self.assertNotIn("number", note)

    def test_the_public_failure_list_keeps_only_the_reasons_own_words(self):
        from collector.incidents import plain_reason
        self.assertEqual(plain_reason("text in another script: новее"), "text in another script")

    def test_a_stored_summary_with_a_word_in_another_script_is_made_again_within_the_limit(self):
        incident = {"id": "CVE-2026-29508", "cves": ["CVE-2026-29508"], "kev": False, "mentions": [],
                    "brief": {"text": "A flaw before 1.3.3."}, "summary": {"ko": {"mitigation": "1.3.3보다 новее인지 확인하세요."}, "fixed": "", "fixes": []},
                    "summary_basis": {"cves": ["CVE-2026-29508"], "kev": False, "advisories": [], "n": 1}}
        self.assertTrue(summaries.needs_summary(incident))
        self.assertFalse(summaries.needs_summary(incident | {"summary": {"ko": {"mitigation": "1.3.3 이상인지 확인하세요."}}}))
        self.assertFalse(summaries.needs_summary(incident | {"summary_basis": incident["summary_basis"] | {"n": summaries.MAX_SUMMARIES}}))


class TitleEntityTest(unittest.TestCase):
    """11-11: CNA product names carry HTML entities ("Contact Form 7 &#8211; Post Fields") and the model copied one into
    the title and names. Titles, names and products are unescaped; the body may explain an entity on purpose."""

    def test_titles_names_and_products_are_unescaped_and_the_body_is_not(self):
        name = "Contact Form 7 &#8211; Post Fields"
        body = SSHOLE_SUMMARY["en"]["summary"] + " Replacing '&' with '&amp;' fixes it."
        reply = SSHOLE_SUMMARY | {"products": [name],
                                  "ko": SSHOLE_SUMMARY["ko"] | {"title": f"{name} 결함", "names": [name]},
                                  "en": SSHOLE_SUMMARY["en"] | {"title": f"{name} flaw", "easy_title": "Forms &amp; Fields at risk",
                                                                "names": [name], "summary": body}}
        text = f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n" + json.dumps(reply, ensure_ascii=False)
        summary = summaries.parse(FakeClaude.message(reply), text, [SSHOLE_SUMMARY["lead"]])
        self.assertEqual(summary["ko"]["title"], "Contact Form 7 – Post Fields 결함")
        self.assertEqual(summary["en"]["title"], "Contact Form 7 – Post Fields flaw")
        self.assertEqual(summary["en"]["easy_title"], "Forms & Fields at risk")
        self.assertEqual(summary["ko"]["names"], ["Contact Form 7 – Post Fields"])
        self.assertEqual(summary["en"]["names"], ["Contact Form 7 – Post Fields"])
        self.assertEqual(summary["products"], ["Contact Form 7 – Post Fields"])
        self.assertEqual(summary["en"]["summary"], body)


class NumberWordTest(unittest.TestCase):
    """11-11: CVE-2026-58805's description says "a possible way to zero arbitrary secure memory" and the model wrote "0"
    on all three tries. A digit whose number word the input spells passes, as for per-CVE lines (number_words)."""

    def parse(self, ko, en, source):
        reply = SSHOLE_SUMMARY | {"ko": SSHOLE_SUMMARY["ko"] | {"summary": f"{SSHOLE_SUMMARY['ko']['summary']} {ko}"},
                                  "en": SSHOLE_SUMMARY["en"] | {"summary": f"{SSHOLE_SUMMARY['en']['summary']} {en}"}}
        text = (f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n"
                + json.dumps(SSHOLE_SUMMARY, ensure_ascii=False) + " " + source)
        return summaries.parse(FakeClaude.message(reply), text, [SSHOLE_SUMMARY["lead"]])

    def test_a_digit_the_input_spells_as_a_word_passes(self):
        summary = self.parse("메모리를 0으로 덮어쓸 수 있습니다.", "It can set memory to 0.", "a possible way to zero arbitrary secure memory")
        self.assertTrue(summary["en"]["summary"].endswith("set memory to 0."))

    def test_other_numbers_stay_exact(self):
        cases = {"neither 2 nor two": ("2바이트입니다.", "It is 2 bytes.", "a few bytes", "['2']"),
                 "one is not a number word": ("1개입니다.", "It is 1 flaw.", "one of the flaws", "['1']"),
                 "a version stays exact": ("8.0 버전입니다.", "It is version 8.0.", "version 8.0.5.2", "['8.0']")}
        for case, (ko, en, source, unknown) in cases.items():
            with self.subTest(case), self.assertRaises(summaries.Rejected) as caught:
                self.parse(ko, en, source)
            self.assertEqual(str(caught.exception), f"numbers not in the input: {unknown}")

    def test_a_korean_digit_and_its_english_word_are_the_same_number(self):
        """11-11: CVE-2026-58805 then failed "Korean and English numbers differ: ['0']" (ko "0으로", en "zero")."""
        summary = self.parse("메모리를 0으로 덮어쓸 수 있습니다.", "It can zero memory.", "a possible way to zero arbitrary secure memory")
        self.assertTrue(summary["en"]["summary"].endswith("zero memory."))
        summary = self.parse("8바이트를 씁니다.", "It writes eight bytes.", "an eight-byte write")
        self.assertTrue(summary["en"]["summary"].endswith("eight bytes."))

    def test_one_before_a_unit_is_the_number(self):
        """Trial rounds 1 to 4: httpd's mod_vhost_alias "1 byte stack buffer overwrite" was refused under every input
        ("1바이트" beside "a one-byte overwrite" or "by one byte")."""
        for en in ("A one-byte stack overwrite can crash it.", "A stack buffer is overwritten by one byte."):
            with self.subTest(en):
                summary = self.parse("스택 버퍼를 1바이트 넘겨 씁니다.", en, "mod_vhost_alias 1 byte stack buffer overwrite")
                self.assertEqual(summary["en"]["summary"].rsplit(". ", 1)[-1], en)

    def test_other_korean_and_english_numbers_still_differ(self):
        cases = {"2 is not 3": ("2바이트입니다.", "It is 3 bytes.", "2 or 3 bytes", "['2', '3']"),
                 "one is not a number word": ("1개입니다.", "It is one flaw.", "1 of the flaws", "['1']"),
                 "one byte is not 2": ("2바이트를 씁니다.", "It writes one byte.", "1 or 2 bytes", "['2']")}
        for case, (ko, en, source, differ) in cases.items():
            with self.subTest(case), self.assertRaises(summaries.Rejected) as caught:
                self.parse(ko, en, source)
            self.assertEqual(str(caught.exception), f"Korean and English numbers differ: {differ}")


class LineNameTest(unittest.TestCase):
    """11-15: about a quarter of the unclean replies in the re-summary named a product line beside its fixed version
    ("Update the 26.1 line to 26.1.11", OPNsense) and were rejected for "26.1", which the input writes only as 26.1.11."""
    SOURCE = ("Fixed in 26.1.11 and 26.4.1p1; 26.1.12 fixes a second flaw. Affected: 26.1.0 through 26.1.10, and 26.2.0 with no fix."
              " 26.1 million downloads.")
    FIXES = [{"for": "OPNsense 26.1", "version": "26.1.11"}, {"for": "OPNsense 26.4", "version": "26.4.1p1"}]

    def parse(self, ko, en, fixes=FIXES, fixed=""):
        reply = SSHOLE_SUMMARY | {"fixed": fixed, "fixes": fixes, "ko": SSHOLE_SUMMARY["ko"] | {"mitigation": ko},
                                  "en": SSHOLE_SUMMARY["en"] | {"mitigation": en}}
        text = (f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n"
                + json.dumps(SSHOLE_SUMMARY, ensure_ascii=False) + " " + self.SOURCE)
        return summaries.parse(FakeClaude.message(reply), text, [SSHOLE_SUMMARY["lead"]])

    def test_a_line_named_in_the_sentence_that_gives_its_fixed_version_passes(self):
        summary = self.parse("26.1 계열은 26.1.11, 26.4 계열은 26.4.1p1 이상으로 업데이트하세요.",
                             "Update the 26.1 line to 26.1.11 and the 26.4 line to 26.4.1p1 or later.")
        self.assertTrue(summary["en"]["mitigation"].startswith("Update the 26.1 line"))
        self.parse("26.1.x는 26.1.11로 업데이트하세요.", "Update 26.1.x to 26.1.11.", fixes=[], fixed="26.1.11")
        # CVE-2026-92735 (Vault): the reply's fixes give 1.19.25; a second CVE's fix on that line is only in the input.
        self.parse("두 번째 결함은 26.1 라인에서 26.1.12가 필요합니다.", "The second flaw needs 26.1.12 on the 26.1 line.")
        # Vault (CVE-2026-92735, 11-15): a line with no fix, named as a line, after the M5 prompt rule.
        self.parse("26.2 계열의 수정 버전은 확인되지 않았습니다.", "A fixed version for the 26.2 line is not confirmed.")
        # An amount is not a line: "26.1 million" stays 26100000 in English, as 2610만 is in Korean.
        self.parse("26.1.11에서 고쳐졌고 다운로드는 2610만 회입니다.", "Fixed in 26.1.11, with 26.1 million downloads.")
        with self.assertRaises(summaries.Rejected):  # 26.1.11 is in the input, but the reply does not give it as a fix
            self.parse("26.1.x는 26.1.11로 업데이트하세요.", "Update 26.1.x to 26.1.11.", fixes=[{"for": "x", "version": "26.4.1p1"}])

    def test_a_line_name_in_fixes_holds_only_its_own_line_or_numbers_the_input_has(self):
        # 11-15: fixes[].for was never number-checked, so "Vault Enterprise 1.22" over 1.19.25 reached the page.
        mitigation = ("26.1.11, 26.4.1p1로 업데이트하세요.", "Update to 26.1.11 or 26.4.1p1.")
        for line in ("OPNsense 26.1", "OPNsense 26.x", "OPNsense 26.1.0 through 26.1.10"):
            with self.subTest(line):
                self.parse(*mitigation, fixes=[{"for": line, "version": "26.1.11"}, self.FIXES[1]])
        with self.assertRaises(summaries.Rejected) as caught:
            self.parse(*mitigation, fixes=[{"for": "OPNsense 26.2", "version": "26.1.11"}, self.FIXES[1]])
        self.assertEqual(str(caught.exception), "numbers not in the input: ['26.2']")

    def test_a_shortened_version_to_install_stays_rejected(self):
        cases = {"alone": ("26.1로 업데이트하세요.", "Update to 26.1."),
                 "in another sentence than a version of its line": ("26.1이 해당합니다. 26.1.11로 업데이트하세요.", "26.1 is affected. Update to 26.1.11."),
                 "beside a version not in the input": ("26.1 계열을 26.1.13으로 올리세요.", "Move the 26.1 line to 26.1.13."),
                 "not a prefix by whole parts": ("26.4.1p1로 업데이트하세요(26.1.1 계열).", "Update to 26.4.1p1 (the 26.1.1 line)."),
                 # Found by the adversarial review: a shortened version to install beside the full one.
                 "a line with no fix as the version to install": ("26.2로 업데이트하세요.", "Update to 26.2."),
                 "or later, beside its fix": ("26.1 이상(26.1.11)으로 업데이트하세요.", "Update to 26.1 or later (26.1.11)."),
                 "to it, beside its fix": ("26.1로 업데이트하세요, 26.1.11에서 수정되었습니다.", "Update to 26.1, as 26.1.11 fixes it.")}
        for case, (ko, en) in cases.items():
            with self.subTest(case), self.assertRaises(summaries.Rejected) as caught:
                self.parse(ko, en)
            self.assertIn("numbers not in the input", str(caught.exception))


class LanguageGapsTest(unittest.TestCase):
    """11-11 review of 2,254 Summaries: two had en.mitigation and en.easy_action written and the Korean ones empty, one
    had a ko.title in English. A field written in one language only, or a Korean title or summary without Hangul, costs
    a retry, never the Summary."""

    def gaps(self, ko=None, en=None):
        return summaries.language_gaps({"ko": SSHOLE_SUMMARY["ko"] | (ko or {}), "en": SSHOLE_SUMMARY["en"] | (en or {})})

    def test_a_field_written_in_one_language_only_is_a_gap(self):
        self.assertEqual(self.gaps(ko={"mitigation": ""}), "mitigation is empty in Korean only")
        self.assertEqual(self.gaps(en={"easy_title": ""}), "easy_title is empty in English only")

    def test_a_field_empty_in_both_or_written_in_both_passes(self):
        self.assertEqual(self.gaps(), "")
        self.assertEqual(self.gaps(ko={"mitigation": "", "easy_action": ""}, en={"mitigation": "", "easy_action": ""}), "")

    def test_a_korean_title_or_summary_without_hangul_is_a_gap(self):
        title = "HP Poly EagleEye Cube USB management service command injection"
        self.assertEqual(self.gaps(ko={"title": title}), "the Korean title is not in Korean")
        self.assertEqual(self.gaps(ko={"summary": "OpenSSH 10.6p2."}), "the Korean summary is not in Korean")
        self.assertEqual(self.gaps(ko={"title": "HP Poly EagleEye Cube USB 관리 서비스 명령 실행"}), "")

    def test_a_range_written_in_english_inside_korean_text_is_a_gap_with_its_own_retry_sentence(self):
        # Review L2 (CVE-2026-116500, CVE-2026-126170); Frappe HRMS: "15.0.0 before 15.64.6 버전이면".
        for ko in ("15.0.0 before 15.64.6 버전이면 15.64.6으로 업데이트하세요.", "26.2.0 through 26.2.3이 해당합니다.",
                   "prior to 2.6.2 버전이 해당합니다.", "2.6.1 and earlier 버전이 해당합니다."):
            with self.subTest(ko):
                gap = self.gaps(ko={"summary": ko}, en={"summary": " ".join(re.findall(r"\d+(?:\.\d+)+", ko))})
                self.assertTrue(gap.startswith(summaries.RANGE_GAP), gap)
                self.assertIn("1.0.5 미만", summaries.retry({"summary_error": {"reason": gap}})["note"])
        for ko in ("::before·::after 규칙을 제한하세요.", "15.0.0 이상 15.64.6 미만이 해당합니다.", "Path to Glory 플러그인 결함"):
            with self.subTest(ko):
                self.assertEqual(self.gaps(ko={"summary": ko}, en={"summary": " ".join(["x", *re.findall(r"\d+(?:\.\d+)+", ko)])}), "")

    def save(self, tries=0):
        incident = {"id": "x", "mentions": [{"kind": "writeup", "url": SSHOLE_SUMMARY["lead"]}]}
        if tries:
            incident["summary_error"] = {"tries": tries, "reason": "earlier"}
        reply = SSHOLE_SUMMARY | {"ko": SSHOLE_SUMMARY["ko"] | {"mitigation": "", "easy_action": ""}}
        text = f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n" + json.dumps(SSHOLE_SUMMARY, ensure_ascii=False)
        summaries.save_reply(incident, FakeClaude.message(reply), text, {"cves": [], "kev": False, "advisories": [], "n": 0}, "2026-11-08T12:00:00Z")
        return incident

    def test_a_gap_is_sent_back_and_the_last_try_is_kept_as_it_is(self):
        incident = self.save()
        self.assertNotIn("summary", incident)
        self.assertEqual(incident["summary_error"]["reason"], "mitigation is empty in Korean only")
        kept = self.save(tries=summaries.MAX_TRIES - 1)
        self.assertEqual(kept["summary"]["ko"]["mitigation"], "")
        self.assertEqual(kept["summary"]["en"]["mitigation"], SSHOLE_SUMMARY["en"]["mitigation"])
        self.assertNotIn("summary_error", kept)

    def test_the_retry_note_asks_for_both_languages_and_the_failure_list_keeps_the_reason(self):
        from collector.incidents import plain_reason
        note = summaries.retry(self.save(), "")["note"]
        self.assertIn("rejected: mitigation is empty in Korean only.", note)
        self.assertIn("fill a field in both languages or in neither", note)
        self.assertNotIn("number", note)
        for reason in ("mitigation is empty in Korean only", "the Korean title is not in Korean"):
            self.assertEqual(plain_reason(reason), reason)

    # Second 11-11 review: CVE-2026-113555 wrote "26.5" in English and "26.5.3" in Korean; 4 of 540 new Summaries
    # still called the sources "소스".
    WRONG_KO = "26.5.3 이하 버전은 26.5.3으로, 25.6.6 이하 버전은 27.0으로 업데이트하세요."
    WRONG_EN = "Update to 26.5.3 if on 26.5 or earlier, and to 27.0 if on 25.6.6 or earlier."

    def test_a_version_in_one_language_only_is_a_gap(self):
        self.assertEqual(self.gaps(ko={"mitigation": self.WRONG_KO}, en={"mitigation": self.WRONG_EN}),
                         "a version stands in one language only: ['26.5']")
        self.assertEqual(self.gaps(ko={"mitigation": "OpenSSH 10.6p2로 업데이트하세요."}, en={"mitigation": "Update."}),
                         "a version stands in one language only: ['10.6p2']")

    def test_the_same_versions_or_an_amount_in_both_languages_pass(self):
        self.assertEqual(self.gaps(ko={"mitigation": "26.5 이하는 26.5.3으로 업데이트하세요."},
                                   en={"mitigation": "Update to 26.5.3 if on 26.5 or earlier."}), "")
        self.assertEqual(self.gaps(ko={"easy": "고객 580만 명의 정보가 샜습니다."},
                                   en={"easy": "Data of 5.8 million customers leaked."}), "")

    def test_a_forbidden_korean_word_is_a_gap(self):
        cases = {"소스에 수정 버전이 나와 있지 않습니다.": "소스 (write 출처)",
                 "소스가 고친 버전을 밝히지 않았습니다.": "소스 (write 출처)",
                 "수정 버전은 소스에 나와 있지 않습니다.": "소스 (write 출처)",
                 "소스에 수정 버전이나 임시 조치가 없습니다.": "소스 (write 출처)",
                 "고정된 버전으로 업데이트하세요.": "고정 버전 (write 수정 버전)",
                 "고정 버전으로 업데이트하세요.": "고정 버전 (write 수정 버전)",
                 "벤더가 패치를 냈습니다.": "벤더 (write 제조사)"}
        for text, reason in cases.items():
            with self.subTest(text):
                self.assertEqual(self.gaps(ko={"easy": text}), f"Korean wording: {reason}")

    def test_look_alikes_of_the_forbidden_words_pass(self):
        for text in ("리소스가 없으면 서비스가 멈춥니다.", "오픈소스에 수정 버전이 나와 있습니다.", "소스 코드에 수정 버전이 없습니다.",
                     "소스 파일에 명시된 경로입니다.", "Git 소스에서 빌드한 설치도 해당합니다.", "멀티벤더 장비가 해당합니다.",
                     "고정된 암호 키가 들어 있습니다.", "버전을 고정해 두세요."):
            with self.subTest(text):
                self.assertEqual(self.gaps(ko={"easy": text}), "")

    def test_a_release_line_written_as_jul_is_a_gap(self):
        # Owner, 11-16 (Git CVE-2026-113408): "release line" put word for word as "줄" ("2.50 줄은 2.50.2"); write 계열.
        for ko, en in (("Git 2.50 줄은 2.50.2 이상으로 업데이트하세요.", "Update Git 2.50 to 2.50.2 or later."),
                       ("2.56.0 줄의 Git이 해당합니다.", "Git 2.56.0 is affected."),
                       ("8.0.0줄은 수정 버전이 없습니다.", "The 8.0.0 line has no fix."),
                       ("최신 버전(2026 R2 줄 등)으로 업데이트하세요.", "Update to the newest version."),
                       ("해당 버전 줄의 수정 버전으로 업데이트하세요.", "Update to your line's fixed version."),
                       # A product's line (round 2 and live, Java).
                       ("쓰는 Java 줄마다 수정 버전으로 업데이트하세요.", "Update each Java line you run."),
                       ("Java 8과 11 줄도 고칩니다.", "It also fixes Java 8 and 11."),
                       ("Java 17 줄은 아래 목록을 보세요.", "For Java 17 see the list."),
                       ("Java 21·25·27 줄만 해당합니다.", "Only Java 21, 25 and 27."),
                       ("쓰는 Java를 해당 줄의 수정 버전으로 올리세요.", "Update Java to its fixed version."),
                       ("그 줄도 최신으로 두세요.", "Keep those current too.")):
            with self.subTest(ko):
                self.assertEqual(self.gaps(ko={"easy": ko}, en={"easy": en}), "Korean wording: 줄 (write 계열)")

    def test_a_release_line_written_as_lain_is_a_gap(self):
        # Owner, 11-16 ("계열로 통일"): 라인 for a release line, as 줄.
        for ko, en in (("5.4 라인은 5.4.56, 6.4 라인은 6.4.50 이상으로 업데이트하세요.", "Update 5.4 to 5.4.56 and 6.4 to 6.4.50."),
                       ("20.x 라인을 쓰면 업데이트하세요.", "Update on 20.x."),
                       ("해당 라인의 수정 버전으로 업데이트하세요.", "Update to your line's fixed version."),
                       ("FortiOS 여러 라인이 해당합니다.", "Several FortiOS lines are affected."),
                       ("수정 버전이 있는 라인으로 옮기세요.", "Move to a line that has a fix."),
                       ("Ulmo 라인은 업데이트하세요.", "Update Ulmo."),
                       ("라인별 수정 버전을 확인하세요.", "Check each line's fix."),
                       # Round 2, Java draw 2 (passed before): a product name ending in capitals, then 그 라인.
                       ("쓰는 GraalVM 라인을 각각 그 라인의 수정 버전으로 올리세요.", "Update the GraalVM you run."),
                       ("Java 21 이상 라인 사용", "Java 21 or later"),
                       ("라인마다 수정 버전이 다릅니다.", "Each line has its own fix."),
                       ("쓰는 제품이나 라인의 수정 버전으로 올리세요.", "Update what you run.")):
            with self.subTest(ko):
                self.assertEqual(self.gaps(ko={"easy": ko}, en={"easy": en}), "Korean wording: 라인 (write 계열)")

    def test_other_uses_of_lain_pass(self):
        for text in ("온라인에서 누구나 볼 수 있습니다.", "보안 가이드라인을 따르세요.", "CI 파이프라인이 멈춥니다.", "새 라인업이 나왔습니다.",
                     "리눅스 커널(메인라인)이 해당합니다.", "리퀘스트 타임라인을 엿볼 수 있습니다.", "사용 중인 카메라인지 확인하세요.",
                     "Cloudflare 기본 라인 기능에 권한 검사가 빠져 있습니다.", "다른 도메인의 DNS 라인 설정을 볼 수 있습니다.",
                     "비밀번호를 오프라인에서 풀 수 있습니다.", "LINE 메신저가 해당합니다."):
            with self.subTest(text):
                self.assertEqual(self.gaps(ko={"easy": text}), "")

    def test_lines_of_text_and_the_verb_jul_pass(self):
        for text in ("명령 한 줄로 업데이트하세요.", "CVE별 줄에 적힌 내용입니다.", "피해를 줄일 수 있습니다.", "로그 줄을 꾸밀 수 있습니다.",
                     "여러 줄을 한 번에 넣을 수 있습니다.", "명령줄에 비밀번호가 남습니다.", "설정에 줄바꿈을 넣을 수 있습니다.",
                     "공격자에게 영향을 줄 수 있습니다.", "10 줄짜리 파일입니다.", "첫 줄이 잘립니다.", "작업 스케줄러가 멈춥니다.",
                     "5줄짜리 스크립트입니다.", "줄 바꿈 문자를 넣습니다.", "아래 줄을 설정에 추가하세요.", "루프에 한 줄 수정을 적용하세요.",
                     "Vim에서 악성 줄을 고르면 실행됩니다.", "CVE-2026-1234만 줄일 수 있습니다.", "파일의 줄 길이를 잘못 계산합니다.",
                     "@import 줄에서 실행됩니다.", "각 줄의 길이를 셉니다."):
            with self.subTest(text):
                self.assertEqual(self.gaps(ko={"easy": text}), "")

    def save_wording(self, tries=0):
        incident = {"id": "x", "mentions": [{"kind": "writeup", "url": SSHOLE_SUMMARY["lead"]}]}
        if tries:
            incident["summary_error"] = {"tries": tries, "reason": "earlier"}
        ko = SSHOLE_SUMMARY["ko"]["mitigation"] + " 벤더 공지를 확인하세요."
        reply = SSHOLE_SUMMARY | {"ko": SSHOLE_SUMMARY["ko"] | {"mitigation": ko}}
        text = f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n" + json.dumps(SSHOLE_SUMMARY, ensure_ascii=False)
        summaries.save_reply(incident, FakeClaude.message(reply), text, {"cves": [], "kev": False, "advisories": [], "n": 0}, "2026-11-08T12:00:00Z")
        return incident, ko

    def test_a_forbidden_word_is_sent_back_and_the_last_try_is_kept_as_it_is(self):
        incident, _ = self.save_wording()
        self.assertNotIn("summary", incident)
        self.assertEqual(incident["summary_error"]["reason"], "Korean wording: 벤더 (write 제조사)")
        kept, ko = self.save_wording(tries=summaries.MAX_TRIES - 1)
        self.assertEqual(kept["summary"]["ko"]["mitigation"], ko)
        self.assertNotIn("summary_error", kept)

    def test_the_retry_note_says_what_to_write_and_the_failure_list_keeps_the_reason(self):
        from collector.incidents import plain_reason
        cases = {"a version stands in one language only: ['26.5']": "name every version in both languages",
                 "Korean wording: 소스 (write 출처)": "call the sources 출처, a fixed version 수정 버전 and the vendor 제조사"}
        for reason, sentence in cases.items():
            with self.subTest(reason):
                note = summaries.retry({"summary_error": {"tries": 1, "reason": reason}}, "")["note"]
                self.assertIn(f"rejected: {reason}.", note)
                self.assertIn(sentence, note)
                self.assertNotIn("never shorten or round", note)
                self.assertEqual(plain_reason(reason), reason)

    def test_the_instructions_name_the_korean_terms_and_the_fixed_version_before_x(self):
        for words in ("출처", "수정 버전", "제조사", "never a word of any other language", "empty in both or in neither",
                      '"prior to X"', "a page that could not be read"):
            self.assertIn(words, summaries.INSTRUCTIONS)


class PagesBudgetTest(unittest.TestCase):
    """Owner's trial 11-18: with four pages in the input, 6 of 9 long one-CVE replies were cut off at MAX_TOKENS and 0 of 9
    at MAX_TOKENS_RETRY, so an input with more than two pages gets the larger room from its first try."""

    def text(self, pages):
        record = "CVE record CVE-2026-1:\nWidget 1.2 lets anyone in."
        return "\n\n".join([record, *(f"Text of https://host{n}.example/a:\nPage {n}." for n in range(pages))])

    def test_more_than_two_pages_ask_with_the_larger_budget_and_two_do_not(self):
        one = {"id": "CVE-2026-1", "cves": ["CVE-2026-1"]}
        self.assertEqual(summaries.retry(one, self.text(3))["max_tokens"], MAX_TOKENS_RETRY)
        self.assertNotIn("max_tokens", summaries.retry(one, self.text(2)))  # the CVE record is not a page
        self.assertEqual(summaries.retry(one | {"cves": ["CVE-2026-1", "CVE-2026-2"]}, self.text(3))["max_tokens"], MAX_TOKENS_GROUP)

    def test_a_cut_off_at_the_larger_budget_is_asked_again_with_the_same_room_never_less(self):
        one = {"id": "CVE-2026-1", "cves": ["CVE-2026-1"]}
        for pages in (3, 1, 3):  # the next input may carry fewer pages: the cut-off keeps the room
            summaries.failed(one, "stop_reason max_tokens")
            self.assertEqual(summaries.retry(one, self.text(pages))["max_tokens"], MAX_TOKENS_RETRY)
        self.assertTrue(one["summary_error"]["final"])  # MAX_TRIES ends it

    def test_the_batch_and_the_instant_path_both_send_it(self):
        hosts = ("vendor.example", "cert.example", "blog.example")
        incident = {"id": "CVE-2026-1", "cves": ["CVE-2026-1"], "first_seen": "2026-11-18T00:00:00Z",
                    "brief": {"text": "Widget flaw.", "lead": f"https://{hosts[0]}/a"}, "products": [], "urls": [],
                    "mentions": [{"kind": "advisory", "url": f"https://{h}/a", "title": "Widget"} for h in hosts]}
        page = lambda url, headers=None: b"<html><body><main><p>Widget 1.2 is affected.</p></main></body></html>"
        claude = FakeClaude()
        with contextlib.redirect_stderr(io.StringIO()):
            summaries.submit_batch([incident], claude, page)
        self.assertEqual(claude.batches[0]["requests"][0]["params"]["max_tokens"], MAX_TOKENS_RETRY)
        claude = FakeClaude(cut("{"))
        with contextlib.redirect_stderr(io.StringIO()):
            summaries.summarize_now(incident, claude, page, "2026-11-18T00:00:00Z")
        self.assertEqual((claude.sent[0]["max_tokens"], claude.sent[0].get("timeout")), (MAX_TOKENS_RETRY, None))


class RecordSaysAffectedTest(unittest.TestCase):
    """A fixed version the CVE record's own text calls affected is kept back and asked again (Apache Roller,
    CVE-2026-129448, integration test 11-18)."""

    ROLLER = ("Deserialization of Untrusted Data in Apache Roller versions 4.0.0 through 6.1.4 allows an unauthenticated"
              " remote attacker to execute arbitrary code.\n\nThis is the same vulnerability as CVE-2026-82384, which listed"
              " only Apache Roller 6.1.5 as affected. This issue is being actively exploited.\n\nUsers are recommended to"
              " upgrade to Apache Roller 6.1.6 or later.")
    GIT = "Git versions before 2.49.1 are affected by a flaw in the credential helper. Fixed in 2.49.1."

    def text(self, description):
        record = json.dumps({"descriptions": [{"lang": "en", "value": description}]})
        return f"Incident: CVE-2026-129448\nMentions:\nCVE record CVE-2026-129448:\n{record}"

    def test_a_version_the_record_calls_affected_is_no_fix_and_its_bound_still_is(self):
        self.assertTrue(summaries.record_says_affected({"fixed": "6.1.5", "fixes": []}, self.text(self.ROLLER))
                        .startswith(summaries.RECORD_AFFECTED + "6.1.5"))
        self.assertTrue(summaries.record_says_affected({"fixed": "", "fixes": [{"for": "Apache Roller", "version": "6.1.5"}]},
                                                       self.text(self.ROLLER)))
        self.assertEqual(summaries.record_says_affected({"fixed": "6.1.6", "fixes": []}, self.text(self.ROLLER)), "")
        self.assertEqual(summaries.record_says_affected({"fixed": "2.49.1", "fixes": []}, self.text(self.GIT)), "")
        # A page's words are not the record's.
        self.assertEqual(summaries.record_says_affected({"fixed": "6.1.5", "fixes": []},
                                                        "Incident: x\nText of https://a.example/:\n6.1.5 is affected"), "")

    def test_a_bound_with_the_product_name_between_and_its_list_stay_fixes(self):
        # PostgreSQL, CVE-2026-116303: every try naming a fix was rejected. FreeSWITCH's 1.11.2 stays affected.
        postgres = ("Use after free in PostgreSQL plperl allows an object creator to execute arbitrary code.  Versions"
                    " before PostgreSQL 18.7, 17.12, 16.16, 15.20, and 14.25 are affected.")
        freeswitch = ("FreeSWITCH is a Software Defined Telecom Stack. In 1.11.2 and earlier, rtp_common_read() in"
                      " src/switch_rtp.c uses one session-wide autoadj_tally. FreeSWITCH 1.11.2 adds two opt-in controls,"
                      " but both default to zero and the release remains affected unless both are configured before RTP"
                      " session creation. This vulnerability is fixed in 1.11.2.")
        self.assertEqual(summaries.page_sheets.record_affected([postgres]), set())
        self.assertEqual(summaries.record_says_affected({"fixed": "", "fixes": [{"for": "PostgreSQL 17", "version": "17.12"}]},
                                                        self.text(postgres)), "")
        self.assertEqual(summaries.page_sheets.record_affected([freeswitch]), {"1.11.2"})
        self.assertEqual(summaries.page_sheets.record_affected(["Versions prior to version 2.3 or 2.4.1 are vulnerable."]), set())
        self.assertEqual(summaries.page_sheets.record_affected(["Versions <= 3.1 and 3.2 are affected."]), {"3.1", "3.2"})
        # A fix list after its fix words, a product name between, and "not affected" (GHES, Revive, Rails records).
        self.assertEqual(summaries.page_sheets.record_affected([
            "This vulnerability affected all versions of GitHub Enterprise Server prior to 3.23 and was fixed in versions"
            " 3.19.14, 3.20.10, 3.21.8, and 3.22.3.", "The issue is fixed in Revive Adserver 6.0.9 by HTML-encoding the"
            " affected values.", "Rails 8.0 and earlier do not serialize SafeBuffer with MessagePack and are not affected."]), set())

    def test_a_vendors_bracketed_build_is_compared_whole(self):
        # Zyxel, CVE-2026-12487 (rewritten): the affected build's bare 5.63 made the fix "affected" three tries running.
        zyxel = self.text("A flaw in the SNMP parameter of Zyxel EE5301-00 firmware version 5.63(ACLD.2)b3_D0 could let an"
                          " attacker crash an affected device.")
        self.assertEqual(summaries.record_says_affected({"fixed": "5.63(ACLD.3.4)D0", "fixes": []}, zyxel), "")
        self.assertTrue(summaries.record_says_affected({"fixed": "5.63(ACLD.2)b3_D0", "fixes": []}, zyxel))
        self.assertEqual(summaries.page_sheets.record_affected(["Firmware 5.63(ACLD.2) is affected; fixed in 5.63(ACLD.3)."]),
                         {"5.63(ACLD.2)"})
        self.assertEqual(summaries.affected_label({"fixes": [{"for": "Zyxel EE5301-00 5.63(ACLD.3.4)D0", "version": "5.63(ACLD.3.4)D0"}]},
                                                  zyxel), "")

    def test_the_reply_is_kept_back_with_its_own_retry_sentence(self):
        incident = {"id": "x", "mentions": [{"kind": "writeup", "url": SSHOLE_SUMMARY["lead"]}]}
        # The Lead's text holds every number the borrowed reply uses; the record's text calls 6.1.5 affected.
        text = (f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n" + json.dumps(SSHOLE_SUMMARY, ensure_ascii=False)
                + "\n" + self.text(self.ROLLER).split("\n", 2)[2])
        with contextlib.redirect_stderr(io.StringIO()):
            summaries.save_reply(incident, FakeClaude.message(SSHOLE_SUMMARY | {"fixed": "6.1.5"}), text,
                                 {"cves": [], "kev": False, "advisories": [], "n": 0}, "2026-11-18T00:00:00Z")
        self.assertNotIn("summary", incident)
        self.assertTrue(incident["summary_error"]["reason"].startswith(summaries.RECORD_AFFECTED + "6.1.5"), incident["summary_error"])
        self.assertIn("The CVE record's own text calls that version affected", summaries.retry(incident, text)["note"])


class FlawNameTitleTest(unittest.TestCase):
    """The flaw's name in a title comes from code (owner 11-18): a name two Mention titles carry is added; the model's own
    closing brackets stay."""

    def mentions(self, *titles):
        return {"mentions": [{"kind": kind, "url": f"https://h{n}.example/", "title": t} for n, (kind, t) in enumerate(titles)]}

    def summary(self, en, ko="위젯 결함"):
        return {"ko": {"title": ko, "easy_title": "위젯 해킹 위험"}, "en": {"title": en, "easy_title": "Widget hackable"}}

    def test_a_name_counts_when_two_titles_carry_it_letter_for_letter(self):
        two = self.mentions(("writeup", "Java4Shell: a flaw in Base64"), ("advisory", "Patch now for Java4Shell"))
        self.assertEqual(summaries.trusted_names(two), ["Java4Shell"])
        for titles in ((("writeup", "Java4Shell"), ("writeup", "java4shell")), (("writeup", "Java4Shell"), ("repo", "Java4Shell PoC")),
                       (("writeup", "Java4Shell"), ("cve_record", "Java4Shell in Widget")),
                       (("writeup", "Backdoor found"), ("writeup", "Backdoor in X")),
                       # CVE-2026-124308: two oss-security posts named a function, "DecLibRecon::createSubPicRefBufs".
                       (("discussion", "UAF in DecLibRecon::createSubPicRefBufs"), ("discussion", "DecLibRecon::createSubPicRefBufs again")),
                       (("discussion", "x.getFile leaks"), ("discussion", "p->getFile too"))):
            with self.subTest(titles):
                self.assertEqual(summaries.trusted_names(self.mentions(*titles)), [])

    def test_the_models_own_brackets_stay_and_the_name_follows_them(self):
        for en, want in (("Widget flaw lets attackers in (SSRF)", "Widget flaw lets attackers in (SSRF) (Java4Shell)"),
                         ("Widget flaw (no login needed)", "Widget flaw (no login needed) (Java4Shell)"),
                         ("Widget flaw (Java4Shell, SSRF)", "Widget flaw (Java4Shell, SSRF)"),  # already holds it
                         ("Widget flaw lets attackers in", "Widget flaw lets attackers in (Java4Shell)")):
            with self.subTest(en):
                summary = self.summary(en)
                summaries.name_titles(summary, ["Java4Shell"])
                self.assertEqual(summary["en"]["title"], want)

    def test_a_title_showing_one_trusted_name_gets_no_second_bracket_and_the_easy_title_none(self):
        summary = self.summary("Widget decoder flaw runs code", ko="위젯 디코더 결함 (Java4Shell)")
        summaries.name_titles(summary, ["Java4Shell", "Base64Bleed"])
        self.assertEqual(summary["en"]["title"], "Widget decoder flaw runs code (Java4Shell, Base64Bleed)")
        self.assertEqual(summary["ko"]["title"], "위젯 디코더 결함 (Java4Shell)")
        # N-able, integration test 11-18: "(Able2Shell)" became "(Able2Shell) (4EverAble2Shell)".
        nable = self.summary("N-able N-central server remote code execution flaws (Able2Shell)")
        summaries.name_titles(nable, ["4EverAble2Shell", "Able2Shell"])
        self.assertEqual(nable["en"]["title"], "N-able N-central server remote code execution flaws (Able2Shell)")
        self.assertEqual((summary["en"]["easy_title"], summary["ko"]["easy_title"]), ("Widget hackable", "위젯 해킹 위험"))
        nothing = self.summary("Widget flaw (VSA-2026-062)")
        summaries.name_titles(nothing, [])
        self.assertEqual(nothing["en"]["title"], "Widget flaw (VSA-2026-062)")

    def test_a_stored_summary_gets_the_name(self):
        incident = {"id": "x", "mentions": [{"kind": "writeup", "url": SSHOLE_SUMMARY["lead"], "title": "SSHole: musl OpenSSH"},
                                            {"kind": "discussion", "url": "https://news.example/1", "title": "SSHole explained"}]}
        text = f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n" + json.dumps(SSHOLE_SUMMARY, ensure_ascii=False)
        reply = SSHOLE_SUMMARY | {"en": SSHOLE_SUMMARY["en"] | {"title": SSHOLE_SUMMARY["en"]["title"] + " (OSS advisory)"}}
        summaries.save_reply(incident, FakeClaude.message(reply), text, {"cves": [], "kev": False, "advisories": [], "n": 0},
                             "2026-11-18T00:00:00Z")
        self.assertNotIn("summary_error", incident, incident.get("summary_error"))
        self.assertEqual(incident["summary"]["en"]["title"], SSHOLE_SUMMARY["en"]["title"] + " (OSS advisory) (SSHole)")
        self.assertEqual(incident["summary"]["ko"]["title"], SSHOLE_SUMMARY["ko"]["title"] + " (SSHole)")


class ReSummaryKeepsWhatTheReviewLeftOutTest(unittest.TestCase):
    """Re-summary dry run, 11-18: a review that gives no attacks answer or no event day takes nothing from the stored
    Summary."""

    CVE_RECORD = "https://www.cve.org/CVERecord?id=CVE-2024-58406"
    VULNCHECK = "https://www.vulncheck.com/advisories/huatian-oa8000"

    def store(self, stored, verdict=None, event_date="", **new):
        incident = {"id": "CVE-2024-58406", "cves": ["CVE-2024-58406"], "mentions": [], "summary": stored}
        summary = copy.deepcopy(SSHOLE_SUMMARY) | {"same_as": ""} | new
        summaries.keep(incident, summary, {}, "2026-11-18T12:00:00Z", [], True, verdict=verdict, event_date=event_date)
        return incident["summary"]

    def test_a_stored_sourced_attack_stays_unless_reply_and_review_both_say_no(self):
        stored = {"exploited": True, "exploited_source": self.CVE_RECORD, "event_date": "2024-11-20"}
        new = {"exploited": True, "exploited_source": self.VULNCHECK, "exploited_unconfirmed": True}
        kept = self.store(stored, None, "2024-11-20", **new)
        self.assertEqual((kept["exploited"], kept["exploited_source"]), (True, self.CVE_RECORD))
        self.assertNotIn("exploited_unconfirmed", kept)
        # The reply says yes, the review no: a stored attack with a source stays (Optimizely, HN 50524767, integration
        # test 11-18: one review draw's no took it from the highest level; another draw said yes).
        held = self.store(stored, False, **new)
        self.assertEqual((held["exploited"], held["exploited_source"]), (True, self.CVE_RECORD))
        # Nothing stored, or stored without a source: the review's no decides, as before.
        self.assertFalse(self.store({}, False, **new)["exploited"])
        self.assertFalse(self.store({"exploited": True, "exploited_source": ""}, False, **new)["exploited"])
        yes = self.store(stored, True, **new)
        self.assertEqual((yes["exploited"], yes["exploited_source"], yes["exploited_review"]), (True, self.VULNCHECK, True))
        # Nothing stored to keep: an unconfirmed flag without an answer drops, as before.
        self.assertFalse(self.store({}, None, **new)["exploited"])

    def test_a_review_with_no_event_day_keeps_the_stored_one_and_a_new_day_replaces_it(self):
        # HN 50496937, the Cursor marketplace extension: attacked 2026-10-29.
        stored = {"event_date": "2026-10-29"}
        self.assertEqual(self.store(stored)["event_date"], "2026-10-29")
        self.assertEqual(self.store(stored, event_date="2026-10-30")["event_date"], "2026-10-30")
        self.assertNotIn("event_date", self.store({}))


class InputReportsAttacksTest(unittest.TestCase):
    """A claimed attack that a reporter in the input states in plain words stands without a review draw (re-summary
    re-check 11-18: TYPO3, Huatian); one the input's reporters do not state still goes to the review (Rootways)."""

    RECORD = "https://www.cve.org/CVERecord?id=CVE-2026-125160"
    WRITEUP = "https://www.vulncheck.com/advisories/huatian-oa8000"
    NEWS = "https://www.bleepingcomputer.com/news/security/x/"

    def parse(self, source, record_text, kev="no", writeup_text="Nothing here.", finders=(), said=""):
        record = json.dumps({"descriptions": [{"lang": "en", "value": record_text}]})
        text = (f"Incident: CVE-2026-125160\nExploited in the wild (CISA KEV): {kev}\nMentions:\n- writeup {SSHOLE_SUMMARY['lead']}\n"
                f"- cve_record {self.RECORD}\n- writeup {self.WRITEUP}\n- writeup {self.NEWS}\n"
                f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n{json.dumps(SSHOLE_SUMMARY, ensure_ascii=False)}\n"
                f"Text of {self.WRITEUP}:\n{writeup_text}\nCVE record CVE-2026-125160:\n{record}")
        en = SSHOLE_SUMMARY["en"] | {"summary": SSHOLE_SUMMARY["en"]["summary"] + said}
        reply = FakeClaude.message(SSHOLE_SUMMARY | {"exploited": True, "exploited_source": source, "en": en})
        return summaries.parse(reply, text, [SSHOLE_SUMMARY["lead"], self.RECORD, self.WRITEUP, self.NEWS], finders)

    def keep(self, summary, verdict):
        incident = {"id": "x", "mentions": []}
        summaries.keep(incident, summary | {"same_as": ""}, {}, "2026-11-18T12:00:00Z", [], True, verdict=verdict)
        return incident["summary"]

    def test_a_record_that_says_actively_exploited_needs_no_review(self):
        # TYPO3, CVE-2026-125160: the first review said yes, the second no, and the flag fell.
        s = self.parse(self.RECORD, "Files are disclosed. This vulnerability is known to be actively exploited.")
        self.assertEqual((s["exploited"], s.get("exploited_input"), s.get("exploited_unconfirmed")), (True, True, None))
        self.assertFalse(summaries.review_params(s, {"id": "x", "mentions": []})["messages"][0]["content"].endswith(summaries.review.ATTACKS_QUESTION))
        self.assertTrue(self.keep(s, None)["exploited"])
        self.assertEqual(summaries.recheck_exploited([{"summary": self.keep(s, None)}]), [])
        # The input's CISA KEV line: a reporter's claim stands; a write-up's still does not.
        self.assertTrue(self.parse(self.NEWS, "Files are disclosed.", kev="yes").get("exploited_input"))
        self.assertFalse(self.parse(self.WRITEUP, "Files are disclosed.", kev="yes")["exploited"])

    def test_a_write_up_claim_takes_the_record_that_says_so_as_its_source(self):
        # Huatian, CVE-2024-58406: the replies cited VulnCheck; the record says the same.
        s = self.parse(self.WRITEUP, "Exploitation evidence was first observed by the Shadowserver Foundation on 2024-11-20.")
        self.assertEqual((s["exploited"], s["exploited_source"], s.get("exploited_input")), (True, self.RECORD, True))

    def test_a_claim_the_reporters_do_not_state_still_falls_on_the_review_no(self):
        # Rootways, CVE-2026-130583: only Sansec's write-up says "Exploited in the wild"; a write-up is no reporter.
        self.assertFalse(self.parse(self.WRITEUP, "SSRF in the Apple Pay endpoint.", writeup_text="Exploited in the wild.")["exploited"])
        s = self.parse(self.RECORD, "SSRF in the Apple Pay endpoint. It could be exploited in the wild.")
        self.assertTrue(s.get("exploited_unconfirmed"))
        self.assertFalse(self.keep(copy.deepcopy(s), False)["exploited"])
        self.assertTrue(self.keep(s, True)["exploited_review"])

    def test_the_finders_own_disclosure_confirms_and_a_first_hand_page_is_the_source(self):
        # Rootways, CVE-2026-130583 (rewritten): the sheet reads Sansec's page as the finder's disclosure, and it reports
        # the attack first-hand; the reply cited a newsletter issue about another story.
        said = "On November 15, an attacker used it to take over a store."
        s = self.parse(self.NEWS, "SSRF in the Apple Pay endpoint.", writeup_text=said, finders=[self.WRITEUP])
        self.assertEqual((s["exploited"], s["exploited_source"], s.get("exploited_input")), (True, self.WRITEUP, True))
        s = self.parse(self.WRITEUP, "SSRF in the Apple Pay endpoint.", writeup_text=said, finders=[self.WRITEUP])
        self.assertEqual((s["exploited_source"], s.get("exploited_input")), (self.WRITEUP, True))
        # A news claim the reply's own words evidence still takes the first-hand page that says so as its source.
        s = self.parse(self.NEWS, "Files are disclosed. It is known to be actively exploited.", said=" Attackers are exploiting it now.")
        self.assertEqual((s["exploited"], s["exploited_source"]), (True, self.RECORD))
        # No first-hand page says so: the news source stays.
        s = self.parse(self.NEWS, "Files are disclosed.", said=" Attackers are exploiting it now.")
        self.assertEqual(s["exploited_source"], self.NEWS)
        # A news page the sheet calls a finder's disclosure is still news.
        self.assertTrue(self.parse(self.NEWS, "Files are disclosed.", finders=[self.NEWS]).get("exploited_unconfirmed"))


class DisputedAttacksTest(unittest.TestCase):
    """A new reply that says "not exploited" never takes down attacks the Board shows with a source (owner 11-18, the
    re-summary dry run's ARTEX and N-central): only the review's no does, and a reply whose own text still reports the
    attacks goes back for another try."""

    SOURCE = "https://www.securityweek.com/hackers-target-n-central-zero-days-as-n-able-rushes-patches/"
    STORED = {"exploited": True, "exploited_source": SOURCE}

    def save(self, reply, tries=0):
        incident = {"id": "nc", "mentions": [{"kind": "writeup", "url": SSHOLE_SUMMARY["lead"]}], "summary": dict(self.STORED)}
        if tries:
            incident["summary_error"] = {"tries": tries, "reason": "earlier"}
        text = f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n" + json.dumps(SSHOLE_SUMMARY, ensure_ascii=False)
        with contextlib.redirect_stderr(io.StringIO()):
            summaries.save_reply(incident, FakeClaude.message(reply), text, {"cves": [], "kev": False, "advisories": [], "n": 0},
                                 "2026-11-18T12:00:00Z", review_with=summaries.BATCH)
        return incident

    def test_a_reply_whose_text_still_reports_the_attacks_goes_back(self):
        # N-central: the Korean said "실제 공격 시도도 확인되었습니다" while the flag was false.
        ko = SSHOLE_SUMMARY["ko"] | {"summary": SSHOLE_SUMMARY["ko"]["summary"] + " 실제 공격 시도도 확인되었습니다."}
        incident = self.save(SSHOLE_SUMMARY | {"ko": ko})
        self.assertEqual(incident["summary"], self.STORED)  # nothing replaced
        self.assertIn(summaries.ATTACKS_UNFLAGGED, incident["summary_error"]["reason"])

    def test_the_review_is_asked_and_only_its_no_takes_the_attacks_down(self):
        # ARTEX: the new text says nothing of attacks and the flag is false.
        incident = self.save(SSHOLE_SUMMARY)
        draft = incident["review_pending"]
        params = summaries.review_params(draft["summary"], incident)
        self.assertIn("attacks_happened", params["output_config"]["format"]["schema"]["required"])
        for answer, kept in ((False, False), (True, True), (None, True)):
            reply = {"findings": [], "event_date": ""} | ({} if answer is None else {"attacks_happened": answer})
            target = copy.deepcopy(incident)
            summaries.finish_review(target, copy.deepcopy(draft), FakeClaude.message(reply))
            self.assertEqual(target["summary"]["exploited"], kept, answer)
            self.assertEqual(target["summary"]["exploited_source"], self.SOURCE if kept else "", answer)
            self.assertNotIn("exploited_disputed", target["summary"])

    def test_a_first_summary_or_one_that_keeps_the_flag_is_not_disputed(self):
        incident = self.save(SSHOLE_SUMMARY)
        self.assertTrue(incident["review_pending"]["summary"].get("exploited_disputed"))
        first = {"id": "x", "mentions": [{"kind": "writeup", "url": SSHOLE_SUMMARY["lead"]}]}
        text = f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n" + json.dumps(SSHOLE_SUMMARY, ensure_ascii=False)
        with contextlib.redirect_stderr(io.StringIO()):
            summaries.save_reply(first, FakeClaude.message(SSHOLE_SUMMARY), text, {"cves": [], "kev": False, "advisories": [], "n": 0},
                                 "2026-11-18T12:00:00Z", review_with=summaries.BATCH)
        self.assertNotIn("exploited_disputed", first["review_pending"]["summary"])


class UpdateOutFindingTest(unittest.TestCase):
    """11-18 dry run: the review kept back five Oracle entries for "the same update also fixes" beside "no source names a
    fixed version", though each mitigation says to apply the November patch update (release_without_fix's case)."""

    def summary(self, fixed="", en_mitigation="No source names a fixed version yet. Apply Oracle's November 2026 Critical Patch Update."):
        return {"fixed": fixed, "fixes": [],
                "ko": {"summary": "공격자가 Foo를 장악할 수 있습니다. 같은 업데이트는 데이터 노출 결함도 고칩니다.",
                       "mitigation": "수정 버전을 밝힌 출처가 아직 없습니다. Oracle 11월 패치를 적용하세요."},
                "en": {"summary": "An attacker can take over Foo. The same update also fixes a data exposure flaw.",
                       "mitigation": en_mitigation}}

    FINDING = {"field": "summary", "lang": "both", "quote": "같은 업데이트는 데이터 노출 결함도", "against": "수정 버전을 밝힌 출처가 아직 없습니다",
               "problem": "Readers think a fix exists.", "severity": "high"}

    def test_the_finding_is_dropped_when_the_mitigation_names_an_update_to_apply(self):
        self.assertTrue(summaries.update_out_finding(self.FINDING, self.summary()))

    def test_it_stays_when_there_is_nothing_to_apply_or_a_version_is_named_or_it_is_another_finding(self):
        cases = {"nothing to apply": (self.FINDING, self.summary(en_mitigation="No source names a fixed version yet.")),
                 "a fixed version": (self.FINDING, self.summary(fixed="1.2.3")),
                 "a graver flaw left out (OpenMage)": (self.FINDING | {"against": "서버에서 코드를 실행할 수 있음"}, self.summary()),
                 "another sentence": (self.FINDING | {"quote": "공격자가 Foo를 장악할 수 있습니다."}, self.summary())}
        for case, (finding, summary) in cases.items():
            with self.subTest(case):
                self.assertFalse(summaries.update_out_finding(finding, summary))


class LostFixTest(unittest.TestCase):
    """A re-summary never drops a fixed version the stored Summary had while the input still gives it as a fix (owner
    11-18: Git's 2.49.1 in the integrated test, yggdrasil's only package in the re-summary dry run)."""

    GIT_RECORD = "Git versions before 2.49.1 are affected by a heap buffer overflow in three-way merge."

    def text(self, description=GIT_RECORD):
        record = json.dumps({"descriptions": [{"lang": "en", "value": description}]})
        return f"Incident: CVE-2026-105437\nMentions:\nCVE record CVE-2026-105437:\n{record}"

    def reply(self, fixed, fixes=(), mitigation="Update."):
        return {"fixed": fixed, "fixes": [{"for": "Git", "version": v, "devices": []} for v in fixes],
                "ko": {"mitigation": mitigation}, "en": {"mitigation": mitigation}}

    def test_a_dropped_version_the_input_still_gives_goes_back(self):
        git = {"id": "CVE-2026-105437", "summary": {"fixed": "2.49.1", "fixes": [{"for": "Git", "version": "2.49.1"}]}}
        self.assertEqual(summaries.lost_fix(git, self.reply("2.50.2", ["2.50.2", "2.51.3"]), self.text()),
                         summaries.LOST_FIX + "2.49.1")
        # yggdrasil, CVE-2026-18379: the record's fix key bounds at the package; the new mitigation alone naming it is a loss.
        ygg = {"id": "CVE-2026-18379", "summary": {"fixed": "0:0.2.3-7.el10_2.9", "fixes": []},
               "fix_keys": ["red_hat:red_hat_enterprise_linux_10:yggdrasil-worker-package-manager<0:0.2.3-7.el10_2.9"]}
        self.assertTrue(summaries.lost_fix(ygg, self.reply("", mitigation="Update to 0.2.3-7.el10_2.9 or later."),
                                           self.text("yggdrasil-worker-package-manager 0.2.3 is affected.")))
        # Cockpit, CVE-2026-91151: RHEL 9's build of the same upstream version is another distribution release.
        cockpit = {"id": "x", "summary": {"fixed": "", "fixes": [{"for": "RHEL 10", "version": "366.1.1-1.el10_3"},
                                                                 {"for": "RHEL 9", "version": "366.1.1-1.el9_9"}]},
                   "fix_keys": ["red_hat:enterprise_linux_10:cockpit<0:366.1.1-1.el10_3"]}
        self.assertEqual(summaries.lost_fix(cockpit, self.reply("", ["366.1.1-1.el9_9"]), self.text("cockpit flaw.")),
                         summaries.LOST_FIX + "366.1.1-1.el10_3")
        self.assertEqual(summaries.lost_fix(cockpit, self.reply("", ["0:366.1.1-1.el10_3", "366.1.1-1.el9_9"]),
                                            self.text("cockpit flaw.")), "")  # the epoch aside

    def test_a_line_the_union_adds_back_from_the_sheet_is_no_loss(self):
        # Java4Shell (rewritten): the draw dropped Corretto's line it wrote before; a trusted sheet row gives it.
        java = {"id": "x", "summary": {"fixed": "17.0.21.1", "fixes": [{"for": "Oracle Java SE 17", "version": "17.0.21.1"},
                                                                       {"for": "Amazon Corretto 21", "version": "21.3.20.1"}]}}
        reply, text = self.reply("17.0.21.1", ["17.0.21.1"]), self.text("Java SE flaw. Fixed in Amazon Corretto 21.3.20.1 and later.")
        row = {"for": "Amazon Corretto 21", "version": "21.3.20.1"}
        self.assertEqual(summaries.lost_fix(java, reply, text), summaries.LOST_FIX + "21.3.20.1")
        self.assertEqual(summaries.lost_fix(java, reply, text, [row]), "")
        self.assertEqual(reply["fixes"], [{"for": "Git", "version": "17.0.21.1", "devices": []}])  # asking changes nothing
        # A row the union's checks refuse (below the records' first fixed version of its line) adds nothing back.
        self.assertTrue(summaries.lost_fix(java | {"fix_keys": ["amazon:corretto<21.3.21"]}, reply, text, [row]))

    def test_a_version_without_a_dotted_number_is_lost_only_when_no_fix_is_left(self):
        # Samsung, CVE-2026-21148 (rewritten): the only fix went to the mitigation.
        samsung = {"id": "x", "summary": {"fixed": "SMR Nov-2026 Release 1", "fixes": []}}
        text = self.text("Messages before SMR Nov-2026 Release 1 lets a local attacker read files.")
        self.assertEqual(summaries.lost_fix(samsung, self.reply("", mitigation="Install SMR Nov-2026 Release 1."), text),
                         summaries.LOST_FIX + "SMR Nov-2026 Release 1")
        self.assertEqual(summaries.lost_fix(samsung, self.reply("", mitigation="Update."), self.text("Messages flaw.")), "")  # not in the input
        # Dassault, CVE-2026-19732 (rewritten): a range's affected upper bound the stored Summary took for a fix.
        dassault = {"id": "x", "summary": {"fixed": "", "fixes": [{"for": "3DEXPERIENCE R2023x", "version": "R2023x.FP.CFA.2613"}]}}
        self.assertEqual(summaries.lost_fix(dassault, self.reply(""), self.text("Launcher up to R2023x.FP.CFA.2613 is affected.")), "")
        braun = {"id": "x", "summary": {"fixed": "U/L 95", "fixes": []}}
        self.assertEqual(summaries.lost_fix(braun, self.reply("build 2041"), self.text("before U/L 95, build 2041")), "")  # a renaming

    def test_renamings_and_versions_the_input_no_longer_gives_are_no_loss(self):
        git = {"id": "CVE-2026-105437", "summary": {"fixed": "2.49.1", "fixes": []}}
        self.assertEqual(summaries.lost_fix(git, self.reply("2.49.1"), self.text()), "")
        self.assertEqual(summaries.lost_fix(git, self.reply("2.49.2"), self.text()), "")  # the same line, higher
        self.assertEqual(summaries.lost_fix(git, self.reply("2.50.2"), self.text("Git has a heap overflow.")), "")
        self.assertEqual(summaries.lost_fix({"id": "x"}, self.reply(""), self.text()), "")  # a first Summary
        krb5 = {"id": "x", "summary": {"fixed": "0:1.21.1-10.el9_8.3", "fixes": []}, "fix_keys": ["red_hat:x:krb5<0:1.21.1-10.el9_8.3"]}
        self.assertEqual(summaries.lost_fix(krb5, self.reply("1.21.1-10.el9_8.3"), self.text("krb5 flaw.")), "")  # the epoch
        braun = {"id": "x", "summary": {"fixed": "U/L 95", "fixes": []}}
        self.assertEqual(summaries.lost_fix(braun, self.reply("U/L 95 build 2041"), self.text("before U/L 95")), "")
        qt = {"id": "x", "summary": {"fixed": "6.8.9", "fixes": []}}
        self.assertEqual(summaries.lost_fix(qt, self.reply("6.8.10"), self.text("Qt before 6.8.9 is affected.")), "")

    def test_the_reply_is_kept_back_with_a_note_naming_the_version(self):
        incident = {"id": "x", "mentions": [{"kind": "writeup", "url": SSHOLE_SUMMARY["lead"]}],
                    "summary": {"fixed": "10.6p2", "fixes": []}, "fix_keys": ["openbsd:openssh<10.6.2"]}
        text = (f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n" + json.dumps(SSHOLE_SUMMARY, ensure_ascii=False)
                + " Upgrade to 10.6.2 fixes it.")
        incident["summary"]["fixed"] = "10.6.2"
        with contextlib.redirect_stderr(io.StringIO()):
            summaries.save_reply(incident, FakeClaude.message(SSHOLE_SUMMARY | {"fixed": "", "fixes": []}), text,
                                 {"cves": [], "kev": False, "advisories": [], "n": 0}, "2026-11-18T12:00:00Z")
        self.assertEqual(incident["summary"]["fixed"], "10.6.2")  # the stored Summary stays
        self.assertEqual(incident["summary_error"]["reason"], summaries.LOST_FIX + "10.6.2")
        self.assertIn("The input still gives that version as a fix", summaries.retry(incident, text)["note"])


class JavaGroupFieldsTest(unittest.TestCase):
    """Java4Shell (CVE-2026-114938), 11-18: the headline fixed version, a fixes label and a repeated condition."""

    OWN = ["CVE-2026-114938", "CVE-2026-114940", "CVE-2026-114941", "CVE-2026-114942", "CVE-2026-114943"]
    RECORD = json.dumps({"descriptions": [{"lang": "en", "value": "Vulnerability in Oracle Java SE. Supported versions that are affected are Oracle Java SE: 8u511b33-perf, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3."}],
                         "affected": [{"product": "Java SE", "versions": [{"version": "8u511b33-perf", "status": "affected"},
                                                                           {"version": "17.0.21.0.3", "status": "affected"}]}]})

    def text(self):
        return f"Incident: {', '.join(self.OWN)}\nLead CVE: {self.OWN[0]}\nMentions:\nCVE record {self.OWN[0]}:\n{self.RECORD}"

    def test_a_groups_fixed_is_on_the_lead_cves_line(self):
        fixes = [{"for": "Oracle Java SE 8 performance build", "version": "8u513-perf"}, {"for": "Oracle Java SE 11", "version": "11.0.33.1"},
                 {"for": "Oracle Java SE 17", "version": "17.0.21.1"}]
        summary = {"fixed": "8u513-perf", "fixes": fixes}
        summaries.lead_fixed(summary, self.text())
        self.assertEqual(summary["fixed"], "17.0.21.1")
        kept = {"fixed": "17.0.21.1", "fixes": fixes}
        summaries.lead_fixed(kept, self.text())
        self.assertEqual(kept["fixed"], "17.0.21.1")
        one = {"fixed": "8u513-perf", "fixes": fixes}
        summaries.lead_fixed(one, f"Incident: {self.OWN[0]}\nCVE record {self.OWN[0]}:\n{self.RECORD}")  # one CVE: as written
        self.assertEqual(one["fixed"], "8u513-perf")

    def test_a_fixes_label_naming_an_affected_build_goes_back(self):
        bad = {"fixes": [{"for": "Oracle Java SE 8u511b33-perf", "version": "8u513-perf"}]}
        self.assertEqual(summaries.affected_label(bad, self.text()), summaries.AFFECTED_LABEL + "Oracle Java SE 8u511b33-perf")
        good = {"fixes": [{"for": "Oracle Java SE 8 performance build", "version": "8u513-perf"},
                          {"for": "Synology DSM 7.2.2", "version": "7.2.2-72806"}]}
        self.assertEqual(summaries.affected_label(good, self.text()), "")

    def test_one_condition_sentence_keeps_one_line_with_every_cve_it_holds_for(self):
        own = self.OWN
        text = "웹 서비스 등으로 외부 데이터를 API에 전달하는 경우"
        conditions = [(own[:1], "Java 17 이상"), ([own[0], own[2]], text), ([own[1], own[4]], text), ([own[3]], "TLS")]
        easy = [(c[0], f"쉬운 {c[1]}") for c in conditions]
        merged, twins = summaries.merge_conditions(conditions, easy, own)
        self.assertEqual(merged, [(own[:1], "Java 17 이상"), ([own[0], own[1], own[2], own[4]], text), ([own[3]], "TLS")])
        self.assertEqual([t[1] for t in twins], ["쉬운 Java 17 이상", f"쉬운 {text}", "쉬운 TLS"])
        self.assertEqual(twins[1][0], [own[0], own[1], own[2], own[4]])
        everyone, _ = summaries.merge_conditions([(own[:3], text), (own[3:], text)], [], own)
        self.assertEqual(everyone, [([], text)])  # together every CVE: no ids
