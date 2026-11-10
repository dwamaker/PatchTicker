"""Seam 1: instant Summaries for Highlight candidates, with a fake Claude client.

pages/sshhole.com.html and pages/release-10.6p2.txt are the real pages (2026-11-07), trimmed.
"""

import json
import unittest
import urllib.error
from types import SimpleNamespace

from collector import summaries
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
        self.assertEqual(sent["output_config"]["format"]["schema"]["required"], ["ko", "en", "products", "lead", "fixed", "command", "stopgap", "devices", "fixes", "incident", "platforms", "stopgap_file", "titles_ko", "exploited", "exploited_source", "poc_public", "library"])
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
            "an exploited source that is not text": SSHOLE_SUMMARY | {"exploited": True, "exploited_source": ["https://sshhole.com"]},
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
        self.merged_sshole(FakeClaude({k: v for k, v in SSHOLE_SUMMARY.items() if k not in ("poc_public", "library")}))
        summary = board(self.store)[HN_STORY]["summary"]
        self.assertEqual((summary["poc_public"], summary["library"]), (False, False))  # replies from before say neither

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
        old = SSHOLE_SUMMARY | {lang: {k: v for k, v in SSHOLE_SUMMARY[lang].items() if k != "easy_action"} for lang in ("ko", "en")}
        self.merged_sshole(FakeClaude(old))
        self.assertEqual(board(self.store)[HN_STORY]["summary"]["en"]["easy_action"], "")

    def test_a_cve_id_the_model_puts_in_a_title_is_taken_out(self):
        reply = SSHOLE_SUMMARY | {"ko": SSHOLE_SUMMARY["ko"] | {"title": SSHOLE_SUMMARY["ko"]["title"] + " (CVE-2026-123158)"},
                                  "en": SSHOLE_SUMMARY["en"] | {"title": "[CVE-2026-123158] " + SSHOLE_SUMMARY["en"]["title"]}}
        self.merged_sshole(FakeClaude(reply))
        summary = board(self.store)[HN_STORY]["summary"]
        self.assertEqual((summary["ko"]["title"], summary["en"]["title"]), (SSHOLE_SUMMARY["ko"]["title"], SSHOLE_SUMMARY["en"]["title"]))

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


class EasyJargonTest(unittest.TestCase):
    """The Easy view's three fields are checked for the words the prompt bans; a hit costs a retry, never the Summary."""

    def save(self, reply, tries=0):
        incident = {"id": "x", "mentions": [{"kind": "writeup", "url": SSHOLE_SUMMARY["lead"]}]}
        if tries:
            incident["summary_error"] = {"tries": tries, "reason": "earlier"}
        # The Lead's text holds every number, the command and the stopgap the replies use.
        text = f"Text of {SSHOLE_SUMMARY['lead']}{summaries.LEAD_MARK}:\n" + json.dumps(SSHOLE_SUMMARY, ensure_ascii=False)
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
        restart = SSHOLE_SUMMARY | {"en": SSHOLE_SUMMARY["en"] | {"mitigation": "Set PasswordAuthentication no and restart sshd."}}
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
        reply = SSHOLE_SUMMARY | {"ko": SSHOLE_SUMMARY["ko"] | {"easy_action": "OpenSSH 10.6p2 이상으로 업데이트하세요."}}
        self.assertIn("summary", self.save(reply))

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

        text = summaries.page_text(summaries.fetch_page(http_get, "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0014"))
        self.assertEqual(asked, ["https://psirtapi.global.sonicwall.com/api/v1/vulndetail/?advisory_id=SNWLID-2026-0014"])
        for words in ("7.3.4-7013 and higher", "8.2.3-8015 and higher", "TZ 270", "7.3.3-7015 and older"):
            self.assertIn(words, text)

    def test_the_fixed_versions_come_before_the_long_detail_so_the_page_cut_keeps_them(self):
        data = json.loads((FIXTURES / "pages" / "sonicwall-SNWLID-2026-0014.json").read_text(encoding="utf-8"))
        data["detail"] = "<p>" + "Long technical detail. " * 1000 + "</p>"
        page = summaries.fetch_page(lambda url: json.dumps(data).encode(), "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0014")
        self.assertIn("7.3.4-7013 and higher", summaries.page_text(page)[:summaries.PAGE_CHARS])


if __name__ == "__main__":
    unittest.main()


class EasyConditionsTest(unittest.TestCase):
    """easy_conditions (after critique 12): the conditions in everyday words, checked like the other Easy fields."""

    def test_a_banned_word_in_the_easy_conditions_is_caught(self):
        summary = {"products": [], "devices": [], **{lang: {"names": [], "easy": "", "easy_title": "", "easy_action": "",
                                                              "easy_conditions": []} for lang in ("ko", "en")}}
        summary["ko"]["easy_conditions"] = ["세션 토큰을 쓸 때"]
        self.assertEqual(summaries.easy_jargon(summary), ["세션", "토큰"])
