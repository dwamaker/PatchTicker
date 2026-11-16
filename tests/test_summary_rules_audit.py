"""The audit of the Summary prompt and checks before the group rules were committed (11-16,
.scratch/checks/summary-rules-audit-2026-11-16.md, F1 to F15)."""

import contextlib
import copy
import io
import json
import unittest

from collector import cve_lines, numbers, summaries, summary_input
from test_cve_lines import MANY, MAX, line, lines_row, saved
from test_summaries import SSHOLE_SUMMARY, FakeClaude

TEXT = f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n" + json.dumps(SSHOLE_SUMMARY, ensure_ascii=False)
GROUP_TEXT = "Incident: CVE-2026-0001, CVE-2026-0002\nLead CVE: CVE-2026-0001\n" + TEXT


def with_fields(lang, **fields):
    return SSHOLE_SUMMARY | {lang: SSHOLE_SUMMARY[lang] | fields}


def save(reply, tries=0, text=TEXT, incident=None):
    incident = incident or {"id": "x", "mentions": [{"kind": "writeup", "url": SSHOLE_SUMMARY["lead"]}]}
    if tries:
        incident["summary_error"] = {"tries": tries, "reason": "earlier"}
    message = FakeClaude.message(reply) if isinstance(reply, dict) else FakeClaude.message(reply)
    summaries.save_reply(incident, message, text, {"cves": [], "kev": False, "advisories": [], "n": 0}, "2026-11-08T12:00:00Z")
    return incident


class WaitCheckTest(unittest.TestCase):
    """F1, F2: the prompt's own example was the phrase the wait check rejects, and the check fired on no-release text."""

    def test_the_prompt_no_longer_teaches_waiting_for_a_new_version(self):
        self.assertNotIn("새 버전이 나오면", summaries.INSTRUCTIONS)
        self.assertIn("새 버전으로 바로 업데이트하세요.", summaries.INSTRUCTIONS)
        self.assertIn("wait for a new version only when fixed and fixes are both empty", summaries.INSTRUCTIONS)

    def test_a_real_wait_beside_a_fixed_version_is_still_caught(self):
        for lang, action in (("ko", "새 버전이 나오면 바로 업데이트하세요."), ("ko", "드라이버 업데이트가 나오면 설치하세요."),
                             ("en", "Update to the newest version as soon as it is available."),
                             ("en", "Update the plugin as soon as the new version is out.")):
            self.assertEqual(summaries.easy_action_mismatch(with_fields(lang, easy_action=action)), [lang], action)

    def test_a_wait_the_mitigation_itself_gives_passes(self):
        # CVE-2026-63489: one CVE of the group has no fix; CVE-2026-104254: the fix is announced, not out.
        for lang, mitigation, action in (
                ("ko", "CVE-2026-0002: 수정 버전은 아직 없습니다.", "새 버전이 나오면 바로 업데이트하세요."),
                ("en", "Update to 10.6p2 or later (not yet released).", "Update once the new version is released."),
                ("ko", "10.6p2로 업데이트하세요(아직 출시 전입니다).", "새 버전이 나오면 바로 업데이트하세요."),
                ("en", "Update to 10.6p2 (planned release date 2026-07-20).", "Install the update as soon as it arrives.")):
            reply = with_fields(lang, mitigation=mitigation, easy_action=action)
            self.assertEqual(summaries.easy_action_mismatch(reply), [], action)

    def test_something_that_appears_is_not_a_release(self):
        for lang, action in (("ko", "이상한 창이 나오면 닫으세요."), ("en", "Close the window when it appears.")):
            self.assertEqual(summaries.easy_action_mismatch(with_fields(lang, easy_action=action)), [], action)


class RetryNoteTest(unittest.TestCase):
    """F3, F4: each reason gets its own sentence; the number sentence only for a number."""

    def note(self, reason):
        return summaries.retry({"summary_error": {"tries": 1, "reason": reason}}, TEXT)["note"]

    def test_each_soft_reason_gets_its_own_sentence_and_not_the_number_one(self):
        number = "never shorten or round one"
        for reason, words in ((f"{summaries.JARGON}: ['CGI']", "everyday words"),
                              ("stopgap step missing in ko: the mitigation says to restart", "stopgap_then"),
                              ("Easy action disagrees with the mitigation in ko", "never to wait"),
                              ("unbalanced brackets or quotes in the ko title", "close every bracket"),
                              (f"{summaries.GROUP_SCOPE} (ko summary)", "only into conditions"),
                              ("lead is not an input URL: https://x", "Mentions list"),
                              ("cve_lines names a CVE not in the input: CVE-2026-1", "Incident line"),
                              ("stop_reason max_tokens", "as short as")):
            note = self.note(reason)
            self.assertIn(words, note, reason)
            self.assertNotIn(number, note, reason)
        self.assertIn(number, self.note("numbers not in the input: ['2.50']"))
        self.assertIn(number, self.note("Korean and English numbers differ: ['3']"))

    def test_every_soft_problem_is_reported_and_answered(self):
        reply = with_fields("ko", easy="SQL 서버가 뚫릴 수 있습니다!", title=SSHOLE_SUMMARY["ko"]["title"] + " 기준)")
        reason = save(reply)["summary_error"]["reason"]
        self.assertIn(summaries.JARGON, reason)
        self.assertIn("unbalanced", reason)
        note = self.note(reason)
        self.assertIn("everyday words", note)
        self.assertIn("close every bracket", note)


class DraftKeptTest(unittest.TestCase):
    """F5: soft, soft, then a hard failure no longer ends with nothing stored."""

    def test_the_last_soft_draft_is_stored_when_the_final_try_fails_hard(self):
        soft = with_fields("ko", easy="SQL 서버가 뚫릴 수 있습니다!")
        incident = save(soft, tries=1)
        self.assertNotIn("summary", incident)
        save("not json", incident=incident)
        self.assertEqual(incident["summary"]["ko"]["easy"], "SQL 서버가 뚫릴 수 있습니다!")
        self.assertNotIn("summary_error", incident)
        self.assertEqual(incident["summary_basis"]["n"], 1)

    def test_a_hard_failure_before_the_last_try_still_only_counts(self):
        incident = save(with_fields("ko", easy="SQL 서버가 뚫릴 수 있습니다!"))
        save("not json", incident=incident)
        self.assertNotIn("summary", incident)
        self.assertEqual(incident["summary_error"]["tries"], 2)


class TitleIdTest(unittest.TestCase):
    """F6: stripping a CVE id from a title no longer leaves half a bracket."""

    def test_a_bracket_left_with_only_a_filler_word_goes_whole(self):
        for title, want in (("Live Composer 워드프레스 플러그인 저장형 XSS (CVE-2025-15711 기준)", "Live Composer 워드프레스 플러그인 저장형 XSS"),
                            ("Live Composer WordPress plugin stored XSS (CVE-2025-15711 lead)", "Live Composer WordPress plugin stored XSS"),
                            ("Kyverno 권한 우회 (CVE-2026-122302 외)", "Kyverno 권한 우회"),
                            ("Kyverno bypass (CVE-2026-122302 and others)", "Kyverno bypass"),
                            ("Foo flaw [CVE-2026-1234]", "Foo flaw"), ("Foo CVE-2026-1234 flaw", "Foo flaw"),
                            ("OpenSSH 신호 경쟁 상태 (regreSSHion, CVE-2024-6387)", "OpenSSH 신호 경쟁 상태 (regreSSHion)"),
                            ("OpenSSH race (regreSSHion)", "OpenSSH race (regreSSHion)")):
            got = summaries.strip_title_ids(title)
            self.assertEqual(got, want)
            self.assertEqual(summaries.unbalanced_title({lang: {"title": got, "easy_title": ""} for lang in ("ko", "en")}), "")


class KoreanAmountTest(unittest.TestCase):
    """F7: 천/만/억/조 is a scale only before a counter or another amount piece."""

    def test_man_meaning_only_is_not_an_amount(self):
        for text, want in (("7.2만 해당합니다", {"7.2"}), ("Windows 11만 영향을 받습니다", {"11"}), ("TLS 1.3만 씁니다", {"1.3"}),
                           ("KB5034441만 설치하세요", {"5034441"}), ("CVE‑2026‑126067만", {"2026", "126067"})):
            self.assertEqual(numbers.ko_numbers(text), want, text)
        self.assertNotIn("3000000000000", numbers.ko_numbers("제3조에 따라"))

    def test_real_amounts_are_still_read(self):
        for text, want in (("3만 대", "30000"), ("12만 개", "120000"), ("1억 2천만 명", "120000000"), ("580만여 명", "5800000"),
                           ("2만 달러", "20000")):
            self.assertIn(want, numbers.ko_numbers(text), text)


class GroupScopeWordsTest(unittest.TestCase):
    """F8."""

    def test_more_ways_of_saying_not_affected_are_caught(self):
        for said in ("단독 mongod는 영향받지 않습니다.", "Panorama는 해당되지 않습니다.", "Panorama is not vulnerable.",
                     "It does not affect Panorama."):
            lang = "en" if said.isascii() else "ko"
            self.assertTrue(summaries.group_scope(with_fields(lang, summary=said)), said)

    def test_a_record_that_lists_no_versions_is_not_a_scope(self):
        # CVE-2026-121501
        self.assertEqual(summaries.group_scope(with_fields("en", summary="No affected or unaffected versions are listed.")), "")


class PromptTextTest(unittest.TestCase):
    """F9: the contradictions are settled in the text."""

    def test_the_group_rules_say_what_they_replace(self):
        group = summaries.GROUP_INSTRUCTIONS
        self.assertIn("instead of", group)
        self.assertIn("easy_conditions", group)
        self.assertIn("same release also fixes", group)  # the short group example

    def test_the_contradicted_lines_are_settled(self):
        text = summaries.INSTRUCTIONS
        self.assertNotIn("(the official advisory or the discoverer's write-up)", text)
        self.assertIn("never write the word Lead", text)
        self.assertIn('"1.0.4 이하"', text)  # the Korean range form is a rule, not only a retry note
        self.assertIn("except mitigation", text)
        self.assertIn("except where a rule above says", text)
        example = text.split("Output:", 1)[1]
        self.assertIn('"easy_conditions"', example)
        self.assertIn("glibc", json.loads(example.strip().strip('"'))["en"]["easy"])


class StopgapStepTest(unittest.TestCase):
    """F10: a restart that follows the update is not the stopgap's step."""

    def test_only_a_restart_after_the_stopgap_needs_stopgap_then(self):
        after_update = with_fields("en", mitigation="Update to OpenSSH 10.6p2, then restart sshd. Until then, set "
                                                    "PasswordAuthentication no.", stopgap_then="")
        self.assertEqual(summaries.missing_stopgap_step(after_update), "")
        after_stopgap = with_fields("en", mitigation="Update to OpenSSH 10.6p2. Until then, set PasswordAuthentication no "
                                                     "and restart sshd.", stopgap_then="")
        self.assertTrue(summaries.missing_stopgap_step(after_stopgap))


class NoFixActionTest(unittest.TestCase):
    """F11: the no-fix rule needed a version the prompt bans from easy_action."""

    def test_update_beside_a_mitigation_that_says_there_is_no_fix_is_caught(self):
        reply = SSHOLE_SUMMARY | {"fixed": "", "en": SSHOLE_SUMMARY["en"] | {
            "mitigation": "There is no fix yet. Turn password logins off.", "easy_action": "Update OpenSSH now."}}
        self.assertEqual(summaries.easy_action_mismatch(reply), ["en"])

    def test_no_source_naming_a_fix_is_not_a_no_fix(self):
        reply = SSHOLE_SUMMARY | {"fixed": "", "en": SSHOLE_SUMMARY["en"] | {
            "mitigation": "No source names a fixed version yet.", "easy_action": "Update OpenSSH when you can."}}
        self.assertEqual(summaries.easy_action_mismatch(reply), [])


class GuardTest(unittest.TestCase):
    """F12, F13, F15."""

    def test_a_stored_summary_without_cve_lines_or_with_a_bad_name_does_not_raise(self):
        row = lines_row() | {"cves": MANY[:3]}
        for lang in ("ko", "en"):
            del row["summary"][lang]["cve_lines"]
        self.assertEqual(cve_lines.missing_lines(row), MANY[:3])
        odd = copy.deepcopy(with_fields("ko", names=[None, "OpenSSH"]))
        self.assertEqual(summaries.easy_jargon(odd), [])

    def test_no_lines_are_asked_while_a_new_summary_is_due(self):
        row = lines_row() | {"mentions": [], "summary_basis": {"cves": sorted(MANY[:-1]), "kev": False, "advisories": [], "n": 1}}
        self.assertEqual(cve_lines.missing_lines(row), [])
        row["summary_basis"]["cves"] = sorted(MANY)
        self.assertEqual(cve_lines.missing_lines(row), MANY)

    def test_a_banned_word_before_a_korean_particle_is_caught(self):
        for easy, word in (("API를 통해 뚫릴 수 있습니다!", "API"), ("SQL로 정보가 털립니다!", "SQL")):
            self.assertEqual(summaries.easy_jargon(with_fields("ko", easy=easy)), [word], easy)
        self.assertEqual(summaries.easy_jargon(with_fields("ko", easy="SQL이 뚫립니다!", names=["OpenSSH SQL"])), [])


class LineScriptTest(unittest.TestCase):
    """F14: a batch line in another script is dropped like a Summary's."""

    def test_a_line_with_a_word_in_another_script_is_dropped_and_asked_again(self):
        row = lines_row()
        log = io.StringIO()
        with contextlib.redirect_stderr(log):
            cves, _ = saved(row, line(MANY[MAX], "범위 外 읽기가 가능합니다.", "Reads out of bounds."),
                            line(MANY[MAX + 1], "파일을 읽을 수 있습니다.", "Files can be read."))
        self.assertEqual(cves, [MANY[MAX + 1]])
        self.assertIn(summaries.STRAY_REASON, _)


if __name__ == "__main__":
    unittest.main()
