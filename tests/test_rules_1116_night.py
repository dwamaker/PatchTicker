"""The owner's decisions of 11-16 night: five more reply checks, the attacked CVE named in a group, and the number check's
line names that kept Summaries old for three tries (.scratch/checks/still-old-2026-11-16.md)."""

import contextlib
import io
import json
import unittest
import unittest.mock

from collector import cve_lines, numbers, review, summaries, summary_input
from test_cve_lines import MANY, MAX, line, lines_row, saved
from test_summaries import SSHOLE_SUMMARY, FakeClaude

TEXT = f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n" + json.dumps(SSHOLE_SUMMARY, ensure_ascii=False)


def with_fields(lang, **fields):
    return SSHOLE_SUMMARY | {lang: SSHOLE_SUMMARY[lang] | fields}


class LineNameNumberTest(unittest.TestCase):
    """C: a release line named by its major, several lines before one line word, and ".x" before a Korean particle are
    line names, as "the 1.19 line" already was (Wasmtime CVE-2026-121439, Frappe -126316, GitLab -13721, ActiveMQ -108949)."""
    KNOWN = numbers.numbers("48.0.7 49.0.4 36.0.19 12.3.11 12.4.2 6.3.0 5.19.0 13.0.2 16.20.1 15.64.6")

    def stripped(self, text, fixed=()):
        return numbers.numbers(numbers.without_line_names(text, set(fixed), self.KNOWN))

    def test_a_line_named_by_its_major_beside_a_line_word_is_a_name(self):
        self.assertEqual(self.stripped("48 계열은 48.0.7, 49 계열은 49.0.4 이상으로 업데이트하세요."), {"48.0.7", "49.0.4"})
        self.assertEqual(self.stripped("Update to 48.0.7 on the 48 line."), {"48.0.7"})
        self.assertEqual(self.stripped("Frappe HRMS 16 라인은 16.20.1 이상으로 업데이트하세요."), {"16.20.1"})

    def test_lines_listed_before_one_line_word_are_names(self):
        self.assertEqual(self.stripped("12.3 및 12.4 계열의 수정 버전은 확인되지 않았습니다."), set())
        self.assertEqual(self.stripped("A fixed version for the 12.3 and 12.4 lines is not confirmed."), set())
        self.assertEqual(self.stripped("12.3~12.4 라인은 옮기세요."), set())

    def test_x_before_a_korean_particle_is_a_line(self):
        self.assertEqual(self.stripped("6.3.x와 5.19.x 계열은 업데이트하세요."), set())
        self.assertEqual(self.stripped("13.x 계열로 옮기세요."), set())

    def test_a_number_that_is_no_line_is_still_checked(self):
        self.assertEqual(self.stripped("Update to 48."), {"48"})  # a target, not a line
        self.assertEqual(self.stripped("48 계열은 업데이트하세요.") , set())  # an input version starts with 48.
        self.assertEqual(self.stripped("77 계열은 업데이트하세요."), {"77"})  # no input version on that line
        self.assertEqual(self.stripped("결함 4건도 고칩니다."), {"4"})  # a count stays a number

    def test_a_fixes_line_the_input_names_passes(self):
        # Adobe "After Effects 25.x" moved to 27.0; B. Braun "SpaceCom 011L line" with version 011L000096.
        text = TEXT + "\nAffected: After Effects 25.6.6 and earlier, fixed in 27.0; SpaceCom fixed in 011L000096."
        for fixes in ([{"for": "Adobe After Effects 25.x", "version": "27.0", "devices": []}],
                      [{"for": "B. Braun SpaceCom 011L line", "version": "011L000096", "devices": []}]):
            with self.subTest(fixes[0]["for"]):
                reply = SSHOLE_SUMMARY | {"fixes": fixes}
                summaries.parse(FakeClaude.message(reply), text, [SSHOLE_SUMMARY["lead"]])
        with self.assertRaises(summaries.Rejected):  # a line no input version names
            summaries.parse(FakeClaude.message(SSHOLE_SUMMARY | {"fixes": [{"for": "Foo 77", "version": "10.6p2", "devices": []}]}),
                            text, [SSHOLE_SUMMARY["lead"]])


class InformalLinesTest(unittest.TestCase):
    """A1: a Korean per-CVE line in 해요 style beside the 합니다 Summary (CVE-2026-102868: 90 of 907 lines)."""

    def test_a_line_in_haeyo_style_is_sent_back(self):
        lines = [{"cve": "CVE-2026-1", "text": "원격에서 코드를 실행할 수 있어요."}, {"cve": "CVE-2026-2", "text": "범위 변경도 있어요"}]
        for bad in lines:
            with self.subTest(bad["text"]):
                reply = with_fields("ko", cve_lines=[bad])
                self.assertEqual(summaries.informal_lines(reply), f"{summaries.INFORMAL} (CVE-2026-{bad['cve'][-1]})")
        for good in ("원격에서 코드를 실행할 수 있습니다.", "서비스가 멈춥니다.", "관리자 권한 필요", "정보 노출"):
            self.assertEqual(summaries.informal_lines(with_fields("ko", cve_lines=[{"cve": "CVE-2026-1", "text": good}])), "", good)

    def test_a_batch_line_in_haeyo_style_is_dropped_and_asked_again(self):
        row = lines_row()
        cves, log = saved(row, line(MANY[MAX], "파일을 읽을 수 있어요.", "Files can be read."),
                          line(MANY[MAX + 1], "파일을 읽을 수 있습니다.", "Files can be read."))
        self.assertEqual(cves, [MANY[MAX + 1]])
        self.assertIn(summaries.INFORMAL, log)

    def test_the_lines_prompt_names_the_style(self):
        self.assertIn("합니다", cve_lines.LINES_INSTRUCTIONS)


class BoundCheckTest(unittest.TestCase):
    """A2: "if you run X or older, check that you run a version newer than X" (CVE-2026-126541, -126991, -124552)."""

    def test_a_check_conditioned_on_running_the_bound_is_sent_back(self):
        for lang, mitigation in (("ko", "수정 버전을 밝힌 출처가 아직 없습니다. 29.7.1 이하 버전을 쓰신다면 29.7.1보다 새 버전을 쓰는지 확인하세요."),
                                 ("ko", "2.670 이하 Webmin을 쓰고 있다면 실행 중인 버전이 2.670보다 새 버전인지 확인하세요."),
                                 ("en", "If you run 3.1.4 or older, check that you run a newer version and read the advisory."),
                                 ("en", "If you run Webmin through 2.670, check that it is newer than 2.670.")):
            with self.subTest(mitigation):
                self.assertEqual(summaries.bound_check(with_fields(lang, mitigation=mitigation)), f"{summaries.BOUND_CHECK} ({lang})")

    def test_the_plain_instruction_passes(self):
        for lang, mitigation in (("ko", "수정 버전을 밝힌 출처가 아직 없습니다. 1.9.0보다 새 버전을 쓰는지 확인하고 제조사 권고문을 읽으세요."),
                                 ("en", "No source names a fixed version yet. Check that you run a version newer than 1.9.0."),
                                 ("en", "If you run 7.2, update to 7.2.14 or later."),
                                 # live, 11-16: a wait, an upgrade, an instruction to use a newer one, a fact then the check
                                 ("ko", "0.116.1 이하를 쓰고 있다면 새 버전이 나올 때까지 기다리고 제작사 공지를 확인하세요."),
                                 ("ko", "2.999.18 이하 버전을 쓰고 있다면 그보다 새 버전으로 올리고 제조사 공지를 확인하세요."),
                                 ("ko", "9.1.1 이하 버전을 쓰고 있다면 그보다 새 버전을 쓰고 제조사 권고를 확인하세요."),
                                 ("ko", "1.0.0 이하 버전이면 취약하므로, 설치된 버전이 1.0.0보다 새로운지 확인하고 제조사 공지를 읽으세요.")):
            self.assertEqual(summaries.bound_check(with_fields(lang, mitigation=mitigation)), "", mitigation)

    def test_the_prompt_asks_for_one_instruction(self):
        self.assertIn('with no "if you run" before it', summaries.INSTRUCTIONS)


class NoActionTest(unittest.TestCase):
    """A3: an Easy action that is no action (CVE-2026-123695, -88799, -125074)."""

    def test_a_statement_alone_is_sent_back(self):
        for lang, action in (("ko", "아직 고친 버전이 없습니다."), ("en", "There is no fix yet."), ("ko", "이 프로그램을 쓰는지 확인하세요."),
                             ("en", "Check whether you use this app."), ("en", "Check whether you use this plugin. There is no fix yet."),
                             ("en", "No source names a fixed version yet.")):
            with self.subTest(action):
                self.assertEqual(summaries.no_action(with_fields(lang, easy_action=action)), f"{summaries.NO_ACTION} ({lang})")

    def test_a_statement_with_an_action_passes(self):
        for lang, action in (("ko", "아직 고친 버전이 없습니다. 고친 버전이 나오면 바로 업데이트하세요."),
                             ("en", "There is no fix yet. Remove the plugin."), ("en", "Update the app now."),
                             ("ko", "관리 화면을 인터넷에 열어 두지 마세요.")):
            self.assertEqual(summaries.no_action(with_fields(lang, easy_action=action)), "", action)

    def test_the_prompts_fallback_is_an_action(self):
        self.assertIn("There is no fix yet. Update as soon as a fixed version is out.", summaries.INSTRUCTIONS)
        reply = SSHOLE_SUMMARY | {"fixed": "",
                                  "ko": SSHOLE_SUMMARY["ko"] | {"mitigation": "수정 버전은 아직 없습니다.", "easy_action": "아직 고친 버전이 없습니다. 고친 버전이 나오면 바로 업데이트하세요."},
                                  "en": SSHOLE_SUMMARY["en"] | {"mitigation": "There is no fix yet.", "easy_action": "There is no fix yet. Update as soon as a fixed version is out."}}
        self.assertEqual(summaries.no_action(reply), "")
        self.assertEqual(summaries.easy_action_mismatch(reply), [])  # the example passes the wait and no-fix rules


class EmptyWithFixTest(unittest.TestCase):
    """A4: an empty mitigation or Easy action beside a fixed version (CVE-2026-67175)."""

    def test_empty_fields_beside_a_fixed_version_are_sent_back(self):
        for field in ("mitigation", "easy_action"):
            reply = SSHOLE_SUMMARY | {lang: SSHOLE_SUMMARY[lang] | {field: ""} for lang in ("ko", "en")}
            self.assertEqual(summaries.empty_with_fix(reply), f"{summaries.EMPTY_WITH_FIX} ({field})", field)
        self.assertEqual(summaries.empty_with_fix(SSHOLE_SUMMARY), "")
        no_fix = SSHOLE_SUMMARY | {"fixed": "", "fixes": [], **{l: SSHOLE_SUMMARY[l] | {"easy_action": ""} for l in ("ko", "en")}}
        self.assertEqual(summaries.empty_with_fix(no_fix), "")
        not_incident = SSHOLE_SUMMARY | {"incident": False, **{l: SSHOLE_SUMMARY[l] | {"mitigation": ""} for l in ("ko", "en")}}
        self.assertEqual(summaries.empty_with_fix(not_incident), "")


class HangulInEnglishTest(unittest.TestCase):
    """A5: Korean text in an English field (CVE-2026-126391: all seven en easy_conditions)."""

    def test_korean_in_an_english_field_is_sent_back(self):
        reply = with_fields("en", easy_conditions=["관리 화면을 인터넷에 열어 둔 경우"])
        self.assertEqual(summaries.hangul_in_english(reply, TEXT), f"{summaries.HANGUL_IN_EN} (en easy_conditions)")
        self.assertTrue(summaries.hangul_in_english(with_fields("en", summary="A flaw 폭발합니다."), TEXT))

    def test_a_korean_name_the_input_writes_passes(self):
        reply = with_fields("en", summary="The 한컴오피스 viewer can run code.")
        self.assertEqual(summaries.hangul_in_english(reply, TEXT + "\nProducts: 한컴오피스"), "")
        self.assertTrue(summaries.hangul_in_english(reply, TEXT))


class AttackedCveTest(unittest.TestCase):
    """B: a group whose input marks a CVE as attacked (CISA KEV) names it beside the claim (Chrome CVE-2026-125345)."""
    GROUP = ("Incident: CVE-2026-125345, CVE-2026-125350\nLead CVE: CVE-2026-125345\n"
             "Exploited in the wild (CISA KEV): yes (CVE-2026-125350)\n") + TEXT

    def summary(self, ko, en):
        return with_fields("ko", summary=ko) | {"en": SSHOLE_SUMMARY["en"] | {"summary": en}}

    def test_a_claim_without_the_attacked_id_is_sent_back(self):
        for ko, en in (("샌드박스 밖 코드 실행 결함이 있습니다. 그중 XML 결함 하나는 이미 공격에 쓰이고 있습니다.", "One XML flaw is already used in attacks (CVE-2026-125350)."),
                       ("코드 실행 결함이 있습니다. CVE-2026-125350은 이미 공격에 쓰이고 있습니다.", "CVE-2026-125345 is already exploited.")):
            with self.subTest(ko):
                self.assertTrue(summaries.attacked_unnamed(self.summary(ko, en), self.GROUP).startswith(summaries.ATTACKED_UNNAMED))

    def test_the_claim_beside_its_id_passes(self):
        ok = self.summary("코드 실행 결함이 있습니다. 그중 XML 결함(CVE-2026-125350)은 이미 공격에 쓰이고 있습니다.",
                          "One XML flaw, CVE-2026-125350, is already exploited in the wild.")
        self.assertEqual(summaries.attacked_unnamed(ok, self.GROUP), "")
        # no claim, no KEV list, or one CVE: nothing to name
        self.assertEqual(summaries.attacked_unnamed(self.summary("코드 실행 결함이 있습니다.", "A flaw lets code run."), self.GROUP), "")
        self.assertEqual(summaries.attacked_unnamed(self.summary("이미 공격에 쓰이고 있습니다.", "It is exploited."),
                                                    self.GROUP.replace("yes (CVE-2026-125350)", "no")), "")

    def test_the_group_prompt_asks_for_it(self):
        self.assertIn("names that CVE id beside the claim", summaries.GROUP_INSTRUCTIONS)


class ManyVersionsTest(unittest.TestCase):
    """Owner, 11-16 late: four or more fixed lines go to `fixes` (the page lists them); the mitigation and the Easy
    action do not list them (CVE-2026-102868: seventeen pairs in a 742-character paragraph)."""
    FIXES = [{"for": f"Widget {n}", "version": f"{n}.0.{n}", "devices": []} for n in (1, 2, 3, 4)]

    def reply(self, ko, en, fixes=FIXES, fixed="1.0.1", field="mitigation"):
        return SSHOLE_SUMMARY | {"fixed": fixed, "fixes": fixes, "ko": SSHOLE_SUMMARY["ko"] | {field: ko},
                                 "en": SSHOLE_SUMMARY["en"] | {field: en}}

    def test_the_prompt_says_four_or_more_go_to_fixes(self):
        self.assertIn("when four or more lines or products have their own fixed version", summaries.INSTRUCTIONS)
        self.assertIn("never four or more versions", summaries.INSTRUCTIONS)

    def test_four_fixed_versions_listed_are_sent_back(self):
        listed = self.reply("Widget 1은 1.0.1, 2는 2.0.2, 3은 3.0.3, 4는 4.0.4 이상으로 업데이트하세요.",
                            "Update Widget 1 to 1.0.1, 2 to 2.0.2, 3 to 3.0.3 and 4 to 4.0.4 or later.")
        self.assertEqual(summaries.many_versions(listed), f"{summaries.MANY_VERSIONS} (ko mitigation)")
        action = self.reply("1.0.1, 2.0.2, 3.0.3, 4.0.4로 업데이트하세요.", "Update to 1.0.1, 2.0.2, 3.0.3 or 4.0.4.", field="easy_action")
        self.assertEqual(summaries.many_versions(action), f"{summaries.MANY_VERSIONS} (ko easy_action)")

    def test_four_targets_with_fewer_fixes_are_sent_back(self):
        # CVE-2026-63282: seven versions in the sentence, fixes empty; the page shows fixes only.
        reply = self.reply("1.0.1, 2.0.2, 3.0.3, 4.0.4 이상으로 업데이트하세요.", "Update to 1.0.1, 2.0.2, 3.0.3 or 4.0.4 or later.",
                           fixes=[], fixed="1.0.1")
        self.assertEqual(summaries.many_versions(reply), f"{summaries.MANY_VERSIONS} (ko mitigation)")
        to_only = self.reply("확인하세요.", "Update to 1.0.1, 2.0.2, 3.0.3 and 4.0.4.", fixes=[], fixed="1.0.1")
        self.assertEqual(summaries.many_versions(to_only), f"{summaries.MANY_VERSIONS} (en mitigation)")

    def test_three_versions_bounds_and_the_short_sentence_pass(self):
        self.assertEqual(summaries.many_versions(self.reply("1.0.1, 2.0.2, 3.0.3 이상으로 업데이트하세요.",
                                                            "Update to 1.0.1, 2.0.2 or 3.0.3 or later.")), "")
        short = self.reply("쓰는 제품이나 계열의 수정 버전으로 업데이트하세요. Widget 5는 수정 버전이 없습니다.",
                           "Update your product or line to its fixed version. Widget 5 has no fix.")
        self.assertEqual(summaries.many_versions(short), "")
        # Line names are no versions to install (CVE-2026-120431: "10.86 계열은 10.86.51" names three, not six).
        lines = self.reply("10.86 계열은 10.86.51, 11.02 계열은 11.02.29, 11.15 계열은 11.15.07 이상으로 업데이트하세요.",
                           "Update the 10.86 line to 10.86.51, 11.02 to 11.02.29 and 11.15 to 11.15.07 or later.",
                           fixes=[{"for": "x", "version": v, "devices": []} for v in ("10.86.51", "11.02.29", "11.15.07")],
                           fixed="10.86.51")
        self.assertEqual(summaries.many_versions(lines), "")
        bounds = self.reply("1.0.0 이상 1.0.1 미만, 2.0.0 이상 2.0.2 미만이 해당합니다. 1.0.1로 업데이트하세요.",
                            "1.0.0 up to 1.0.1 and 2.0.0 up to 2.0.2 are affected. Update to 1.0.1.", fixes=[])
        self.assertEqual(summaries.many_versions(bounds), "")
        # live, 11-16: affected bounds and "newer than" thresholds listed with no fixes are no fixed lines
        for ko, en in (("6.11.0 이상 6.22.0 미만은 6.22.0으로, 7.0.0 이상 7.8.0 미만은 7.8.0으로 업데이트하세요.", "Update."),
                       ("4.33.10M, 4.34.8M, 4.35.6M, 4.36.2F 이하가 영향 범위이므로 새 버전인지 확인하세요.", "Check."),
                       ("13.0.31, 12.11.84, 11.11.218, 10.12.345, 9.80.148보다 낮은 버전이 해당합니다.", "Check."),
                       ("설치된 Moodle이 수정 기준(4.5.15, 5.0.11, 5.1.8, 5.2.4)보다 새 버전인지 확인하세요.", "Check."),
                       ("4.35.0F부터 4.35.6M, 4.36.0F부터 4.36.2F, 4.37.0F가 해당합니다.", "Check."),
                       ("12.10.0.1, 12.9.0.3, 12.8.0.5 이상 버전으로 업데이트하세요. 12.11.0.0 이상도 해당 버전이 아닙니다.", "Update."),
                       ("확인하세요.", "Hinemos 7.0.0 to 7.0.4, 7.1.0 to 7.1.2 and 7.2.0 users should apply the patch."),
                       ("확인하세요.", "Update wasmtime-wasi 48.0.0 or later and before 48.0.8 to 48.0.8, 49.0.0 or later and before "
                                     "49.0.5 to 49.0.5, and 50.0.0 or later and before 50.0.1 to 50.0.1.")):
            with self.subTest(ko):
                self.assertEqual(summaries.many_versions(self.reply(ko, en, fixes=[], fixed="")), "")


class FieldNameTest(unittest.TestCase):
    """Owner, 11-16 late: a reply sent the reader to a field by its name (CVE-2026-122116 "계열별 수정 버전은 fixes에서
    확인하세요.", CVE-2026-99284 "각 계열의 수정 버전은 fixes 항목을 보세요."); the page shows a list under the mitigation."""

    def test_the_prompt_names_the_list_never_the_field(self):
        self.assertIn("아래 목록에서 쓰는 제품의 수정 버전을 확인하세요.", summaries.INSTRUCTIONS)
        self.assertIn("never writes a field name", summaries.INSTRUCTIONS)

    def test_a_field_name_in_korean_text_is_sent_back(self):
        for text in ("계열별 수정 버전은 fixes에서 확인하세요.", "각 계열의 수정 버전은 fixes 항목을 보세요.", "cve_lines를 참고하세요."):
            with self.subTest(text):
                self.assertEqual(summaries.field_names(with_fields("ko", mitigation=text)), f"{summaries.FIELD_NAME} (ko mitigation)")

    def test_a_field_named_in_english_is_sent_back_and_the_word_passes(self):
        for text in ("See fixes for each line's version.", "Each line's fixed version is in the fixes list.",
                     "Check the fixes field for your line.", "The versions are listed in fixes.", "See cve_lines for each flaw."):
            with self.subTest(text):
                self.assertEqual(summaries.field_names(with_fields("en", mitigation=text)), f"{summaries.FIELD_NAME} (en mitigation)")
        # live, 11-16: a file name, a page path, a field written in English, the ordinary "fixed"
        for text in (".library-ms 파일을 여는 것", "@@check-modifier-conditions 페이지에서 확인하세요.", "Using an older Intel library"):
            with self.subTest(text):
                self.assertEqual(summaries.field_names(with_fields("ko", mitigation=text)), "", text)
        for text in ("The update fixes three flaws.", "Install the fixes below.", "Find your product's fixed version in the list below.",
                     "Fixed in 10.6p2; the summary of the advisory lists the conditions.", "It signs tokens with the fixed key 'k'."):
            with self.subTest(text):
                self.assertEqual(summaries.field_names(with_fields("en", mitigation=text)), "", text)


class ExploitedEvidenceTest(unittest.TestCase):
    """Owner, 11-16 ("근거를 엄격하게", then "공격을 밝히면 인정"): exploited only with a KEV CVE, or a Summary reporting that
    attacks were seen, whatever its source, the Incident's own advisory or record included (bird-lg-go cited its own GHSA
    advisory and reported none: it loses the flag; Huatian's own record reports Shadowserver's observations: it keeps it)."""
    ATTACKED = "Attackers are exploiting the flaw to take over servers."
    QUIET = "An unauthenticated attacker can read local files."

    def stored(self, kind, text, url="https://example.com/a"):
        summary = SSHOLE_SUMMARY | {"exploited": True, "exploited_source": url, "en": SSHOLE_SUMMARY["en"] | {"summary": text}}
        return {"id": "x", "cves": ["CVE-2026-1"], "mentions": [{"kind": kind, "url": url}], "summary": summary}

    def test_a_third_party_report_of_attacks_keeps_the_flag(self):
        for kind in ("news", "curator", "notice"):
            self.assertTrue(summaries.attacks_evidenced(self.stored(kind, self.ATTACKED)["summary"], kind), kind)
        # Huatian CVE-2024-58406's words
        first = "Exploitation was first observed by the Shadowserver Foundation on 2024-11-20."
        self.assertTrue(summaries.attacks_evidenced(self.stored("news", first)["summary"], "news"))

    def test_malicious_code_already_delivered_through_the_product_is_an_attack(self):
        # 11-17, the Cursor marketplace case: a tampered Claude Code extension reached users for about 11 hours.
        for text in ("A malicious copy of Anthropic's Claude Code extension placed by the attacker could reach at most 5,000 users.",
                     "Up to 5,000 developers who requested the affected versions may have received malware that tried to install SSH backdoors.",
                     "Attackers pushed tampered copies of the extension to the marketplace for about 11 hours.",
                     "The trojanised installer was distributed from the official download page for two days.",
                     "Users who installed the backdoored package version 1.2.3 must rotate their keys."):
            with self.subTest(text):
                self.assertTrue(summaries.attacks_evidenced(self.stored("news", text)["summary"], "news"))
        for text in ("A proof of concept shows how a malicious extension could be published to the marketplace.",
                     "Researchers warn that attackers could push tampered updates.",
                     "npm removed a malicious package before anyone installed it.",
                     "A malicious update can be delivered if the signing key leaks.",
                     "The company says attackers stole internal data and some credentials.",
                     # how a flaw works is no delivery (live month, 11-17: GeoNode, WCFM, flowintel, Hitachi, Autodesk, Xiaomi)
                     "GeoNode upload check bypass lets malicious files be stored and served",
                     "A stored XSS flaw lets malicious scripts be planted on pages.",
                     "An attacker who has planted a malicious value in the database can run arbitrary SQL.",
                     "A binary planting flaw lets an attacker load a planted malicious file.",
                     "Autodesk Installer can load a malicious DLL placed in an attacker-writable temporary folder.",
                     "A co-installed malicious app can write files to arbitrary paths."):
            with self.subTest(text):
                self.assertFalse(summaries.attacks_evidenced(self.stored("news", text)["summary"], "news"))

    def test_a_supply_chain_attack_that_happened_is_an_attack(self):
        # 11-17 patch run: the fresh SecurityWeek Cursor Summary lost its flag on these words.
        for text in ("Credentials stolen in the Fireworks AI hack let attackers place tampered Claude Code extension copies in the cache.",
                     "A stolen token allowed attackers to publish a malicious update to every customer.",
                     "A supply-chain attack hit the Cursor marketplace on October 29.",
                     "The supply chain compromise affected up to 5,000 developers.",
                     "The supply-chain attack has affected thousands of users."):
            with self.subTest(text):
                self.assertTrue(summaries.attacks_evidenced(self.stored("news", text)["summary"], "news"))
        for text in ("The flaw could lead to a supply chain attack.",
                     "Unsigned updates create a risk of supply-chain attacks.",
                     "A bypass would let attackers push tampered updates.",
                     "The weak check lets attackers upload malicious packages.",
                     "The flaw allows attackers to publish malicious updates.",
                     "A supply-chain attack could hit every user of the plugin."):
            with self.subTest(text):
                self.assertFalse(summaries.attacks_evidenced(self.stored("news", text)["summary"], "news"))

    # 11-17 trial: real attacks lost the flag by wording alone between two runs of the same Incident.
    REPORTED = ("Attacks exploiting this have breached MSPs and their customers' devices.",  # ScreenConnect RMM+
                "Attacks abusing the flaw are hitting exposed servers.",
                "Attacks targeting the flaw have been reported by several vendors.",
                "Attacks are exploiting two flaws across several Barracuda appliances.",  # Barracuda
                "An Outlook spoofing flaw among them is already exploited in attacks.",  # Microsoft November
                "The flaw was exploited in limited, targeted attacks against government agencies.",
                "Exploitation observed by Shadowserver since November 2.",
                "The Shadowserver Foundation first observed exploitation on 2024-11-20.",  # Huatian
                "CISA has seen exploitation of the flaw against federal agencies.",
                "Exploitation has been detected against exposed appliances.",
                "The appliance is under active attack.",
                "The flaw is under attack, Fortinet says.",
                "Researchers tied the flaw to an attack campaign against banks.",
                "Attackers are already exploiting it to deploy ransomware.")
    NOT_REPORTED = ("A proof of concept shows how the flaw could be exploited.",
                    "A researcher's demo shows the flaw used in a simulated attack.",
                    "The researcher's write-up explains how attacks exploiting this would work.",
                    "Attacks are likely once exploit code spreads.",
                    "The flaw may be targeted by attackers.",
                    "The flaw could be exploited in attacks against exposed servers.",
                    "Attacks exploiting the flaw are expected soon.",
                    "Microsoft has not observed exploitation of the flaw.",
                    "No exploitation has been reported so far.",
                    "Exploitation was not observed.",
                    "The servers could come under attack if left exposed.",
                    "The flaw could be used in an attack campaign.",
                    "There is no evidence the flaw has been exploited in the wild.")

    def test_attacks_as_the_subject_and_observed_exploitation_are_reports(self):
        for text in self.REPORTED:
            with self.subTest(text):
                self.assertTrue(summaries.attacks_evidenced(self.stored("news", text)["summary"], "news"))

    def test_a_proof_of_concept_a_demo_a_write_up_a_warning_or_a_denial_is_no_report(self):
        for text in self.NOT_REPORTED:
            with self.subTest(text):
                self.assertFalse(summaries.attacks_evidenced(self.stored("news", text)["summary"], "news"))

    def test_the_source_of_attacks_is_one_the_board_accepts_when_there_is_one(self):
        # 11-17, merged Cursor Incident: 7 of 8 replies named Cursor's own blog post (a write-up) though SecurityWeek,
        # BleepingComputer and a curator stated the same attack; parse() then dropped the flag.
        line = next(l for l in summaries.INSTRUCTIONS.splitlines() if l.startswith("- exploited_source:"))
        self.assertIn("When several sources state them, name a news report, a curator or an official advisory, not a write-up"
                      " or a discussion", line)

    def test_products_name_what_the_reader_installs_not_its_store(self):
        # Owner on the Cursor row (11-17): "저것도 cursor가 맞을텐데 태그" for "Cursor VS Code Extension Marketplace".
        line = next(l for l in summaries.INSTRUCTIONS.splitlines() if l.startswith("- products:"))
        self.assertIn("the product the reader knows and installs, not a part, channel or store of it", line)
        self.assertIn('"Cursor", not "Cursor VS Code Extension Marketplace"', line)

    def test_the_prompt_counts_a_delivered_malicious_package_as_exploited(self):
        line = next(l for l in summaries.INSTRUCTIONS.splitlines() if l.startswith("- exploited:"))
        self.assertIn("put malicious code on users' systems through the product itself", line)
        self.assertIn("a malicious package removed before anyone installed it", line)

    def test_a_summary_that_reports_no_attack_loses_it_whatever_the_source(self):
        for kind in ("advisory", "cve_record", "writeup", "news"):
            self.assertFalse(summaries.attacks_evidenced(self.stored(kind, self.QUIET)["summary"], kind), kind)

    def test_an_own_advisory_or_record_that_reports_attacks_counts(self):
        # The owner's answer of 11-16: a vendor's PSIRT bulletin, or a record that reports observed attacks, is evidence.
        for kind in ("advisory", "cve_record"):
            self.assertTrue(summaries.attacks_evidenced(self.stored(kind, self.ATTACKED)["summary"], kind), kind)

    def test_stored_flags_without_evidence_are_cleared_each_cycle(self):
        weak, strong = self.stored("advisory", self.QUIET), self.stored("news", self.ATTACKED)
        kev = self.stored("advisory", self.QUIET) | {"kev": True}
        changed = summaries.recheck_exploited([weak, strong, kev])
        self.assertEqual([i["id"] for i in changed], ["x"])
        self.assertEqual((weak["summary"]["exploited"], weak["summary"]["exploited_source"]), (False, ""))
        self.assertTrue(strong["summary"]["exploited"])
        self.assertTrue(kev["summary"]["exploited"])  # KEV decides on its own; the Summary flag is not touched
        self.assertEqual(summaries.recheck_exploited([weak, strong]), [])  # a second pass changes nothing


class ReviewedAttackTest(unittest.TestCase):
    """Owner, 11-17 ("패턴이 못 알아보면 검토 요청이 판정"): an exploited flag whose wording ATTACK_SEEN and DELIVERED miss
    is no longer dropped by the pattern when a review runs; the review that follows every Summary is asked whether the
    text reports attacks that already happened, and its answer keeps or drops the flag. Without a review the pattern
    decides, as before; recheck_exploited leaves a flag the review confirmed alone."""
    NEWS = "https://www.securityweek.com/hackers-exploit-widget/"
    MISSED = "Attacks are already confirmed against a couple of dozen Widget customers."  # Barracuda's and Check Point's words
    POC = "A researcher's write-up shows how the flaw could be chained to take over a server."
    SEEN = "Attackers are exploiting the flaw to take over servers."

    def reply(self, text):
        return SSHOLE_SUMMARY | {"lead": self.NEWS, "exploited": True, "exploited_source": self.NEWS,
                                 "en": SSHOLE_SUMMARY["en"] | {"summary": text},
                                 "ko": SSHOLE_SUMMARY["ko"] | {"summary": "Widget 결함에 관한 글입니다."}}

    def save(self, text, claude):
        reply = self.reply(text)
        source = (f"Mentions:\n- writeup {self.NEWS}\nText of {self.NEWS}{summary_input.LEAD_MARK}:\n"
                  + json.dumps(reply, ensure_ascii=False))
        item = {"id": "CVE-2026-1", "cves": ["CVE-2026-1"], "mentions": [{"kind": "writeup", "url": self.NEWS}]}
        with contextlib.redirect_stderr(io.StringIO()):
            summaries.save_reply(item, FakeClaude.message(reply), source, {"cves": [], "kev": False, "advisories": []},
                                 "2026-11-17T12:00:00Z", review_with=claude)
        return item

    def test_a_real_attack_the_pattern_misses_is_kept_when_the_review_says_yes(self):
        self.assertFalse(summaries.attacks_evidenced(self.reply(self.MISSED), "writeup"))
        claude = FakeClaude({"findings": [], "attacks_happened": True})
        item = self.save(self.MISSED, claude)
        self.assertEqual((item["summary"]["exploited"], item["summary"]["exploited_source"]), (True, self.NEWS))
        self.assertTrue(item["summary"]["exploited_review"])
        self.assertNotIn("exploited_unconfirmed", item["summary"])
        self.assertEqual(claude.sent[0]["output_config"]["format"]["schema"], review.ATTACKS_SCHEMA)
        self.assertIn(review.ATTACKS_QUESTION, claude.user_text())

    def test_the_question_excludes_what_the_exploited_rule_excludes(self):
        # 11-17 measurement: without it the review said yes to 6 of 20 company breaches and leaks forced to exploited.
        for words in ("proof of concept", "a warning that attacks may come", "a company's own breach or data leak that delivered nothing to users"):
            self.assertIn(words, review.ATTACKS_QUESTION)

    def test_a_poc_write_up_flagged_exploited_is_dropped_when_the_review_says_no(self):
        item = self.save(self.POC, FakeClaude({"findings": [], "attacks_happened": False}))
        self.assertEqual((item["summary"]["exploited"], item["summary"]["exploited_source"]), (False, ""))
        self.assertNotIn("exploited_review", item["summary"])

    def test_the_verdict_is_no_finding_a_finding_still_costs_the_retry(self):
        finding = {"field": "summary", "lang": "both", "quote": self.MISSED[:30], "against": "", "problem": "x.", "severity": "high"}
        item = self.save(self.MISSED, FakeClaude({"findings": [finding], "attacks_happened": True}))
        self.assertNotIn("summary", item)
        self.assertTrue(item["summary_error"]["reason"].startswith(review.REASON))
        item = self.save(self.MISSED, FakeClaude({"findings": [], "attacks_happened": False}))
        self.assertNotIn("summary_error", item)  # a no drops the flag, never the Summary

    def test_without_a_review_the_pattern_decides(self):
        self.assertFalse(self.save(self.MISSED, None)["summary"]["exploited"])
        self.assertTrue(self.save(self.SEEN, None)["summary"]["exploited"])

    def test_a_review_cut_off_or_unreadable_leaves_the_pattern_to_decide(self):
        item = self.save(self.MISSED, FakeClaude({"findings": []}))  # no attacks_happened in the reply
        self.assertFalse(item["summary"]["exploited"])

    def test_a_flag_the_pattern_recognises_asks_the_review_nothing_more(self):
        claude = FakeClaude({"findings": []})
        item = self.save(self.SEEN, claude)
        self.assertTrue(item["summary"]["exploited"])
        self.assertNotIn("exploited_review", item["summary"])
        self.assertEqual(claude.sent[0]["output_config"]["format"]["schema"], review.SCHEMA)
        self.assertNotIn(review.ATTACKS_QUESTION, claude.user_text())

    def test_recheck_leaves_a_review_confirmed_flag_and_clears_an_unconfirmed_one(self):
        def stored(confirmed):
            summary = self.reply(self.MISSED) | ({"exploited_review": True} if confirmed else {})
            return {"id": "x", "cves": ["CVE-2026-1"], "mentions": [{"kind": "writeup", "url": self.NEWS}], "summary": summary}
        confirmed, unconfirmed = stored(True), stored(False)
        changed = summaries.recheck_exploited([confirmed, unconfirmed])
        self.assertEqual([i["summary"]["exploited"] for i in (confirmed, unconfirmed)], [True, False])
        self.assertEqual(changed, [unconfirmed])


class SameAsProductNameTest(unittest.TestCase):
    """11-17, Optimizely: HN 50524767 ("Optimizely Web") and the BleepingComputer story ("Optimizely") named each other as
    same_as and were refused, "no shared Product". A Product that is the other's name plus further words, on a word
    boundary, is the same Product for a same_as answer; a different product of one vendor still is not."""

    def decide(self, asked, named):
        from test_same_event import PLEX_BC, PLEX_SW, at, no_pages, plain, quiet, story
        from collector import same_event
        candidate = story(PLEX_BC, "2026-11-06T17:10:00Z", "A story", [named])
        asker = story(PLEX_SW, "2026-11-09T13:20:00Z")
        incidents = [candidate, asker]
        stamp = "2026-11-09T13:30:00Z"
        listed = same_event.same_as_candidates(asker, incidents, at(stamp[:-1]))
        quiet(summaries.summarize_now, asker, FakeClaude(plain(asked) | {"same_as": PLEX_BC}), no_pages, stamp, listed)
        (_, log), _ = quiet(same_event.apply_same_as, incidents, stamp)
        return log[0]["why"]

    def test_a_name_plus_further_words_is_the_same_product(self):
        self.assertEqual(self.decide("Optimizely Web", "Optimizely"), "accepted")
        self.assertEqual(self.decide("Optimizely", "Optimizely Web"), "accepted")

    def test_a_longer_word_or_another_product_of_the_vendor_is_not(self):
        self.assertEqual(self.decide("Plexamp", "Plex"), "no shared Product")
        self.assertEqual(self.decide("Plex Web App", "Plex Media Server"), "no shared Product")


class ShownProductNameTest(unittest.TestCase):
    """11-17, owner's screenshot (TELLUS / TELLUS Lite against FUJI ELECTRIC TELLUS / FUJI ELECTRIC TELLUS Lite, "계속
    나오긴 하네"): one Product id shows one name in each language, chosen over the Board's Incidents, and every view shows it.
    The stored Summary is untouched."""
    TELLUS = [{"id": "fuji:tellus", "name": "TELLUS"}, {"id": "fuji:tellus_lite", "name": "TELLUS Lite"}]

    def row(self, n, products, records=(), first_seen=None, ko=None, en=None, platforms=()):
        summary = {"products": list(products), "platforms": list(platforms), "incident": True,
                   "ko": {"names": list(products if ko is None else ko)}, "en": {"names": list(products if en is None else en)}}
        return {"id": f"CVE-2026-{n}", "cves": [f"CVE-2026-{n}"], "first_seen": first_seen or f"2026-11-{n:02d}T00:00:00Z",
                "products": [dict(p) for p in records], "summary": summary, "brief": {"text": "A flaw", "lead": ""}, "mentions": []}

    def shown(self, rows, lang="en"):
        from collector.incidents import named, products_of
        return [{p["id"]: p["name"] for p in products_of(i, lang)} for i in named(rows)]

    def test_a_longer_record_name_is_matched_before_a_shorter_one_it_contains(self):
        from collector.incidents import products_of
        row = self.row(1, ["TELLUS", "TELLUS Lite"], self.TELLUS)
        self.assertEqual({p["id"]: p["name"] for p in products_of(row, "en")}, {"fuji:tellus": "TELLUS", "fuji:tellus_lite": "TELLUS Lite"})

    def test_every_row_shows_one_name_per_id(self):
        rows = [self.row(1, ["TELLUS", "TELLUS Lite"], self.TELLUS),
                self.row(2, ["FUJI ELECTRIC TELLUS", "FUJI ELECTRIC TELLUS Lite"], self.TELLUS)]
        first, second = self.shown(rows)
        self.assertEqual(first, second)

    def test_the_vendor_led_and_bare_names_are_one_group_the_most_used_spelling_wins(self):
        records = [{"id": "jetbrains:youtrack", "name": "Youtrack"}]
        rows = [self.row(n, [name], records) for n, name in enumerate(["YouTrack", "JetBrains YouTrack", "YouTrack"], 1)]
        self.assertEqual({s["jetbrains:youtrack"] for s in self.shown(rows)}, {"YouTrack"})

    def test_a_spelling_that_is_not_all_lower_case_wins_inside_the_group(self):
        rows = [self.row(n, ["nocodb"]) for n in range(1, 5)] + [self.row(9, ["NocoDB"])]
        self.assertEqual({s["name:nocodb"] for s in self.shown(rows)}, {"NocoDB"})

    def test_the_group_most_rows_use_wins_ties_go_to_the_earliest_incident(self):
        records = [{"id": "redhat:enterprise_linux_10", "name": "Enterprise Linux 10"}]
        rows = [self.row(n, [name], records) for n, name in enumerate(
            ["Red Hat Enterprise Linux 10", "Red Hat Enterprise Linux 10.2 Extended Update Support", "Red Hat Enterprise Linux 10"], 1)]
        self.assertEqual({s["redhat:enterprise_linux_10"] for s in self.shown(rows)}, {"Red Hat Enterprise Linux 10"})
        records = [{"id": "acme:gizmo", "name": "Gizmo"}]
        tie = [self.row(2, ["Gizmo Pro Edition"], records), self.row(1, ["Gizmo"], records)]
        self.assertEqual({s["acme:gizmo"] for s in self.shown(tie)}, {"Gizmo"})  # one row each: the earlier Incident's group

    def test_the_record_products_own_name_wins_over_that_name_plus_further_words(self):
        # Parent's decision, 11-17: one id, one name; a sub-product row then shows the product's name.
        grav = [{"id": "getgrav:grav", "name": "Grav"}]
        rows = [self.row(1, ["Grav Lightbox Gallery"], grav), self.row(2, ["grav"], grav)]
        self.assertEqual({s["getgrav:grav"] for s in self.shown(rows)}, {"grav"})
        rancher = [{"id": "suse:rancher", "name": "Rancher"}]  # no row writes the bare name: the record's own name stands
        rows = [self.row(1, ["SUSE Rancher Webhook"], rancher), self.row(2, ["SUSE Rancher Fleet"], rancher)]
        self.assertEqual({s["suse:rancher"] for s in self.shown(rows)}, {"Rancher"})
        nocobase = [{"id": "nocobase:nocobase", "name": "nocobase"}]  # the vendor word is the product: compare whole names
        rows = [self.row(1, ["NocoBase plugin-ai"], nocobase), self.row(2, ["nocobase"], nocobase)]
        self.assertEqual({s["nocobase:nocobase"] for s in self.shown(rows)}, {"nocobase"})
        mi250 = [{"id": "amd:amd_instinct_mi250", "name": "AMD Instinct MI250"}]  # MI250X is no further word
        rows = [self.row(1, ["AMD Instinct MI250"], mi250), self.row(2, ["AMD Instinct MI250X"], mi250)]
        self.assertEqual({s["amd:amd_instinct_mi250"] for s in self.shown(rows)}, {"AMD Instinct MI250"})

    def test_words_only_in_front_of_the_record_name_are_its_vendor_spelling_not_a_sub_product(self):
        # Live month, 11-17: read as a sub-product, "Thales SafeNet ..." lost to the record's machine casing "Safenet ...".
        thales = [{"id": "thalesgroup:safenet_authentication_client_service", "name": "Safenet Authentication Client Service"}]
        rows = [self.row(1, ["Thales SafeNet Authentication Client Service"], thales),
                self.row(2, ["Safenet Authentication Client Service"], [dict(thales[0])] + [{"id": "x:y", "name": "Other"}])]
        rows[1]["summary"] = rows[1]["summary"] | {"products": ["Other"], "ko": {"names": ["Other"]}, "en": {"names": ["Other"]}}
        self.assertEqual({s["thalesgroup:safenet_authentication_client_service"] for s in self.shown(rows)},
                         {"Thales SafeNet Authentication Client Service"})

    def test_a_spelling_a_summary_wrote_comes_before_one_derived_from_the_record_id(self):
        openshift = [{"id": "redhat:openshift", "name": "Openshift"}]
        record_only = [self.row(n, ["Red Hat Satellite"], openshift + [{"id": "redhat:satellite", "name": "Satellite"}]) for n in (1, 2, 3)]
        rows = record_only + [self.row(4, ["Red Hat OpenShift"], openshift)]
        self.assertEqual({s["redhat:openshift"] for s in self.shown(rows)}, {"Red Hat OpenShift"})
        self.assertEqual({s["redhat:openshift"] for s in self.shown(record_only)}, {"Openshift"})  # none written: the record's
        # Live month: 8 Summaries copied "Openshift" from the input's Products line; the machine spelling stays behind.
        copied = [self.row(n, ["Openshift"], openshift) for n in range(5, 13)]
        self.assertEqual({s["redhat:openshift"] for s in self.shown(rows + copied)}, {"Red Hat OpenShift"})

    def test_a_misaligned_names_list_never_puts_one_products_name_under_another_id(self):
        records = [{"id": "redhat:enterprise_linux_10", "name": "Enterprise Linux 10"}]
        row = self.row(1, ["GStreamer", "Red Hat Enterprise Linux 10"], records, en=["Red Hat Enterprise Linux 10"], ko=["GStreamer"])
        for lang in ("en", "ko"):
            shown = self.shown([row], lang)[0]
            self.assertEqual((shown["redhat:enterprise_linux_10"], shown["name:gstreamer"]), ("Red Hat Enterprise Linux 10", "GStreamer"))

    def test_a_korean_name_stays_korean_and_platforms_are_untouched(self):
        rows = [self.row(1, ["Microsoft Paint"], ko=["Windows 그림판"], platforms=["Windows"]), self.row(2, ["Microsoft Paint"], platforms=["Windows"])]
        ko = self.shown(rows, "ko")
        self.assertEqual({s["name:paint"] for s in ko}, {"Windows 그림판"})
        self.assertEqual({s["os:windows"] for s in ko}, {"Windows"})

    def test_the_views_carry_the_chosen_names_and_the_store_keeps_the_summary(self):
        from collector.incidents import board_view, named, rows_view
        rows = [self.row(1, ["TELLUS", "TELLUS Lite"], self.TELLUS),
                self.row(2, ["FUJI ELECTRIC TELLUS", "FUJI ELECTRIC TELLUS Lite"], self.TELLUS)]
        stored = json.dumps(rows, sort_keys=True)
        views = [board_view(i) for i in named(rows)] + [rows_view(i) for i in named(rows)]
        self.assertEqual(len({json.dumps(v["summary"]["products"]) for v in views}), 1)
        self.assertEqual(len({json.dumps(v["summary"]["en"]["names"]) for v in views}), 1)
        self.assertEqual(json.dumps(rows, sort_keys=True), stored)


class KevWindowTest(unittest.TestCase):
    """Owner, 11-17: only an Incident published in the last seven days can be a Highlight; a KEV listing this week no
    longer brings an older one in, so rows carry no kev_last (11-16's field for that rule) any more."""

    def test_no_kev_last_on_rows(self):
        from collector.incidents import order_fields
        group = {"id": "x", "cves": ["CVE-2026-1", "CVE-2026-2"], "kev": True, "kev_date": "2026-11-01",
                 "kev_cves": {"CVE-2026-1": "2026-11-01", "CVE-2026-2": "2026-11-13"}}
        for maps in (True, False):
            self.assertNotIn("kev_last", order_fields(group, maps))

    def test_an_old_incident_listed_this_week_is_not_a_highlight(self):
        from collector import cycle
        old = {"id": "CVE-2026-1", "cves": ["CVE-2026-1"], "first_seen": "2026-10-17T00:00:00Z", "cvss": 9.8, "kev": True,
               "kev_date": "2026-11-15", "mentions": [{"kind": "cve_record"}]}
        self.assertEqual(cycle.highlights([old], "2026-11-09T12:00:00Z"), [])
        self.assertEqual([v["id"] for v in cycle.highlights([old | {"published": "2026-11-10T00:00:00Z"}], "2026-11-09T12:00:00Z")],
                         ["CVE-2026-1"])


class WiredTest(unittest.TestCase):
    """Each new reason costs a retry through save_reply, with its own sentence in the retry note."""

    def test_each_reason_has_a_retry_sentence(self):
        for reason in (summaries.INFORMAL, summaries.BOUND_CHECK, summaries.NO_ACTION, summaries.EMPTY_WITH_FIX,
                       summaries.HANGUL_IN_EN, summaries.ATTACKED_UNNAMED, summaries.MANY_VERSIONS):
            note = summaries.retry({"summary_error": {"tries": 1, "reason": f"{reason} (ko)"}}, TEXT)["note"]
            self.assertNotIn("never shorten or round one", note, reason)
            self.assertGreater(len(note), len(f"Your previous reply for this Incident was rejected: {reason} (ko).") + 20, reason)

    def test_a_reply_with_a_new_problem_is_a_failed_try(self):
        incident = {"id": "x", "mentions": [{"kind": "writeup", "url": SSHOLE_SUMMARY["lead"]}]}
        summaries.save_reply(incident, FakeClaude.message(with_fields("en", easy_action="There is no fix yet.")), TEXT,
                             {"cves": [], "kev": False, "advisories": [], "n": 0}, "2026-11-08T12:00:00Z")
        self.assertIn(summaries.NO_ACTION, incident["summary_error"]["reason"])


if __name__ == "__main__":
    unittest.main()
