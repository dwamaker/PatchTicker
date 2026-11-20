"""Owner, 11-20: an official advisory's own CVSS score, read by code from the Summary's input (summary_input.page_scores,
advisory_scores) and kept by the higher-wins rule (summaries.take_advisory_scores). Synology-SA-26:21 stated
"CVSS3 Base Score: 9.8" while CVE-2026-120382 had no published record, and its row stood with no score. The Synology text
is cut from the real page of 11-20 as page_text() gave it."""

import unittest

from collector import summaries, summary_input
from test_advisory_severity import SYNOLOGY, WRITEUP, input_text

CVE = "CVE-2026-120382"
SYNOLOGY_DETAIL = ("Detail CVE-2026-120382 Severity: Critical CVSS3 Base Score: 9.8 CVSS3 Vector: "
                   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H CWE-88: Improper Neutralization of Argument Delimiters in a "
                   "Command An improper neutralization of argument delimiters in a command vulnerability in the OAuth API in "
                   "Synology DiskStation Manager (DSM) before 6.2.4-25556-9 allows remote attackers to read or write arbitrary "
                   "files. Reference CVE-2026-120382 Revision Revision Date Description 1 2026-11-19 Initial public release.")
A, B = "CVE-2026-11111", "CVE-2026-22222"


class PageScoresTest(unittest.TestCase):

    def test_the_real_synology_advisory_gives_9_8_under_cvss_3_1(self):
        self.assertEqual(summary_input.page_scores(SYNOLOGY_DETAIL, [CVE]), {CVE: {"cvss": 9.8, "version": "3.1"}})

    def test_a_page_of_several_cves_gives_each_the_score_after_it(self):
        text = f"{A} Severity: High CVSS v3.1 Base Score: 7.5 text {B} Severity: Medium CVSS v3.1 Base Score: 5.3"
        self.assertEqual(summary_input.page_scores(text, [A, B]), {A: {"cvss": 7.5, "version": "3.1"}, B: {"cvss": 5.3, "version": "3.1"}})

    def test_a_score_after_a_list_of_cves_belongs_to_none(self):
        self.assertEqual(summary_input.page_scores(f"{A} and {B} are fixed. CVSS Score: 9.8", [A, B]), {})

    def test_a_score_far_from_any_cve_on_a_page_of_several_belongs_to_none(self):
        self.assertEqual(summary_input.page_scores(f"{A} {B} " + "x " * 300 + "CVSS Score: 9.8", [A, B]), {})

    def test_a_vector_version_is_never_a_score(self):
        self.assertEqual(summary_input.page_scores(f"{A} CVSS:3.1/AV:N/AC:L/PR:N", [A]), {})

    def test_two_versions_keep_the_higher_and_two_unversioned_scores_keep_none(self):
        self.assertEqual(summary_input.page_scores(f"{A} CVSS 3.1 Base Score: 9.8 CVSS 4.0 Base Score: 9.3", [A]),
                         {A: {"cvss": 9.8, "version": "3.1"}})
        self.assertEqual(summary_input.page_scores(f"{A} CVSS Score: 9.8 and later CVSS Score: 7.0", [A]), {})

    def test_a_score_its_own_vector_contradicts_is_a_typo_and_not_taken(self):
        # Adobe APSB26-101 (11-20 page): 7.8 beside a vector that gives 6.7, the CVE record's score; the next row stands.
        text = (f"{A} Severity: High CVSS base score: 7.8 CVSS vector: CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H "
                f"{B} Severity: High CVSS base score: 7.8 CVSS vector: CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")
        self.assertEqual(summary_input.page_scores(text, [A, B]), {B: {"cvss": 7.8, "version": "3.1"}})

    def test_the_next_scores_vector_is_not_this_ones(self):
        # Siemens and Arista state a 3.1 and a 4.0 score in a row; the 3.1 vector after the second belongs to neither alone.
        text = f"{A} CVSS v3.1 Base Score: 8.2 CVSS v4.0 Base Score: 8.6 Vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        self.assertEqual(summary_input.page_scores(text, [A]), {A: {"cvss": 8.6, "version": "4.0"}})

    def test_cvss3_score_matches_the_specification(self):
        for vector, score in (("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8), ("AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H", 6.7),
                              ("AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N", 7.2), ("AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1),
                              ("AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", 0.0), ("AV:N/AC:L", None)):
            with self.subTest(vector):
                self.assertEqual(summary_input.cvss3_score(vector), score)

    def test_only_the_incidents_own_cves(self):
        self.assertEqual(summary_input.page_scores(f"{A} CVSS v3.1 Base Score: 7.5", [B]), {})


class AdvisoryScoresTest(unittest.TestCase):

    def test_only_an_advisory_page_counts(self):
        text = input_text([("writeup", WRITEUP), ("advisory", SYNOLOGY)], [(WRITEUP, f"{CVE} CVSS Score: 10.0"), (SYNOLOGY, SYNOLOGY_DETAIL)])
        self.assertEqual(summary_input.advisory_scores(text, [CVE]), {CVE: {"cvss": 9.8, "version": "3.1", "source": SYNOLOGY}})
        self.assertEqual(summary_input.advisory_scores(input_text([("writeup", WRITEUP)], [(WRITEUP, SYNOLOGY_DETAIL)]), [CVE]), {})

    def test_the_score_raises_an_unscored_incident_and_never_lowers_a_record(self):
        text = input_text([("advisory", SYNOLOGY)], [(SYNOLOGY, SYNOLOGY_DETAIL)])
        bare = {"id": CVE, "cves": [CVE], "mentions": [{"kind": "advisory", "url": SYNOLOGY}]}
        summaries.take_advisory_scores(bare, text)
        self.assertEqual(bare["cvss"], 9.8)
        self.assertEqual(bare["cve_scores"][CVE], {"cvss": 9.8, "vector": "", "by": "www.synology.com", "version": "3.1"})
        scored = bare | {"cvss": 10.0, "cve_scores": {CVE: {"cvss": 10.0, "vector": "CVSS:3.1/AV:N"}}}
        summaries.take_advisory_scores(scored, text)
        self.assertEqual((scored["cvss"], scored["cve_scores"][CVE]["cvss"]), (10.0, 10.0))
        lower = bare | {"cvss": 7.5, "cve_scores": {CVE: {"cvss": 7.5, "vector": "CVSS:3.1/AV:N"}}}
        summaries.take_advisory_scores(lower, text)
        self.assertEqual(lower["cvss"], 9.8)
        self.assertEqual(lower["cve_scores"][CVE]["record"], {"cvss": 7.5, "vector": "CVSS:3.1/AV:N"})


if __name__ == "__main__":
    unittest.main()
