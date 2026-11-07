"""Seam 1: Mention sources and Incident linking, replayed against recorded responses.

hn/sshole.json, github/sshole.json and oss-security/oss-sec.rss are real responses, trimmed.
The sshole CVE record, its delta log, the Axis2 records and the two-CVE advisory are hand-built
in the real shapes (the non-security HN story in hn/sshole.json is hand-built too).
"""

import json
import unittest

from collector.cycle import run_cycle
from collector.store import MemoryStore
from test_cycle import FIXTURES, at, recorded

HN_STORY = "https://news.ycombinator.com/item?id=50378228"
RELEASE_NOTE = "https://www.openssh.com/txt/release-10.6p2"


class SsholeReplayTest(unittest.TestCase):
    """The HN story, sshhole.com, the oz9un/sshole repo and CVE-2026-123158, in their real order."""

    def setUp(self):
        self.store = MemoryStore()
        self.store.write("checkpoints.json", {"cvelist": "2026-11-05T12:00:00.000Z"})

    def incidents(self):
        return self.store.read("months/2026-11.json")["incidents"]

    def test_hn_story_alone_is_an_unassigned_incident_on_the_board(self):
        run_cycle(self.store, recorded(None, hn="sshole.json"), at("2026-11-05T12:30:00"), "test-box")

        # The non-security story in the same response is not an Incident.
        self.assertEqual(
            self.incidents(),
            [{
                "id": HN_STORY,
                "cves": [],
                "first_seen": "2026-11-05T12:30:00Z",
                "mentions": [
                    {"kind": "discussion", "url": HN_STORY, "title": "sshole", "points": 2935},
                    {"kind": "writeup", "url": "https://sshhole.com"},
                ],
                "urls": ["news.ycombinator.com/item?id=50378228", "sshhole.com"],
                "brief": {"text": "sshole", "lead": "https://sshhole.com"},
            }],
        )

    def test_cve_merges_into_the_unassigned_incident_and_release_note_becomes_lead(self):
        run_cycle(self.store, recorded(None, hn="sshole.json"), at("2026-11-05T12:30:00"), "test-box")
        run_cycle(self.store, recorded("deltaLog-sshole.json"), at("2026-11-05T16:00:00"), "test-box")

        [incident] = self.incidents()
        self.assertEqual(incident["id"], HN_STORY)  # same row as before the CVE
        self.assertEqual(incident["first_seen"], "2026-11-05T12:30:00Z")
        self.assertEqual(incident["cves"], ["CVE-2026-123158"])
        self.assertEqual(
            incident["mentions"],
            [
                {"kind": "discussion", "url": HN_STORY, "title": "sshole", "points": 2935},
                {"kind": "writeup", "url": "https://sshhole.com"},
                {"kind": "cve_record", "url": "https://www.cve.org/CVERecord?id=CVE-2026-123158"},
                {"kind": "advisory", "url": RELEASE_NOTE},
            ],
        )
        self.assertEqual(incident["brief"]["lead"], RELEASE_NOTE)
        self.assertTrue(incident["brief"]["text"].startswith("sshd in OpenSSH before 10.6p2"))

    def test_repos_join_by_homepage_and_by_cve_and_the_replay_ends_as_one_incident(self):
        run_cycle(self.store, recorded(None, hn="sshole.json"), at("2026-11-05T12:30:00"), "test-box")
        run_cycle(self.store, recorded("deltaLog-sshole.json"), at("2026-11-05T16:00:00"), "test-box")
        run_cycle(self.store, recorded(None, github="sshole.json"), at("2026-11-05T23:00:00"), "test-box")

        [incident] = self.incidents()
        self.assertEqual(incident["cves"], ["CVE-2026-123158"])
        self.assertEqual(
            incident["mentions"][4:],
            [
                {"kind": "repo", "url": "https://github.com/oz9un/sshole", "title": "oz9un/sshole"},
                {
                    "kind": "repo",
                    "url": "https://github.com/gabrielunknown/CVE-2026-123158_SSHole",
                    "title": "gabrielunknown/CVE-2026-123158_SSHole",
                },
            ],
        )  # leonjza/sshhole-lab cites neither a CVE nor a known URL, so it is not listed
        self.assertEqual(incident["brief"]["lead"], RELEASE_NOTE)
        # The Board test (seam 2) reads this same row to check that sshole becomes a Highlight.
        self.assertEqual(incident, json.loads((FIXTURES / "board" / "sshole.json").read_bytes()))


class LinkingTest(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.store.write("checkpoints.json", {"cvelist": "2026-11-06T09:00:00.000Z"})

    def incidents(self):
        return self.store.read("months/2026-11.json")["incidents"]

    def test_two_cves_named_in_one_advisory_are_one_row_and_stay_one(self):
        run_cycle(self.store, recorded("deltaLog-axis2.json"), at("2026-11-06T09:15:00"), "test-box")
        self.assertEqual([i["cves"] for i in self.incidents()], [["CVE-2026-123770"], ["CVE-2026-123766"]])

        run_cycle(self.store, recorded(None, oss="axis2-two-cves.rss"), at("2026-11-06T10:00:00"), "test-box")
        run_cycle(self.store, recorded(None, oss="axis2-two-cves.rss"), at("2026-11-06T10:15:00"), "test-box")

        [incident] = self.incidents()
        self.assertEqual(incident["cves"], ["CVE-2026-123770", "CVE-2026-123766"])
        self.assertEqual(
            [m["kind"] for m in incident["mentions"]], ["cve_record", "cve_record", "discussion"]
        )

    def test_merged_rows_keep_the_highest_cvss_and_all_products(self):
        run_cycle(self.store, recorded("deltaLog-axis2.json"), at("2026-11-06T09:15:00"), "test-box")
        month = self.store.read("months/2026-11.json")
        month["incidents"][0] |= {"cvss": 5.3, "products": [{"id": "apache:axis2", "name": "Axis2"}]}
        month["incidents"][1] |= {"cvss": 6.1, "products": [{"id": "apache:axis2_openapi", "name": "Axis2 Openapi"}]}
        self.store.write("months/2026-11.json", month)

        run_cycle(self.store, recorded(None, oss="axis2-two-cves.rss"), at("2026-11-06T10:00:00"), "test-box")

        [incident] = self.incidents()
        self.assertEqual(incident["cvss"], 6.1)
        self.assertEqual([p["id"] for p in incident["products"]], ["apache:axis2", "apache:axis2_openapi"])

    def test_oss_security_posts_start_incidents_and_unmatched_replies_do_not(self):
        run_cycle(self.store, recorded(None, oss="oss-sec.rss"), at("2026-11-07T06:00:00"), "test-box")

        self.assertEqual(
            [(i["cves"], i["brief"]["text"], i["brief"]["lead"]) for i in self.incidents()],
            [
                (
                    ["CVE-2026-118196"],
                    "CVE-2026-118196: Apache Allura: OAuth1 rebinding",
                    "https://seclists.org/oss-sec/2026/q4/565",
                ),
                (
                    [],
                    "InfiniteWP Client: the NOSSL signing key has 31 bits of secret — recovered live in 291.9 seconds",
                    "https://seclists.org/oss-sec/2026/q4/563",
                ),
            ],
        )
        month = self.store.read("months/2026-11.json")
        run_cycle(self.store, recorded(None, oss="oss-sec.rss"), at("2026-11-07T06:15:00"), "test-box")
        self.assertEqual(self.store.read("months/2026-11.json"), month)


class SourceLimitTest(unittest.TestCase):
    """Each adapter stays inside its source's documented limit, even when the source has more."""

    def run_against(self, prefix, page, **cycle_args):
        clock, calls = [0.0], []
        others = recorded(None)

        def get(url, headers=None):
            if not url.startswith(prefix):
                return others(url, headers)
            calls.append((clock[0], headers))
            return page

        def sleep(seconds):
            clock[0] += seconds

        run_cycle(MemoryStore(), get, at("2026-11-07T12:00:00"), "test-box", sleep=sleep, **cycle_args)
        return calls

    def test_github_search_stays_under_30_per_minute_with_the_token(self):
        repo = {"full_name": "a/b", "html_url": "https://github.com/a/b", "created_at": "2026-11-07T11:00:00Z"}
        full_page = json.dumps({"items": [repo] * 100}).encode()

        calls = self.run_against("https://api.github.com/", full_page, github_token="test-token")

        times = [t for t, _ in calls]
        self.assertGreater(len(times), 1)
        for i, t in enumerate(times):
            self.assertLessEqual(sum(1 for u in times[i:] if u < t + 60), 30)
        self.assertGreaterEqual(min(b - a for a, b in zip(times, times[1:])), 60 / 30)
        self.assertTrue(all(h["Authorization"] == "Bearer test-token" for _, h in calls))

    def test_github_search_without_a_token_stays_under_10_per_minute(self):
        repo = {"full_name": "a/b", "html_url": "https://github.com/a/b", "created_at": "2026-11-07T11:00:00Z"}
        calls = self.run_against("https://api.github.com/", json.dumps({"items": [repo] * 100}).encode())

        times = [t for t, _ in calls]
        self.assertGreaterEqual(min(b - a for a, b in zip(times, times[1:])), 60 / 10)
        self.assertTrue(all("Authorization" not in h for _, h in calls))

    def test_hn_reads_at_most_ten_pages_a_cycle(self):
        # 10 requests per 15-minute cycle is 40/h, far under Algolia's 10,000/h per IP.
        calls = self.run_against("https://hn.algolia.com/", b'{"hits": [], "nbPages": 500}')

        self.assertEqual(len(calls), 10)


if __name__ == "__main__":
    unittest.main()
