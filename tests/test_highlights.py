"""Seam 1: the signals a Highlight score reads, replayed against recorded responses.

kev/kev.json and curators/tldrsec.rss are real responses, trimmed (tl;dr sec to three issues,
each cut to the one paragraph that cites something).
"""

import unittest

from collector.cycle import run_cycle
from collector.store import MemoryStore
from test_cycle import at, incident, recorded


class KevTest(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.store.write("checkpoints.json", {"cvelist": "2026-11-07T12:00:00.000Z"})
        self.store.write("index.json", {"months": ["2026-11"]})
        self.store.write("months/2026-11.json", {"month": "2026-11", "incidents": [
            incident("CVE-2026-19868", "SonicWall SonicOS SSLVPN ...", "2026-11-06T20:00:00Z"),
            incident("CVE-2024-6387", "regreSSHion ...", "2026-11-06T20:00:00Z"),
        ]})

    def incidents(self):
        return {i["id"]: i for i in self.store.read("months/2026-11.json")["incidents"]}

    def test_a_recorded_kev_feed_flags_the_listed_incidents_only(self):
        run_cycle(self.store, recorded(None, kev="kev.json"), at("2026-11-07T12:15:00"), "test-box")

        incidents = self.incidents()
        self.assertIs(incidents["CVE-2026-19868"]["kev"], True)
        self.assertNotIn("kev", incidents["CVE-2024-6387"])
        # KEV CVEs that are not on the Board do not become Incidents.
        self.assertEqual(sorted(incidents), ["CVE-2024-6387", "CVE-2026-19868"])

    def test_the_flag_is_written_once(self):
        run_cycle(self.store, recorded(None, kev="kev.json"), at("2026-11-07T12:15:00"), "test-box")
        month = self.store.read("months/2026-11.json")

        run_cycle(self.store, recorded(None, kev="kev.json"), at("2026-11-07T12:30:00"), "test-box")

        self.assertEqual(self.store.read("months/2026-11.json"), month)


TLDRSEC = "https://rss.beehiiv.com/feeds/xgTKUmMmUm.xml"
PHP2SHELL = {  # an Unassigned incident whose write-up tl;dr sec #351 links (with utm_ parameters)
    "id": "https://calif.io/php2shell/",
    "cves": [],
    "first_seen": "2026-10-21T10:00:00Z",
    "mentions": [{"kind": "writeup", "url": "https://calif.io/php2shell/"}],
    "urls": ["calif.io/php2shell"],
    "brief": {"text": "PHP2Shell", "lead": "https://calif.io/php2shell/"},
}


class CuratorTest(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.store.write("checkpoints.json", {"cvelist": "2026-11-07T12:00:00.000Z"})
        self.store.write("index.json", {"months": ["2026-09", "2026-10"]})
        self.store.write("months/2026-09.json", {"month": "2026-09", "incidents": [
            incident("CVE-2026-39987", "marimo ...", "2026-09-10T08:00:00Z"),
            incident("CVE-2024-6387", "regreSSHion ...", "2026-09-10T08:00:00Z"),
        ]})
        self.store.write("months/2026-10.json", {"month": "2026-10", "incidents": [PHP2SHELL]})

    def run_at(self, when, http_get=None):
        run_cycle(self.store, http_get or recorded(None, curators="tldrsec.rss"), at(when), "test-box",
                  curator_feeds=[TLDRSEC])

    def incidents(self):
        return {i["id"]: i for m in ("2026-09", "2026-10") for i in self.store.read(f"months/{m}.json")["incidents"]}

    def test_a_curator_issue_joins_the_incidents_it_cites_by_cve_or_url(self):
        self.run_at("2026-11-07T12:15:00")

        incidents = self.incidents()
        self.assertEqual(incidents["CVE-2026-39987"]["mentions"][1:], [{
            "kind": "curator",
            "url": "https://tldrsec.com/p/tldr-sec-346",
            "title": "[tl;dr sec] #346 - Can AI Do Novel Security Research?, Anthropic's Threat Intel Report, "
                     "How Cloudflare Enforces Engineering Standards",
        }])
        self.assertEqual(
            [m["url"] for m in incidents["https://calif.io/php2shell/"]["mentions"]],
            ["https://calif.io/php2shell/", "https://tldrsec.com/p/tldr-sec-351"],
        )
        self.assertEqual(incidents["CVE-2024-6387"], incident("CVE-2024-6387", "regreSSHion ...", "2026-09-10T08:00:00Z"))
        # The issue's own address is not a key, so the Incidents it cites are not tied together.
        self.assertEqual(incidents["CVE-2026-39987"]["urls"], ["cve.org/CVERecord?id=CVE-2026-39987"])

    def test_an_issue_is_read_once_and_a_failing_feed_does_not_stop_the_cycle(self):
        self.run_at("2026-11-07T12:15:00")
        months = [self.store.read(f"months/{m}.json") for m in ("2026-09", "2026-10")]
        others = recorded(None)

        def down(url, headers=None):
            if url == TLDRSEC:
                raise OSError("HTTP Error 404: Not Found")
            return others(url, headers)

        self.run_at("2026-11-07T12:30:00", down)
        self.run_at("2026-11-07T12:45:00")

        self.assertEqual([self.store.read(f"months/{m}.json") for m in ("2026-09", "2026-10")], months)
        self.assertEqual(self.store.read("status.json")["updated"], "2026-11-07T12:45:00Z")


if __name__ == "__main__":
    unittest.main()
