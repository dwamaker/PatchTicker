"""An old CVE after its Incident aged out (owner, 11-10: keep 90 days, really). A mere update to its record, an NVD
change, a KEV listing, a PoC repo, a curator issue, a KISA notice or an oss-security reply must not start it again;
a new story about it (HN, a news site, a fresh oss-security post) may, as a new Incident: the accepted cost."""

import json
import unittest
from datetime import datetime, timezone

from test_cycle import KEYCLOAK_TEXT, at, incident, recorded
from test_news_sources import kisa_feed, kisa_link, rss

from collector import curators, kisa, news, nvd
from collector.cvelist import DELTA_LOG_URL
from collector.cycle import run_cycle
from collector.store import MemoryStore

OLD = "CVE-2026-120984"  # the record fixture tests/fixtures/cvelist/CVE-2026-120984.json
RECORD = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/120xxx/CVE-2026-120984.json"
NOW = "2026-11-07T13:30:00"
POSTED = "Sat, 07 Nov 2026 13:00:00 +0000"


def store_with_an_old_incident():
    """OLD first seen 91 days ago (pruned this cycle) beside one recent Incident, so the guard does not trip."""
    store = MemoryStore()
    store.write("checkpoints.json", {"cvelist": "2026-11-07T12:00:00.000Z", "nvd": "2026-11-07T13:15:00.000Z"})
    store.write("index.json", {"months": ["2026-08", "2026-11"]})
    store.write("months/2026-08.json", {"month": "2026-08", "incidents": [incident(OLD, KEYCLOAK_TEXT, "2026-08-08T13:30:00Z")]})
    store.write("months/2026-11.json", {"month": "2026-11", "incidents": [incident("CVE-2026-2", "recent", "2026-11-01T00:00:00Z")]})
    return store


def serve(answers):
    """recorded(), with some URLs (or URL prefixes) answered from `answers` instead; records every URL asked."""
    base, asked = recorded(None), []

    def get(url, headers=None):
        asked.append(url)
        for prefix, body in answers.items():
            if url.startswith(prefix) and "points" not in url:  # the HN points refresh stays recorded()'s
                return body
        return base(url, headers)

    get.asked = asked
    return get


def held(store):
    return [i for m in store.read("index.json")["months"] for i in store.read(f"months/{m}.json")["incidents"]]


class OldCveTest(unittest.TestCase):
    def test_updates_to_an_aged_out_cve_start_nothing_from_any_source(self):
        store = store_with_an_old_incident()
        oss = rss((f"Re: {OLD}: Keycloak policy upload", "https://seclists.org/oss-sec/2026/q4/9", POSTED, OLD))
        get = serve({
            DELTA_LOG_URL: json.dumps([{"fetchTime": "2026-11-07T13:22:16.396Z", "new": [],
                                        "updated": [{"cveId": OLD, "githubLink": RECORD}], "error": []}]).encode(),
            nvd.API_URL: json.dumps({"startIndex": 0, "totalResults": 1, "vulnerabilities": [
                {"cve": {"id": OLD, "published": "2026-08-01T00:00:00.000", "metrics": {}}}]}).encode(),
            "https://www.cisa.gov/": json.dumps({"vulnerabilities": [{"cveID": OLD, "dateAdded": "2026-11-07"}]}).encode(),
            "https://api.github.com/": json.dumps({"items": [{"html_url": "https://github.com/a/poc", "full_name": f"a/{OLD}-poc",
                                                             "description": "PoC", "homepage": None,
                                                             "created_at": "2026-11-07T13:00:00Z"}]}).encode(),
            curators.FEEDS[0]: rss(("Issue 300", "https://tldrsec.com/p/300", POSTED, f"{OLD} again")),
            kisa.FEED: kisa_feed((72300, "Keycloak 보안 업데이트 권고")),
            kisa_link(72300): f"<p>{OLD}</p>".encode(),
            "https://seclists.org/": oss,
        })
        run_cycle(store, get, at(NOW), "test-box", sleep=lambda s: None, curator_feeds=[curators.FEEDS[0]], kisa_feed=kisa.FEED)

        self.assertEqual([i["id"] for i in held(store)], ["CVE-2026-2"])
        self.assertIsNone(store.read("months/2026-08.json"))
        # The cvelist gate reads updated records only of CVEs still held: pruning comes first, so the record is not read.
        self.assertNotIn(RECORD, get.asked)

    def test_a_new_story_about_an_aged_out_cve_starts_a_new_incident(self):
        stories = {
            "hn": ({"https://hn.algolia.com/": json.dumps({"nbPages": 1, "hits": [{
                "objectID": "999", "title": f"{OLD}: Keycloak exploit in the wild", "url": "https://example.org/kc",
                "points": 5, "created_at_i": int(datetime(2026, 11, 7, 13, tzinfo=timezone.utc).timestamp())}]}).encode()}, {}),
            "news": ({news.FEEDS[0]: rss((f"Keycloak flaw {OLD} exploited", "https://www.bleepingcomputer.com/news/security/kc/",
                                          POSTED, "Attacks."))}, {"news_feeds": [news.FEEDS[0]]}),
            "oss-security": ({"https://seclists.org/": rss((f"{OLD}: Keycloak policy upload, new details",
                                                             "https://seclists.org/oss-sec/2026/q4/9", POSTED, OLD))}, {}),
        }
        for source, (answers, options) in stories.items():
            with self.subTest(source):
                store = store_with_an_old_incident()
                run_cycle(store, serve(answers), at(NOW), "test-box", sleep=lambda s: None, **options)

                back = next(i for i in held(store) if OLD in i["cves"])
                self.assertEqual(back["first_seen"], "2026-11-07T13:30:00Z")  # a new Incident, kept 90 days from now
                self.assertIsNone(store.read("months/2026-08.json"))


if __name__ == "__main__":
    unittest.main()
