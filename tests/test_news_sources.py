"""Security news sites and KISA notices (owner, 2026-11-10): the NIKKE launcher compromise (11-04) had no CVE and only
3-5 HN points, so it waited for a batch; a news site's story is summarized at once and KISA notices join by CVE."""

import unittest
from datetime import datetime

from test_cycle import at, incident, recorded
from test_summaries import FakeClaude, board

from collector import hn, kisa, news, summaries
from collector.cycle import run_cycle
from collector.incidents import on_board
from collector.store import MemoryStore

NIKKE = "https://www.bleepingcomputer.com/news/security/nikke-pc-game-launcher-hacked-to-spread-remote-access-data-stealing-malware/"
FEED = news.FEEDS[0]


def rss(*items):
    return ("<rss><channel>" + "".join(
        f"<item><title>{t}</title><link>{u}</link><pubDate>{d}</pubDate><description>{s}</description></item>"
        for t, u, d, s in items) + "</channel></rss>").encode()


NEWS_FEED = rss(
    ("Nikke PC game launcher hacked to spread remote access, data-stealing malware", NIKKE,
     "Wed, 04 Nov 2026 12:00:00 -0500", "Hackers tampered with the launcher scripts."),
    ("FBI agent stole $2.5 million in crypto from hackers under investigation",
     "https://www.bleepingcomputer.com/news/security/fbi-agent-stole/", "Wed, 04 Nov 2026 11:00:00 -0500", "An arrest."),
)


def kisa_feed(*notices):
    return ("<rss><channel>" + "".join(
        f"<item><title><![CDATA[ {t} ]]></title><link><![CDATA[ {kisa_link(n)} ]]></link><pubDate><![CDATA[ 2026-11-07 ]]></pubDate></item>"
        for n, t in notices) + "</channel></rss>").encode()


def kisa_link(n):
    return f"https://www.boho.or.kr/kr/bbs/view.do?searchCnd=&bbsId=B0000133&menuNo=205020&nttId={n}"


class NewsSourceTest(unittest.TestCase):
    def test_a_news_story_with_a_security_word_may_start_an_incident_and_others_only_join(self):
        groups, checkpoints = news.fetch(None, lambda url, headers=None: NEWS_FEED, [FEED])

        self.assertEqual([g["join_only"] for g in groups], [False, True])
        self.assertEqual(groups[0]["mentions"], [{"kind": "writeup", "url": NIKKE, "title": groups[0]["text"]}])
        self.assertEqual(checkpoints, {FEED: "2026-11-04T17:00:00Z"})
        again, _ = news.fetch(checkpoints, lambda url, headers=None: NEWS_FEED, [FEED])
        self.assertEqual(again, [])

    def test_a_dead_news_feed_is_skipped(self):
        def get(url, headers=None):
            raise OSError("down")
        self.assertEqual(news.fetch({FEED: "x"}, get, [FEED]), ([], {FEED: "x"}))

    def test_supply_chain_attack_is_a_security_word(self):
        story = hn.mention_group({"objectID": "1", "title": "The Gacha game I play everyday, Nikke, was targeted by a supply chain attack",
                                  "url": "https://twitter.com/x/status/1", "created_at_i": 1793800000})
        self.assertFalse(story["join_only"])

    def test_an_hn_story_linking_a_news_site_is_summarized_at_once_whatever_its_points(self):
        now = datetime(2026, 11, 4, 18, 0)
        story = {"cves": [], "first_seen": "2026-11-04T17:30:00Z", "published": "2026-11-04T17:00:00Z",
                 "mentions": [{"kind": "discussion", "url": "https://news.ycombinator.com/item?id=1", "points": 3},
                              {"kind": "writeup", "url": NIKKE}]}
        self.assertTrue(summaries.is_candidate(story, now))
        blog = {**story, "mentions": [story["mentions"][0], {"kind": "writeup", "url": "https://example.com/post"}]}
        self.assertFalse(summaries.is_candidate(blog, now))

    def test_a_cve_less_news_story_waits_for_its_summary_like_an_hn_story(self):
        story = {"id": NIKKE, "cves": []}
        self.assertFalse(on_board(story))
        self.assertTrue(on_board({**story, "summary": {"incident": True}}))
        self.assertFalse(on_board({**story, "summary": {"incident": False}}))
        self.assertTrue(on_board({"id": "https://example.com/post", "cves": []}))

    def test_the_cycle_reads_news_feeds_and_summarizes_their_stories_at_once(self):
        store, claude = MemoryStore(), FakeClaude("not json")
        answer = recorded(None)

        def get(url, headers=None):
            if url == FEED:
                return NEWS_FEED
            if url == NIKKE:
                return b"<html><body><p>Hackers tampered with the NIKKE PC launcher and spread malware to players.</p></body></html>"
            return answer(url, headers)

        run_cycle(store, get, at("2026-11-04T18:00:00"), "test-box", news_feeds=[FEED], claude=claude)

        rows = board(store)
        self.assertEqual(list(rows), [NIKKE])  # the arrest story had no security word and joined nothing
        self.assertFalse(on_board(rows[NIKKE]))  # off the Board until its Summary calls it an Incident
        self.assertEqual(len(claude.sent), 1)
        self.assertIn(NIKKE, claude.user_text())
        self.assertEqual(store.read("checkpoints.json")["news"], {FEED: "2026-11-04T17:00:00Z"})


class KisaTest(unittest.TestCase):
    def test_a_notice_cites_the_cves_on_its_page_and_the_checkpoint_is_its_number(self):
        pages = {kisa_link(72288): "<p>OpenSSH 보안 업데이트 권고 CVE-2026-123158</p>".encode(),
                 kisa_link(72289): "<p>제품 보안 업데이트 권고 (CVE 없음)</p>".encode()}
        feed = kisa_feed((72289, "인피니트헬스케어 제품 보안 업데이트 권고"), (72288, "OpenSSH 보안 업데이트 권고"))
        get = lambda url, headers=None: feed if url == kisa.FEED else pages[url]

        found, checkpoint = kisa.fetch(None, get, kisa.FEED)

        self.assertEqual(found, [{"mention": {"kind": "notice", "url": kisa_link(72288),
                                              "title": "KISA 보호나라: OpenSSH 보안 업데이트 권고"},
                                  "cves": ["CVE-2026-123158"], "urls": []}])
        self.assertEqual(checkpoint, 72289)
        self.assertEqual(kisa.fetch(checkpoint, get, kisa.FEED), ([], 72289))

    def test_a_page_that_fails_is_read_again_next_cycle(self):
        feed = kisa_feed((72289, "B"), (72288, "A"))

        def get(url, headers=None):
            if url == kisa.FEED:
                return feed
            raise OSError("timeout")

        self.assertEqual(kisa.fetch(72287, get, kisa.FEED), ([], 72287))

    def test_the_cycle_adds_a_notice_to_the_incident_of_its_cve(self):
        store = MemoryStore()
        sshole = incident("CVE-2026-123158", "OpenSSH sshd ...", "2026-11-06T00:46:00Z")
        store.write("index.json", {"months": ["2026-11"]})
        store.write("months/2026-11.json", {"month": "2026-11", "incidents": [sshole]})
        feed = kisa_feed((72288, "OpenSSH 보안 업데이트 권고"))
        answer = recorded(None)

        def get(url, headers=None):
            if url == kisa.FEED:
                return feed
            if url == kisa_link(72288):
                return b"<p>CVE-2026-123158</p>"
            return answer(url, headers)

        run_cycle(store, get, at("2026-11-07T01:00:00"), "test-box", kisa_feed=kisa.FEED)

        mentions = board(store)["CVE-2026-123158"]["mentions"]
        self.assertIn({"kind": "notice", "url": kisa_link(72288), "title": "KISA 보호나라: OpenSSH 보안 업데이트 권고"}, mentions)


if __name__ == "__main__":
    unittest.main()
