"""IndexNow (owner, 11-11): with VR_INDEXNOW_KEY set, a cycle tells search engines which Incident pages it wrote."""

import unittest
import urllib.error

from test_discord import FakePoster, quiet
from test_pages import WatchedStore, cycle, row

from collector import indexnow
from collector.cycle import run_cycle
from test_cycle import at, recorded

KEY = "0123456789abcdef0123456789abcdef"


def run(store, ping, now="2026-11-09T12:00:00"):
    _, err = quiet(run_cycle, store, recorded(None), at(now), "test-box", ping=ping)
    return err


class IndexNowTest(unittest.TestCase):
    def setUp(self):
        self.post = FakePoster()
        self.ping, _ = quiet(indexnow.make_pinger, KEY, self.post)

    def test_unset_sends_nothing_and_says_nothing(self):
        for value in (None, ""):
            pinger, err = quiet(indexnow.make_pinger, value, self.post)
            self.assertIsNone(pinger)
            self.assertEqual(err, "")

    def test_a_key_that_is_not_32_lowercase_hex_characters_is_refused_and_never_printed(self):
        for key in ("0123456789ABCDEF0123456789ABCDEF", KEY[:-1], KEY + "0", "../" + KEY[3:], KEY[:-1] + "\n"):
            with self.subTest(key):
                pinger, err = quiet(indexnow.make_pinger, key, self.post)
                self.assertIsNone(pinger)
                self.assertIn("indexnow: VR_INDEXNOW_KEY refused", err)
                self.assertNotIn(KEY[:12], err)
        self.assertEqual(self.post.posts, [])

    def test_a_cycle_sends_its_newly_written_pages_in_both_languages_once(self):
        store = cycle(WatchedStore(), [row(1, cvss=9.8), row(2, cvss=8.0), row(3)])  # row 3 is 참고: noindex, not sent
        self.post.posts.clear()
        run(store, self.ping)
        self.assertEqual(self.post.posts, [])  # nothing written: no request
        months = store.read("months/2026-11.json")
        months["incidents"][1]["cvss"] = 9.1
        store.write("months/2026-11.json", months)
        run(store, self.ping, now="2026-11-09T12:10:00")
        self.assertEqual(self.post.posts, [("https://api.indexnow.org/indexnow", {
            "host": "patchticker.com", "key": KEY, "keyLocation": f"https://patchticker.com/{KEY}.txt",
            "urlList": ["https://patchticker.com/i/CVE-2026-1002", "https://patchticker.com/en/i/CVE-2026-1002"]})])

    def test_the_first_cycle_with_the_key_sends_only_what_it_wrote(self):
        store = cycle(WatchedStore(), [row(1, cvss=9.8), row(2, cvss=9.8)])  # pages written before the key was set
        months = store.read("months/2026-11.json")
        months["incidents"].append(row(3, cvss=9.8))
        store.write("months/2026-11.json", months)
        run(store, self.ping, now="2026-11-09T12:10:00")
        self.assertEqual(self.post.posts[0][1]["urlList"], ["https://patchticker.com/i/CVE-2026-1003", "https://patchticker.com/en/i/CVE-2026-1003"])

    def test_at_most_10000_urls_go_in_one_request(self):
        self.ping([f"CVE-2026-{n}" for n in range(10000, 15001)])
        urls = self.post.posts[0][1]["urlList"]
        self.assertEqual(len(urls), 10000)
        self.assertEqual(urls[-2:], ["https://patchticker.com/i/CVE-2026-14999", "https://patchticker.com/en/i/CVE-2026-14999"])

    def test_a_failed_post_is_one_line_and_the_cycle_still_finishes(self):
        for error in (urllib.error.HTTPError("https://api.indexnow.org/indexnow", 422, "Unprocessable", {}, None), OSError("timed out")):
            with self.subTest(error):
                ping, _ = quiet(indexnow.make_pinger, KEY, FakePoster(error))
                store = WatchedStore()
                store.write("index.json", {"months": ["2026-11"]})
                store.write("months/2026-11.json", {"month": "2026-11", "incidents": [row(1, cvss=9.8)]})
                err = run(store, ping)
                line = [l for l in err.splitlines() if l.startswith("indexnow:")]
                self.assertEqual(line, [f"indexnow: post failed: {422 if isinstance(error, urllib.error.HTTPError) else 'OSError'}"])
                self.assertNotIn(KEY, err)
                self.assertIsNotNone(store.read("status.json"))


if __name__ == "__main__":
    unittest.main()
