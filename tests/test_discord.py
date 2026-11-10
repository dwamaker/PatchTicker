"""Owner, 11-10: the collector posts to a Discord webhook when a Summary is newly given up or a same_as merge happens,
so the owner knows without opening summary_failures.json or merge_log.json."""

import contextlib
import io
import unittest

from collector import discord
from collector.cycle import run_cycle
from collector.store import MemoryStore
from test_batch_summaries import plain
from test_cycle import at, incident, recorded
from test_same_event import PLEX_BC, PLEX_SW, story
from test_summaries import FakeClaude

HOOK = "https://discord.com/api/webhooks/123/secret-token"


class FakePoster:
    def __init__(self, error=None):
        self.posts, self.error = [], error

    def __call__(self, url, payload):
        self.posts.append((url, payload))
        if self.error:
            raise self.error


def quiet(fn, *args, **kwargs):
    with contextlib.redirect_stderr(io.StringIO()) as err:
        result = fn(*args, **kwargs)
    return result, err.getvalue()


def given_up(n, first_seen="2026-11-09T00:00:00Z", **extra):
    return incident(f"CVE-2026-{1000 + n}", f"Brief {n}", first_seen) | {
        "summary_error": {"tries": 3, "final": True, "reason": f"numbers not in the input: ['{n}.9']"}} | extra


def cycle(store, rows, notify, now="2026-11-09T12:00:00", claude=None):
    store.write("index.json", {"months": ["2026-11"]})
    store.write("months/2026-11.json", {"month": "2026-11", "incidents": rows})
    _, err = quiet(run_cycle, store, recorded(None), at(now), "test-box", claude=claude, notify=notify)
    return err


class WebhookSettingTest(unittest.TestCase):
    def test_unset_sends_nothing_and_logs_nothing(self):
        for value in (None, ""):
            notifier, err = quiet(discord.make_notifier, value, FakePoster())
            self.assertIsNone(notifier)
            self.assertEqual(err, "")

    def test_only_a_discord_webhook_url_is_used_and_the_url_is_never_printed(self):
        for url in ("https://example.com/api/webhooks/1/x", "http://discord.com/api/webhooks/1/x",
                    "https://discord.com.evil.test/api/webhooks/1/x", "https://discord.com/api/v9/channels/1",
                    "https://discord.com@evil.test/api/webhooks/1/x", "https://discord.com/api/webhooks/1/x y"):
            with self.subTest(url):
                post = FakePoster()
                notifier, err = quiet(discord.make_notifier, url, post)
                self.assertIsNone(notifier)
                self.assertIn("discord: VR_DISCORD_WEBHOOK refused", err)
                self.assertNotIn("webhooks/1", err)
                self.assertEqual(post.posts, [])
        for url in (HOOK, "https://discordapp.com/api/webhooks/123/secret-token"):
            notifier, err = quiet(discord.make_notifier, url, FakePoster())
            self.assertIsNotNone(notifier)
            self.assertNotIn("secret-token", err)


class CycleNotifyTest(unittest.TestCase):
    def setUp(self):
        self.store, self.post = MemoryStore(), FakePoster()
        self.notify, _ = quiet(discord.make_notifier, HOOK, self.post)

    def test_a_newly_given_up_summary_posts_once_and_not_again_next_cycle(self):
        rows = [given_up(1, summary={"incident": True, "en": {"title": "Old"}, "ko": {"title": "옛"}}), given_up(2)]
        cycle(self.store, rows, self.notify)
        [(url, payload)] = self.post.posts
        self.assertEqual(url, HOOK)
        self.assertEqual(payload["allowed_mentions"], {"parse": []})
        text = payload["content"]
        self.assertIn("`CVE-2026-1001`", text)
        self.assertIn("<https://patchticker.com/#i=CVE-2026-1001>", text)
        self.assertIn("`numbers not in the input: ['1.9']`", text)
        first, second = [line for line in text.split("\n") if "CVE-2026-100" in line]
        self.assertIn("주의", first)  # an old Summary still shows: the dangerous case
        self.assertNotIn("주의", second)

        cycle(self.store, rows, self.notify, now="2026-11-09T12:10:00")
        self.assertEqual(len(self.post.posts), 1)  # already in summary_failures.json

        cycle(self.store, rows + [given_up(3)], self.notify, now="2026-11-09T12:20:00")
        self.assertEqual(len(self.post.posts), 2)
        self.assertIn("CVE-2026-1003", self.post.posts[1][1]["content"])
        self.assertNotIn("CVE-2026-1001", self.post.posts[1][1]["content"])

    def test_nothing_new_posts_nothing(self):
        cycle(self.store, [incident("CVE-2026-1", "Fine", "2026-11-09T00:00:00Z")], self.notify)
        self.assertEqual(self.post.posts, [])

    def test_an_accepted_merge_posts_both_titles_and_the_survivors_link(self):
        old = story(PLEX_BC, "2026-11-06T17:10:00Z", "Plex2Shell lets attackers take over Plex Media Server", ["Plex Media Server"])
        new = story(PLEX_SW, "2026-11-09T13:20:00Z")
        cycle(self.store, [old, new], self.notify, now="2026-11-09T13:30:00",
              claude=FakeClaude(plain("Plex Media Server") | {"same_as": PLEX_BC}))
        [(_, payload)] = self.post.posts
        text = payload["content"]
        self.assertIn("`Plex2Shell lets attackers take over Plex Media Server`", text)
        self.assertIn("`Plex Media Server flaw`", text)
        self.assertIn("<https://patchticker.com/#i=https%3A%2F%2Fwww.bleepingcomputer.com%2F", text)

    def test_the_message_stays_under_discords_limit(self):
        rows = [given_up(n) for n in range(1, 200)]
        cycle(self.store, rows, self.notify)
        text = self.post.posts[0][1]["content"]
        self.assertLessEqual(len(text), 2000)
        self.assertRegex(text.rsplit("\n", 1)[1], r"^외 \d+건$")
        shown = sum(1 for line in text.split("\n") if line.startswith("- "))
        self.assertEqual(int(text.rsplit("\n", 1)[1][2:-1]), 199 - shown)

    def test_a_failing_post_is_logged_and_the_cycle_still_finishes(self):
        notify, _ = quiet(discord.make_notifier, HOOK, FakePoster(OSError("HTTP Error 429: Too Many Requests")))
        err = cycle(self.store, [given_up(1)], notify)
        self.assertIn("discord: post failed", err)
        self.assertNotIn("secret-token", err)
        self.assertEqual(self.store.read("status.json")["collector"], "test-box")
        self.assertEqual(self.store.read("summary_failures.json")[0]["id"], "CVE-2026-1001")


class MessageTextTest(unittest.TestCase):
    def test_backticks_cannot_break_out_of_the_code_span(self):
        text = discord.message([{"id": "CVE-2026-1", "shows": "brief", "reason": "x` @everyone [a](https://evil.test)"}], [])
        self.assertIn("`x' @everyone [a](https://evil.test)`", text)

    def test_no_news_is_no_message(self):
        self.assertEqual(discord.message([], []), "")


if __name__ == "__main__":
    unittest.main()
