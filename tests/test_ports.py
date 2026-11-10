"""Values written in both the collector and web/board.mjs stay equal."""

import re
import unittest

from collector import cycle, hn, incidents, summaries


class SharedConstantsTest(unittest.TestCase):
    board = open("web/board.mjs", encoding="utf-8").read()

    def literal(self, name, value):
        """The JS literal assigned to `name`; fails, never skips, when a rename hides it."""
        found = re.search(rf"^(?:export )?const {name} = {value};$", self.board, re.MULTILINE)
        self.assertIsNotNone(found, f"const {name} not found in web/board.mjs")
        return found.group(1)

    def number(self, name):
        return int(self.literal(name, r"(\d+)"))

    def strings(self, name, wrap=r"\[{}\]"):
        return re.findall(r"'([^']*)'", self.literal(name, wrap.format(r"([^\]]*)")))

    def test_the_numbers_match(self):
        for python, js in ((cycle.PAGE_DAYS, "PAGE_DAYS"), (cycle.HIGHLIGHTS, "HIGHLIGHTS"),
                           (cycle.HIGHLIGHTS_MAX, "HIGHLIGHTS_MAX"),
                           (incidents.MENTION_CAP, "MENTION_CAP"), (incidents.HIGHEST_CVSS, "HIGHEST_CVSS"),
                           (hn.BUZZ_POINTS, "HN_BUZZ")):
            with self.subTest(js):
                self.assertEqual(python, self.number(js))

    def test_the_lists_match(self):
        self.assertEqual(incidents.NEWS_HOSTS, set(self.strings("NEWS_HOSTS", r"new Set\(\[{}\]\)")))
        self.assertEqual(incidents.LEAD_ORDER, self.strings("MENTION_ORDER"))
        self.assertEqual(summaries.PLATFORMS, self.strings("OSES"))


if __name__ == "__main__":
    unittest.main()
