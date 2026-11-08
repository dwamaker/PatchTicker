"""The picker's Product list: every Product of the last 90 days, not only those on the Board's week.
The same fixture is checked against productList in tests/board.test.mjs, so the two stay in step."""

import json
import unittest
from pathlib import Path

from collector.incidents import product_list

CASE = json.loads((Path(__file__).parent / "fixtures" / "board" / "products-case.json").read_text(encoding="utf-8"))


class ProductListTest(unittest.TestCase):
    def test_lists_products_of_the_last_90_days_in_both_languages(self):
        self.assertEqual(product_list(CASE["incidents"], "2026-08-09T00:00:00Z"), CASE["expected"])


if __name__ == "__main__":
    unittest.main()
