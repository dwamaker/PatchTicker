"""A cycle spends at most BULK_SECONDS on Incident page and check documents (2026-11-17: a field added to every check
document held one cycle 25 minutes): the rest waits for the next cycle, and a reader meets an older document, never a
name with no document behind it."""

import unittest

from test_cycle import at, recorded
from test_pages import NOW, WatchedStore, row

from collector import cycle as cycle_module
from collector.checks import check_slug
from collector.cycle import digest_of, run_cycle, write_checks
from collector.incidents import named

PER_CYCLE = 3  # documents the fake clock lets through a cycle
BULK = ("pages/", "check/p/")


class Killed(BaseException):
    """What `timeout` does to a cycle: it stops wherever it is, no handler runs."""


class BulkStore(WatchedStore):
    """Its clock moves BULK_SECONDS / PER_CYCLE a page or check written; it dies after `kill_after` of them, if set."""

    kill_after = None

    def write(self, name, doc):
        if name.startswith(BULK):
            if self.kill_after is not None and len(self.bulk()) >= self.kill_after:
                raise Killed(name)
        super().write(name, doc)

    def bulk(self):
        return [n for n in self.writes if n.startswith(BULK)]

    def clock(self):
        return len(self.bulk()) * cycle_module.BULK_SECONDS / PER_CYCLE


def rows(n):
    # Search-worthy (9.8), each with its own Product: n pages and n check documents.
    # kev: attacked, so each page is also worth a sitemap listing (sitemap_worthy, 11-27), which the tests below read.
    return [row(k, cvss=9.8, kev=True, products=[{"id": f"acme:p{k}", "name": f"P{k}"}]) for k in range(1, n + 1)]


def cycle(store, rows=None, now=NOW, bounded=True):
    if rows is not None:
        store.write("index.json", {"months": ["2026-11"]})
        store.write("months/2026-11.json", {"month": "2026-11", "incidents": rows})
    store.reads, store.writes = [], []
    run_cycle(store, recorded(None), at(now), "test-box", clock=store.clock if bounded else lambda: 0)
    return store


def stale(store):
    """The store as a change of format finds it: every document in the old format, its hash that document's own."""
    def old(name):
        doc = store.read(name) | {"old": True}
        store.write(name, doc)
        return digest_of({k: v for k, v in doc.items() if k != "changed"})  # a page's stamp is outside its hash
    store.write("page_hashes.json", {s: e | {"hash": old(f"pages/{s}.json")} for s, e in store.read("page_hashes.json").items()})
    store.write("check_hashes.json", {s: old(f"check/p/{s}.json") for s in store.read("check_hashes.json")})


def old_left(store):
    return [n for n in store.names() if n.startswith(BULK) and store.read(n).get("old")]


def assert_named_exist(test, store):
    """Nothing a reader is pointed to is missing: sitemap pages and products, check index slugs, check details."""
    sitemap = store.read("sitemap.json")
    for slug in sitemap["pages"]:
        test.assertIsNotNone(store.read(f"pages/{slug}.json"), slug)
    for slug in sitemap["products"] + [s for slugs in store.read("check/index.json").values() for s in slugs]:
        doc = store.read(f"check/p/{slug}.json")
        test.assertIsNotNone(doc, slug)
        for entry in doc["incidents"]:
            if "detail" in entry:
                test.assertIsNotNone(store.read(entry["detail"].split(".com/", 1)[1]), entry["detail"])


def assert_hashes_tell_the_store(test, store):
    """Each hash is the stored document's own, so a hash that differs from a cycle's means: still to write."""
    for slug, entry in store.read("page_hashes.json").items():
        page = store.read(f"pages/{slug}.json")
        # The stamp of the change (dateModified) rides outside the hash, which is of the fields alone (write_pages).
        test.assertEqual(page.pop("changed"), entry["changed"], slug)
        test.assertEqual(digest_of(page), entry["hash"], slug)
    for slug, digest in (store.read("check_hashes.json") or {}).items():
        test.assertEqual(digest_of(store.read(f"check/p/{slug}.json")), digest, slug)


class BoundTest(unittest.TestCase):
    def test_a_change_of_format_is_spread_over_cycles_and_every_cycle_ends(self):
        store = cycle(BulkStore(), rows(5), bounded=False)
        stale(store)
        written = []
        for minute in range(10, 60, 10):
            cycle(store, now=f"2026-11-09T12:{minute}:00")
            written.append(len(store.bulk()))
            self.assertIn("status.json", store.writes)  # the cycle reached its end
            assert_named_exist(self, store)
            assert_hashes_tell_the_store(self, store)
        self.assertEqual(written, [3, 3, 3, 1, 0])  # 5 pages, then 5 checks, then nothing left
        self.assertEqual(old_left(store), [])

    def test_new_documents_go_first_and_nothing_names_one_not_yet_written(self):
        store = cycle(BulkStore(), rows(4))
        self.assertEqual(store.bulk(), [f"pages/CVE-2026-100{k}.json" for k in (1, 2, 3)])
        self.assertEqual(sorted(store.read("sitemap.json")["pages"]), ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"])
        self.assertEqual(store.read("check/index.json"), {})  # no check document yet: no name for one
        self.assertEqual(store.read("check_hashes.json") or {}, {})
        assert_named_exist(self, store)
        cycle(store, now="2026-11-09T12:10:00")
        self.assertEqual(store.bulk()[0], "pages/CVE-2026-1004.json")
        self.assertEqual(len(store.read("check_hashes.json")), 2)
        assert_named_exist(self, store)
        assert_hashes_tell_the_store(self, store)

    def test_a_delete_left_over_keeps_its_hash_and_a_later_cycle_deletes_it(self):
        store = cycle(BulkStore(), rows(2), bounded=False)
        gone = f"check/p/{check_slug('acme:p2')}.json"
        months = store.read("months/2026-11.json")
        months["incidents"][1]["products"] = [{"id": "acme:p1", "name": "P1"}]
        store.write("months/2026-11.json", months)
        incidents = named(months["incidents"])
        write_checks(store, incidents, at(NOW), more=lambda: False)
        self.assertIsNotNone(store.read(gone))
        self.assertIn(check_slug("acme:p2"), store.read("check_hashes.json"))
        self.assertNotIn("p2", store.read("check/index.json"))
        write_checks(store, incidents, at(NOW))
        self.assertIsNone(store.read(gone))
        self.assertNotIn(check_slug("acme:p2"), store.read("check_hashes.json"))


class KilledTest(unittest.TestCase):
    def test_a_cycle_killed_half_way_leaves_older_documents_and_the_next_cycle_repairs_them(self):
        store = cycle(BulkStore(), rows(5), bounded=False)
        stale(store)
        store.kill_after = 7  # the 5 pages and 2 checks are written, then the box stops
        with self.assertRaises(Killed):
            cycle(store, now="2026-11-09T12:10:00", bounded=False)
        self.assertEqual(store.read("status.json")["updated"], "2026-11-09T12:00:00Z")  # the killed cycle's never came
        assert_named_exist(self, store)
        store.kill_after = None
        cycle(store, now="2026-11-09T12:20:00", bounded=False)
        assert_named_exist(self, store)
        assert_hashes_tell_the_store(self, store)
        self.assertEqual(old_left(store), [])

    def test_a_first_cycle_killed_half_way_names_nothing_it_did_not_write(self):
        store = BulkStore()
        store.kill_after = 2
        with self.assertRaises(Killed):
            cycle(store, rows(4), bounded=False)
        self.assertIsNone(store.read("sitemap.json"))
        self.assertIsNone(store.read("check/index.json"))
        store.kill_after = None
        cycle(store)  # bounded again: the 3 newest pages, then the next cycle the rest
        assert_named_exist(self, store)
        assert_hashes_tell_the_store(self, store)


if __name__ == "__main__":
    unittest.main()
