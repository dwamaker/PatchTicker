"""Store contract: every store implementation must pass these (the R2 store will too)."""

import tempfile
import unittest

from collector.store import FolderStore, MemoryStore
import test_cycle  # module import, so discovery doesn't run CycleTest a second time here


class MemoryStoreTest(unittest.TestCase):
    def make_store(self):
        return MemoryStore()

    def test_missing_document_reads_as_none(self):
        self.assertIsNone(self.make_store().read("months/2026-11.json"))

    def test_written_document_reads_back_equal(self):
        store = self.make_store()
        doc = {"month": "2026-11", "incidents": [{"id": "CVE-2026-1", "brief": {"text": "요약 준비 중"}}]}
        store.write("months/2026-11.json", doc)
        self.assertEqual(store.read("months/2026-11.json"), doc)

    def test_write_replaces_the_whole_document(self):
        store = self.make_store()
        store.write("status.json", {"updated": "a", "collector": "x"})
        store.write("status.json", {"updated": "b"})
        self.assertEqual(store.read("status.json"), {"updated": "b"})


class FolderStoreTest(MemoryStoreTest):
    def make_store(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return FolderStore(tmp.name)


class CycleOnFolderStoreTest(test_cycle.CycleTest):
    make_store = FolderStoreTest.make_store


if __name__ == "__main__":
    unittest.main()
