"""Store contract: every store implementation must pass these (the R2 store will too)."""

import json
import tempfile
import unittest

from botocore.exceptions import ClientError

from collector.__main__ import load_settings, make_store, restore_main, seed_backup_main
from collector.store import BackedUpStore, FolderStore, MemoryStore, R2Store, SqliteStore, restore
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

    def test_names_lists_every_document_once(self):
        store = self.make_store()
        store.write("months/2026-11.json", {"a": 1})
        store.write("status.json", {"b": 1})
        store.write("status.json", {"b": 2})
        self.assertEqual(store.names(), ["months/2026-11.json", "status.json"])

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


class FakeS3:
    """The two S3 calls R2Store makes, answering as boto3 does (a missing key raises NoSuchKey)."""

    def __init__(self):
        self.objects = {}

    def get_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey", "Message": "missing"}}, "GetObject")
        body = self.objects[(Bucket, Key)]["Body"]
        return {"Body": type("Body", (), {"read": lambda self: body})()}

    def put_object(self, Bucket, Key, **kwargs):
        self.objects[(Bucket, Key)] = kwargs

    def list_objects_v2(self, Bucket, ContinuationToken=None):
        # One key per page, as boto3 pages at 1000, so the paging loop is exercised.
        keys = sorted(k for b, k in self.objects if b == Bucket)
        start = int(ContinuationToken or 0)
        page = {"Contents": [{"Key": k} for k in keys[start:start + 1]], "IsTruncated": start + 1 < len(keys)}
        if page["IsTruncated"]:
            page["NextContinuationToken"] = str(start + 1)
        return page


class R2StoreTest(MemoryStoreTest):
    def make_store(self):
        self.s3 = FakeS3()
        return R2Store(self.s3, "patchradar")

    def test_documents_are_served_as_short_lived_json(self):
        # The page checks status.json every 30 s, so nothing may be cached longer than that.
        store = self.make_store()
        store.write("status.json", {"updated": "a"})
        obj = self.s3.objects[("patchradar", "status.json")]
        self.assertEqual(obj["ContentType"], "application/json; charset=utf-8")
        self.assertEqual(obj["CacheControl"], "public, max-age=30")
        self.assertEqual(json.loads(obj["Body"].decode("utf-8")), {"updated": "a"})

    def test_other_errors_are_not_read_as_missing(self):
        store = self.make_store()
        def denied(Bucket, Key):
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetObject")
        self.s3.get_object = denied
        with self.assertRaises(ClientError):
            store.read("status.json")


class CycleOnR2StoreTest(test_cycle.CycleTest):
    make_store = R2StoreTest.make_store


def temp_db(test):
    tmp = tempfile.TemporaryDirectory()
    test.addCleanup(tmp.cleanup)
    return f"{tmp.name}/backup.sqlite"


class SqliteStoreTest(MemoryStoreTest):
    def make_store(self):
        store = SqliteStore(temp_db(self))
        self.addCleanup(store.close)
        return store


class BackedUpStoreTest(MemoryStoreTest):
    def make_store(self):
        self.main = MemoryStore()
        self.backup = SqliteStore(temp_db(self))
        self.addCleanup(self.backup.close)
        return BackedUpStore(self.main, self.backup)

    def test_every_write_lands_in_both(self):
        store = self.make_store()
        store.write("status.json", {"updated": "a"})
        self.assertEqual(self.main.read("status.json"), {"updated": "a"})
        self.assertEqual(self.backup.read("status.json"), {"updated": "a"})

    def test_reads_come_from_the_main_store(self):
        store = self.make_store()
        self.backup.write("status.json", {"updated": "old"})
        self.assertIsNone(store.read("status.json"))


class CycleOnBackedUpStoreTest(test_cycle.CycleTest):
    make_store = BackedUpStoreTest.make_store


class RestoreTest(unittest.TestCase):
    def test_restore_rebuilds_every_document_from_the_backup(self):
        # A real cycle fills the main store and the backup; a fresh store rebuilt from the backup matches it.
        main, backup = MemoryStore(), SqliteStore(temp_db(self))
        self.addCleanup(backup.close)
        store = BackedUpStore(main, backup)
        store.write("checkpoints.json", {"cvelist": "2026-11-07T12:00:00.000Z"})
        test_cycle.run_cycle(store, test_cycle.recorded(), test_cycle.at("2026-11-07T13:30:00"), "test-box")

        names = backup.names()
        for expected in ("status.json", "index.json", "months/2026-11.json", "board/recent.json"):
            self.assertIn(expected, names)
        fresh = MemoryStore()
        self.assertEqual(restore(backup, fresh), len(names))
        for name in names:
            self.assertEqual(fresh.read(name), main.read(name), name)


class StoreChoiceTest(unittest.TestCase):
    def settings(self, text):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = f"{tmp.name}/env"
        with open(path, "w", encoding="utf-8") as f:
            f.write("VR_COLLECTOR_ID=t\nVR_CONTACT=c\n" + text)
        return load_settings(path)

    def test_folder_wins_when_set(self):
        self.assertIsInstance(make_store(self.settings("VR_STORE_DIR=x\nVR_R2_BUCKET=b\n")), FolderStore)

    def test_r2_when_no_folder(self):
        store = make_store(self.settings(
            "VR_R2_ENDPOINT=https://a.r2.cloudflarestorage.com\nVR_R2_BUCKET=b\n"
            "VR_R2_ACCESS_KEY_ID=k\nVR_R2_SECRET_ACCESS_KEY=s\n"))
        self.assertIsInstance(store, R2Store)
        self.assertEqual(store.bucket, "b")

    def test_backup_db_wraps_the_store(self):
        db = temp_db(self)
        store = make_store(self.settings(f"VR_STORE_DIR=x\nVR_BACKUP_DB={db}\n"))
        self.addCleanup(store.backup.close)
        self.assertIsInstance(store, BackedUpStore)
        self.assertIsInstance(store.main, FolderStore)

    def test_restore_command_fills_the_store_from_the_backup(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = f"{tmp.name}/backup.sqlite"
        backup = SqliteStore(db)
        backup.write("months/2026-11.json", {"month": "2026-11", "incidents": []})
        backup.write("index.json", {"months": ["2026-11"]})
        backup.close()
        env = f"{tmp.name}/env"
        with open(env, "w", encoding="utf-8") as f:
            f.write(f"VR_COLLECTOR_ID=t\nVR_CONTACT=c\nVR_STORE_DIR={tmp.name}/store\nVR_BACKUP_DB={db}\n")
        restore_main(env)
        folder = FolderStore(f"{tmp.name}/store")
        self.assertEqual(folder.read("index.json"), {"months": ["2026-11"]})
        self.assertEqual(folder.read("months/2026-11.json"), {"month": "2026-11", "incidents": []})

    def test_seed_copies_the_whole_store_into_the_backup(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        folder = FolderStore(f"{tmp.name}/store")
        folder.write("index.json", {"months": ["2026-11"]})
        folder.write("months/2026-11.json", {"month": "2026-11", "incidents": []})
        db = f"{tmp.name}/backup.sqlite"
        env = f"{tmp.name}/env"
        with open(env, "w", encoding="utf-8") as f:
            f.write(f"VR_COLLECTOR_ID=t\nVR_CONTACT=c\nVR_STORE_DIR={tmp.name}/store\nVR_BACKUP_DB={db}\n")
        seed_backup_main(env)
        backup = SqliteStore(db)
        self.addCleanup(backup.close)
        self.assertEqual(backup.names(), ["index.json", "months/2026-11.json"])
        self.assertEqual(backup.read("index.json"), {"months": ["2026-11"]})

    def test_restore_without_a_backup_stops(self):
        with self.assertRaises(SystemExit):
            restore_main(self.settings_path("VR_STORE_DIR=x\nVR_BACKUP_DB=/nonexistent/backup.sqlite\n"))

    def settings_path(self, text):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = f"{tmp.name}/env"
        with open(path, "w", encoding="utf-8") as f:
            f.write("VR_COLLECTOR_ID=t\nVR_CONTACT=c\n" + text)
        return path

    def test_half_an_r2_setup_stops_with_the_missing_names(self):
        with self.assertRaises(SystemExit) as stop:
            self.settings("VR_R2_BUCKET=b\n")
        self.assertIn("VR_R2_SECRET_ACCESS_KEY", str(stop.exception))


if __name__ == "__main__":
    unittest.main()
