"""Store contract: every store implementation must pass these (the R2 store will too)."""

import json
import tempfile
import unittest

from botocore.exceptions import ClientError

from collector.__main__ import load_settings, make_store
from collector.store import FolderStore, MemoryStore, R2Store
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

    def test_half_an_r2_setup_stops_with_the_missing_names(self):
        with self.assertRaises(SystemExit) as stop:
            self.settings("VR_R2_BUCKET=b\n")
        self.assertIn("VR_R2_SECRET_ACCESS_KEY", str(stop.exception))


if __name__ == "__main__":
    unittest.main()
