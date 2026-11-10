"""The store: named JSON documents. A fake for tests, a local folder for laptops, an R2 bucket when live."""

import json
import os
import sqlite3
from pathlib import Path

import brotli
from botocore.exceptions import ClientError


class MemoryStore:
    def __init__(self):
        self._docs = {}

    def read(self, name):
        raw = self._docs.get(name)
        return None if raw is None else json.loads(raw)

    def write(self, name, doc):
        # Kept serialized so callers can't mutate stored docs by accident, as with a real store.
        self._docs[name] = json.dumps(doc)

    def names(self):
        return sorted(self._docs)


class FolderStore:
    def __init__(self, root):
        self.root = Path(root)

    def read(self, name):
        path = self.root / name
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def write(self, name, doc):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)  # whole-file replace, so a crash never leaves a half-written file

    def names(self):
        return sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob("*")
                      if p.is_file() and not p.name.endswith(".tmp"))


# Stored brotli-compressed (quality 10) with Content-Encoding br: the week a phone downloads first, 1.23 MB against the
# 1.87 MB of Cloudflare's own on-the-fly brotli (owner, 2026-11-10). Never a document the Pages Functions read through
# the R2 binding (pages/, board/feed.json, sitemap.json), which hands them the stored bytes as they are.
BROTLI = {"board/recent.json"}


class R2Store:
    """An R2 bucket through its S3 API; the page reads the same object names through the bucket's custom domain."""

    def __init__(self, s3, bucket):
        self.s3 = s3
        self.bucket = bucket

    def read(self, name):
        try:
            body = self.s3.get_object(Bucket=self.bucket, Key=name)["Body"].read()
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                return None
            raise  # a denied or failed read must not look like an empty store, or a cycle would overwrite real data
        return json.loads(brotli.decompress(body) if name in BROTLI else body)

    def write(self, name, doc):
        # A single PUT replaces the object whole. Short cache: the page checks status.json every 30 s.
        body = json.dumps(doc, ensure_ascii=False).encode("utf-8")
        packed = {"Body": brotli.compress(body, quality=10), "ContentEncoding": "br"} if name in BROTLI else {"Body": body}
        self.s3.put_object(
            Bucket=self.bucket,
            Key=name,
            ContentType="application/json; charset=utf-8",
            CacheControl="public, max-age=30",
            **packed,
        )

    def names(self):
        names, token = [], {}
        while True:  # one page holds at most 1000 keys
            page = self.s3.list_objects_v2(Bucket=self.bucket, **token)
            names += [o["Key"] for o in page.get("Contents", [])]
            if not page.get("IsTruncated"):
                return sorted(names)
            token = {"ContinuationToken": page["NextContinuationToken"]}


class SqliteStore:
    """Every document in one SQLite file: the collector's own copy of the store, to rebuild R2 from."""

    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS docs (name TEXT PRIMARY KEY, body TEXT NOT NULL)")

    def read(self, name):
        row = self.db.execute("SELECT body FROM docs WHERE name = ?", (name,)).fetchone()
        return None if row is None else json.loads(row[0])

    def write(self, name, doc):
        with self.db:  # one transaction per document, so a crash never leaves a half-written row
            self.db.execute(
                "INSERT INTO docs (name, body) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET body = excluded.body",
                (name, json.dumps(doc, ensure_ascii=False)),
            )

    def names(self):
        return [row[0] for row in self.db.execute("SELECT name FROM docs ORDER BY name")]

    def close(self):
        self.db.close()


class BackedUpStore:
    """Reads from the main store; writes to the backup first, so the backup is never behind what R2 got."""

    def __init__(self, main, backup):
        self.main = main
        self.backup = backup

    def read(self, name):
        return self.main.read(name)

    def write(self, name, doc):
        self.backup.write(name, doc)
        self.main.write(name, doc)

    def names(self):
        return self.main.names()


def restore(backup, store):
    """Copy every document from one store into another (months, index, board files, status); returns the count.
    Used both ways: backup into R2 to rebuild it, R2 into the backup to seed it."""
    names = backup.names()
    for name in names:
        store.write(name, backup.read(name))
    return len(names)


def r2_store(endpoint, access_key_id, secret_access_key, bucket):
    import boto3  # only live collectors need it loaded

    # Keys are passed in, never left for boto3 to find in a login profile.
    s3 = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        region_name="auto",
    )
    return R2Store(s3, bucket)
