"""The store: named JSON documents. A fake for tests, a local folder for laptops, an R2 bucket when live."""

import json
import os
from pathlib import Path

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
        return json.loads(body)

    def write(self, name, doc):
        # A single PUT replaces the object whole. Short cache: the page checks status.json every 30 s.
        self.s3.put_object(
            Bucket=self.bucket,
            Key=name,
            Body=json.dumps(doc, ensure_ascii=False).encode("utf-8"),
            ContentType="application/json; charset=utf-8",
            CacheControl="public, max-age=30",
        )


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
