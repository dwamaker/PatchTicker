"""The store: named JSON documents. A fake for tests, a local folder for laptops (R2 comes later)."""

import json
import os
from pathlib import Path


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
