"""One collection cycle: read the store, fetch each source, link Mentions, write changed files."""

import time

from collector import cvelist, github, hn, osssec
from collector.incidents import link


def run_cycle(store, http_get, now, collector_id, sleep=time.sleep, github_token=None):
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    checkpoints = store.read("checkpoints.json") or {}
    index = store.read("index.json") or {"months": []}
    # shortcut: loads every month to link against; fine for v1 volumes, revisit past a year.
    incidents = [i for m in index["months"] for i in store.read(f"months/{m}.json")["incidents"]]

    records, checkpoints["cvelist"] = cvelist.fetch(checkpoints.get("cvelist"), http_get)
    posts, checkpoints["oss-security"] = osssec.fetch(checkpoints.get("oss-security"), http_get)
    stories, checkpoints["hn"] = hn.fetch(checkpoints.get("hn"), http_get)
    repos, checkpoints["github"] = github.fetch(checkpoints.get("github"), http_get, sleep, github_token)

    changed = set()
    # Join-only repos go last, so they can join Incidents that started this cycle.
    for group in [cvelist.mention_group(r) for r in records] + posts + stories + repos:
        changed |= link(incidents, group, stamp)

    for m in changed:
        # Incidents stay in the month they were first seen; a merge can empty an older month's row.
        store.write(f"months/{m}.json", {"month": m, "incidents": [i for i in incidents if i["first_seen"][:7] == m]})
    if changed - set(index["months"]):
        store.write("index.json", {"months": sorted(changed | set(index["months"]))})
    store.write("checkpoints.json", checkpoints)
    store.write("status.json", {"updated": stamp, "collector": collector_id})
