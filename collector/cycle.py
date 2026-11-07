"""One collection cycle: read the store, fetch each source, link Mentions, write changed files."""

import json
import sys
import time

import anthropic

from collector import curators, cvelist, github, hn, kev, nvd, osssec, summaries
from collector.incidents import cite, enrich, link


def run_cycle(store, http_get, now, collector_id, sleep=time.sleep, nvd_api_key="", github_token=None,
              curator_feeds=(), claude=None):
    """claude: an anthropic.Anthropic client, or None for Briefs only."""
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

    try:
        enriched, checkpoints["nvd"] = nvd.fetch(checkpoints.get("nvd"), now, http_get, sleep, nvd_api_key)
    except (OSError, ValueError, KeyError) as err:
        # NVD is often down; Briefs still go out and the next cycle retries the same range.
        print(f"nvd: skipped this cycle: {err!r}", file=sys.stderr)
        enriched = {}
    exploited = kev.fetch(http_get)
    citations, checkpoints["curators"] = curators.fetch(checkpoints.get("curators"), http_get, curator_feeds)
    for incident in incidents:
        before = json.dumps(incident)
        for cve in incident["cves"]:
            if cve in enriched:
                enrich(incident, enriched[cve])
        if exploited & set(incident["cves"]):
            incident["kev"] = True
        for c in citations:
            cite(incident, c)
        if json.dumps(incident) != before:
            changed.add(incident["first_seen"][:7])

    if claude:
        due = [i for i in incidents if summaries.is_candidate(i, now) and summaries.needs_summary(i)]
        for incident in due[:summaries.MAX_PER_CYCLE]:
            try:
                summaries.summarize(incident, claude, http_get, stamp)
            except anthropic.APIError as err:
                # Briefs still go out; the next cycle asks again (ticket 07 adds the 'paused' status).
                print(f"summaries: stopped this cycle: {err!r}", file=sys.stderr)
                break
            changed.add(incident["first_seen"][:7])

    for m in changed:
        # Incidents stay in the month they were first seen; a merge can empty an older month's row.
        store.write(f"months/{m}.json", {"month": m, "incidents": [i for i in incidents if i["first_seen"][:7] == m]})
    if changed - set(index["months"]):
        store.write("index.json", {"months": sorted(changed | set(index["months"]))})
    store.write("checkpoints.json", checkpoints)
    store.write("status.json", {"updated": stamp, "collector": collector_id})
