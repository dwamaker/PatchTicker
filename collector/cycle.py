"""One collection cycle: read the store, fetch each source, link Mentions, write changed files."""

import json
import sys
import time
from datetime import timedelta

import anthropic

from collector import curators, cvelist, github, hn, kev, nvd, osssec, summaries
from collector.incidents import STAMP, cite, enrich, link, month_of


def run_cycle(store, http_get, now, collector_id, sleep=time.sleep, nvd_api_key="", github_token=None,
              curator_feeds=(), claude=None):
    """claude: an anthropic.Anthropic client, or None for Briefs only."""
    stamp = now.strftime(STAMP)
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
    changed |= hn.refresh_points(incidents, now, http_get)

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
            changed.add(month_of(incident["first_seen"]))

    status = {"updated": stamp, "collector": collector_id}
    batches = store.read("batches.json") or []
    if claude:
        was_paused = (store.read("status.json") or {}).get("summaries") == "paused"
        try:
            route_summaries(incidents, batches, claude, http_get, now, stamp, changed, probe=was_paused)
        except anthropic.APIError as err:
            # Briefs still go out; the next cycle asks again.
            print(f"summaries: stopped this cycle: {err!r}", file=sys.stderr)
            if summaries.is_budget_error(err):
                status["summaries"] = "paused"
        store.write("batches.json", batches)

    for m in changed:
        # Incidents stay in the month they were first seen; a merge can empty an older month's row.
        store.write(f"months/{m}.json", {"month": m, "incidents": [i for i in incidents if month_of(i["first_seen"]) == m]})
    if changed - set(index["months"]):
        store.write("index.json", {"months": sorted(changed | set(index["months"]))})
    store.write("checkpoints.json", checkpoints)
    store.write("status.json", status)


def route_summaries(incidents, batches, claude, http_get, now, stamp, changed, probe):
    """Collect ended batches, summarize Highlight candidates at once, batch the rest. Lets API errors
    through. probe: Summaries were paused last cycle, so send a one-request batch to test the budget
    instead of building a full one that would likely fail."""
    for pending in list(batches):
        touched = summaries.collect_batch(pending, incidents, claude, stamp)
        if touched is not None:
            batches.remove(pending)
            changed.update(month_of(i["first_seen"]) for i in touched)
    waiting = {r["incident"] for b in batches for r in b["requests"].values()}
    due = [i for i in incidents if i["id"] not in waiting and summaries.needs_summary(i)]
    instant = sorted((i for i in due if summaries.is_candidate(i, now)), key=summaries.priority)
    for incident in instant[:summaries.MAX_PER_CYCLE]:
        summaries.summarize_now(incident, claude, http_get, stamp)
        changed.add(month_of(incident["first_seen"]))
    since = (now - timedelta(days=summaries.BATCH_DAYS)).strftime(STAMP)
    rest = [i for i in due if i not in instant and i["first_seen"] >= since]
    pending = summaries.submit_batch(rest, claude, http_get, limit=1 if probe else summaries.MAX_PER_BATCH)
    if pending:
        batches.append(pending)
